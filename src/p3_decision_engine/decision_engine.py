#!/usr/bin/env python3
"""
P3 Decision Engine - AI-Powered Security Decision Making
Part of the CTI Pipeline Project

This module processes enriched vulnerability data from P2 and applies
mathematical risk scoring with AI-powered decision making.
"""

import json
import yaml
import os
import sys
from datetime import datetime
from pathlib import Path
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed


class DecisionEngine:
    def __init__(self, config_path="config.yaml"):
        """Initialize the decision engine with configuration."""
        self.config = self.load_config(config_path)
        self.high_context_components = set(self.config.get("high_context_components", []))
        
        # AI Configuration from config file
        ai_config = self.config.get("ai_config", {})
        featherless_api_key = os.environ.get("FEATHERLESS_API_KEY", "")
        self.ai_client = OpenAI(
            base_url=ai_config.get("base_url", "https://api.featherless.ai/v1"),
            api_key=featherless_api_key
        ) if featherless_api_key else None
        # Model name from config with fallback
        self.model_name = ai_config.get("model_name", "deepseek-ai/DeepSeek-V4-Flash")
        self.temperature = ai_config.get("temperature", 0.1)
        self.max_tokens = ai_config.get("max_tokens", 4000)
        self.timeout_seconds = ai_config.get("timeout_seconds", 30)
        self.retry_attempts = ai_config.get("retry_attempts", 3)
        
    def load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[!] Config file {config_path} not found, using defaults")
            return {"high_context_components": []}
        except yaml.YAMLError as e:
            print(f"[!] Error parsing config file: {e}")
            return {"high_context_components": []}
    
    def load_enriched_data(self, input_path):
        """Load enriched vulnerability data from P2."""
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"[!] Input file {input_path} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing JSON file: {e}")
            sys.exit(1)
    
    def calculate_srp(self, vulnerability):
        """
        Calculate SRP (Score de Risque Pipeline) for a vulnerability.
        
        FORMULE DU SRP:
        SRP = [(CVSS × 0.4) + (EPSS × 10 × 0.3) + (Exploit_Public × 0.2) + (Threat_Actor × 0.1)] × Modificateur_Contexte
        """
        
        # Extract base values from vulnerability data
        cvss = float(vulnerability.get("cvss_score", 0.0))
        epss = float(vulnerability.get("epss_score", 0.0))
        
        # Extract exploit availability
        threat_intel = vulnerability.get("threat_intelligence", {})
        exploit_public = 10 if threat_intel.get("exploit_available", False) else 0
        
        # Extract threat actor presence
        otx_indicators = vulnerability.get("otx_indicators", [])
        threat_actor = 10 if len(otx_indicators) > 0 else 0
        
        # Calculate context modifier
        package_name = vulnerability.get("package", "")
        context_modifier = 1.5 if package_name in self.high_context_components else 1.0
        
        # Apply SRP formula
        srp_base = (cvss * 0.4) + (epss * 10 * 0.3) + (exploit_public * 0.2) + (threat_actor * 0.1)
        srp_score = srp_base * context_modifier
        
        # Cap at 10.0 as specified
        return min(srp_score, 10.0)
    
    def make_decision(self, srp_score):
        """
        Make decision based on SRP score.
        
        RÈGLES DE DÉCISION:
        - SRP > 7.0 -> "BLOQUER"
        - SRP entre 4.0 et 7.0 -> "ALERTER"  
        - SRP < 4.0 -> "PASSER"
        """
        # Get thresholds from config
        decision_config = self.config.get("decision_thresholds", {})
        block_threshold = decision_config.get("block_threshold", 7.0)
        alert_threshold = decision_config.get("alert_threshold", 4.0)
        
        if srp_score > block_threshold:
            return "BLOQUER"
        elif srp_score >= alert_threshold:
            return "ALERTER"
        else:
            return "PASSER"
    
    def get_ai_analysis(self, vulnerability, srp_score, decision):
        """Appelle Featherless AI pour générer une explication DevSecOps."""
        cve_id = vulnerability.get("cve_id", "Unknown")
        package = vulnerability.get("package", "Unknown")
        
        # Fast-path: Pas d'appel IA pour les failles mineures
        if decision == "PASSER" or not self.ai_client:
            return {
                "ai_explanation": f"Vulnérabilité mineure ({cve_id}) avec SRP de {srp_score:.1f}. Risque faible.",
                "ai_fix": f"Planifier la mise à jour de {package} lors d'un prochain sprint."
            }

        cisa_notes = vulnerability.get("cisa_kev", {}).get("notes", "Non listé dans le KEV")
        otx_data = vulnerability.get("otx_indicators", [])
        threat_actors = [pulse.get("name") for indicator in otx_data for pulse in indicator.get("pulses", [])]
        actors_str = ", ".join(threat_actors) if threat_actors else "Aucun acteur spécifique identifié"
        # Contexte complet (32K tokens dispos, pas de troncature)
        desc = vulnerability.get("description", "") 

        system_prompt = """Tu es un expert DevSecOps impartial et précis.
Ton but est d'expliquer une vulnérabilité à un développeur pour justifier le blocage ou l'alerte de son pipeline CI/CD.
Tu dois être très concis (3 phrases maximum pour l'explication). Utilise un ton professionnel mais alarmiste si la décision est BLOQUER, et pédagogique si c'est ALERTER.

RÈGLES CRUCIALES:
1. Réponds UNIQUEMENT avec un objet JSON valide
2. L'objet doit contenir EXACTEMENT ces deux clés:
   - "ai_explanation": L'explication du risque intégrant le contexte CTI (max 200 caractères)
   - "ai_fix": L'action de remédiation (max 150 caractères)
3. NE JAMAIS tronquer les réponses
4. Vérifie que le JSON est complet avant de répondre
5. Pas de texte avant ou après le JSON

Exemple de format attendu:
{"ai_explanation": "Risque critique avec exploitation active confirmée.", "ai_fix": "Mettre à jour glibc vers 2.35-0ubuntu3.6 immédiatement."}"""

        user_prompt = f"""
Analyse cette vulnérabilité ({decision} - Score SRP: {srp_score:.1f}/10) :
- CVE : {cve_id}
- Package : {package}
- Description : {desc}
- CISA KEV : {cisa_notes}
- Threat Actors : {actors_str}"""

        try:
            print(f"    [IA] Début de l'analyse pour {cve_id}...")
            response = self.ai_client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            # --- NOUVEAU CODE DE NETTOYAGE JSON ---
            raw_content = response.choices[0].message.content.strip()
            
            # Nettoyage complet du contenu JSON
            # 1. Supprime les balises markdown
            if raw_content.startswith("```json"):
                raw_content = raw_content[7:-3].strip()
            elif raw_content.startswith("```"):
                raw_content = raw_content[3:-3].strip()
            
            # 2. Nettoyage des caractères problématiques
            raw_content = raw_content.replace('\u0000', '')  # Caractères nuls
            raw_content = raw_content.replace('\u200b', '')  # Zero-width spaces
            
            # 3. Nettoyage avancé et reconstruction JSON
            try:
                # Vérifie si le JSON commence correctement
                raw_content = raw_content.strip()
                
                # Reconstruction JSON robuste
                # Cas 1: JSON commence par 'ai_explanation"
                if raw_content.startswith("'ai_explanation"):
                    # 'ai_explanation": "texte..." → {"ai_explanation": "texte...", "ai_fix": "..."}
                    parts = raw_content.split('"ai_fix":')
                    if len(parts) > 1:
                        raw_content = '{"ai_explanation":' + parts[0].replace("'ai_explanation\": ", "") + '"ai_fix":' + parts[1]
                    else:
                        raw_content = '{"ai_explanation":' + raw_content.replace("'ai_explanation\": ", "") + '}'
                
                # Cas 2: JSON commence par autre chose
                elif not raw_content.startswith('{'):
                    if 'ai_explanation' in raw_content:
                        raw_content = '{"ai_explanation": ' + raw_content.replace("'ai_explanation": ", "")
                    elif 'ai_fix' in raw_content:
                        raw_content = '{"ai_fix": ' + raw_content.replace("'ai_fix": ", "")
                
                # Cas 3: Nettoyage des apostrophes incorrectes
                raw_content = raw_content.replace("'ai_explanation\"", '"ai_explanation"')
                raw_content = raw_content.replace("'ai_fix\"", '"ai_fix"')
                
                # Vérifie si le JSON se termine correctement
                if not raw_content.endswith('}'):
                    raw_content = raw_content + '}'
                
                result = json.loads(raw_content)
                
            except json.JSONDecodeError as e:
                print(f"    [!] JSON parsing error: {e}")
                print(f"    [!] Raw content: {repr(raw_content[:200])}")
                # Fallback sur réponse par défaut
                result = {
                    "ai_explanation": f"Alerte CTI de niveau {decision}. (Erreur parsing JSON).",
                    "ai_fix": f"Vérifiez les correctifs de sécurité pour {package}."
                }
            # --------------------------------------
            print(f"    [IA] Analyse terminée pour {cve_id}.")
            return {
                "ai_explanation": result.get("ai_explanation", "Alerte CTI critique."),
                "ai_fix": result.get("ai_fix", "Mettre à jour le package immédiatement.")
            }
        except Exception as e:
            print(f"    [!] Erreur IA pour {cve_id}: {e}")
            return {
                "ai_explanation": f"Alerte CTI de niveau {decision}. (Analyse IA indisponible).",
                "ai_fix": f"Vérifiez les correctifs de sécurité pour {package}."
            }
    
    def _process_single_vuln(self, vuln):
        """Process a single vulnerability with SRP calculation and AI analysis."""
        cve_id = vuln.get('cve_id', 'Unknown')
        print(f"[*] Processing vulnerability: {cve_id}")
        
        # Calculate SRP score
        srp_score = self.calculate_srp(vuln)
        
        # Make decision
        decision = self.make_decision(srp_score)
        
        # Get AI analysis
        ai_analysis = self.get_ai_analysis(vuln, srp_score, decision)
        
        # Build final report entry
        report_entry = {
            "cve_id": vuln.get("cve_id", ""),
            "package": vuln.get("package", ""),
            "srp_score": round(srp_score, 1),
            "decision": decision,
            "ai_explanation": ai_analysis["ai_explanation"],
            "ai_fix": ai_analysis["ai_fix"],
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # Print progress
        print(f"    SRP: {srp_score:.1f} -> {decision}")
        return report_entry
    
    def process_vulnerabilities(self, enriched_data):
        """Process all vulnerabilities with multithreading and generate final report."""
        enriched_vulns = enriched_data.get("enriched_vulnerabilities", [])
        final_report = []
        
        # Get performance config
        perf_config = self.config.get("performance", {})
        max_workers = perf_config.get("max_workers", 4)
        
        print(f"[*] Processing {len(enriched_vulns)} vulnerabilities with {max_workers} parallel threads...")
        
        # Use ThreadPoolExecutor for parallel processing (configurable workers)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all vulnerabilities for processing
            future_to_vuln = {
                executor.submit(self._process_single_vuln, vuln): vuln 
                for vuln in enriched_vulns
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_vuln):
                try:
                    result = future.result()
                    final_report.append(result)
                except Exception as e:
                    vuln = future_to_vuln[future]
                    print(f"[!] Error processing {vuln.get('cve_id', 'Unknown')}: {e}")
        
        # Sort final report by SRP score descending
        final_report.sort(key=lambda x: x["srp_score"], reverse=True)
        
        return final_report
    
    def generate_final_report(self, final_report, output_path):
        """Generate and save the final report."""
        # Create report structure
        report_data = {
            "decision_metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "engine_version": "1.0.0",
                "config_used": {
                    "high_context_components": list(self.high_context_components)
                },
                "total_processed": len(final_report),
                "decisions": {
                    "BLOQUER": sum(1 for r in final_report if r["decision"] == "BLOQUER"),
                    "ALERTER": sum(1 for r in final_report if r["decision"] == "ALERTER"),
                    "PASSER": sum(1 for r in final_report if r["decision"] == "PASSER")
                },
                "average_srp": round(sum(r["srp_score"] for r in final_report) / len(final_report), 1) if final_report else 0.0
            },
            "vulnerability_decisions": final_report
        }
        
        # Save to file
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"[*] Final report saved to: {output_path}")
        return report_data
    
    def run(self, input_path="../../shared/2_enriched.json", output_path="../../shared/3_final_report.json"):
        """Run the complete decision engine process."""
        print("=" * 60)
        print("  P3 DECISION ENGINE - AI-POWERED SECURITY ANALYSIS")
        print("=" * 60)
        
        # Load enriched data
        print(f"[*] Loading enriched data from: {input_path}")
        enriched_data = self.load_enriched_data(input_path)
        
        # Process vulnerabilities
        final_report = self.process_vulnerabilities(enriched_data)
        
        # Generate final report
        report_data = self.generate_final_report(final_report, output_path)
        
        # Print summary
        print(f"\n{'='*60}")
        print("  DECISION ENGINE SUMMARY")
        print(f"{'='*60}")
        print(f"  Total vulnerabilities processed: {len(final_report)}")
        print(f"  BLOQUER (critical): {report_data['decision_metadata']['decisions']['BLOQUER']}")
        print(f"  ALERTER (moderate):  {report_data['decision_metadata']['decisions']['ALERTER']}")
        print(f"  PASSER (low):        {report_data['decision_metadata']['decisions']['PASSER']}")
        print(f"  Average SRP score:   {report_data['decision_metadata']['average_srp']}")
        print(f"  Final report:        {output_path}")
        print(f"{'='*60}\n")
        
        # Exit with appropriate code based on critical decisions
        if report_data['decision_metadata']['decisions']['BLOQUER'] > 0:
            print("[!] Critical vulnerabilities detected - pipeline should be blocked!")
            sys.exit(1)
        
        print("[✓] No critical decisions - pipeline can continue")
        return report_data


def main():
    """Main entry point for the decision engine."""
    # Initialize and run decision engine
    engine = DecisionEngine()
    return engine.run()


if __name__ == "__main__":
    main()