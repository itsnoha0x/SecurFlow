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
import re
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
        
        if decision == "PASSER" or not self.ai_client:
            return {
                "ai_explanation": f"Vulnérabilité mineure ({cve_id}) avec SRP de {srp_score:.1f}. Risque faible.",
                "ai_fix": f"Planifier la mise à jour de {package} lors d'un prochain sprint."
            }

        cisa_notes = vulnerability.get("cisa_kev", {}).get("notes", "Non listé dans le KEV")
        otx_data = vulnerability.get("otx_indicators", [])
        threat_actors = [pulse.get("name") for indicator in otx_data for pulse in indicator.get("pulses", [])]
        actors_str = ", ".join(threat_actors) if threat_actors else "Aucun acteur spécifique identifié"
        desc = vulnerability.get("description", "") 

        # --- CHARGEMENT DES PROMPTS DEPUIS LES FICHIERS ---
        # Charger le system prompt depuis le fichier
        with open('prompts/system_prompt.txt', 'r', encoding='utf-8') as f:
            system_prompt = f.read()
        
        # Charger le template de user prompt depuis le fichier
        with open('prompts/user_prompt_template.txt', 'r', encoding='utf-8') as f:
            user_template = f.read()
        
        # Formater le user prompt avec les variables
        user_prompt = user_template.format(
            decision=decision,
            srp_score=srp_score,
            cve_id=cve_id,
            package=package,
            desc=desc,
            cisa_notes=cisa_notes,
            actors_str=actors_str
        )

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
            
            raw_content = response.choices[0].message.content.strip()
            print(f"    [DEBUG RAW] {repr(raw_content)}")
            
            # --- LE BLINDAGE ABSOLU ---
            
            # 1. Si l'IA a oublié l'accolade ouvrante, on la rajoute !
            if not raw_content.startswith('{'):
                # On enlève les guillemets ou apostrophes parasites au tout début
                raw_content = raw_content.lstrip("'")
                if raw_content.startswith('"ai_explanation"'):
                    raw_content = '{' + raw_content
                else:
                    raw_content = '{"ai_explanation": "' + raw_content
                    
            # 2. Si l'IA a oublié l'accolade fermante
            if not raw_content.endswith('}'):
                raw_content = raw_content + '}'
                
            # 3. Nettoyage des vieilles hallucinations
            raw_content = raw_content.replace('"ai_explanation": ai_explanation":', '"ai_explanation":')
            raw_content = raw_content.replace('"ai_fix": ai_fix":', '"ai_fix":')

            try:
                # On essaie de lire le JSON réparé
                start_idx = raw_content.find('{')
                end_idx = raw_content.rfind('}')
                clean_json = raw_content[start_idx:end_idx+1]
                
                result = json.loads(clean_json)
                
            except Exception as e:
                # 4. MODE SURVIE ULTIME : Le Regex
                print(f"    [!] Le JSON est toujours rebelle, passage au Regex : {e}")
                import re
                # On cherche tout ce qui est entre les guillemets après la clé
                exp_match = re.search(r'"ai_explanation"\s*:\s*"(.*?)"\s*,', raw_content, re.DOTALL)
                fix_match = re.search(r'"ai_fix"\s*:\s*"(.*?)"\s*}', raw_content, re.DOTALL)
                
                result = {
                    "ai_explanation": exp_match.group(1).strip() if exp_match else "Alerte CTI critique détectée.",
                    "ai_fix": fix_match.group(1).strip() if fix_match else "Mise à jour immédiate requise."
                }

            print(f"    [IA] Analyse terminée pour {cve_id}.")
            return {
                "ai_explanation": result.get("ai_explanation", "Alerte CTI critique."),
                "ai_fix": result.get("ai_fix", "Mettre à jour le package immédiatement.")
            }
            
        except Exception as e:
            print(f"    [!] Erreur IA critique pour {cve_id}: {e}")
            return {
                "ai_explanation": f"Alerte CTI de niveau {decision}. (Erreur API IA).",
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
            # Conclusion et affichage du lien pour le jury
            print(f"\n{'='*60}")
            print(" 🔍 ANALYSE SECURFLOW TERMINÉE")
            print(f" 🌐 Dashboard : https://itsnoha0x.github.io/SecurFlow/")
            print(f"{'='*60}\n")
            sys.exit(1)
        
        print("[✓] No critical decisions - pipeline can continue")
        # Conclusion et affichage du lien pour le jury
        print(f"\n{'='*60}")
        print(" 🔍 ANALYSE SECURFLOW TERMINÉE")
        print(f" 🌐 Dashboard : https://itsnoha0x.github.io/SecurFlow/")
        print(f"{'='*60}\n")
        return report_data


def main():
    """Main entry point for the decision engine."""
    # Initialize and run decision engine
    engine = DecisionEngine()
    return engine.run()


if __name__ == "__main__":
    main()