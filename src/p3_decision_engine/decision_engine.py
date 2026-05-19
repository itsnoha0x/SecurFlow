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
import time
import sys
import re
from datetime import datetime
from pathlib import Path
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed


class DecisionEngine:
    def __init__(self, config_path=None):
        """Initialize the decision engine with configuration."""
        self.base_dir = Path(__file__).parent
        # Utilise un chemin absolu pour config.yaml si aucun chemin n'est fourni
        effective_config = config_path if config_path else self.base_dir / "config.yaml"
        self.config = self.load_config(effective_config)
        self.high_context_components = set(self.config.get("high_context_components", []))
        
        # AI Configuration from config file
        ai_config = self.config.get("ai_config", {})
        featherless_api_key = os.environ.get("FEATHERLESS_API_KEY", "")
        self.ai_client = OpenAI(
            base_url=ai_config.get("base_url", "https://api.featherless.ai/v1"),
            api_key=featherless_api_key
        ) if featherless_api_key else None
        # Model name from config with fallback
        self.model_name = ai_config.get("model_name", "Qwen/Qwen3.6-35B-A3B")
        self.temperature = ai_config.get("temperature", 0.1)
        self.max_tokens = ai_config.get("max_tokens", 1000)
        self.timeout_seconds = ai_config.get("timeout_seconds", 30)
        self.retry_attempts = ai_config.get("retry_attempts", 3)
        
        # Pré-chargement des prompts pour de meilleures performances et robustesse
        self.system_prompt = self._load_prompt_file("prompts/system_prompt.txt")
        self.user_template = self._load_prompt_file("prompts/user_prompt_template.txt")

    def _load_prompt_file(self, relative_path):
        """Charge un fichier de prompt de manière sécurisée."""
        path = self.base_dir / relative_path
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            print(f"[!] Impossible de charger le prompt {path}: {e}")
            return ""

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

        # Préparation des données CTI
        cisa_data = vulnerability.get("cisa_kev", {})
        cisa_notes = cisa_data.get("notes", "Non listé dans le KEV") if isinstance(cisa_data, dict) else "Non listé"
        
        otx_data = vulnerability.get("otx_indicators", [])
        threat_actors = [pulse.get("name") for indicator in otx_data for pulse in indicator.get("pulses", [])]
        actors_str = ", ".join(threat_actors) if threat_actors else "Aucun acteur spécifique identifié"
        
        # Correction de l'extraction de la description (recherche profonde)
        description = vulnerability.get("description")
        if not description:
            description = vulnerability.get("threat_intelligence", {}).get("nvd", {}).get("description", "Aucune description fournie.")
        
        user_prompt = self.user_template.format(
            decision=decision,
            srp_score=srp_score,
            cve_id=cve_id,
            package=package,
            desc=description,
            cisa_notes=cisa_notes,
            actors_str=actors_str
        )

        for attempt in range(self.retry_attempts):
            try:
                print(f"    [IA] Début de l'analyse pour {cve_id} (Tentative {attempt + 1})...")
                response = self.ai_client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"},
                    max_tokens=self.max_tokens,
                    timeout=self.timeout_seconds,
                    temperature=self.temperature
                )
                
                raw_content = response.choices[0].message.content.strip()

                # --- EXTRACTION JSON ROBUSTE ---
                # On cherche le premier { et le dernier } pour ignorer le texte superflu (Markdown, etc.)
                try:
                    start = raw_content.find('{')
                    end = raw_content.rfind('}')
                    result = json.loads(raw_content[start:end+1])
                except Exception:
                    # FALLBACK REGEX (Mode survie)
                    exp_match = re.search(r'"ai_explanation"\s*:\s*"(.*?)"', raw_content, re.DOTALL)
                    fix_match = re.search(r'"ai_fix"\s*:\s*"(.*?)"', raw_content, re.DOTALL)
                    if exp_match:
                        result = {
                            "ai_explanation": exp_match.group(1).strip(),
                            "ai_fix": fix_match.group(1).strip() if fix_match else "Mise à jour recommandée."
                        }
                    else:
                        continue # On tente le retry

                # Affichage d'un aperçu pour confirmer que l'IA a travaillé
                preview = result.get('ai_explanation', '')[:75] + "..."
                print(f"    [IA] Analyse terminée pour {cve_id}. Réponse: {preview}")
                
                # Délai augmenté pour garantir la libération des unités de confluence sur Featherless
                time.sleep(2.0)
                return {
                    "ai_explanation": result.get("ai_explanation", "Alerte CTI critique."),
                    "ai_fix": result.get("ai_fix", "Mettre à jour le package immédiatement.")
                }
                
            except Exception as e:
                if any(msg in str(e).lower() for msg in ["429", "concurrency_limit_exceeded"]) and attempt < self.retry_attempts - 1:
                    # Backoff plus agressif pour les limites de confluence
                    wait_time = (attempt + 1) * 5
                    print(f"    [!] Limite de confluence atteinte (429). Pause de {wait_time}s...")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"    [!] Erreur IA critique pour {cve_id}: {e}")
                    return {
                        "ai_explanation": f"Alerte CTI de niveau {decision}. (Erreur API IA).",
                        "ai_fix": f"Vérifiez les correctifs de sécurité pour {package}."
                    }

        return {
            "ai_explanation": f"Analyse IA échouée après {self.retry_attempts} tentatives.",
            "ai_fix": "Vérification manuelle requise."
                }
    
    def _process_single_vuln(self, vuln):
        """Process a single vulnerability with SRP calculation and AI analysis."""
        cve_id = vuln.get('cve_id', 'Inconnu')
        print(f"[*] Processing vulnerability: {cve_id}")
        
        # Calcul et arrondi immédiat pour la cohérence de la décision
        srp_score = round(self.calculate_srp(vuln), 1)
        
        # Make decision
        decision = self.make_decision(srp_score)
        
        # Get AI analysis
        ai_analysis = self.get_ai_analysis(vuln, srp_score, decision)
        
        # Build final report entry
        report_entry = {
            "cve_id": vuln.get("cve_id", ""),
            "package": vuln.get("package", ""),
            "srp_score": srp_score,
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
        
        # Restauration du parallélisme depuis la config
        perf_config = self.config.get("performance", {})
        max_workers = perf_config.get("max_workers", 1) # Par défaut 1 pour éviter les 429
        
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
    
    def run(self, input_path=None, output_path=None):
        """Run the complete decision engine process."""
        # Priorité aux chemins fournis en argument, sinon ceux du config.yaml, sinon les défauts
        config_paths = self.config.get("paths", {})
        input_path = input_path or config_paths.get("input_file", "../../shared/2_enriched.json")
        output_path = output_path or config_paths.get("output_file", "../../shared/3_final_report.json")

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