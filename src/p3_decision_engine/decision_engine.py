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


class DecisionEngine:
    def __init__(self, config_path="config.yaml"):
        """Initialize the decision engine with configuration."""
        self.config = self.load_config(config_path)
        self.high_context_components = set(self.config.get("high_context_components", []))
        
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
        if srp_score > 7.0:
            return "BLOQUER"
        elif srp_score >= 4.0:
            return "ALERTER"
        else:
            return "PASSER"
    
    def get_ai_analysis(self, vulnerability, srp_score, decision):
        """
        Mock AI analysis function.
        Returns AI-generated explanation and fix recommendations.
        """
        cve_id = vulnerability.get("cve_id", "Unknown")
        package = vulnerability.get("package", "Unknown")
        
        # Mock AI explanations based on decision and vulnerability characteristics
        if decision == "BLOQUER":
            ai_explanation = f"CRITICAL: {cve_id} in {package} présente un risque élevé avec score SRP de {srp_score:.1}. Cette vulnérabilité est activement exploitée selon les données CISA KEV et OTX. Bloquer immédiatement le déploiement et appliquer les correctifs."
            ai_fix = f"URGENT: Mettre à jour {package} vers la version {vulnerability.get('version_fixed', 'latest')} et redémarrer les services affectés. Surveiller les logs d'intrusion pour les 72 prochaines heures."
        
        elif decision == "ALERTER":
            ai_explanation = f"MODÉRÉ: {cve_id} dans {package} a un score SRP de {srp_score:.1}. Bien que non critique, cette vulnérabilité mérite une attention particulière. Planifier la correction dans les prochains jours."
            ai_fix = f"PLANIFIÉ: Mettre à jour {package} vers la version {vulnerability.get('version_fixed', 'latest')} lors de la prochaine fenêtre de maintenance. Documenter la procédure de contournement si nécessaire."
        
        else:  # PASSER
            ai_explanation = f"FAIBLE: {cve_id} dans {package} présente un faible risque avec score SRP de {srp_score:.1}. Pas d'exploitation connue, peut être traitée selon le cycle de maintenance normal."
            ai_fix = f"ROUTINE: Inclure la mise à jour de {package} dans le prochain cycle de patch mensuel. Aucune action immédiate requise."
        
        return {
            "ai_explanation": ai_explanation,
            "ai_fix": ai_fix
        }
    
    def process_vulnerabilities(self, enriched_data):
        """Process all vulnerabilities and generate final report."""
        enriched_vulns = enriched_data.get("enriched_vulnerabilities", [])
        final_report = []
        
        print(f"[*] Processing {len(enriched_vulns)} vulnerabilities...")
        
        for i, vuln in enumerate(enriched_vulns, 1):
            print(f"[*] Processing vulnerability {i}/{len(enriched_vulns)}: {vuln.get('cve_id', 'Unknown')}")
            
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
            
            final_report.append(report_entry)
            
            # Print progress
            print(f"    SRP: {srp_score:.1f} -> {decision}")
        
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