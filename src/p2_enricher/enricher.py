"""
P2 - Enrichisseur CTI (Cyber Threat Intelligence)
==================================================
Auteur  : Hajar
Rôle    : Prend 1_raw_results.json (sorti par P1/Kenza) et produit
          2_enriched.json en croisant chaque CVE avec 4 sources CTI :
            1. NVD (NIST)
            2. CISA KEV
            3. OSV (Google)
            4. AlienVault OTX

Usage   : python enricher.py
"""

import json
import os
import sqlite3
import time
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv

# ── Tentative d'import OTX (optionnel, fallback si absent) ──────────────────
try:
    from OTXv2 import OTXv2
    OTX_AVAILABLE = True
except ImportError:
    OTX_AVAILABLE = False
    logging.warning("Librairie OTXv2 non installée. pip install OTXv2")

# ── Configuration du logging ─────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# ── Chargement des variables d'environnement ──────────────────────────────────
load_dotenv()
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
OTX_API_KEY  = os.getenv("OTX_API_KEY", "")

# ── Chemins des fichiers ──────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
SHARED_DIR  = os.path.join(BASE_DIR, "..", "..", "shared")
INPUT_FILE  = os.path.join(SHARED_DIR, "1_raw_results.json")
OUTPUT_FILE = os.path.join(SHARED_DIR, "2_enriched.json")
CACHE_DB    = os.path.join(BASE_DIR, "cache.sqlite")

# ── URLs des APIs ─────────────────────────────────────────────────────────────
NVD_BASE_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API_URL   = "https://api.osv.dev/v1/query"


# =============================================================================
#  CACHE SQLITE
# =============================================================================

def init_cache(db_path: str) -> sqlite3.Connection:
    """Initialise la base de données cache SQLite."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache (
            cache_key   TEXT PRIMARY KEY,
            data        TEXT NOT NULL,
            cached_at   TEXT NOT NULL
        )
    """)
    conn.commit()
    log.info(f"Cache SQLite initialisé : {db_path}")
    return conn


def cache_get(conn: sqlite3.Connection, key: str):
    """Récupère une valeur depuis le cache. Retourne None si absent."""
    row = conn.execute(
        "SELECT data FROM cache WHERE cache_key = ?", (key,)
    ).fetchone()
    return json.loads(row[0]) if row else None


def cache_set(conn: sqlite3.Connection, key: str, data: dict):
    """Sauvegarde une valeur dans le cache."""
    conn.execute(
        "INSERT OR REPLACE INTO cache (cache_key, data, cached_at) VALUES (?, ?, ?)",
        (key, json.dumps(data), datetime.now(timezone.utc).isoformat())
    )
    conn.commit()


# =============================================================================
#  SOURCE 1 : NVD (NIST)
# =============================================================================

def fetch_nvd(cve_id: str, conn: sqlite3.Connection) -> dict:
    """
    Interroge l'API NVD pour une CVE.
    Utilise le cache SQLite pour éviter les appels répétés.
    """
    cache_key = f"nvd:{cve_id}"
    cached = cache_get(conn, cache_key)
    if cached:
        log.info(f"  [NVD] Cache hit : {cve_id}")
        return cached

    log.info(f"  [NVD] Appel API : {cve_id}")
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        # Respecter le rate limit NVD (sans clé : 5 req/30s)
        time.sleep(0.6 if NVD_API_KEY else 6)

        resp = requests.get(
            NVD_BASE_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=15
        )
        resp.raise_for_status()
        raw = resp.json()

        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            return {}

        cve_data = vulns[0].get("cve", {})
        metrics  = cve_data.get("metrics", {})
        cvss_v3  = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        weaknesses = cve_data.get("weaknesses", [])
        cwe_ids = [
            d.get("value")
            for w in weaknesses
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        ]

        result = {
            "published_date" : cve_data.get("published", ""),
            "modified_date"  : cve_data.get("lastModified", ""),
            "cvss_v3_vector" : cvss_v3.get("vectorString", ""),
            "cvss_v3_base_score"    : cvss_v3.get("baseScore", 0),
            "cvss_v3_base_severity" : cvss_v3.get("baseSeverity", ""),
            "weaknesses"     : cwe_ids,
            "references_count": len(cve_data.get("references", []))
        }
        cache_set(conn, cache_key, result)
        return result

    except Exception as e:
        log.warning(f"  [NVD] Erreur pour {cve_id} : {e}")
        return {}


# =============================================================================
#  SOURCE 2 : CISA KEV
# =============================================================================

def load_cisa_kev(conn: sqlite3.Connection) -> dict:
    """
    Télécharge le catalogue CISA KEV (1 seul appel pour tout le run).
    Retourne un dict indexé par CVE ID.
    """
    cache_key = "cisa_kev_full"
    cached = cache_get(conn, cache_key)
    if cached:
        log.info("  [CISA KEV] Cache hit (catalogue complet)")
        return cached

    log.info("  [CISA KEV] Téléchargement du catalogue...")
    try:
        resp = requests.get(CISA_KEV_URL, timeout=20)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        # Indexer par CVE ID pour recherche rapide
        catalog = {v["cveID"]: v for v in vulns}
        cache_set(conn, cache_key, catalog)
        log.info(f"  [CISA KEV] {len(catalog)} entrées chargées")
        return catalog
    except Exception as e:
        log.warning(f"  [CISA KEV] Erreur : {e}")
        return {}


def get_cisa_info(cve_id: str, kev_catalog: dict) -> dict:
    """Cherche une CVE dans le catalogue CISA KEV."""
    entry = kev_catalog.get(cve_id)
    if entry:
        return {
            "listed"          : True,
            "date_added"      : entry.get("dateAdded", ""),
            "due_date"        : entry.get("dueDate", ""),
            "required_action" : entry.get("requiredAction", ""),
            "notes"           : entry.get("notes", "Actively exploited vulnerability")
        }
    return {
        "listed"          : False,
        "date_added"      : None,
        "due_date"        : None,
        "required_action" : None,
        "notes"           : "Not in KEV catalog"
    }


# =============================================================================
#  SOURCE 3 : OSV (Google)
# =============================================================================

def fetch_osv(cve_id: str, conn: sqlite3.Connection) -> dict:
    """Interroge l'API OSV de Google pour une CVE."""
    cache_key = f"osv:{cve_id}"
    cached = cache_get(conn, cache_key)
    if cached:
        log.info(f"  [OSV] Cache hit : {cve_id}")
        return cached

    log.info(f"  [OSV] Appel API : {cve_id}")
    try:
        resp = requests.post(
            OSV_API_URL,
            json={"id": cve_id},
            timeout=10
        )
        resp.raise_for_status()
        data = resp.json()

        affected = data.get("affected", [])
        result = {
            "affected_packages": [
                {
                    "package": p.get("package", {}),
                    "ranges" : p.get("ranges", [])
                }
                for p in affected
            ],
            "database_specific": data.get("database_specific", {
                "cwe_ids": [],
                "github_reviewed": False
            })
        }
        cache_set(conn, cache_key, result)
        return result

    except Exception as e:
        log.warning(f"  [OSV] Erreur pour {cve_id} : {e}")
        return {"affected_packages": [], "database_specific": {}}


# =============================================================================
#  SOURCE 4 : AlienVault OTX
# =============================================================================

def fetch_otx(cve_id: str, conn: sqlite3.Connection) -> list:
    """Interroge AlienVault OTX pour les indicateurs de menace d'une CVE."""
    cache_key = f"otx:{cve_id}"
    cached = cache_get(conn, cache_key)
    if cached:
        log.info(f"  [OTX] Cache hit : {cve_id}")
        return cached

    if not OTX_AVAILABLE:
        log.warning("  [OTX] Librairie OTXv2 non disponible — skip")
        return []

    if not OTX_API_KEY:
        log.warning("  [OTX] OTX_API_KEY manquante — skip")
        return []

    log.info(f"  [OTX] Appel API : {cve_id}")
    try:
        otx = OTXv2(OTX_API_KEY)
        pulses_data = otx.get_indicator_details_by_section(
            indicator_type="CVE",
            indicator=cve_id,
            section="general"
        )
        pulses = pulses_data.get("pulse_info", {}).get("pulses", [])

        indicators = []
        if pulses:
            indicators.append({
                "type"       : "cve",
                "indicator"  : cve_id,
                "tags"       : list({tag for p in pulses for tag in p.get("tags", [])}),
                "created"    : pulses[0].get("created", ""),
                "description": pulses[0].get("description", ""),
                "pulses"     : [
                    {
                        "name"            : p.get("name", ""),
                        "tags"            : p.get("tags", []),
                        "malware_families": p.get("malware_families", [])
                    }
                    for p in pulses[:3]   # Limité aux 3 premiers
                ]
            })

        cache_set(conn, cache_key, indicators)
        return indicators

    except Exception as e:
        log.warning(f"  [OTX] Erreur pour {cve_id} : {e}")
        return []


# =============================================================================
#  CALCUL DES MÉTADONNÉES DE MENACE
# =============================================================================

def compute_threat_intelligence(nvd: dict, cisa: dict, otx: list) -> dict:
    """Synthétise les données CTI en indicateurs de menace."""
    exploit_available   = cisa.get("listed", False) or len(otx) > 0
    known_in_wild       = cisa.get("listed", False)
    active_exploitation = cisa.get("listed", False)

    vector = nvd.get("cvss_v3_vector", "")
    exploit_complexity = "low"  if "AC:L" in vector else (
                         "high" if "AC:H" in vector else "unknown")
    privileges_required = "none" if "PR:N" in vector else (
                          "low"  if "PR:L" in vector else (
                          "high" if "PR:H" in vector else "unknown"))

    return {
        "exploit_available"   : exploit_available,
        "known_in_wild"       : known_in_wild,
        "active_exploitation" : active_exploitation,
        "exploit_complexity"  : exploit_complexity,
        "privileges_required" : privileges_required
    }


def compute_mitigation_priority(vuln: dict, cisa: dict, threat: dict) -> dict:
    """Calcule la priorité de mitigation d'une vulnérabilité."""
    cvss = vuln.get("cvss_score", 0)

    if cvss >= 9.0:
        business_impact = "CRITICAL"
    elif cvss >= 7.0:
        business_impact = "HIGH"
    elif cvss >= 4.0:
        business_impact = "MEDIUM"
    else:
        business_impact = "LOW"

    # Complexité de remédiation (heuristique simple)
    ecosystem = vuln.get("ecosystem", "")
    if ecosystem in ["os", "windows"]:
        remediation_complexity = "LOW"
        time_to_patch = "1-2 hours"
    elif ecosystem == "java":
        remediation_complexity = "MEDIUM"
        time_to_patch = "4-8 hours"
    else:
        remediation_complexity = "MEDIUM"
        time_to_patch = "2-6 hours"

    # Risk score simplifié
    epss        = vuln.get("epss_score", 0)
    exploit_pts = 2.0 if threat.get("exploit_available") else 0
    cisa_pts    = 1.0 if cisa.get("listed") else 0
    risk_score  = round(min((cvss * 0.6) + (epss * 10 * 0.2) + exploit_pts + cisa_pts, 10), 2)

    return {
        "business_impact"        : business_impact,
        "remediation_complexity" : remediation_complexity,
        "time_to_patch"          : time_to_patch,
        "risk_score"             : risk_score,
        "patch_availability"     : True
    }


def compute_confidence(nvd: dict, cisa: dict, osv: dict, otx: list) -> float:
    """Calcule un score de confiance d'enrichissement (0 à 1)."""
    score = 0.0
    if nvd.get("cvss_v3_base_score"):     score += 0.35
    if cisa.get("listed") is not None:    score += 0.25
    if osv.get("affected_packages"):      score += 0.25
    if otx:                               score += 0.15
    return round(score, 2)


# =============================================================================
#  ENRICHISSEMENT D'UNE CVE (fonction principale)
# =============================================================================

def enrich_vulnerability(vuln: dict, kev_catalog: dict, conn: sqlite3.Connection) -> dict:
    """
    Enrichit une seule vulnérabilité avec les 4 sources CTI.
    Cette fonction est appelée en parallèle pour chaque CVE.
    """
    cve_id = vuln["cve_id"]
    log.info(f"Enrichissement de {cve_id}...")

    # Appels API (NVD en série à cause du rate limit, les autres en parallèle)
    nvd_data  = fetch_nvd(cve_id, conn)
    cisa_info = get_cisa_info(cve_id, kev_catalog)

    with ThreadPoolExecutor(max_workers=2) as ex:
        future_osv = ex.submit(fetch_osv, cve_id, conn)
        future_otx = ex.submit(fetch_otx, cve_id, conn)
        osv_data       = future_osv.result()
        otx_indicators = future_otx.result()

    # Calculs synthétiques
    threat      = compute_threat_intelligence(nvd_data, cisa_info, otx_indicators)
    mitigation  = compute_mitigation_priority(vuln, cisa_info, threat)
    confidence  = compute_confidence(nvd_data, cisa_info, osv_data, otx_indicators)

    # Construction de l'objet enrichi final
    enriched = {
        **vuln,                          # Toutes les données brutes de P1
        "nvd_data"             : nvd_data,
        "cisa_kev"             : cisa_info,
        "osv_data"             : osv_data,
        "otx_indicators"       : otx_indicators,
        "threat_intelligence"  : threat,
        "mitigation_priority"  : mitigation,
        "enrichment_confidence": confidence,
        "last_updated"         : datetime.now(timezone.utc).isoformat()
    }
    log.info(f"  ✅ {cve_id} enrichi (confiance : {confidence})")
    return enriched


# =============================================================================
#  PROGRAMME PRINCIPAL
# =============================================================================

def main():
    start_time = time.time()
    log.info("=" * 60)
    log.info("  P2 - ENRICHISSEUR CTI - Démarrage")
    log.info("=" * 60)

    # 1. Charger le fichier d'entrée (sorti par P1/Kenza)
    if not os.path.exists(INPUT_FILE):
        log.error(f"Fichier d'entrée introuvable : {INPUT_FILE}")
        raise FileNotFoundError(f"Manque : {INPUT_FILE}")

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw_scan = json.load(f)

    vulnerabilities = raw_scan.get("vulnerabilities", [])
    log.info(f"  {len(vulnerabilities)} CVE(s) à enrichir")

    # 2. Initialiser le cache SQLite
    conn = init_cache(CACHE_DB)

    # 3. Charger le catalogue CISA KEV (1 seul téléchargement pour tout le run)
    log.info("Chargement du catalogue CISA KEV...")
    kev_catalog = load_cisa_kev(conn)

    # 4. Enrichir toutes les CVE en parallèle (max 3 threads pour NVD)
    log.info("Début de l'enrichissement parallèle...")
    enriched_vulns = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(enrich_vulnerability, vuln, kev_catalog, conn): vuln["cve_id"]
            for vuln in vulnerabilities
        }
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                enriched_vulns.append(future.result())
            except Exception as e:
                log.error(f"  ❌ Échec enrichissement {cve_id} : {e}")

    # 5. Trier par score CVSS décroissant
    enriched_vulns.sort(key=lambda v: v.get("cvss_score", 0), reverse=True)

    # 6. Calculer le résumé
    exploitable_count = sum(1 for v in enriched_vulns if v["threat_intelligence"]["exploit_available"])
    cisa_kev_count    = sum(1 for v in enriched_vulns if v["cisa_kev"]["listed"])
    otx_count         = sum(1 for v in enriched_vulns if v["otx_indicators"])
    critical_count    = sum(1 for v in enriched_vulns if v["severity"] == "CRITICAL")
    high_count        = sum(1 for v in enriched_vulns if v["severity"] == "HIGH")
    avg_confidence    = round(
        sum(v["enrichment_confidence"] for v in enriched_vulns) / len(enriched_vulns)
        if enriched_vulns else 0, 2
    )

    processing_time = round(time.time() - start_time, 1)

    # 7. Construire l'output final
    output = {
        "enrichment_metadata": {
            "timestamp"               : datetime.now(timezone.utc).isoformat(),
            "sources_used"            : ["NIST NVD", "CISA KEV Catalog", "OSV Database", "AlienVault OTX"],
            "processing_time_seconds" : processing_time,
            "enrichment_version"      : "2.0"
        },
        "original_scan"          : raw_scan,
        "enriched_vulnerabilities": enriched_vulns,
        "enrichment_summary": {
            "total_vulnerabilities"    : len(enriched_vulns),
            "exploitable_count"        : exploitable_count,
            "cisa_kev_count"           : cisa_kev_count,
            "known_exploits"           : exploitable_count,
            "otx_indicators_count"     : otx_count,
            "high_risk_count"          : high_count,
            "critical_risk_count"      : critical_count,
            "average_enrichment_confidence": avg_confidence,
            "source_coverage": {
                "nvd_coverage"     : 1.0,
                "cisa_kev_coverage": round(cisa_kev_count / len(enriched_vulns), 2) if enriched_vulns else 0,
                "osv_coverage"     : 1.0,
                "otx_coverage"     : round(otx_count / len(enriched_vulns), 2) if enriched_vulns else 0
            }
        }
    }

    # 8. Écrire le fichier de sortie
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    log.info("=" * 60)
    log.info(f"  ✅ Enrichissement terminé en {processing_time}s")
    log.info(f"  📄 Output : {OUTPUT_FILE}")
    log.info(f"  📊 {len(enriched_vulns)} CVE | {exploitable_count} exploitables | {cisa_kev_count} dans CISA KEV")
    log.info("=" * 60)


if __name__ == "__main__":
    main()