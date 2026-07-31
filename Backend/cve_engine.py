# cve_engine.py

import requests
import time


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Délai entre chaque appel, pour rester sous la limite NIST (5 req / 30s sans clé,
# donc ~6s de marge de sécurité entre deux requêtes)
RATE_LIMIT_DELAY = 6


def _extract_severity(cve_item: dict) -> str:
    """
    Extrait le niveau de sévérité CVSS le plus pertinent disponible.
    Le NVD peut renvoyer plusieurs versions de métriques (v3.1, v3.0, v2.0) ;
    on essaie la plus récente en premier.
    """
    metrics = cve_item.get("metrics", {})

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and len(metrics[key]) > 0:
            data = metrics[key][0]
            # La structure diffère légèrement entre v2 et v3
            cvss_data = data.get("cvssData", {})
            severity = cvss_data.get("baseSeverity") or data.get("baseSeverity")
            if severity:
                return severity

    return "UNKNOWN"


def _extract_summary(cve_item: dict, max_length: int = 200) -> str:
    """Extrait la description en anglais, tronquée pour rester lisible dans une carte UI."""
    descriptions = cve_item.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            text = desc.get("value", "")
            return text[:max_length] + ("..." if len(text) > max_length else "")
    return "Aucune description disponible."


def search_cve(product: str, version: str) -> list[dict]:
    """
    Interroge l'API NVD pour trouver les CVE connues correspondant
    à un produit et une version donnés.

    Retourne une liste vide si product ou version sont absents,
    ou si l'API échoue / ne renvoie aucun résultat.
    """
    # --- Garde-fou : pas de recherche possible sans ces deux infos ---
    if not product or not version:
        return []

    query = f"{product} {version}"

    try:
        response = requests.get(
            NVD_API_URL,
            params={
                "keywordSearch": query,
                "resultsPerPage": 5,  # on limite volontairement le nombre de résultats
            },
            timeout=10,
        )

        # --- Gestion du rate limit (429) ---
        # Si on est bloqué malgré le sleep, on attend plus longtemps puis on
        # abandonne cette recherche plutôt que de bloquer l'upload indéfiniment
        if response.status_code == 429:
            time.sleep(15)
            return []

        if response.status_code != 200:
            # Erreur API (500, timeout NVD, etc.) : on ne bloque pas l'upload pour autant
            return []

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        results = []
        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            results.append({
                "id": cve_item.get("id"),
                "severity": _extract_severity(cve_item),
                "summary": _extract_summary(cve_item),
            })

        return results

    except requests.RequestException:
        # Timeout, connexion refusée, DNS, etc. : on n'interrompt pas
        # l'analyse du scan pour une simple indisponibilité de l'API externe
        return []

    finally:
        # --- Respect systématique du rate limit avant l'appel suivant ---
        time.sleep(RATE_LIMIT_DELAY)