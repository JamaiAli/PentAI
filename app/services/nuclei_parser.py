from typing import List, Dict, Any

def is_nuclei_format(data: Any) -> bool:
    """
    Vérifie si les données fournies correspondent au format Nuclei.
    Nuclei exporte généralement une liste d'objets ou un objet contenant 'info'.
    """
    if isinstance(data, list):
        if len(data) > 0 and isinstance(data[0], dict) and "info" in data[0]:
            return True
    elif isinstance(data, dict):
        if "info" in data:
            return True
    return False

def parse_nuclei_to_pentai(data: Any) -> Dict[str, Any]:
    """
    Convertit un export Nuclei brut en un format compréhensible par PentAI (ScanReport).
    """
    if isinstance(data, dict):
        data = [data] # Transforme en liste si un seul objet

    vulnerabilities = []
    
    # Mapping des sévérités Nuclei vers un faux score CVSS (si manquant)
    # Pour que notre IA ait quand même une base numérique.
    severity_to_cvss = {
        "critical": 9.5,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
        "info": 0.0
    }

    for item in data:
        if not isinstance(item, dict) or "info" not in item:
            continue
            
        info = item["info"]
        
        # Extraction du CVE (Nuclei le range souvent dans une liste dans classification)
        cve_id = "N/A"
        classification = info.get("classification", {})
        if classification and "cve-id" in classification:
            cves = classification["cve-id"]
            if cves and len(cves) > 0:
                cve_id = cves[0]
                
        # Extraction du CVSS
        cvss_score = classification.get("cvss-score")
        if cvss_score is None:
            # On infère depuis la sévérité textuelle de Nuclei
            severity_str = str(info.get("severity", "info")).lower()
            cvss_score = severity_to_cvss.get(severity_str, 0.0)
            
        # Extraction de la description (parfois Nuclei n'a que le nom)
        description = info.get("description")
        if not description:
            description = info.get("name", "Vulnerabilité détectée par Nuclei sans description détaillée.")
            
        # On peut aussi ajouter d'autres champs utiles de Nuclei dans la description
        matcher_name = item.get("matcher-name", "")
        if matcher_name:
            description += f" (Matched by: {matcher_name})"

        vulnerabilities.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": float(cvss_score)
        })

    return {
        "scan_id": "nuclei-imported-scan",
        "vulnerabilities": vulnerabilities
    }
