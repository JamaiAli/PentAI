from typing import Dict, Any
from .parser import extract_features
from ..model.predict import predict_severity
from .cti_feed import load_kev_catalog

def process_and_prioritize_scan(scan_data: Dict[str, Any]) -> list:
    """
    Main business logic to handle incoming vulnerability scan results,
    extract features, predict criticality, and sort accordingly.
    """
    vulnerabilities = scan_data.get("vulnerabilities", [])
    prioritized = []
    
    # 1. Chargement du catalogue CTI
    kev_set = load_kev_catalog()
    
    for vuln in vulnerabilities:
        # Extract features for prediction
        cve_id, description, cvss_score = extract_features(vuln)
        
        # Predict Criticality via AI
        criticality = predict_severity(description, cvss_score)
        
        # 2. Surcharge CTI (Threat Intelligence)
        is_kev = cve_id in kev_set
        if is_kev:
            criticality = "Critical"  # Force au maximum
        
        prioritized.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "predicted_criticality": criticality,
            "is_kev": is_kev
        })
        
    # Sort by criticality manually
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    # Second critère de tri : Les vulnérabilités KEV passent avant les autres Critical
    prioritized.sort(key=lambda x: (severity_rank.get(x["predicted_criticality"], 0), x["is_kev"]), reverse=True)
    
    return prioritized
