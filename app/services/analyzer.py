from typing import Dict, Any
from .parser import extract_features
from ..model.predict import predict_criticality

def process_and_prioritize_scan(scan_data: Dict[str, Any]) -> list:
    """
    Main business logic to handle incoming vulnerability scan results,
    extract features, predict criticality, and sort accordingly.
    """
    vulnerabilities = scan_data.get("vulnerabilities", [])
    prioritized = []
    
    for vuln in vulnerabilities:
        # Extract features for prediction
        cve_id, description, cvss_score = extract_features(vuln)
        
        # Predict Criticality
        criticality = predict_criticality(description, cvss_score)
        
        prioritized.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "predicted_criticality": criticality
        })
        
    # Sort by criticality manually (Critical first, High, Medium, Low)
    severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    prioritized.sort(key=lambda x: severity_rank.get(x["predicted_criticality"], 0), reverse=True)
    
    return prioritized
