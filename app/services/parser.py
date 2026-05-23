def extract_features(vulnerability: dict) -> tuple:
    """ Extract raw details from a vulnerability object into format for model """
    cve_id = vulnerability.get("cve_id", "Unknown")
    description = vulnerability.get("description", "")
    cvss_score = vulnerability.get("cvss_score", 0.0)
    return cve_id, description, cvss_score
