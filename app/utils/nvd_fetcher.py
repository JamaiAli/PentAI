import urllib.request
import json
import pandas as pd
import time
import os

def fetch_real_nvd_data(output_path: str = "data/raw/real_cves.csv", max_results: int = 2000):
    """
    Télécharge de vraies données CVE depuis l'API NVD (NIST) v2.0.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={max_results}"
    print(f"Téléchargement de {max_results} vraies CVEs depuis l'API NVD...")
    
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            
        cve_items = data.get("vulnerabilities", [])
        records = []
        
        for item in cve_items:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            
            # Extraction de la description (anglais)
            descriptions = cve.get("descriptions", [])
            desc_en = next((d['value'] for d in descriptions if d['lang'] == 'en'), "")
            
            # Extraction du score CVSS v3.1
            metrics = cve.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [])
            
            if cvss_data:
                base_score = cvss_data[0]["cvssData"]["baseScore"]
                severity = cvss_data[0]["cvssData"]["baseSeverity"]
                
                # Formatage du label pour correspondre à notre logique (Capitalize)
                severity = severity.capitalize()
                
                records.append({
                    "cve_id": cve_id,
                    "description": desc_en,
                    "cvss_score": base_score,
                    "severity_label": severity
                })
        
        df = pd.DataFrame(records)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"Téléchargement réussi : {len(df)} failles sauvegardées dans {output_path}")
        return df
        
    except Exception as e:
        print(f"Erreur lors du téléchargement : {e}")
        return None

if __name__ == "__main__":
    fetch_real_nvd_data()
