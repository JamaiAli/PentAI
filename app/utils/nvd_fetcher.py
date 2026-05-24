import urllib.request
import json
import pandas as pd
import time
import os
import urllib.error
import socket

def fetch_real_nvd_data(output_path: str = "data/raw/real_cves.csv", target_count: int = 10000, results_per_page: int = 2000):
    print(f"Début du téléchargement massif : Objectif {target_count} CVEs...")
    
    records = []
    start_index = 0
    max_retries = 10
    
    while len(records) < target_count:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage={results_per_page}&startIndex={start_index}"
        print(f"Fetching à partir de l'index {start_index} (actuellement {len(records)}/{target_count} récupérées)...")
        
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        
        retries = 0
        success = False
        
        while retries < max_retries and not success:
            try:
                # Ajout d'un timeout de 30 secondes
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    
                cve_items = data.get("vulnerabilities", [])
                if not cve_items:
                    print("Plus aucune vulnérabilité renvoyée par l'API. Fin de la pagination.")
                    # Force la sortie de la boucle principale
                    retries = max_retries 
                    break
                    
                for item in cve_items:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    
                    descriptions = cve.get("descriptions", [])
                    desc_en = next((d['value'] for d in descriptions if d['lang'] == 'en'), "")
                    
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", [])
                    
                    if cvss_data:
                        base_score = cvss_data[0]["cvssData"]["baseScore"]
                        severity = cvss_data[0]["cvssData"]["baseSeverity"].capitalize()
                        
                        records.append({
                            "cve_id": cve_id,
                            "description": desc_en,
                            "cvss_score": base_score,
                            "severity_label": severity
                        })
                        
                start_index += results_per_page
                success = True
                
                print("Pause de 6 secondes (Anti-Ban NVD)...")
                time.sleep(6)
                
            except urllib.error.HTTPError as e:
                print(f"Erreur HTTP {e.code}: {e.reason}. Attente de 15s...")
                time.sleep(15)
                retries += 1
            except (urllib.error.URLError, ConnectionResetError, socket.timeout, ConnectionError) as e:
                print(f"Erreur de connexion ({e}). Le serveur a coupé. Nouvelle tentative dans 10s... ({retries+1}/{max_retries})")
                time.sleep(10)
                retries += 1
            except Exception as e:
                print(f"Erreur critique inattendue : {e}")
                retries = max_retries
                break

        if not success:
            print("Impossible de récupérer la page après plusieurs tentatives. Sauvegarde des données en cours...")
            break
            
    df = pd.DataFrame(records)
    if not df.empty:
        df = df.drop_duplicates(subset=['cve_id'])
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Opération terminée : {len(df)} failles uniques sauvegardées dans {output_path}")
    return df

if __name__ == "__main__":
    fetch_real_nvd_data()
