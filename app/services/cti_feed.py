import urllib.request
import json
import os
import time

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILE = "data/cache/cisa_kev.json"
CACHE_EXPIRY_SECONDS = 86400  # 24 hours (1 jour)

_kev_set = None

def load_kev_catalog() -> set:
    """
    Charge le catalogue CISA KEV et retourne un Set (O(1) lookup) des identifiants CVE activement exploités.
    """
    global _kev_set
    if _kev_set is not None:
        return _kev_set
        
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    
    # Vérifie si le cache existe et est encore frais
    if os.path.exists(CACHE_FILE):
        file_age = time.time() - os.path.getmtime(CACHE_FILE)
        if file_age < CACHE_EXPIRY_SECONDS:
            try:
                with open(CACHE_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                _kev_set = {vuln.get('cveID', '') for vuln in data.get('vulnerabilities', [])}
                return _kev_set
            except Exception:
                pass # Si le cache est corrompu, on télécharge à nouveau
                
    # Téléchargement en direct depuis le gouvernement américain
    print("Téléchargement du catalogue officiel CTI (CISA KEV)...")
    req = urllib.request.Request(KEV_URL, headers={'User-Agent': 'Mozilla/5.0'})
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
            
        # Sauvegarde en cache
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)
            
        _kev_set = {vuln.get('cveID', '') for vuln in data.get('vulnerabilities', [])}
        print(f"CISA KEV mis à jour : {len(_kev_set)} failles activement exploitées dans la nature.")
        return _kev_set
    except Exception as e:
        print(f"Alerte : Impossible d'accéder au flux CTI ({e}). L'analyse se basera uniquement sur l'IA.")
        return set() # Fail open : en cas de problème réseau, on retourne un set vide
