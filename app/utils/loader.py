import json
import pandas as pd
import numpy as np
import random
import os

def load_json_data(filepath: str) -> dict:
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def generate_synthetic_cve_data(output_path: str = "data/raw/synthetic_cves.csv", num_samples: int = 1000):
    """
    Génère un dataset synthétique simulant des CVEs avec leurs descriptions,
    scores CVSS et un label de criticité (Low, Medium, High, Critical).
    Cela permet d'entraîner le modèle sans télécharger des Go de données NVD.
    """
    
    # Mots-clés associés aux différentes criticités
    critical_keywords = ["remote code execution", "rce", "unauthenticated", "root privilege", "default password", "sql injection"]
    high_keywords = ["privilege escalation", "cross-site scripting", "xss", "buffer overflow", "denial of service", "dos"]
    medium_keywords = ["information disclosure", "spoofing", "csrf", "bypass", "directory traversal"]
    low_keywords = ["local access", "complex setup", "version exposure", "deprecated algorithm", "minor ui bug"]

    data = []
    
    for i in range(num_samples):
        # Tirage au sort de la "vraie" criticité (notre label cible pour le ML)
        severity = random.choices(
            ["Critical", "High", "Medium", "Low"], 
            weights=[0.15, 0.25, 0.40, 0.20]
        )[0]
        
        # Génération du texte et du score en fonction de la criticité
        if severity == "Critical":
            desc = f"A vulnerability allows {random.choice(critical_keywords)} via crafted payload."
            score = round(random.uniform(9.0, 10.0), 1)
        elif severity == "High":
            desc = f"An attacker can exploit a {random.choice(high_keywords)} vulnerability to compromise the system."
            score = round(random.uniform(7.0, 8.9), 1)
        elif severity == "Medium":
            desc = f"The application suffers from {random.choice(medium_keywords)} which may lead to sensitive data leaks."
            score = round(random.uniform(4.0, 6.9), 1)
        else:
            desc = f"A minor issue related to {random.choice(low_keywords)} was discovered."
            score = round(random.uniform(1.0, 3.9), 1)
            
        # Parfois, on introduit du "bruit" (faux positifs : score élevé mais criticité basse dans la vraie vie)
        if random.random() < 0.05:
            score = round(random.uniform(7.0, 10.0), 1)
            desc += " However, it requires physical access and user interaction."
            severity = "Low" # Le score CVSS est haut mais le ML devra apprendre à rétrograder grâce au texte
            
        data.append({
            "cve_id": f"CVE-2023-{str(1000 + i).zfill(4)}",
            "description": desc,
            "cvss_score": score,
            "severity_label": severity
        })

    df = pd.DataFrame(data)
    
    # Création du dossier si nécessaire
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Genere {num_samples} failles fictives dans {output_path}")
    
    return df

def load_training_data(filepath: str = "data/raw/real_cves.csv") -> pd.DataFrame:
    """ Charge le dataset d'entraînement sous forme de DataFrame pandas """
    if not os.path.exists(filepath):
        print("Dataset introuvable. Veuillez exécuter app/utils/nvd_fetcher.py d'abord.")
        return pd.DataFrame() # Retourne un dataframe vide
    return pd.read_csv(filepath)

