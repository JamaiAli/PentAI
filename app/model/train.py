import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sentence_transformers import SentenceTransformer
import joblib
import os
import numpy as np

def train_model(data_path: str = "data/raw/real_cves.csv", model_dir: str = "data/model"):
    print(f"Chargement des données depuis {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except FileNotFoundError:
        print("Fichier CSV introuvable. Veuillez exécuter nvd_fetcher.py d'abord.")
        return

    if len(df) < 10:
        print("Pas assez de données pour entraîner le modèle (min 10).")
        return

    X_text = df["description"].fillna("")
    y = df["severity_label"]
    cvss_scores = df["cvss_score"].fillna(0.0).values.reshape(-1, 1)

    print("Chargement du modèle LLM (SentenceTransformer)...")
    # all-MiniLM-L6-v2 est extrêmement rapide sur CPU et comprend parfaitement le contexte de l'anglais technique.
    llm = SentenceTransformer('all-MiniLM-L6-v2')
    
    print(f"Génération des embeddings sémantiques pour {len(X_text)} vulnérabilités...")
    embeddings = llm.encode(X_text.tolist(), show_progress_bar=True)
    
    # On concatène les embeddings (384 dimensions) avec le score CVSS (1 dimension)
    X_features = np.hstack((embeddings, cvss_scores))

    print("Entraînement du RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_features, y)

    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "classifier.pkl")
    
    # On sauvegarde uniquement le classifieur. Le SentenceTransformer sera téléchargé/chargé par predict.py
    joblib.dump(clf, model_path)
    
    print(f"Entraînement terminé ! Modèle ML sauvegardé dans {model_path}")

if __name__ == "__main__":
    train_model()
