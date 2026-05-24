import os
import joblib
import numpy as np
from sentence_transformers import SentenceTransformer

# Cache global pour ne pas recharger le modèle lourd à chaque requête
_classifier = None
_llm = None

def load_models():
    global _classifier, _llm
    if _classifier is None:
        model_path = os.path.join("data", "model", "classifier.pkl")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Modèle ML manquant : {model_path}. Entraînez l'IA d'abord.")
        _classifier = joblib.load(model_path)
        
    if _llm is None:
        print("Chargement du modèle de langage LLM pour l'inférence...")
        _llm = SentenceTransformer('all-MiniLM-L6-v2')

def predict_severity(description: str, cvss_score: float) -> str:
    load_models()
    
    # 1. Génération de l'embedding via le LLM
    # encode retourne un numpy array
    embedding = _llm.encode([description])
    
    # 2. Concaténation avec le score CVSS
    cvss_array = np.array([[float(cvss_score)]])
    X_features = np.hstack((embedding, cvss_array))
    
    # 3. Prédiction via RandomForest
    prediction = _classifier.predict(X_features)
    return prediction[0]
