import os
import joblib
import pandas as pd

# Variables globales pour mettre le modèle en cache dans la mémoire de l'API
_clf = None
_vectorizer = None

def _load_model():
    global _clf, _vectorizer
    if _clf is None or _vectorizer is None:
        try:
            model_path = "data/model/classifier.pkl"
            vect_path = "data/model/vectorizer.pkl"
            if os.path.exists(model_path) and os.path.exists(vect_path):
                _clf = joblib.load(model_path)
                _vectorizer = joblib.load(vect_path)
            else:
                print("Avertissement: Modèles .pkl introuvables. Mode fallback actif.")
        except Exception as e:
            print(f"Erreur lors du chargement du modèle: {e}")

def predict_criticality(description: str, cvss_score: float) -> str:
    """
    Utilise le modèle de Machine Learning entraîné (RandomForest) pour prédire la criticité.
    En cas de problème avec le modèle, un fallback sur le score CVSS est effectué.
    """
    _load_model()
    
    if _clf and _vectorizer:
        try:
            # Transformation de la description en utilisant le vectorizer existant
            text_features = _vectorizer.transform([description]).toarray()
            df_features = pd.DataFrame(text_features)
            
            # Ajout du score CVSS comme feature numérique
            df_features['cvss_score'] = [cvss_score]
            
            # Assurer que les noms de colonnes sont en string (pour sklearn)
            df_features.columns = df_features.columns.astype(str)
            
            # Prédiction
            prediction = _clf.predict(df_features)
            return prediction[0]
        except Exception as e:
            print(f"Erreur de prédiction IA: {e}")

    # Fallback (Règles statiques) si le modèle plante ou n'est pas encore généré
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"
