import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from app.utils.loader import load_training_data
from app.model.features import transform_features

def train_and_save_model():
    print("1. Chargement des données réelles NVD...")
    df = load_training_data()
    if df.empty:
        print("Erreur: Pas de données pour l'entraînement.")
        return
        
    print(f"   -> {len(df)} vulnérabilités chargées.")
    
    # Nettoyage
    df = df.dropna(subset=['description', 'cvss_score', 'severity_label'])
    
    descriptions = df['description'].tolist()
    cvss_scores = df['cvss_score'].tolist()
    y_target = df['severity_label'].tolist()
    
    print("2. Extraction des features (TF-IDF sur le texte + CVSS)...")
    X_features, vectorizer = transform_features(descriptions, cvss_scores)
    
    # Afin de garder les noms de colonnes valides pour le modèle
    X_features.columns = X_features.columns.astype(str)
    
    print("3. Entraînement du RandomForestClassifier...")
    # On ajoute random_state pour être reproductible
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_features, y_target)
    
    score = clf.score(X_features, y_target)
    print(f"   -> Précision sur les données d'entraînement: {score * 100:.2f}%")
    
    print("4. Sauvegarde du modèle et du vectorizer...")
    os.makedirs("data/model", exist_ok=True)
    joblib.dump(clf, "data/model/classifier.pkl")
    joblib.dump(vectorizer, "data/model/vectorizer.pkl")
    print("Modele final sauvegarde avec succes dans 'data/model/' !")

if __name__ == "__main__":
    train_and_save_model()
