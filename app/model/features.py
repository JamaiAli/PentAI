from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd

def transform_features(descriptions: list, cvss_scores: list, vectorizer: TfidfVectorizer = None):
    """
    Example of advanced feature engineering logic for string descriptions,
    creating numerical matrices that model architectures can process.
    """
    if not vectorizer:
        vectorizer = TfidfVectorizer(max_features=100)
        # In a real training process, we call fit:
        vectorizer.fit(descriptions)
        
    text_features = vectorizer.transform(descriptions).toarray()
    
    # Combine arrays
    df_text = pd.DataFrame(text_features)
    df_text['cvss_score'] = cvss_scores
    return df_text, vectorizer
