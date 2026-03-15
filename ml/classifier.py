# ml/classifier.py
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import re
import math

class XSSMLClassifier:
    """
    ML classifier for XSS detection
    Trained on multiple datasets (Ali, CSIC, Sunny)
    """
    
    def __init__(self, model_path: str = None):
        self.vectorizer = TfidfVectorizer(
            max_features=2000,
            ngram_range=(1, 4),
            analyzer='char',
            sublinear_tf=True
        )
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            verbose=1,          # <--- добавляем для вывода прогресса
            n_jobs=-1            # <--- использовать все ядра процессора
        )
        self.is_trained = False
        
        if model_path:
            self.load_model(model_path)
    
    def extract_features(self, payload: str) -> np.ndarray:
        """Extract 12 features from payload"""
        features = []
        
        # 1. Payload length
        features.append(len(payload))
        
        # 2. Dangerous characters
        dangerous = sum(1 for c in payload if c in '<>"/\'&;:()[]{}')
        features.append(dangerous)
        
        # 3. Event handlers
        events = ['onerror', 'onload', 'onclick', 'onmouseover']
        features.append(sum(1 for e in events if e in payload.lower()))
        
        # 4. JS functions
        js_funcs = ['alert', 'prompt', 'confirm', 'eval', 'fetch']
        features.append(sum(1 for f in js_funcs if f in payload.lower()))
        
        # 5. HTML tags
        tags = re.findall(r'<[^>]+>', payload)
        features.append(len(tags))
        
        # 6. Entropy (chaos measure)
        probs = [payload.count(c)/len(payload) for c in set(payload)]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        features.append(entropy)
        
        # 7. Digits count
        features.append(sum(c.isdigit() for c in payload))
        
        # 8. Uppercase letters
        features.append(sum(c.isupper() for c in payload))
        
        # 9. Special chars ratio
        ratio = dangerous / len(payload) if len(payload) > 0 else 0
        features.append(ratio)
        
        # 10. URL encoding
        url_encoded = len(re.findall(r'%[0-9A-Fa-f]{2}', payload))
        features.append(url_encoded)
        
        # 11. Unicode escape
        unicode_escaped = len(re.findall(r'\\u[0-9A-Fa-f]{4}', payload))
        features.append(unicode_escaped)
        
        # 12. Base64 pattern
        base64 = 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', payload) else 0
        features.append(base64)
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, payload: str) -> dict:
        """Predict if payload is XSS"""
        if not self.is_trained:
            return {'confidence': 0.5, 'is_vulnerable': False}
        
        # Transform payload
        X_tfidf = self.vectorizer.transform([payload]).toarray()
        X_features = self.extract_features(payload)
        X_combined = np.hstack([X_tfidf, X_features.reshape(1, -1)])
        
        # Get prediction
        proba = self.classifier.predict_proba(X_combined)[0]
        prediction = self.classifier.predict(X_combined)[0]
        
        return {
            'is_vulnerable': bool(prediction),
            'confidence': float(max(proba))
        }
    
    def train(self, training_data: list):
        """Train model on (payload, label) data"""
        X_text = [p for p, _ in training_data]
        y = [int(l) for _, l in training_data]
        
        # Text features
        X_tfidf = self.vectorizer.fit_transform(X_text).toarray()
        
        # Numerical features
        X_features_list = []
        for payload, _ in training_data:
            X_features_list.append(self.extract_features(payload).flatten())
        X_features = np.vstack(X_features_list)
        
        # Combine
        X_combined = np.hstack([X_tfidf, X_features])
        
        # Train
        self.classifier.fit(X_combined, y)
        self.is_trained = True

    def save_model(self, path: str):
        """Save trained model"""
        joblib.dump({
            'vectorizer': self.vectorizer,
            'classifier': self.classifier
        }, path)
    
    def load_model(self, path: str):
        """Load trained model"""
        data = joblib.load(path)
        self.vectorizer = data['vectorizer']
        self.classifier = data['classifier']
        self.is_trained = True