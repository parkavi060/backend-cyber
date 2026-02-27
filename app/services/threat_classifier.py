import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from flask import current_app
from app.constants.incident_constants import ThreatTypes, THREAT_TYPES_LIST

class ThreatClassifierService:
    def __init__(self):
        self.model_dir = os.path.join(os.path.dirname(__file__), "models")
        self.model_path = os.path.join(self.model_dir, "threat_rf_model.joblib")
        self.vectorizer_path = os.path.join(self.model_dir, "tfidf_vectorizer.joblib")
        self.model = None
        self.vectorizer = None
        
        # Ensure model directory exists
        if not os.path.exists(self.model_dir):
            os.makedirs(self.model_dir)
            
        self._load_or_train()

    def _load_or_train(self):
        """Loads existing model or trains an initial one."""
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            try:
                self.model = joblib.load(self.model_path)
                self.vectorizer = joblib.load(self.vectorizer_path)
                current_app.logger.info("Random Forest Threat Model loaded successfully.")
            except Exception as e:
                current_app.logger.error(f"Error loading model: {e}")
                self._train_initial_model()
        else:
            self._train_initial_model()

    def _train_initial_model(self):
        """Trains an initial model with synthetic data if no model exists."""
        current_app.logger.info("Training initial Random Forest model...")
        
        # Synthetic training data
        data = [
            # Phishing
            ("Click here to claim your prize and login to your account", ThreatTypes.PHISHING),
            ("Your account has been suspended. Please verify your identity at this link", ThreatTypes.PHISHING),
            ("Verify your bank account details immediately to avoid lockout", ThreatTypes.PHISHING),
            ("Login to secure your email and prevent unauthorized access", ThreatTypes.PHISHING),
            
            # Malware
            ("Download this attachment to view the invoice", ThreatTypes.MALWARE),
            ("Install this software to update your drivers and fix bugs", ThreatTypes.MALWARE),
            ("Detected virus on your computer. Click to download cleaner", ThreatTypes.MALWARE),
            ("Run this .exe file to get free premium features", ThreatTypes.MALWARE),
            
            # Malicious Link
            ("Check out this cool website: http://fake-site.com/login", ThreatTypes.MALICIOUS_LINK),
            ("Visit this URL to win a free iPhone: https://malicious-url.tk", ThreatTypes.MALICIOUS_LINK),
            ("Click here for a surprise: bit.ly/untrusted-link", ThreatTypes.MALICIOUS_LINK),
            
            # Credential Theft
            ("Enter your password here to continue using the service", ThreatTypes.CREDENTIAL_THEFT),
            ("Please provide your OTP to confirm the transaction", ThreatTypes.CREDENTIAL_THEFT),
            ("We need your login credentials for maintenance purposes", ThreatTypes.CREDENTIAL_THEFT),
            
            # Social Engineering
            ("Hi, I'm from technical support. I need access to your computer", ThreatTypes.SOCIAL_ENGINEERING),
            ("I'm your boss. Please send me the gift card codes immediately", ThreatTypes.SOCIAL_ENGINEERING),
            ("Urgent help needed! Can you transfer money to this account?", ThreatTypes.SOCIAL_ENGINEERING),
            
            # Suspicious Message
            ("Hello, how are you? Just checking in.", ThreatTypes.SUSPICIOUS_MESSAGE),
            ("Are you available for a quick chat today?", ThreatTypes.SUSPICIOUS_MESSAGE),
            ("Check your mail for the latest updates on our project", ThreatTypes.SUSPICIOUS_MESSAGE)
        ]
        
        df = pd.DataFrame(data, columns=['text', 'label'])
        
        self.vectorizer = TfidfVectorizer(stop_words='english')
        X = self.vectorizer.fit_transform(df['text'])
        y = df['label']
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        
        # Save model and vectorizer
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        current_app.logger.info("Initial Random Forest model trained and saved.")

    def predict(self, text):
        """Predicts the threat type and returns confidence score."""
        if not self.model or not self.vectorizer:
            return ThreatTypes.SUSPICIOUS_MESSAGE, 0.0
            
        X = self.vectorizer.transform([text.lower()])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        # Get confidence score for the predicted label
        class_index = list(self.model.classes_).index(prediction)
        confidence = float(probabilities[class_index])
        
        return prediction, confidence

# Singleton instance
classifier = None

def get_threat_classifier():
    global classifier
    if classifier is None:
        classifier = ThreatClassifierService()
    return classifier
