import sys
import os

# Add parent directory to path to allow imports from app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask
from app.services.threat_classifier import get_threat_classifier
from app.constants.incident_constants import ThreatTypes

def test_classifier():
    # Mock Flask app context for logging and current_app
    app = Flask(__name__)
    with app.app_context():
        classifier = get_threat_classifier()
        
        test_cases = [
            ("Click here to win a free prize and login now", ThreatTypes.PHISHING),
            ("Your account security is at risk, verify here", ThreatTypes.PHISHING),
            ("Download this invoice.zip to see your bill", ThreatTypes.MALWARE),
            ("Install this critical system update from unknown-source.com", ThreatTypes.MALWARE),
            ("Visit http://suspicious-link.com for free money", ThreatTypes.MALICIOUS_LINK),
            ("Check out this link: https://bit.ly/fake-login", ThreatTypes.MALICIOUS_LINK),
            ("Please provide your password and OTP for verification", ThreatTypes.CREDENTIAL_THEFT),
            ("Send me your login details for account maintenance", ThreatTypes.CREDENTIAL_THEFT),
            ("I'm from IT support, I need your remote access password", ThreatTypes.SOCIAL_ENGINEERING),
            ("Transfer $500 to this account for urgent help", ThreatTypes.SOCIAL_ENGINEERING),
            ("Hello, hope you are having a good day", ThreatTypes.SUSPICIOUS_MESSAGE),
            ("Are we meeting for lunch today?", ThreatTypes.SUSPICIOUS_MESSAGE)
        ]
        
        print("\n--- Threat Classifier Verification ---")
        passed = 0
        for text, expected in test_cases:
            prediction, confidence = classifier.predict(text)
            print(f"Text: '{text[:40]}...'")
            print(f"  Expected: {expected}")
            print(f"  Predicted: {prediction} (Confidence: {confidence:.2f})")
            
            if prediction == expected:
                print("  Result: PASS")
                passed += 1
            else:
                print("  Result: FAIL")
            print("-" * 30)
            
        print(f"\nTotal Passed: {passed}/{len(test_cases)}")
        
        # Verify model persistence
        print("\nVerifying model persistence...")
        if os.path.exists(classifier.model_path) and os.path.exists(classifier.vectorizer_path):
            print("Model and Vectorizer files exist.")
        else:
            print("Model or Vectorizer files MISSING.")

if __name__ == "__main__":
    test_classifier()
