from .ai_analysis import vader_risk_score
from .threat_classifier import get_threat_classifier
from .url_checker import extract_urls, is_malicious

def calculate_risk_score(title: str, description: str, evidence: str):
    score = 0
    reasons = []   # ✅ ADD (for explainability)

    raw_text = title + " " + description + " " + evidence
    text = raw_text.lower()

    # ... (rest of the logic using text) ...
    # (re-writing the relevant part to avoid confusion)
    
    # HIGH RISK
    high_risk = ["password", "bank", "otp", "login", "verify", "account locked"]
    for word in high_risk:
        if word in text:
            score += 25
            reasons.append(f"high risk keyword: {word}")

    # MEDIUM RISK
    medium_risk = ["urgent", "click", "link", "security alert", "update"]
    for word in medium_risk:
        if word in text:
            score += 15
            reasons.append(f"medium risk keyword: {word}")

    # URL Check
    urls = extract_urls(raw_text)
    if urls:
        score += 20
        reasons.append("URL detected")
        
        # Deep check for malicious URLs
        for url in urls:
            if is_malicious(url):
                score += 40
                reasons.append(f"malicious URL identified: {url}")
                break # Only add once

    # evidence present
    if evidence:
        score += 10
        reasons.append("evidence provided")

    # LOW RISK indicators
    low_risk = ["newsletter", "promotion", "discount", "offer"]
    for word in low_risk:
        if word in text:
            score -= 10
            reasons.append(f"low risk indicator: {word}")

    # ✅ ADD THIS BLOCK (VADER NLP scoring) - Use raw_text for case sensitivity
    nlp_score, nlp_reasons = vader_risk_score(raw_text)
    score += nlp_score
    reasons.extend(nlp_reasons)

    # normalize score
    score = max(0, min(score, 100))

    # assign risk level
    if score <= 25:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return score, level, reasons   # ✅ UPDATED RETURN

def detect_threat_type(text, malicious_url_found, urgency_score):
    classifier = get_threat_classifier()
    ml_type, confidence = classifier.predict(text)
    
    # Hybrid approach: Rule-based fallback if ML confidence is low
    if confidence > 0.6:
        return ml_type, confidence
        
    text_lower = text.lower()

    if malicious_url_found:
        return "Malicious Link", 1.0

    elif any(word in text_lower for word in ["otp", "password", "bank", "verify", "login"]):
        return "Credential Theft", 0.9

    elif urgency_score > 10:
        return "Social Engineering", 0.8

    return ml_type, confidence  # Return ML type even if low confidence if no rules match