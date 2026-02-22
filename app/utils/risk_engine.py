from .nlp_analyzer import vader_risk_score   # ✅ ADD THIS IMPORT

def calculate_risk_score(title: str, description: str, evidence: str):
    score = 0
    reasons = []   # ✅ ADD (for explainability)

    text = (title + " " + description + " " + evidence).lower()

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

    # URL present
    if "http://" in text or "https://" in text:
        score += 20
        reasons.append("URL detected")

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

    # ✅ ADD THIS BLOCK (VADER NLP scoring)
    nlp_score, nlp_reasons = vader_risk_score(text)
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

    text_lower = text.lower()

    if malicious_url_found:
        return "Malicious Link"

    elif any(word in text_lower for word in ["otp", "password", "bank", "verify", "login"]):
        return "Credential Theft"

    elif urgency_score > 10:
        return "Social Engineering"

    else:
        return "Suspicious Message"