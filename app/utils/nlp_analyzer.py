from nltk.sentiment import SentimentIntensityAnalyzer

sia = SentimentIntensityAnalyzer()

def vader_risk_score(text):
    """
    Analyze emotional pressure & urgency tone.
    Returns score contribution + explanation.
    """

    sentiment = sia.polarity_scores(text)
    compound = sentiment["compound"]

    score = 0
    reasons = []

    # Strong fear / pressure tone
    if compound <= -0.5:
        score += 15
        reasons.append("strong negative / fear tone detected")

    # mild urgency tone
    elif -0.5 < compound < -0.2:
        score += 8
        reasons.append("mild urgency tone detected")

    return score, reasons
