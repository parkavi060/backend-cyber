from flask import current_app
import requests
import re

def extract_urls(text):
    pattern = r'(https?://[^\s]+)'
    return re.findall(pattern, text)

def is_malicious(url):
    api_key = current_app.config.get("SAFE_BROWSING_API_KEY")

    if not api_key:
        current_app.logger.warning("SAFE_BROWSING_API_KEY is missing. Skipping URL check.")
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "cyberguard",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
        current_app.logger.debug(f"Safe Browsing API response: {result}") 
        return "matches" in result
    except Exception as e:
        current_app.logger.error(f"Error checking URL with Safe Browsing: {e}")
        return False
