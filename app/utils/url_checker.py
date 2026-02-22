from flask import current_app
import requests
import re

def extract_urls(text):
    pattern = r'(https?://[^\s]+)'
    return re.findall(pattern, text)

def is_malicious(url):
    api_key = current_app.config["SAFE_BROWSING_API_KEY"]

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

    response = requests.post(endpoint, json=payload)
    print(response.json()) 
    result = response.json()

    return "matches" in result
