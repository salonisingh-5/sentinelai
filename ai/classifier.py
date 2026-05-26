def classify_log(log_text):

    log = log_text.lower()

    if "failed login" in log:
        return {
            "threat_type": "brute_force",
            "severity_label": "High",
            "confidence_pct": 85,
            "matched_keywords": ["failed login"]
        }

    elif "malware" in log:
        return {
            "threat_type": "malware",
            "severity_label": "Critical",
            "confidence_pct": 92,
            "matched_keywords": ["malware"]
        }

    elif "phishing" in log:
        return {
            "threat_type": "phishing",
            "severity_label": "Medium",
            "confidence_pct": 78,
            "matched_keywords": ["phishing"]
        }

    return {
        "threat_type": "unknown",
        "severity_label": "Low",
        "confidence_pct": 20,
        "matched_keywords": []
    }