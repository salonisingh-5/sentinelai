def analyze_log(log_text):

    log_text = log_text.lower()

    if "failed login" in log_text:
        return {
            "threat": "Brute Force Attack",
            "severity": "High",
            "explanation": "Multiple failed login attempts detected.",
            "mitigation": "Block suspicious IP and enable MFA."
        }

    elif "malware" in log_text:
        return {
            "threat": "Malware Activity",
            "severity": "Critical",
            "explanation": "Malware signature detected in system logs.",
            "mitigation": "Isolate infected machine immediately."
        }

    else:
        return {
            "threat": "Unknown Activity",
            "severity": "Medium",
            "explanation": "Suspicious behavior detected.",
            "mitigation": "Monitor activity closely."
        }


def ask_question(question, alert_data):

    return {
        "answer": f"AI response for '{question}' regarding '{alert_data['threat']}'"
    }
