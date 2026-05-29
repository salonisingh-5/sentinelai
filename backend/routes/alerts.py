from fastapi import APIRouter
from database import SessionLocal
from models import Alert

# FIX AI IMPORT PATH
import sys
import os

sys.path.append(
    os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../")
    )
)

# AI IMPORTS
from ai.classifier import classify_log, get_fallback_explanation

router = APIRouter()


# =========================
# GET ALERTS
# =========================
@router.get("/alerts")
def get_alerts():

    db = SessionLocal()

    try:

        alerts = db.query(Alert).all()

        result = []

        for alert in alerts:

            result.append({
                "id": alert.id,
                "log_text": alert.log_text,
                "threat_type": alert.threat_type,
                "severity": alert.severity,
                "explanation": alert.explanation
            })

        return result

    finally:
        db.close()


# =========================
# CREATE ALERT
# =========================
@router.post("/alerts")
def create_alert(data: dict):

    db = SessionLocal()

    try:

        log_text = data["log_text"]

        ai_result = classify_log(log_text)

        threat_type = ai_result["threat_type"]
        severity = ai_result["severity_label"]

        explanation_data = get_fallback_explanation(
            threat_type
        )

        explanation = explanation_data["explanation"]

        new_alert = Alert(
            log_text=log_text,
            threat_type=threat_type,
            severity=severity,
            explanation=explanation
        )

        db.add(new_alert)
        db.commit()

        return {
            "message": "AI alert created successfully",
            "ai_result": ai_result,
            "explanation": explanation_data
        }

    finally:
        db.close()


# =========================
# GET STATS
# =========================
@router.get("/stats")
def get_stats():

    db = SessionLocal()

    try:

        alerts = db.query(Alert).all()

        low = 0
        medium = 0
        high = 0
        critical = 0

        for alert in alerts:

            severity = alert.severity.lower()

            if severity == "low":
                low += 1

            elif severity == "medium":
                medium += 1

            elif severity == "high":
                high += 1

            elif severity == "critical":
                critical += 1

        return {
            "low": low,
            "medium": medium,
            "high": high,
            "critical": critical
        }

    finally:
        db.close()


# =========================
# SIMULATE ATTACK
# =========================
@router.post("/simulate")
def simulate_attack():

    db = SessionLocal()

    try:

        sample_log = "Mass file encryption started on server"

        ai_result = classify_log(sample_log)

        explanation_data = get_fallback_explanation(
            ai_result["threat_type"]
        )

        new_alert = Alert(
            log_text=sample_log,
            threat_type=ai_result["threat_type"],
            severity=ai_result["severity_label"],
            explanation=explanation_data["explanation"]
        )

        db.add(new_alert)
        db.commit()

        return {
            "message": "Attack simulated successfully"
        }

    finally:
        db.close()


# =========================
# AI CHAT
# =========================
@router.post("/ask")
def ask_ai(data: dict):

    question = data["question"].lower()

    if "malware" in question:
        answer = "This looks like malware activity. The system detected suspicious executable behavior and possible ransomware patterns."

    elif "phishing" in question:
        answer = "This appears to be a phishing attempt involving suspicious login requests and credential harvesting behavior."

    elif "severity" in question:
        answer = "Severity is calculated using attack impact, privilege escalation risk, and lateral movement indicators."

    elif "prevent" in question:
        answer = "Recommended prevention includes firewall hardening, MFA, endpoint monitoring, and regular patch updates."

    else:
        answer = "AI could not fully identify the query, but suspicious cybersecurity activity was detected."

    return {
        "answer": answer
    }
    