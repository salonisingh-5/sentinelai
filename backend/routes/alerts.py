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


@router.get("/alerts")
def get_alerts():

    db = SessionLocal()

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


@router.post("/alerts")
def create_alert(data: dict):

    db = SessionLocal()

    # USER INPUT
    log_text = data["log_text"]

    # AI CLASSIFICATION
    ai_result = classify_log(log_text)

    threat_type = ai_result["threat_type"]
    severity = ai_result["severity_label"]

    # AI EXPLANATION
    explanation_data = get_fallback_explanation(threat_type)
    explanation = explanation_data["explanation"]

    # SAVE TO DATABASE
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