from fastapi import APIRouter

from ..database import SessionLocal
from ..models import Alert

from database import SessionLocal
from models import Alert

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

    new_alert = Alert(
        log_text=data["log_text"],
        threat_type=data["threat_type"],
        severity=data["severity"],
        explanation=data["explanation"]
    )

    db.add(new_alert)
    db.commit()

    return {
        "message": "Alert created successfully"

    }

    }

