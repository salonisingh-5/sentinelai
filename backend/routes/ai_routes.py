from fastapi import APIRouter
from pydantic import BaseModel

from ..services.ai_service import analyze_log, ask_question

router = APIRouter()


# ---------------- ANALYZE ----------------

class LogRequest(BaseModel):
    log: str


@router.post("/analyze")
def analyze(request: LogRequest):

    result = analyze_log(request.log)

    return result


# ---------------- ASK ----------------

class AskRequest(BaseModel):
    question: str
    alert_id: int


@router.post("/ask")
def ask(request: AskRequest):

    # MOCK ALERT DATA
    alert_data = {
        "threat": "Brute Force Attack",
        "severity": "High"
    }

    response = ask_question(
        request.question,
        alert_data
    )

    return response
