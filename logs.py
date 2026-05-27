from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import SessionLocal
from models import Log
from datetime import datetime

router = APIRouter()


# DATABASE SESSION
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# REQUEST BODY FORMAT
class LogRequest(BaseModel):
    log: str


# ---------------------------------------------------
# POST /logs/ingest
# ---------------------------------------------------

@router.post("/logs/ingest")
def ingest_log(data: LogRequest, db: Session = Depends(get_db)):

    new_log = Log(
        raw_text=data.log,
        source="manual",
        timestamp=datetime.utcnow()
    )

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return {
        "status": "stored",
        "log_id": new_log.id
    }