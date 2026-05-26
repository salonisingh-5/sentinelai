from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from database import Base

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    log_text = Column(String)
    threat_type = Column(String)
    severity = Column(String)
    explanation = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    raw_text = Column(String)
    source = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)