from sqlalchemy import Column, Integer, String
from .database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    threat = Column(String)
    severity = Column(String)
    explanation = Column(String)
    mitigation = Column(String)
