from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean
from sqlalchemy.sql import func
from database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, index=True)
    type = Column(String, index=True)
    message = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    raw_content = Column(JSON, nullable=True)
    
    # AI/RAG Analysis
    is_threat = Column(Boolean, default=False)
    threat_confidence = Column(String, nullable=True)
    threat_signature = Column(String, nullable=True)
    remediation = Column(String, nullable=True)
