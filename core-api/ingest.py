from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from database import get_db
from models import Log
from datetime import datetime
import sys
import os

# Add parent directory to path to import ai_engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from ai_engine.engine import AIEngine
    print("Initializing AI Engine...")
    ai_engine = AIEngine()
    print("AI Engine initialized.")
except Exception as e:
    print(f"Failed to initialize AI Engine: {e}")
    ai_engine = None

router = APIRouter()

class LogEntry(BaseModel):
    source: str
    timestamp: str
    type: str = "INFO"
    message: str
    content: Dict[str, Any] = {}

@router.post("/logs")
async def ingest_logs(log: LogEntry, db: Session = Depends(get_db)):
    # Run AI Analysis
    is_threat = False
    threat_confidence = None
    threat_signature = None
    remediation = None
    
    if ai_engine:
        try:
            analysis = ai_engine.analyze_log(log.message)
            if analysis.get("is_threat"):
                is_threat = True
                threat_confidence = analysis.get("confidence")
                threat_signature = analysis.get("matched_signature")
                remediation = analysis.get("remediation")
        except Exception as e:
            print(f"Error during AI analysis: {e}")

    db_log = Log(
        source=log.source,
        type=log.type,
        message=log.message,
        timestamp=datetime.fromisoformat(log.timestamp.replace("Z", "+00:00")) if log.timestamp else datetime.now(),
        raw_content=log.content,
        is_threat=is_threat,
        threat_confidence=threat_confidence,
        threat_signature=threat_signature,
        remediation=remediation
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return {"status": "received", "id": db_log.id, "is_threat": is_threat}

@router.get("/logs")
async def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(Log).order_by(Log.timestamp.desc()).limit(limit).all()
