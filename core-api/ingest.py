from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from database import get_db
from models import Log
from datetime import datetime

router = APIRouter()

class LogEntry(BaseModel):
    source: str
    timestamp: str
    type: str = "INFO"
    message: str
    content: Dict[str, Any] = {}

@router.post("/logs")
async def ingest_logs(log: LogEntry, db: Session = Depends(get_db)):
    db_log = Log(
        source=log.source,
        type=log.type,
        message=log.message,
        timestamp=datetime.fromisoformat(log.timestamp.replace("Z", "+00:00")) if log.timestamp else datetime.now(),
        raw_content=log.content
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return {"status": "received", "id": db_log.id}

@router.get("/logs")
async def get_logs(limit: int = 50, db: Session = Depends(get_db)):
    return db.query(Log).order_by(Log.timestamp.desc()).limit(limit).all()
