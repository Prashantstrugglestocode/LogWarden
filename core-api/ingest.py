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
            # Only trust high confidence matches (Tier 2) for ingestion
            if analysis and analysis['distance'] < 0.4:
                meta = analysis['metadata']
                if meta.get('is_threat') == 'True':
                    is_threat = True
                    threat_confidence = "High" # We trust the DB match
                    threat_signature = analysis.get("document")
                    remediation = meta.get("remediation")
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

@router.get("/stats/threats")
async def get_threat_stats(db: Session = Depends(get_db)):
    """
    Returns top threat sources based on 'is_threat' flag.
    """
    from sqlalchemy import func
    results = db.query(Log.source, func.count(Log.id).label('count'))\
        .filter(Log.is_threat == True)\
        .group_by(Log.source)\
        .order_by(func.count(Log.id).desc())\
        .limit(5)\
        .all()
    
    return [{"source": r[0], "count": r[1]} for r in results]

@router.get("/stats/traffic")
async def get_traffic_stats(db: Session = Depends(get_db)):
    """
    Returns traffic volume vs blocked volume by hour.
    """
    from sqlalchemy import func, text, case
    # Postgres specific date truncation
    results = db.query(
        func.to_char(Log.timestamp, 'HH24:00').label('hour'),
        func.count(Log.id).label('total'),
        func.sum(case((Log.is_threat == True, 1), else_=0)).label('blocked')
    ).group_by(func.to_char(Log.timestamp, 'HH24:00'))\
     .order_by(func.to_char(Log.timestamp, 'HH24:00'))\
     .all()

    return [{"time": r[0], "inbound": r[1], "blocked": r[2] or 0} for r in results]

@router.get("/stats/summary")
async def get_summary_stats(db: Session = Depends(get_db)):
    """
    Returns summary stats for the dashboard.
    """
    from sqlalchemy import func
    
    # Active Collectors (from config + logs)
    # real_sources = db.query(models.LogSource).count() 
    # Or just distinct sources in logs if no config
    cols = db.query(func.count(func.distinct(Log.source))).scalar()
    
    # Blocked Threats (total)
    blocked = db.query(func.count(Log.id)).filter(Log.is_threat == True).scalar()
    
    # Health Calculation (Based on last 100 logs to be responsive)
    # If recent logs are mostly threats, health drops.
    recent_total = db.query(Log).order_by(Log.timestamp.desc()).limit(100).count()
    recent_threats = db.query(Log).filter(Log.is_threat == True).order_by(Log.timestamp.desc()).limit(100).count()
    
    health = 100
    if recent_total > 0:
        threat_ratio = recent_threats / recent_total
        # Penalize heavily: 10% threats = 50% health? No, let's say 100 - (ratio * 100)
        health = int(100 - (threat_ratio * 100))
    
    # Latency (Mocking real variance for "AI Processing Time")
    # In a real app, we'd store `processing_time` in Log model.
    import random
    latency_ms = random.randint(800, 1500)
    latency_str = f"{latency_ms/1000}s"
    
    return {
        "collectors": cols,
        "blocked": blocked,
        "latency": latency_str,
        "health": health
    }
