from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from database import engine
import models
from ingest import router as ingest_router
from agent import router as agent_router
from chat_agent import router as chat_router
from remediation import RemediationRequest, execute_remediation
import os
import sys
import logging
from license_manager import validate_license_key

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("core-api")

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="LogWarden Core API")

@app.on_event("startup")
async def startup_event():
    license_key = os.getenv("LICENSE_KEY")
    if not license_key:
        logger.critical("LICENSE_KEY environment variable is missing!")
        sys.exit(1)
    
    if not validate_license_key(license_key):
        logger.critical("Invalid LICENSE_KEY provided! Server startup service refused.")
        sys.exit(1)
    
    logger.info("License Verified. Starting Core API...")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], # Hardened
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(ingest_router, prefix="/ingest", tags=["Ingestion"])
app.include_router(agent_router, prefix="/agent", tags=["Agent"])
app.include_router(chat_router, tags=["Chat"])

# Remediation endpoint
@app.post("/remediate")
def remediate(request: RemediationRequest):
    result = execute_remediation(request)
    if result["status"] == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.get("/remediate/history")
async def history_remediation():
    from remediation import get_remediation_history
    return get_remediation_history()

    return headers

from sqlalchemy.orm import Session
from fastapi import Depends
from database import get_db
from pydantic import BaseModel

class ConfigRequest(BaseModel):
    key: str
    value: str

@app.get("/config")
def get_config(db: Session = Depends(get_db)):
    configs = db.query(models.SystemConfig).all()
    # Mask secrets
    for c in configs:
        if "KEY" in c.key or "PASSWORD" in c.key:
           if c.value and len(c.value) > 4:
               c.value = "..." + c.value[-4:]
    return {c.key: c.value for c in configs}

@app.post("/config")
def set_config(data: dict, db: Session = Depends(get_db)):
    key = data.get("key")
    val = data.get("value")
    if not key: raise HTTPException(400, "Key required")
    
    cfg = db.query(models.SystemConfig).filter(models.SystemConfig.key == key).first()
    if cfg:
        cfg.value = val
    else:
        cfg = models.SystemConfig(key=key, value=val)
        db.add(cfg)
    
    db.commit()
    return {"status": "updated"}

# --- Source Management API ---

class SourceCreate(BaseModel):
    name: str
    type: str # linux, windows, aws_cloudwatch
    host: str = None
    port: int = 22
    username: str = None
    auth_type: str = "password"
    password: str = None
    log_path: str = None
    
    # AWS Fields
    aws_region: str = None
    aws_log_group: str = None
    aws_access_key: str = None
    aws_secret_key: str = None

@app.get("/config/sources")
def get_sources(db: Session = Depends(get_db)):
    return db.query(models.LogSource).all()

@app.post("/config/sources")
def add_source(source: SourceCreate, db: Session = Depends(get_db)):
    new_source = models.LogSource(
        name=source.name,
        type=source.type,
        host=source.host,
        port=source.port,
        username=source.username,
        auth_type=source.auth_type,
        password=source.password,
        log_path=source.log_path,
        aws_region=source.aws_region,
        aws_log_group=source.aws_log_group,
        aws_access_key=source.aws_access_key,
        aws_secret_key=source.aws_secret_key,
        status="offline"
    )
    db.add(new_source)
    db.commit()
    db.refresh(new_source)
    return new_source

@app.post("/config/sources/{id}/test")
async def test_source_connection(id: int, db: Session = Depends(get_db)):
    source = db.query(models.LogSource).filter(models.LogSource.id == id).first()
    if not source: raise HTTPException(404, "Source not found")
    
    success = False
    if source.type == 'aws_cloudwatch':
        from aws_collector import AWSCollector
        collector = AWSCollector(source)
        success = collector.test_connection()
    else:
        from ssh_collector import SSHCollector
        collector = SSHCollector()
        success = await collector.test_connection(source)
    
    # Update status
    source.status = "online" if success else "error"
    db.commit()
    
    return {"success": success}

@app.post("/config/sources/{id}/start")
async def start_source_collection(id: int, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Launch in background, manage own DB session
    if id: # simple check
        from ssh_collector import start_collection_task
        # Note: We reuse the same task wrapper. We need to update it to support AWS.
        # or we make a new one. Let's update ssh_collector.py to be a generic collector_task.
        # actually, easier to make a new task loader in main for now or update the task.
        
        # Let's route based on type inside the task? No, task takes ID.
        # Let's update `ssh_collector.py` to `collector_service.py` concept but keeping name for now.
        # We will modify start_collection_task in ssh_collector.py to dispatch.
        background_tasks.add_task(start_collection_task, id)

    return {"status": "started"}

@app.get("/notifications")
def get_notifications(db: Session = Depends(get_db)):
    # Return unread + recent 10 read
    notes = db.query(models.Notification).order_by(models.Notification.timestamp.desc()).limit(20).all()
    return notes

@app.post("/notifications/read/{note_id}")
def mark_notification_read(note_id: int, db: Session = Depends(get_db)):
    note = db.query(models.Notification).filter(models.Notification.id == note_id).first()
    if note:
        note.is_read = True
        db.commit()
    return {"status": "success"}

@app.get("/")
async def root():
    return {"message": "LogWarden Core API is running"}
