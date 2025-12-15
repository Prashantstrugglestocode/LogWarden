from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
from sqlalchemy.sql import func

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

class SystemConfig(Base):
    __tablename__ = "system_config"

    key = Column(String, primary_key=True, index=True)
    value = Column(String)

class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String) # CRITICAL, WARNING, INFO
    message = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    is_read = Column(Boolean, default=False)

class LogSource(Base):
    __tablename__ = "log_sources"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True) # e.g. "Web Server Prod"
    type = Column(String) # "linux" or "windows"
    host = Column(String) # IP or Hostname
    port = Column(Integer, default=22)
    username = Column(String)
    auth_type = Column(String, default="password") # "password" or "key"
    password = Column(String, nullable=True) # Encrypt in prod!
    key_path = Column(String, nullable=True) # Path to private key on server
    log_path = Column(String) # /var/log/syslog or "Security"
    status = Column(String, default="offline") # online, offline, error
    last_collected_at = Column(DateTime, nullable=True)

    # AWS Specific Fields
    aws_region = Column(String, nullable=True)
    aws_log_group = Column(String, nullable=True)
    aws_access_key = Column(String, nullable=True)
    aws_secret_key = Column(String, nullable=True)
