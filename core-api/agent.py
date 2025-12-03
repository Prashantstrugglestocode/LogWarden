from fastapi import APIRouter
from pydantic import BaseModel
import httpx
import os
import json
import hashlib
from cvss_calculator import calculate_severity, get_severity_description

router = APIRouter()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# Simple in-memory cache for analysis results
analysis_cache = {}

class AnalysisRequest(BaseModel):
    log_message: str
    source: str
    context: str = ""

def get_cache_key(log_message: str, source: str) -> str:
    """Generate cache key from log message and source"""
    return hashlib.md5(f"{source}:{log_message}".encode()).hexdigest()




# Add parent directory to path to import ai_engine
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from ai_engine.engine import AIEngine
    print("Initializing AI Engine in Agent...")
    ai_engine = AIEngine()
except Exception as e:
    print(f"Failed to initialize AI Engine in Agent: {e}")
    ai_engine = None

# Import Playbooks
try:
    from .playbooks import get_playbook
except ImportError:
    # Fallback if relative import fails (e.g. running directly)
    from playbooks import get_playbook

class LearnRequest(BaseModel):
    log_message: str
    is_threat: bool
    severity: str = "Medium"
    remediation: str = "None"

@router.post("/learn")
async def learn_from_log(request: LearnRequest):
    if not ai_engine:
        return {"status": "error", "message": "AI Engine not available"}
    
    result = ai_engine.learn_log(
        text=request.log_message,
        is_threat=request.is_threat,
        severity=request.severity,
        remediation=request.remediation
    )
    return result

@router.post("/analyze")
async def analyze_security_event(request: AnalysisRequest):
    # Check cache first for faster response
    cache_key = get_cache_key(request.log_message, request.source)
    if cache_key in analysis_cache:
        return analysis_cache[cache_key]
    
    # Calculate severity using CVSS (fallback/initial)
    log_type = "INFO"
    if "error" in request.log_message.lower() or "fail" in request.log_message.lower():
        log_type = "ERROR"
    if "critical" in request.log_message.lower() or "brute" in request.log_message.lower():
        log_type = "CRITICAL"
    
    severity, confidence = calculate_severity(
        log_type=log_type,
        keywords=[request.log_message, request.source]
    )

    # Use RAG Engine if available
    if ai_engine:
        try:
            analysis = ai_engine.analyze_log(request.log_message)
            
            # If RAG finds a threat, use its findings ENRICHED with Playbooks
            if analysis.get("is_threat"):
                matched_sig = analysis.get('matched_signature', 'Unknown')
                
                # Get Expert Playbook based on the signature/threat type
                playbook = get_playbook(matched_sig)
                
                final_analysis = {
                    "severity": analysis.get("severity", severity),
                    "confidence": analysis.get("confidence", confidence),
                    "root_cause": f"{playbook['root_cause']} (Matched: {matched_sig})",
                    "remediation": playbook['remediation'], # Use detailed steps from playbook
                    "title": playbook['title']
                }
                analysis_cache[cache_key] = final_analysis
                return final_analysis
            else:
                # If RAG says safe, but CVSS says high severity, we might want to trust CVSS or return "Safe"
                # For now, let's return a "Safe" or "Info" response if RAG doesn't flag it, 
                # but keep CVSS severity if it's high to be safe.
                final_analysis = {
                    "severity": severity,
                    "confidence": "Medium", # Lower confidence if RAG didn't match
                    "root_cause": "No known threat signature matched.",
                    "remediation": ["Monitor for anomalies"]
                }
                analysis_cache[cache_key] = final_analysis
                return final_analysis

        except Exception as e:
            print(f"RAG Analysis failed: {e}")
            # Fall through to fallback
