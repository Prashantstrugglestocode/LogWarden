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

@router.post("/analyze")
async def analyze_security_event(request: AnalysisRequest):
    # Check cache first for faster response
    cache_key = get_cache_key(request.log_message, request.source)
    if cache_key in analysis_cache:
        return analysis_cache[cache_key]
    
    # Calculate severity using CVSS before calling AI (for speed)
    log_type = "INFO"  # Default
    if "error" in request.log_message.lower() or "fail" in request.log_message.lower():
        log_type = "ERROR"
    if "critical" in request.log_message.lower() or "brute" in request.log_message.lower():
        log_type = "CRITICAL"
    
    severity, confidence = calculate_severity(
        log_type=log_type,
        keywords=[request.log_message, request.source]
    )
    
    # Optimized, concise system prompt for faster inference
    system_prompt = """You are LogWarden AI Security Analyst. Analyze logs and provide concise security insights.

Response format (JSON only, no markdown):
{
    "root_cause": "Brief technical explanation (max 2 sentences)",
    "remediation": ["Action 1", "Action 2", "Action 3"]
}

Focus on actionable remediation steps. Be specific and concise."""

    user_prompt = f"Source: {request.source}\nLog: {request.log_message}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": "qwen2.5:1.5b",
                    "prompt": f"{system_prompt}\n\n{user_prompt}",
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": 0.3,  # Lower temperature for faster, more consistent responses
                        "num_predict": 200   # Limit response length for speed
                    }
                },
                timeout=10.0  # Reduced timeout for faster failure
            )
            
            if response.status_code == 200:
                result = response.json()
                try:
                    ai_analysis = json.loads(result.get("response", "{}"))
                    
                    # Combine CVSS scoring with AI analysis
                    final_analysis = {
                        "severity": severity,
                        "confidence": confidence,
                        "root_cause": ai_analysis.get("root_cause", "Security event detected"),
                        "remediation": ai_analysis.get("remediation", ["Review logs", "Investigate source", "Apply security patches"])
                    }
                    
                    # Cache the result
                    analysis_cache[cache_key] = final_analysis
                    
                    return final_analysis
                except json.JSONDecodeError:
                    # Fallback if AI fails to parse
                    fallback = {
                        "severity": severity,
                        "confidence": confidence,
                        "root_cause": f"{get_severity_description(severity)}: {request.log_message[:100]}",
                        "remediation": ["Review event details", "Check system logs", "Apply security best practices"]
                    }
                    return fallback
            else:
                # Fallback on API error
                return {
                    "severity": severity,
                    "confidence": confidence,
                    "root_cause": f"Event classified as {severity} based on log analysis",
                    "remediation": ["Manual investigation required", "Review event context"]
                }
    except Exception as e:
        # Fallback on exception
        return {
            "severity": severity,
            "confidence": confidence,
            "root_cause": f"Analysis unavailable. Event severity: {severity}",
            "remediation": ["System analysis pending", "Review logs manually"],
            "error": str(e)
        }

