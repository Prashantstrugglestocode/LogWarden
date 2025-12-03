from fastapi import APIRouter
from pydantic import BaseModel
import httpx
import os
import json

router = APIRouter()

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

class AnalysisRequest(BaseModel):
    log_message: str
    source: str
    context: str = ""

@router.post("/analyze")
async def analyze_security_event(request: AnalysisRequest):
    # Interaction with Ollama
    # Model: qwen2.5:1.5b
    
    system_prompt = """You are LogWarden, an elite AI Security Officer specializing in Threat Detection and Incident Response.
    
    Your goal is to analyze the provided log entry and provide actionable security insights.
    
    **Analysis Guidelines:**
    1. **OWASP Alignment**: Map the event to relevant OWASP Top 10 risks (e.g., Injection, Broken Access Control, Security Misconfiguration) if applicable.
    2. **Root Cause**: Explain *why* this happened in technical terms.
    3. **Remediation**: Provide specific, copy-pasteable shell commands (e.g., `iptables`, `chmod`, `systemctl`) or configuration changes to fix the issue.
    
    **Response Format (JSON Only):**
    {
        "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
        "confidence": <0-100>,
        "root_cause": "Detailed explanation...",
        "remediation": ["Step 1: description", "Step 2: command"]
    }
    
    Do not include markdown formatting like ```json. Just return the raw JSON.
    """
    
    user_prompt = f"Log Source: {request.source}\nLog Message: {request.log_message}\nContext: {request.context}"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": "qwen2.5:1.5b",
                    "prompt": f"{system_prompt}\n\n{user_prompt}",
                    "stream": False,
                    "format": "json" 
                },
                timeout=30.0
            )
            
            if response.status_code == 200:
                result = response.json()
                # Parse the JSON from the model's response
                try:
                    analysis = json.loads(result.get("response", "{}"))
                    return analysis
                except json.JSONDecodeError:
                    return {"error": "Failed to parse AI response", "raw": result.get("response")}
            else:
                return {"error": f"Ollama error: {response.text}"}
    except Exception as e:
        return {"error": str(e)}
