from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
import httpx
import os
import json
import hashlib
import random
from database import get_db
from models import Log
from datetime import datetime, timedelta
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

async def query_ollama(prompt: str, model: str = "qwen2.5:1.5b") -> dict:
    """
    Queries the Ollama LLM for analysis.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json" 
                },
                timeout=30.0
            )
            if response.status_code == 200:
                return response.json()
            else:
                print(f"Ollama Error: {response.status_code} - {response.text}")
                return None
    except Exception as e:
        print(f"Ollama Connection Failed: {e}")
        return None

@router.post("/analyze")
async def analyze_security_event(request: AnalysisRequest):
    # Tier 1: Memory (Cache) - Check cache first for faster response
    cache_key = get_cache_key(request.log_message, request.source)
    if cache_key in analysis_cache:
        return analysis_cache[cache_key]
    
    # Calculate severity using CVSS (fallback/initial baseline)
    log_type = "INFO"
    if "error" in request.log_message.lower() or "fail" in request.log_message.lower():
        log_type = "ERROR"
    if "critical" in request.log_message.lower() or "brute" in request.log_message.lower():
        log_type = "CRITICAL"
    
    cvss_severity, cvss_confidence = calculate_severity(
        log_type=log_type,
        keywords=[request.log_message, request.source]
    )

    final_analysis = {
        "severity": cvss_severity,
        "confidence": "Low",
        "root_cause": "Automated CVSS scan",
        "remediation": ["Monitor for anomalies"]
    }

    # Tier 2 & 3: AI Analysis (VectorDB + LLM)
    if ai_engine:
        try:
            # 1. Retrieve Context (Vector Search)
            retrieval = ai_engine.analyze_log(request.log_message)
            context_str = "No similar past incidents found."
            
            # Tier 2: Knowledge Base (High Confidence Match)
            # If we have a very strong match (distance < 0.35), trust the DB. 
            # This saves GPU reliability and time.
            if retrieval and retrieval['distance'] < 0.35:
                # High confidence match found!
                matched_sig = retrieval['document']
                print(f"Tier 2 Hit: Matched '{matched_sig}' with distance {retrieval['distance']}")
                
                # Get Expert Playbook based on the signature/threat type
                matched_doc = retrieval['document']
                playbook = get_playbook(matched_doc)
                
                final_analysis = {
                    "severity": retrieval['metadata']['severity'],
                    "confidence": "High",
                    "root_cause": f"Known Pattern: {playbook['root_cause']}",
                    "remediation": playbook['remediation'],
                    "title": playbook['title']
                }
                analysis_cache[cache_key] = final_analysis
                return final_analysis

            # Tier 3: Expert Analysis (Generative AI)
            # If we are here, it means we didn't find an exact match.
            # We will ask the LLM to analyze it, providing any "weak" matches as context.
            if retrieval:
                context_str = f"Found a somewhat similar past log (Distance {retrieval['distance']:.2f}):\nLog: {retrieval['document']}\nVerdict: {retrieval['metadata'].get('type', 'Unknown')}\nRemediation: {retrieval['metadata'].get('remediation', 'None')}"
            
            print(f"Tier 3 Triggered: Analyzing with Ollama... (Context: {context_str[:50]}...)")
            
            prompt = f"""
            Act as a Senior Security Analyst. Analyze this log for security threats.
            
            New Log Entry: "{request.log_message}"
            Source: {request.source}
            
            Context:
            {context_str}
            
            Instructions:
            1. Determine if this is a threat (is_threat).
            2. Assign Severity (Low, Medium, High, Critical).
            3. Choose immediate remediation ACTION from: ["block_ip", "disable_user", "isolate_host", "none"].
            4. Identify the TARGET for the action (IP address or Username).
            
            Respond ONLY in JSON format:
            {{
                "is_threat": boolean,
                "severity": "string",
                "root_cause": "string",
                "remediation": ["step 1", "step 2"],
                "suggested_action": "block_ip"|"disable_user"|"isolate_host"|"none",
                "action_target": "string"
            }}
            """
            
            llm_response = await query_ollama(prompt)
            
            if llm_response and 'response' in llm_response:
                try:
                    analysis_json = json.loads(llm_response['response'])
                    
                    final_analysis = {
                        "severity": analysis_json.get('severity', "Medium"),
                        "confidence": "Medium (Generative)",
                        "root_cause": analysis_json.get('root_cause', "Detected by AI Analysis"),
                        "remediation": analysis_json.get('remediation', ["Investigate source"]),
                        "title": "AI Detected Anomaly"
                    }

                    # AUTO-REMEDIATION LOOP
                    # If Critical/High threat, execute the action immediately
                    if analysis_json.get('is_threat') and final_analysis['severity'] in ["Critical", "High"]:
                        action = analysis_json.get('suggested_action')
                        target = analysis_json.get('action_target')
                        
                        if action and target and action != "none":
                            print(f"⚡ AUTO-REMEDIATION TRIGGERED: {action} on {target}")
                            from remediation import execute_remediation, RemediationRequest
                            
                            rem_req = RemediationRequest(
                                action=action,
                                target=target,
                                reason=f"Auto-Triggered by High Severity AI Analysis: {final_analysis['root_cause']}"
                            )
                            rem_result = execute_remediation(rem_req)
                            
                            # Append remediation info to the analysis result for the dashboard
                            final_analysis["auto_remediation"] = rem_result

                except json.JSONDecodeError:
                    print(f"Failed to parse LLM JSON: {llm_response['response']}")
                    # Fallback to CVSS if JSON fails
            
        except Exception as e:
            print(f"AI Analysis failed: {e}")
            import traceback
            traceback.print_exc()

    analysis_cache[cache_key] = final_analysis
    return final_analysis

@router.get("/users/risk")
def get_user_risk_profile(db: Session = Depends(get_db)):
    """
    Analyzes logs to build a risk profile for users.
    Implements 'Impossible Travel' and 'Data Exfiltration' detection via Graph-like queries.
    """
    # Look back 24 hours
    since = datetime.utcnow() - timedelta(hours=24)
    logs = db.query(Log).filter(Log.timestamp >= since).all()
    
    user_risk = {}
    
    for log in logs:
        # Extract user (naive extraction for MVP)
        user = None
        if log.raw_content and "user" in log.raw_content:
            user = log.raw_content["user"]
        elif "@" in log.message: # Simple regex-like email extraction
            parts = log.message.split()
            for p in parts:
                if "@" in p and "." in p:
                    user = p.strip(",")
                    break
        
        if not user:
            continue
            
        if user not in user_risk:
            user_risk[user] = {"score": 0, "issues": set()}
            
        # 1. Impossible Travel Logic
        if "unfamiliar location" in log.message.lower() or "travel" in log.message.lower():
            user_risk[user]["score"] += 80
            user_risk[user]["issues"].add("Impossible Travel")
            
        # 2. Data Exfiltration Logic
        if "sensitive file" in log.message.lower() or "downloaded" in log.message.lower():
            user_risk[user]["score"] += 10
            user_risk[user]["issues"].add("Bulk Data Download")
            
        # 3. Brute Force / Failures
        if "failed" in log.message.lower():
            user_risk[user]["score"] += 5
            user_risk[user]["issues"].add("Failed Login")
            
    # Format for frontend
    results = []
    for user, data in user_risk.items():
        score = min(data["score"], 100) # Cap at 100
        if score > 10: # Only show interesting users
            results.append({
                "user": user,
                "score": score,
                "issues": list(data["issues"])
            })
            
    # Sort by score desc
    results.sort(key=lambda x: x["score"], reverse=True)
    return results

@router.get("/users/{username}/graph")
def get_user_graph_data(username: str):
    """
    Simulates a Microsoft Graph API response for user details.
    Returns M365 account configuration, MFA status, and risk state.
    """
    # Deterministic simulation based on username
    is_admin = "admin" in username or "root" in username
    
    # Base Profile
    profile = {
        "displayName": username.split('@')[0].title(),
        "userPrincipalName": username,
        "id": hashlib.md5(username.encode()).hexdigest(),
        "accountEnabled": True,
        "jobTitle": "Administrator" if is_admin else "Employee",
        "officeLocation": "New York, USA",
        "mobilePhone": "+1 555-0100"
    }

    # Security Profile (Simulated Entra ID data)
    security = {
        "mfaEnabled": True if is_admin else False,
        "mfaMethod": "Authenticator App" if is_admin else "SMS",
        "conditionalAccess": "Report-Only" if is_admin else "Enforced",
        "riskLevel": "high" if "alice" in username or "admin" in username else "low",
        "lastPasswordChange": (datetime.utcnow() - timedelta(days=random.randint(5, 90))).isoformat(),
        "registeredDevices": random.randint(1, 3)
    }

    # Recent Sign-ins (Simulated)
    sign_ins = []
    locations = ["New York, US", "London, UK", "Moscow, RU"] if "alice" in username else ["New York, US"]
    
    for i in range(3):
        sign_ins.append({
            "createdDateTime": (datetime.utcnow() - timedelta(minutes=i*15)).isoformat(),
            "location": locations[i % len(locations)],
            "status": "failure" if locations[i % len(locations)] == "Moscow, RU" else "success",
            "appDisplayName": "Office 365 Exchange Online"
        })

    return {
        "profile": profile,
        "security": security,
        "recentSignIns": sign_ins
    }
