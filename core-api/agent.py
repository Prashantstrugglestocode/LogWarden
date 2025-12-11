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

import re

def _get_user_context(username: str) -> dict:
    """
    Helper to simulate retrieving User Context from Graph API.
    """
    is_admin = "admin" in username.lower() or "root" in username.lower()
    
    return {
        "displayName": username.split('@')[0].title(),
        "jobTitle": "Administrator" if is_admin else "Employee",
        "is_admin": is_admin,
        "riskLevel": "high" if "alice" in username or "admin" in username else "low",
        "mfaEnabled": True if is_admin else False
    }

def _check_ip_reputation(ip: str) -> dict:
    """
    Helper to simulate checking IP Reputation.
    """
    # Mock malicious IPs for demo
    if ip.startswith("51.") or ip.startswith("185."):
        return {"score": 90, "status": "Malicious", "asn": "BadActor Network"}
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("127."):
        return {"score": 0, "status": "Safe (Private)", "asn": "Internal"}
    return {"score": 20, "status": "Unknown/Neutral", "asn": "ISP"}

def _extract_entities(log_message: str):
    """
    Extracts IP addresses and potential Usernames/Emails from log text.
    """
    # Regex for IPv4
    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log_message)
    ip = ip_match.group(0) if ip_match else None
    
    # Simple Regex for Email/User
    user_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', log_message)
    user = user_match.group(0) if user_match else None
    
    # Fallback for simple "user root" or "user admin" patterns common in logs
    if not user:
        simple_user_match = re.search(r'user\s+(\w+)', log_message, re.IGNORECASE)
        if simple_user_match:
            user = simple_user_match.group(1)
            
    return ip, user

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
            if retrieval:
                context_str = f"Found a somewhat similar past log (Distance {retrieval['distance']:.2f}):\nLog: {retrieval['document']}\nVerdict: {retrieval['metadata'].get('type', 'Unknown')}\nRemediation: {retrieval['metadata'].get('remediation', 'None')}"
            
            print(f"Tier 3 Triggered: Analyzing with Ollama... (Context: {context_str[:50]}...)")
            
            # --- CONTEXT ENRICHMENT START ---
            ip, user = _extract_entities(request.log_message)
            entity_context = ""
            
            if user:
                u_ctx = _get_user_context(user)
                entity_context += f"- User '{user}': Role={u_ctx['jobTitle']}, IsAdmin={u_ctx['is_admin']}, RiskLevel={u_ctx['riskLevel']}\n"
                
            if ip:
                i_ctx = _check_ip_reputation(ip)
                entity_context += f"- IP '{ip}': Reputation Score={i_ctx['score']}/100, Status={i_ctx['status']}\n"
            
            if not entity_context:
                entity_context = "- No specific entities (User/IP) extracted."
            # --- CONTEXT ENRICHMENT END ---

            # IMPROVED PROMPT: Chain-of-Thought (CoT) + Entity Context
            prompt = f"""
            You are a Senior Security Analyst. analyze the following log entry.
            
            Log: "{request.log_message}"
            Source: {request.source}
            
            Entity Intelligence (Contextual Awareness):
            {entity_context}
            
            Context from Knowledge Base (Past Incidents):
            {context_str}
            
            Your Task(Think Step-by-Step):
            1.  **Analyze the Log:** What is happening?
            2.  **Context Check:** Look at the 'Entity Intelligence'.
                - If the User is an ADMIN, this is CRITICAL.
                - If the IP has a Bad Reputation (Score > 50), this is MALICIOUS.
            3.  **Threat Assessment:** Combine Log + Identity + Reputation.
            4.  **Action Plan:** Should we block the IP or Disable the User?
            
            Output strictly in this JSON format:
            {{
                "reasoning": "Step-by-step thought process... (Mention user role/IP reputation)",
                "is_threat": boolean,
                "severity": "Low"|"Medium"|"High"|"Critical",
                "root_cause": "Short description",
                "remediation": ["step 1", "step 2"],
                "suggested_action": "block_ip"|"disable_user"|"isolate_host"|"none",
                "action_target": "IP or Username"
            }}
            """
            
            llm_response = await query_ollama(prompt)
            
            if llm_response and 'response' in llm_response:
                raw_text = llm_response['response']
                try:
                    # Robust Parsing: Find JSON block if model chatted around it
                    if "```json" in raw_text:
                        raw_text = raw_text.split("```json")[1].split("```")[0].strip()
                    elif "{" in raw_text:
                        # Best effort to find the first { and last }
                        start = raw_text.find("{")
                        end = raw_text.rfind("}") + 1
                        raw_text = raw_text[start:end]

                    analysis_json = json.loads(raw_text)
                    
                    # Log the CoT reasoning for debugging
                    print(f"🤖 AI Reasoning: {analysis_json.get('reasoning', 'No reasoning provided')}")
                    
                    final_analysis = {
                        "severity": analysis_json.get('severity', "Medium"),
                        "confidence": "Medium (Generative)",
                        "root_cause": analysis_json.get('root_cause', "Detected by AI Analysis"),
                        "remediation": analysis_json.get('remediation', ["Investigate source"]),
                        "title": "AI Detected Anomaly"
                    }

                    # AUTO-REMEDIATION LOOP
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
                            final_analysis["auto_remediation"] = rem_result

                except json.JSONDecodeError:
                    print(f"Failed to parse LLM JSON: {llm_response['response']}")
            
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
    """
    # Use the shared helper logic
    ctx = _get_user_context(username)
    
    # Base Profile
    profile = {
        "displayName": ctx['displayName'],
        "userPrincipalName": username,
        "id": hashlib.md5(username.encode()).hexdigest(),
        "accountEnabled": True,
        "jobTitle": ctx['jobTitle'],
        "officeLocation": "New York, USA",
        "mobilePhone": "+1 555-0100"
    }

    # Security Profile
    security = {
        "mfaEnabled": ctx['mfaEnabled'],
        "mfaMethod": "Authenticator App" if ctx['is_admin'] else "SMS",
        "conditionalAccess": "Report-Only" if ctx['is_admin'] else "Enforced",
        "riskLevel": ctx['riskLevel'],
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
