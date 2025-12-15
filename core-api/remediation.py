import logging
from pydantic import BaseModel
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("remediation")

# In-memory history (volatile, but good for demo/evidence)
remediation_history = []

def get_remediation_history():
    return sorted(remediation_history, key=lambda x: x['timestamp'], reverse=True)

class RemediationRequest(BaseModel):
    action: str
    target: str
    reason: str = "Automated remediation by LogWarden"
    ai_analysis: dict = {} # Full AI context (root cause, confidence, etc)

def execute_remediation(request: RemediationRequest):
    """
    Executes a SAFE, simulated remediation action.
    In a real production environment, this would interface with firewalls, IAM, etc.
    For this 'Safe Mode', it logs the action and returns a success message.
    """
    action = request.action.lower()
    target = request.target
    
    logger.info(f"Received remediation request: {action} on {target}")

    result = None
    if action == "block_ip":
        # Simulation: In real life -> subprocess.run(["iptables", "-A", "INPUT", "-s", target, "-j", "DROP"])
        logger.warning(f"SIMULATION: Blocking IP {target} via firewall...")
        result = {
            "status": "success", 
            "message": f"IP {target} has been blocked successfully (Simulated).",
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "target": target,
            "reason": request.reason
        }
    
    elif action == "disable_user":
        # Simulation: In real life -> subprocess.run(["usermod", "-L", target])
        logger.warning(f"SIMULATION: Disabling user account {target}...")
        result = {
            "status": "success", 
            "message": f"User account '{target}' has been disabled (Simulated).",
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "target": target,
            "reason": request.reason
        }
        
    elif action == "isolate_host":
        # Simulation: Network isolation
        logger.warning(f"SIMULATION: Isolating host {target} from network...")
        result = {
            "status": "success", 
            "message": f"Host {target} has been isolated from the network (Simulated).",
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "target": target,
            "reason": request.reason,
            "ai_analysis": request.ai_analysis
        }

    else:
        return {
            "status": "error", 
            "message": f"Unknown remediation action: {action}"
        }

    # Add to history
    remediation_history.append(result)
    return result
