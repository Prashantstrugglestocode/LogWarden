import requests
import time
import random
import datetime
import threading

API_URL = "http://localhost:8000/ingest/logs"

# Configuration
USERS = ["alice@company.com", "bob@company.com", "admin@company.com", "svc_backup"]
IPS = {
    "NY": "198.51.100.1",
    "London": "203.0.113.1",
    "Moscow": "185.70.1.1", 
    "Beijing": "223.5.5.5", 
    "Internal": "10.0.0.5"
}

def send_log(log_type, message, content, source="traffic-sim"):
    payload = {
        "source": source,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "type": log_type,
        "message": message,
        "content": content
    }
    try:
        requests.post(API_URL, json=payload, timeout=2)
        # print(f"Sent: {message[:50]}...")
    except Exception as e:
        print(f"Failed to send log: {e}")

def sim_ssh_brute_force():
    """High Volume Brute Force from China/Russia"""
    target = "linux-prod-01"
    attacker_ip = random.choice([IPS["Moscow"], IPS["Beijing"]])
    
    for _ in range(5):
        send_log(
            "CRITICAL", 
            f"Failed password for root from {attacker_ip} port 22 ssh2",
            {"ip": attacker_ip, "user": "root", "port": 22},
            source=target
        )
        time.sleep(0.5)

def sim_impossible_travel():
    """Alice logs in from NY then London in 5 mins"""
    print("--- Simulating Impossible Travel (Alice) ---")
    # 1. Login from NY (Success)
    send_log(
        "INFO",
        "User alice@company.com logged in successfully",
        {"user": "alice@company.com", "ip": IPS["NY"], "location": "New York, USA", "action": "Login"},
        source="azure-ad"
    )
    
    time.sleep(2)
    
    # 2. Login from Moscow (Fail/Suspicious)
    send_log(
        "WARNING",
        "Sign-in detected from unfamiliar location",
        {"user": "alice@company.com", "ip": IPS["Moscow"], "location": "Moscow, Russia", "action": "Login", "risk": "High"},
        source="azure-ad"
    )

def sim_data_exfil():
    """Bob downloads 50 sensitive files"""
    print("--- Simulating Data Exfiltration (Bob) ---")
    for i in range(10):
        send_log(
            "WARNING",
            f"Sensitive file 'Budget_2025_Part{i}.xlsx' downloaded by bob@company.com",
            {"user": "bob@company.com", "file": f"Budget_2025_Part{i}.xlsx", "action": "FileDownloaded", "volume": "High"},
            source="m365-sharepoint"
        )
        time.sleep(0.2)

def main():
    print("Starting Advanced Traffic Simulator...")
    while True:
        mode = random.choice(["brute", "travel", "exfil", "idle"])
        
        if mode == "brute":
            sim_ssh_brute_force()
        elif mode == "travel":
            sim_impossible_travel()
        elif mode == "exfil":
            sim_data_exfil()
        else:
            print("--- Idle Traffic ---")
            send_log("INFO", "Health check passed", {"status": "ok"}, source="k8s-cluster")
        
        time.sleep(random.randint(5, 15))

if __name__ == "__main__":
    main()
