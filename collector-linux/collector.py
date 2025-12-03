import time
import os
import requests
import json
import subprocess

# Configuration
API_URL = os.getenv("API_URL", "http://localhost:8000/ingest/logs")

# Determine log file based on OS
if os.path.exists("/var/log/syslog"):
    LOG_FILE = "/var/log/syslog"
    OS_TYPE = "linux"
elif os.path.exists("/var/log/system.log"):
    LOG_FILE = "/var/log/system.log"
    OS_TYPE = "macos"
else:
    LOG_FILE = "test.log" # Fallback
    OS_TYPE = "unknown"

HOSTNAME = os.uname().nodename

def follow(thefile):
    thefile.seek(0, 2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def send_log(content):
    # Basic filtering to reduce noise from macOS system logs
    if OS_TYPE == "macos" and "last message repeated" in content:
        return

    payload = {
        "source": f"{OS_TYPE}-{HOSTNAME}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "content": {"raw": content.strip()},
        "message": content.strip(), # Ensure message field is populated for UI
        "type": "INFO" # Default type
    }
    
    # Simple heuristic for log type
    if "error" in content.lower() or "fail" in content.lower():
        payload["type"] = "ERROR"
    if "warning" in content.lower():
        payload["type"] = "WARNING"

    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code != 200:
            print(f"Failed to send log: {response.text}")
    except Exception as e:
        print(f"Error sending log: {e}")

def main():
    print(f"Starting Log Collector on {HOSTNAME} ({OS_TYPE})...")
    print(f"Monitoring {LOG_FILE}")
    
    # Check if file exists
    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found.")
        # For testing purposes, we might want to create a dummy file or exit
        # return

    try:
        with open(LOG_FILE, "r") as f:
            for line in follow(f):
                send_log(line)
    except KeyboardInterrupt:
        print("Stopping collector...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
