import time
import os
import requests
import json
import subprocess

# Configuration
API_URL = os.getenv("API_URL", "http://localhost:8000/ingest/logs")
LOG_FILE = "/var/log/syslog"  # Default to syslog, can be changed
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
    payload = {
        "source": f"linux-{HOSTNAME}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "content": {"raw": content.strip()}
    }
    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code != 200:
            print(f"Failed to send log: {response.text}")
    except Exception as e:
        print(f"Error sending log: {e}")

def main():
    print(f"Starting Linux Log Collector on {HOSTNAME}...")
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
