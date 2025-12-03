import time
import os
import requests
import json
import platform

# Only import windows specific modules if on windows
if platform.system() == "Windows":
    import win32evtlog

# Configuration
API_URL = os.getenv("API_URL", "http://localhost:8000/ingest/logs")
HOSTNAME = platform.node()

def get_windows_logs():
    if platform.system() != "Windows":
        print("Not running on Windows. Skipping Event Log collection.")
        return

    server = 'localhost'
    log_type = 'Security'
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(hand)

    print(f"Reading {log_type} logs...")
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                data = {
                    "event_id": event.EventID,
                    "source_name": event.SourceName,
                    "time_generated": event.TimeGenerated.Format(),
                    "message": str(event.StringInserts)
                }
                send_log(data)
        time.sleep(5)

def send_log(content):
    payload = {
        "source": f"windows-{HOSTNAME}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "content": content
    }
    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code != 200:
            print(f"Failed to send log: {response.text}")
    except Exception as e:
        print(f"Error sending log: {e}")

def main():
    print(f"Starting Windows Log Collector on {HOSTNAME}...")
    try:
        get_windows_logs()
    except KeyboardInterrupt:
        print("Stopping collector...")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
