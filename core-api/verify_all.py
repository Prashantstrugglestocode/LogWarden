import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def test_ingest_safe():
    print("1. Testing Safe Log Ingestion...")
    payload = {
        "source": "verify_script",
        "message": "User logged in successfully",
        "timestamp": "2023-10-27T10:00:00Z"
    }
    try:
        res = requests.post(f"{BASE_URL}/ingest/logs", json=payload)
        if res.status_code == 200:
            data = res.json()
            if not data.get("is_threat"):
                print("   [PASS] Log ingested and marked Safe.")
                return True
            else:
                print(f"   [FAIL] Log marked as threat: {data}")
        else:
            print(f"   [FAIL] Status code {res.status_code}")
    except Exception as e:
        print(f"   [FAIL] Exception: {e}")
    return False

def test_ingest_threat():
    print("\n2. Testing Threat Log Ingestion (SQL Injection)...")
    payload = {
        "source": "verify_script",
        "message": "SELECT * FROM users WHERE 1=1",
        "timestamp": "2023-10-27T10:00:00Z"
    }
    try:
        res = requests.post(f"{BASE_URL}/ingest/logs", json=payload)
        if res.status_code == 200:
            data = res.json()
            if data.get("is_threat"):
                print("   [PASS] Log ingested and correctly marked as THREAT.")
                return True
            else:
                print(f"   [FAIL] Log NOT marked as threat: {data}")
        else:
            print(f"   [FAIL] Status code {res.status_code}")
    except Exception as e:
        print(f"   [FAIL] Exception: {e}")
    return False

def test_analyze_threat():
    print("\n3. Testing AI Analysis (Playbook Integration)...")
    payload = {
        "log_message": "SELECT * FROM users WHERE 1=1",
        "source": "verify_script"
    }
    try:
        res = requests.post(f"{BASE_URL}/agent/analyze", json=payload)
        if res.status_code == 200:
            data = res.json()
            # Check for Playbook specific content
            if "SQL Injection Attempt" in data.get("title", ""):
                print("   [PASS] Analysis returned Expert Playbook title.")
                return True
            else:
                print(f"   [FAIL] Analysis did not return Playbook title. Got: {data}")
        else:
            print(f"   [FAIL] Status code {res.status_code}")
    except Exception as e:
        print(f"   [FAIL] Exception: {e}")
    return False

def main():
    print("Waiting for API to be ready...")
    time.sleep(3) # Give it a moment to start
    
    results = [
        test_ingest_safe(),
        test_ingest_threat(),
        test_analyze_threat()
    ]
    
    if all(results):
        print("\n>>> ALL CHECKS PASSED <<<")
        sys.exit(0)
    else:
        print("\n>>> SOME CHECKS FAILED <<<")
        sys.exit(1)

if __name__ == "__main__":
    main()
