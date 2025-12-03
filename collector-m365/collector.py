import os
import requests
import json
import time

# Configuration
API_URL = os.getenv("API_URL", "http://localhost:8000/ingest/logs")
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

def get_access_token():
    url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    data = {
        "client_id": CLIENT_ID,
        "scope": "https://graph.microsoft.com/.default",
        "client_secret": CLIENT_SECRET,
        "grant_type": "client_credentials"
    }
    response = requests.post(url, data=data)
    response.raise_for_status()
    return response.json().get("access_token")

def fetch_security_configs(token):
    headers = {"Authorization": f"Bearer {token}"}
    # Example: Fetch Secure Score
    url = "https://graph.microsoft.com/v1.0/security/secureScores"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching M365 data: {response.text}")
        return None

def send_data(content):
    payload = {
        "source": "m365-config",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "content": content
    }
    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code != 200:
            print(f"Failed to send data: {response.text}")
    except Exception as e:
        print(f"Error sending data: {e}")

def main():
    print("Starting M365 Configuration Fetcher...")
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("Error: Missing M365 credentials (TENANT_ID, CLIENT_ID, CLIENT_SECRET).")
        return

    try:
        token = get_access_token()
        configs = fetch_security_configs(token)
        if configs:
            send_data(configs)
            print("M365 configurations sent successfully.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
