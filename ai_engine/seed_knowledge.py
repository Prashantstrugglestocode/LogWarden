from embedding import Embedder
from database import VectorDB

def seed():
    print("Seeding knowledge base...")
    embedder = Embedder()
    db = VectorDB()
    
    threats = [
        {
            "text": "Failed password for root from 192.168.1.100 port 22 ssh2",
            "metadata": {"severity": "High", "remediation": "Block IP address and disable root login."}
        },
        {
            "text": "Invalid user admin from 10.0.0.5",
            "metadata": {"severity": "Medium", "remediation": "Check for brute force attempts."}
        },
        {
            "text": "Accepted publickey for ubuntu from 192.168.1.50 port 54321 ssh2",
            "metadata": {"severity": "None", "remediation": "None (Normal behavior)"}
        },
        {
            "text": "POSSIBLE BREAK-IN ATTEMPT! [123.45.67.89]",
            "metadata": {"severity": "Critical", "remediation": "Immediate isolation of host."}
        },
        {
            "text": "sql_injection_attack: SELECT * FROM users WHERE '1'='1'",
            "metadata": {"severity": "High", "remediation": "Patch SQL vulnerability and sanitize inputs."}
        }
    ]
    
    for threat in threats:
        print(f"Adding: {threat['text']}")
        vector = embedder.embed(threat['text'])
        db.add_threat_signature(threat['text'], threat['metadata'], vector)
        
    print("Seeding complete.")

if __name__ == "__main__":
    seed()
