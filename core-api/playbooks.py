"""
LogWarden Security Playbooks
Detailed expert guidance for common security threats.
"""

PLAYBOOKS = {
    "sql_injection": {
        "title": "SQL Injection Attempt",
        "root_cause": "An attacker is attempting to manipulate your database queries by injecting malicious SQL code via input fields or URL parameters. This often targets vulnerabilities in input sanitization.",
        "remediation": [
            "Block the offending IP address immediately at the firewall/WAF level.",
            "Review the application code for the targeted endpoint; ensure parameterized queries (Prepared Statements) are used.",
            "Enable strict input validation and sanitization for all user inputs.",
            "Check database logs for any successful unauthorized queries or data exfiltration."
        ],
        "severity": "High",
        "references": ["OWASP Top 10: A03:2021-Injection"]
    },
    "brute_force": {
        "title": "Brute Force Authentication",
        "root_cause": "High volume of failed login attempts detected. An attacker is trying to guess user credentials using automated tools.",
        "remediation": [
            "Temporarily lock the targeted user account(s) to prevent further attempts.",
            "Implement or enforce rate limiting (e.g., max 5 attempts per minute) on the login endpoint.",
            "Block the source IP address if it originates from a non-trusted location.",
            "Recommend or enforce Multi-Factor Authentication (MFA) for all users."
        ],
        "severity": "Medium",
        "references": ["OWASP Top 10: A07:2021-Identification and Authentication Failures"]
    },
    "port_scan": {
        "title": "Port Scanning Activity",
        "root_cause": "A single source IP is connecting to multiple ports in a short timeframe. This indicates reconnaissance activity to find open vulnerabilities.",
        "remediation": [
            "Block the source IP address at the network perimeter.",
            "Review firewall rules to ensure only necessary ports are open to the public.",
            "Check if any internal services were accessed or if the scan was blocked.",
            "Enable 'stealth mode' on firewalls to drop packets without responding."
        ],
        "severity": "Low",
        "references": []
    },
    "default": {
        "title": "Security Anomaly Detected",
        "root_cause": "An anomalous pattern was detected that matches a known threat signature.",
        "remediation": [
            "Investigate the source IP address and user activity.",
            "Review surrounding logs for context.",
            "If confirmed malicious, block the source and reset associated credentials."
        ],
        "severity": "Medium",
        "references": []
    }
}

def get_playbook(threat_type: str):
    """
    Retrieves the playbook for a given threat type (keyword).
    """
    threat_type = threat_type.lower()
    
    # SQL Injection matching
    if any(x in threat_type for x in ["sql", "injection", "select *", "union select", "drop table", "1=1"]):
        return PLAYBOOKS["sql_injection"]
        
    # Brute Force matching
    if any(x in threat_type for x in ["brute", "login", "auth", "failed password", "invalid user"]):
        return PLAYBOOKS["brute_force"]
        
    # Port Scan matching
    if any(x in threat_type for x in ["scan", "nmap", "recon"]):
        return PLAYBOOKS["port_scan"]
    
    return PLAYBOOKS["default"]
