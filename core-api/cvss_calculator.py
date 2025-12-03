"""
CVSS (Common Vulnerability Scoring System) v3.1 Calculator
Maps log events to industry-standard severity ratings.
"""

def calculate_severity(log_type: str, keywords: list, impact_score: float = 0) -> tuple[str, int]:
    """
    Calculate severity based on log type, keywords, and optional impact score.
    
    Returns: (severity_level, confidence_score)
    
    Severity Levels (CVSS v3.1):
    - CRITICAL: 9.0-10.0 (Immediate threat, system compromise)
    - HIGH: 7.0-8.9 (Significant threat, requires urgent action)
    - MEDIUM: 4.0-6.9 (Moderate threat, should be addressed)
    - LOW: 0.1-3.9 (Minor issue, monitor)
    - INFO: 0.0 (Informational, no threat)
    """
    
    # Base severity from log type
    type_severity = {
        "CRITICAL": 9.0,
        "ERROR": 6.0,
        "WARNING": 3.0,
        "INFO": 0.0
    }.get(log_type.upper(), 0.0)
    
    # Keyword-based severity boosting
    critical_keywords = ["injection", "sql", "xss", "rce", "remote code", "breach", "exploit", "malware", "ransomware"]
    high_keywords = ["brute force", "unauthorized", "access denied", "authentication failed", "privilege escalation"]
    medium_keywords = ["failed login", "connection refused", "timeout", "misconfiguration"]
    
    keyword_boost = 0.0
    matched_keywords = []
    
    log_lower = " ".join(keywords).lower()
    
    for kw in critical_keywords:
        if kw in log_lower:
            keyword_boost = max(keyword_boost, 5.0)
            matched_keywords.append(kw)
    
    for kw in high_keywords:
        if kw in log_lower:
            keyword_boost = max(keyword_boost, 3.0)
            matched_keywords.append(kw)
    
    for kw in medium_keywords:
        if kw in log_lower:
            keyword_boost = max(keyword_boost, 1.5)
            matched_keywords.append(kw)
    
    # Calculate final CVSS score
    cvss_score = min(10.0, type_severity + keyword_boost + impact_score)
    
    # Map to severity level
    if cvss_score >= 9.0:
        severity = "CRITICAL"
        confidence = 95
    elif cvss_score >= 7.0:
        severity = "HIGH"
        confidence = 90
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
        confidence = 85
    elif cvss_score > 0.0:
        severity = "LOW"
        confidence = 80
    else:
        severity = "INFO"
        confidence = 100
    
    return severity, confidence


def get_severity_description(severity: str) -> str:
    """Get human-readable description of severity level"""
    descriptions = {
        "CRITICAL": "Immediate threat requiring urgent action",
        "HIGH": "Significant threat requiring prompt attention",
        "MEDIUM": "Moderate threat to be addressed soon",
        "LOW": "Minor issue requiring monitoring",
        "INFO": "Informational event, no action required"
    }
    return descriptions.get(severity, "Unknown severity")
