from engine import AIEngine
import time

def test():
    print("Initializing AI Engine...")
    engine = AIEngine()
    
    test_logs = [
        "Failed password for root from 192.168.1.105 port 22 ssh2", # Should be High threat
        "Accepted publickey for user prashant", # Should be benign
        "User admin login failed from 10.0.0.99", # Should be Medium/High threat
        "System uptime is 100 days" # Should be benign
    ]
    
    print("\nRunning Tests...")
    for log in test_logs:
        print(f"\nAnalyzing: '{log}'")
        start = time.time()
        result = engine.analyze_log(log)
        duration = (time.time() - start) * 1000
        
        print(f"Result: {result}")
        print(f"Time: {duration:.2f}ms")
        
        if result['is_threat']:
            print(f"✅ DETECTED THREAT: {result['matched_signature']} (Severity: {result['severity']})")
        else:
            print("ℹ️  No threat detected.")

if __name__ == "__main__":
    test()
