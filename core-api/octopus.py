import time
import logging
import json
import random
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("octopus")

class OctopusEngine:
    """
    The Octopus Engine is an Agentless Log Retriever.
    It connects to remote infrastructure via standard protocols (SSH, WinRM, API)
    to pull logs and execute remediation actions without installing agents.
    """

    def __init__(self):
        self.sources = []
        logger.info("Initializing Octopus Engine: Agentless Mode Active")

    def add_source(self, source_type, identifier, credentials):
        """
        Adds a source to the monitoring list.
        :param source_type: 'ssh', 'winrm', 'aws', 'azure'
        :param identifier: IP address, Hostname, or Account ID
        :param credentials: Dict containing keys/passwords/ARNs
        """
        self.sources.append({
            "type": source_type,
            "id": identifier,
            "creds": credentials, # In production, use a vault!
            "status": "connected"
        })
        logger.info(f"Added source: {source_type.upper()} -> {identifier}")

    def pull_logs_ssh(self, host):
        """
        Simulates connecting via SSH to a Linux server and running 'journalctl' or 'tail'.
        """
        logger.info(f"[SSH] Connecting to {host} via port 22...")
        time.sleep(0.5) # Simulate network latency
        logger.info(f"[SSH] Authenticated with RSA Key.")
        
        # Simulate pulling logs
        logs = []
        events = [
            f"Failed password for invalid user admin from {self._random_ip()} port 4455 ssh2",
            f"Accepted publickey for root from 192.168.1.10 port 5566 ssh2",
            "pam_unix(sshd:session): session opened for user root by (uid=0)",
            "error: maximum authentication attempts exceeded for invalid user"
        ]
        
        if random.random() > 0.7:
             log_content = random.choice(events)
             logger.info(f"[SSH] << Pulled log from {host}: {log_content}")
             return log_content
        return None

    def pull_logs_winrm(self, host):
        """
        Simulates connecting via WinRM (HTTPs) to a Windows server and querying Event Viewer.
        """
        logger.info(f"[WinRM] Connecting to {host} via port 5986...")
        time.sleep(0.5)
        logger.info(f"[WinRM] Authenticated as Administrator.")

        events = [
            "Event 4625: An account failed to log on. Account Name: Administrator.",
            "Event 4624: An account was successfully logged on.",
            "Event 1102: The audit log was cleared.",
            "Event 4720: A user account was created."
        ]
        
        if random.random() > 0.7:
             log_content = random.choice(events)
             logger.info(f"[WinRM] << Pulled log from {host}: {log_content}")
             return log_content
        return None

    def poll_cloud_api(self, provider):
        """
        Simulates polling CloudWatch (AWS) or Azure Monitor.
        """
        logger.info(f"[{provider.upper()}] Polling API for new events...")
        time.sleep(0.3)
        
        if provider == "aws":
            events = [
                "CloudTrail: ConsoleLogin failure for user 'deploy-bot'",
                "GuardDuty: UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                "CloudWatch: Alarm 'CPU_High' triggered on i-0123456789"
            ]
        else:
            events = [
                "AzureAD: User blocked due to Conditional Access policy",
                "SecurityAlert: Suspicious authentication activity",
                "AzureMonitor: Virtual Machine 'prod-db' stopped deallocated"
            ]

        if random.random() > 0.7:
             log_content = random.choice(events)
             logger.info(f"[{provider.upper()}] << API Response: {log_content}")
             return log_content
        return None

    def execute_remediation(self, action, target, source_type):
        """
        Executes a remote remediation action using the existing connection.
        """
        logger.warning(f"!!! INITIATING REMEDIATION ACTION !!!")
        logger.info(f"Action: {action} | Target: {target} | Via: {source_type.upper()}")
        
        time.sleep(1)
        
        if source_type == "ssh":
            logger.info(f"[SSH] Executing remotely: `iptables -A INPUT -s {target} -j DROP`")
            logger.info(f"[SSH] Success: IP {target} dropped.")
        elif source_type == "winrm":
            logger.info(f"[WinRM] Executing remotely: `Disable-LocalUser -Name \"{target}\"`")
            logger.info(f"[WinRM] Success: User {target} disabled.")
        elif source_type == "aws":
             logger.info(f"[AWS] Calling boto3.client('ec2').revoke_security_group_ingress(...)")
             logger.info(f"[AWS] Success: Security Group updated.")
        
        return True

    def _random_ip(self):
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

def main():
    engine = OctopusEngine()
    
    # Configure Dummy Sources
    engine.add_source("ssh", "10.0.0.5 (Linux DB)", {"key": "/path/to/key.pem"})
    engine.add_source("winrm", "10.0.0.8 (Windows AD)", {"user": "Administrator"})
    engine.add_source("aws", "AWS Account 123456789", {"role": "arn:aws:iam::..."})

    print("\n--- Starting Octopus Engine Loop (Press Ctrl+C to stop) ---\n")
    try:
        while True:
            # Simulate Pull Cycle
            print("-" * 20)
            
            # 1. Linux Pull
            log = engine.pull_logs_ssh("10.0.0.5")
            if log and "Failed password" in log:
                 # Simulate autonomous reaction
                 ip = log.split("from")[1].split("port")[0].strip()
                 engine.execute_remediation("block_ip", ip, "ssh")

            # 2. Windows Pull
            log = engine.pull_logs_winrm("10.0.0.8")
            if log and "Event 1102" in log:
                # Log clearing is suspicious!
                engine.execute_remediation("isolate_host", "10.0.0.8", "winrm")

            # 3. Cloud Poll
            engine.poll_cloud_api("aws")
            
            time.sleep(3)
            
    except KeyboardInterrupt:
        print("Stopping engine.")

if __name__ == "__main__":
    main()
