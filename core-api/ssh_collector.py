import asyncssh
import asyncio
from datetime import datetime
from models import LogSource, Log
from sqlalchemy.orm import Session
from database import SessionLocal

class SSHCollector:
    async def test_connection(self, source: LogSource) -> bool:
        """
        Tests SSH connection to the remote source.
        """
        try:
            if source.auth_type == 'password':
                async with asyncssh.connect(source.host, port=source.port, username=source.username, password=source.password, known_hosts=None) as conn:
                    return True
            else:
                # Key based (stub for future expansion, assuming key_path usage or agent)
                # Client keys usually expected to be loaded in agent or passed as client_keys=[path]
                async with asyncssh.connect(source.host, port=source.port, username=source.username, client_keys=[source.key_path] if source.key_path else None, known_hosts=None) as conn:
                    return True
        except Exception as e:
            print(f"SSH Connection Failed to {source.host}: {e}")
            return False

    async def collect_stream(self, source: LogSource, ingest_callback):
        """
        Connects and streams logs via `tail -f` (Linux only for MVP).
        Calls ingest_callback(log_entry) for each line.
        """
        try:
             async with asyncssh.connect(source.host, port=source.port, username=source.username, password=source.password if source.auth_type=='password' else None, known_hosts=None) as conn:
                
                # Determine command based on OS type
                cmd = f"tail -f {source.log_path}" if source.type == 'linux' else f"Get-Content -Path '{source.log_path}' -Wait"
                
                # If windows, we'd need a different shell or powershell invocation, keeping simple for now
                if source.type == 'windows':
                   # Basic PowerShell wrapper
                   cmd = f"powershell -Command \"Get-Content -Path '{source.log_path}' -Wait\""

                async with conn.create_process(cmd) as process:
                    print(f"Started collection from {source.name} ({source.host})")
                    async for line in process.stdout:
                        # Ingest the line
                        line = line.strip()
                        if line:
                             await ingest_callback({
                                 "source": source.name,
                                 "timestamp": datetime.utcnow().isoformat(),
                                 "message": line,
                                 "type": "INFO" # Default, AI will enrich later
                             })
        except Exception as e:
            print(f"Collection Error on {source.name}: {e}")

# Global instance manager stub
_active_collectors = {}

async def start_collection_task(source_id: int):
    print(f"DEBUG: Starting collection task for Source ID {source_id}")
    db = SessionLocal()
    try:
        source = db.query(LogSource).filter(LogSource.id == source_id).first()
        if not source:
            print(f"ERROR: Source ID {source_id} not found in DB")
            return

        print(f"DEBUG: Found source {source.name} ({source.host}). Initializing collector...")
        
        collector = None
        if source.type == 'aws_cloudwatch':
            from aws_collector import AWSCollector
            collector = AWSCollector(source)
        else:
            collector = SSHCollector()
        
        import httpx
        async def send_to_api(log_data):
            try:
                # print(f"DEBUG: Sending log: {log_data['message'][:20]}...")
                async with httpx.AsyncClient() as client:
                    await client.post("http://localhost:8000/ingest/logs", json=log_data)
            except Exception as e:
                print(f"ERROR: Failed to forward log from {source.name}: {e}")

        # AWS Collector collect_stream takes only callback
        # SSH Collector collect_stream takes source + callback
        if source.type == 'aws_cloudwatch':
             await collector.collect_stream(send_to_api)
        else:
             await collector.collect_stream(source, send_to_api)
             
        print(f"DEBUG: Collection finished for {source.name}")

    except Exception as e:
        print(f"CRITICAL ERROR in collection task: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()
