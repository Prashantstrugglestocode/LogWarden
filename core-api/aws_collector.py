import boto3
import asyncio
import time
from datetime import datetime, timedelta
from models import LogSource

class AWSCollector:
    def __init__(self, source: LogSource):
        self.source = source
        self.client = boto3.client(
            'logs',
            region_name=source.aws_region,
            aws_access_key_id=source.aws_access_key,
            aws_secret_access_key=source.aws_secret_key
        )

    def test_connection(self) -> bool:
        """
        Tests connection by listing log groups (limit 1).
        """
        try:
            self.client.describe_log_groups(limit=1)
            return True
        except Exception as e:
            print(f"AWS Connection Failed: {e}")
            return False

    async def collect_stream(self, ingest_callback):
        """
        Polls CloudWatch Logs for new events.
        """
        print(f"Started AWS collection from {self.source.aws_log_group}")
        
        # Start from 1 minute ago
        start_time = int((datetime.utcnow() - timedelta(minutes=1)).timestamp() * 1000)
        
        while True:
            try:
                # Poll for events
                # Note: filter_log_events is better for tailing than get_log_events
                response = self.client.filter_log_events(
                    logGroupName=self.source.aws_log_group,
                    startTime=start_time,
                    limit=50
                )
                
                events = response.get('events', [])
                for event in events:
                    # Ingest
                    timestamp = event.get('timestamp')
                    message = event.get('message', '').strip()
                    
                    if message:
                         await ingest_callback({
                             "source": self.source.name,
                             "timestamp": datetime.fromtimestamp(timestamp/1000).isoformat(),
                             "message": message,
                             "type": "CLOUD"
                         })
                    
                    # Update start_time to avoid duplicates (naive approach)
                    # Ideally track nextToken, but filter_log_events pagination is complex for tailing
                    if timestamp >= start_time:
                        start_time = timestamp + 1

                await asyncio.sleep(5) # Poll interval
                
            except Exception as e:
                print(f"AWS Collection Error: {e}")
                await asyncio.sleep(10)
