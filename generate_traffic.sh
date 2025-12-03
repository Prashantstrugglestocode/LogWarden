#!/bin/bash

API_URL="http://localhost:8000/ingest/logs"

echo "Generating traffic for LogWarden..."

while true; do
  echo "Generating traffic batch..."

  # 1. SSH Brute Force (CRITICAL) - Triggers AI
  echo "Sending SSH Brute Force Log..."
  curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "source": "linux-server-01",
      "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
      "type": "CRITICAL",
      "message": "Failed password for root from 192.168.1.105 port 22 ssh2",
      "content": {"ip": "192.168.1.105", "user": "root", "attempts": 50}
    }' > /dev/null
  
  sleep 2

  # 2. SQL Injection Attempt (CRITICAL) - Triggers AI
  echo "Sending SQL Injection Log..."
  curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "source": "web-app-prod",
      "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
      "type": "CRITICAL",
      "message": "SQL Injection detected in query parameter: UNION SELECT * FROM users",
      "content": {"ip": "45.33.22.11", "url": "/api/login", "payload": "UNION SELECT..."}
    }' > /dev/null

  sleep 3

  # 3. Windows Firewall Warning (WARNING)
  echo "Sending Windows Firewall Log..."
  curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "source": "windows-dc-01",
      "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
      "type": "WARNING",
      "message": "Windows Firewall has blocked a new connection from 10.0.0.50",
      "content": {"event_id": 5157, "protocol": "TCP"}
    }' > /dev/null

  sleep 1

  # 4. Normal System Activity (INFO)
  echo "Sending Normal Activity Log..."
  curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{
      "source": "k8s-cluster-prod",
      "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
      "type": "INFO",
      "message": "Pod payment-service-v2 scaled up to 3 replicas",
      "content": {"namespace": "default", "replicas": 3}
    }' > /dev/null
    
  sleep 4
done
