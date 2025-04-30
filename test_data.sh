#!/bin/bash

# Generate timestamps
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOUR_AGO=$(date -u +"%Y-%m-%dT%H:%M:%SZ" --date="-1 hour")
DAY_AGO=$(date -u +"%Y-%m-%dT%H:%M:%SZ" --date="-1 day")

# 1. SSH Attacks
echo "Generating SSH brute force attempts..."
for i in {1..8}; do
  curl -X POST http://localhost:5000/ingest -H "Content-Type: application/json" -d '{
    "event": "ssh_failed",
    "source_ip": "203.0.113.'$i'",
    "count": '$((i+3))',
    "message": "Failed SSH login for user root",
    "severity": "high",
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ" --date="-$((i*5)) minutes")'"
  }'
done

# 2. Web Attacks
echo "Generating web application attacks..."
curl -X POST http://localhost:5000/ingest -H "Content-Type: application/json" -d '{
  "event": "web_attack",
  "source_ip": "198.51.100.22",
  "url": "/wp-admin",
  "payload": "../etc/passwd",
  "message": "Path traversal attempt",
  "severity": "high",
  "timestamp": "'$HOUR_AGO'"
}'

# 3. Malware Events
echo "Generating malware alerts..."
curl -X POST http://localhost:5000/ingest -H "Content-Type: application/json" -d '{
  "event": "malware_detected",
  "host": "fileserver-01",
  "malware_type": "Mimikatz",
  "message": "Credential dumping tool detected",
  "severity": "critical",
  "timestamp": "'$NOW'"
}'

# 4. Normal Traffic
echo "Generating normal traffic..."
for i in {1..20}; do
  curl -X POST http://localhost:5000/ingest -H "Content-Type: application/json" -d '{
    "event": "http_request",
    "source_ip": "192.168.1.'$((i+10))'",
    "method": "GET",
    "status_code": 200,
    "message": "Normal web traffic",
    "severity": "low",
    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ" --date="-$((i*2)) minutes")'"
  }'
done

echo "Test data generation complete!"