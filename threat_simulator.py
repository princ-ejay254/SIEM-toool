import random
import time
from datetime import datetime
import json
import requests

# SIEM API Endpoint (update with your URL)
SIEM_INGEST_URL = "http://localhost:5000/ingest"

def generate_ssh_bruteforce(src_ip):
    """Simulate failed SSH login attempts"""
    for i in range(15):  # 15 failed attempts triggers brute-force rule
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": src_ip,
            "event": "ssh_failed",
            "username": "root",
            "count": i+1,
            "severity": "high"
        }
        requests.post(SIEM_INGEST_URL, json=log)
        time.sleep(random.uniform(0.1, 0.5))  # Random delay between attempts

def simulate_data_exfiltration(src_ip):
    """Simulate large data transfer"""
    log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": src_ip,
        "event": "data_transfer",
        "bytes_out": 1500000,  # 1.5MB (triggers >1MB exfiltration rule)
        "destination_ip": "45.67.89.123",
        "severity": "critical"
    }
    requests.post(SIEM_INGEST_URL, json=log)

if __name__ == "__main__":
    attacker_ip = f"192.168.1.{random.randint(100, 200)}"
    
    print(f"🚨 Starting attack simulation from {attacker_ip}")
    generate_ssh_bruteforce(attacker_ip)
    time.sleep(2)
    simulate_data_exfiltration(attacker_ip)
    print("✅ Attack simulation complete. Check SIEM alerts!")