import random
import time
from datetime import datetime, timedelta
import json
import requests
from faker import Faker

fake = Faker()
SIEM_INGEST_URL = "http://localhost:5000/ingest"

def generate_log(event_type, **kwargs):
    """Generate standardized log with threat payload"""
    base_log = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": kwargs.get("source_ip", fake.ipv4()),
        "severity": kwargs.get("severity", "medium")
    }
    return {**base_log, **kwargs, "event": event_type}

def simulate_ssh_bruteforce():
    """Trigger Rule: SSH Bruteforce (count > 5)"""
    src_ip = fake.ipv4()
    for i in range(8):  # 8 failed attempts
        requests.post(SIEM_INGEST_URL, json=generate_log(
            "ssh_failed",
            source_ip=src_ip,
            username="admin",
            count=i+1,
            severity="high" if i >=4 else "medium"
        ))
        time.sleep(0.3)

def simulate_port_scan():
    """Trigger Rule: Port Scan (ports_scanned > 10)"""
    requests.post(SIEM_INGEST_URL, json=generate_log(
        "port_scan",
        ports_scanned=15,
        protocol="tcp",
        severity="high"
    ))

def simulate_admin_access():
    """Trigger Rule: Unauthorized Admin Access"""
    requests.post(SIEM_INGEST_URL, json=generate_log(
        "access_denied",
        resource="/admin/config.php",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        severity="critical"
    ))

def simulate_data_exfiltration():
    """Trigger Rule: Data Exfiltration (bytes_out > 1MB)"""
    requests.post(SIEM_INGEST_URL, json=generate_log(
        "data_transfer",
        bytes_out=2500000,  # 2.5MB
        destination_ip=fake.ipv4(),
        severity="critical"
    ))

def simulate_anomalous_behavior():
    """Trigger ML Anomaly Detection"""
    # Rare combination of high login count + data transfer
    requests.post(SIEM_INGEST_URL, json=generate_log(
        "user_activity",
        login_count=25,
        bytes_transferred=500000,
        user_id="service_account_123",
        severity="high"
    ))

def simulate_connection_attempts():
    """Trigger Rule: Basic Port Scan (dst_port > 5)"""
    for port in [22, 80, 443, 8080, 3389, 5900]:
        requests.post(SIEM_INGEST_URL, json=generate_log(
            "connection_attempt",
            dst_port=port,
            protocol="tcp",
            severity="medium"
        ))

def run_full_simulation():
    print("🔥 Starting comprehensive threat simulation...")
    
    # Sequence of attacks with realistic timing
    simulate_ssh_bruteforce()
    time.sleep(1.5)
    simulate_port_scan()
    simulate_admin_access()
    time.sleep(0.8)
    simulate_data_exfiltration()
    simulate_anomalous_behavior()
    simulate_connection_attempts()
    
    print("✅ Simulation complete. Verify alerts in dashboard!")

if __name__ == "__main__":
    run_full_simulation()