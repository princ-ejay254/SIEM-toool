import random
import time
from datetime import datetime
import requests

SIEM_INGEST_URL = "http://localhost:5000/ingest"

def generate_log(event_type, count=1, **kwargs):
    """Send logs to SIEM"""
    for _ in range(count):
        log = {
            "timestamp": datetime.now().isoformat(),
            "source_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
            "event": event_type,
            **kwargs
        }
        requests.post(SIEM_INGEST_URL, json=log)
        time.sleep(random.uniform(0.1, 0.3))  # Random delay between logs

def balanced_simulation():
    """Generate balanced threat distribution"""
    print("⚖️ Running balanced threat simulation...")

    # 1. SSH Bruteforce (target: ~12 events)
    generate_log("ssh_failed", count=12, username="root", severity="high")

    # 2. Connection Attempts (target: ~10 events)
    for port in [22, 80, 443, 3389, 8080, 21, 25, 53, 3306, 5900]:
        generate_log("connection_attempt", dst_port=port, protocol="tcp")

    # 3. Test Events (target: ~8 events)
    generate_log("test_event", count=8, message="simulated event")

    # 4. Data Transfers (target: ~6 events)
    for size in [500000, 1200000, 800000, 1500000, 2000000, 950000]:
        generate_log("data_transfer", bytes_out=size, severity="critical" if size>1000000 else "high")

    # 5. Port Scans (target: ~5 events)
    generate_log("port_scan", ports_scanned=random.randint(8,20), severity="high")
    generate_log("port_scan", ports_scanned=random.randint(8,20), severity="high")
    generate_log("port_scan", ports_scanned=random.randint(8,20), severity="high")
    generate_log("port_scan", ports_scanned=random.randint(8,20), severity="high")
    generate_log("port_scan", ports_scanned=random.randint(8,20), severity="high")

    # 6. Admin Access (target: ~4 events)
    for resource in ["/admin", "/wp-admin", "/admin/config", "/backend"]:
        generate_log("access_denied", resource=resource, severity="critical")

    # 7. User Activity (target: ~3 events)
    generate_log("user_activity", login_count=15, bytes_transferred=400000)
    generate_log("user_activity", login_count=3, bytes_transferred=1200000)
    generate_log("user_activity", login_count=25, bytes_transferred=80000)

    print("✅ Balanced simulation complete. Check your dashboard!")

if __name__ == "__main__":
    balanced_simulation()
