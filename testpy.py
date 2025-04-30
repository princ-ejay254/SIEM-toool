#######################
### SIEM CORE ENGINE ###
#######################
import re
import yaml
import json
import smtplib
import socket
from datetime import datetime
from kafka import KafkaProducer, KafkaConsumer
from elasticsearch import Elasticsearch
from flask import Flask, jsonify, request
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest

# ===== CONFIGURATION =====
ES_HOST = "http://localhost:9200"
KAFKA_HOST = "localhost:9091"
ALERT_EMAIL = "katumangajayson@gmail.com"
SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX"  # Replace with your webhook
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "katumangajayson@gmail.com"
SMTP_PASS = "12345678j"  # Use app-specific password

# ===== 1. ELASTICSEARCH SETUP =====
es = Elasticsearch([ES_HOST])

# ===== 2. LOG INGESTION =====
def ingest_log(log_source, log_data):
    """Ingest logs from syslog, JSON, or CSV"""
    try:
        if log_source == "syslog":
            parsed = [parse_syslog(log_data)]
        elif log_source == "json":
            parsed = [json.loads(log_data)]
        else:  # CSV
            parsed = pd.read_csv(log_data).to_dict(orient="records")

        for entry in parsed:
            # Add timestamp if not present
            if "timestamp" not in entry:
                entry["timestamp"] = datetime.now().isoformat()
            es.index(index="security_logs", body=entry)

        return True
    except Exception as e:
        print(f"Error ingesting log: {str(e)}")
        return False

def parse_syslog(log):
    """Parse RFC 5424 syslog messages"""
    pattern = r'<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (.*)'
    match = re.match(pattern, log)
    return {
        "priority": match.group(1),
        "timestamp": datetime.now().isoformat(),
        "host": match.group(3),
        "app": match.group(4),
        "message": match.group(7)
    }

# ===== 3. REAL-TIME PROCESSING =====
# ===== KAFKA CONFIG =====
from kafka import KafkaProducer, KafkaConsumer
from kafka.errors import NoBrokersAvailable
import time

def get_kafka_producer():
    for i in range(3):  # Retry 3 times
        try:
            return KafkaProducer(
                bootstrap_servers=[KAFKA_HOST],
                api_version=(2, 8, 0),
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
        except NoBrokersAvailable:
            if i == 2:  # Last attempt
                raise
            time.sleep(5)

producer = get_kafka_producer()
consumer = KafkaConsumer(
    "security_logs",
    bootstrap_servers=[KAFKA_HOST],
    auto_offset_reset='earliest',
    group_id='siem-group',
    api_version=(2, 8, 0)
)
'''producer = KafkaProducer(
    bootstrap_servers=[KAFKA_HOST],  # Expects "host:port" format
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

consumer = KafkaConsumer(
    "security_logs",
    bootstrap_servers=[KAFKA_HOST],
    auto_offset_reset='earliest',
    group_id='siem-group'
)
def stream_logs():
    """Process logs from Kafka in real-time"""
    for msg in consumer:
        try:
            log = json.loads(msg.value.decode('utf-8'))
            detect_threats(log)
        except Exception as e:
            print(f"Error processing message: {str(e)}")'''

# ===== 4. THREAT DETECTION =====
RULES = [
    {
        "name": "SSH Bruteforce",
        "condition": "'event' in log and log['event'] == 'ssh_failed' and log.get('count', 0) > 5",
        "severity": "high"
    },
    {
        "name": "Port Scan Detected",
        "condition": "'event' in log and log['event'] == 'port_scan' and log.get('ports_scanned', 0) > 10",
        "severity": "medium"
    }
]

def detect_threats(log):
    """Evaluate log against all rules"""
    for rule in RULES:
        try:
            if eval(rule["condition"], {'log': log}):  # Limited scope for security
                trigger_alert(rule, log)
        except Exception as e:
            print(f"Error evaluating rule {rule['name']}: {str(e)}")

# ===== 5. ALERTING =====
def trigger_alert(rule, log):
    """Send alerts via email and Slack"""
    alert_msg = f"""ALERT: {rule['name']}
Severity: {rule['severity']}
Timestamp: {log.get('timestamp', 'N/A')}
Source IP: {log.get('source_ip', 'N/A')}
Details: {json.dumps(log, indent=2)}"""

    # Email Alert
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(
                SMTP_USER,
                ALERT_EMAIL,
                alert_msg
            )
    except Exception as e:
        print(f"Failed to send email alert: {str(e)}")

    # Slack Alert
    if SLACK_WEBHOOK and not SLACK_WEBHOOK.startswith("https://hooks.slack.com/services/XXX"):
        try:
            import requests
            requests.post(
                SLACK_WEBHOOK,
                json={"text": alert_msg}
            )
        except Exception as e:
            print(f"Failed to send Slack alert: {str(e)}")

# ===== 6. USER BEHAVIOR ANALYTICS =====
def detect_anomalies():
    """Detect anomalous behavior using Isolation Forest"""
    try:
        logs = es.search(index="security_logs", size=1000)["hits"]["hits"]
        if not logs:
            return []

        df = pd.DataFrame([log["_source"] for log in logs])

        # Convert relevant fields to numeric
        for col in ['login_count', 'bytes_transferred']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        if len(df) < 10:  # Need minimum samples
            return []

        clf = IsolationForest(contamination=0.01, random_state=42)
        features = df[['login_count', 'bytes_transferred']].dropna()
        if len(features) > 0:
            anomalies = clf.fit_predict(features)
            return features[anomalies == -1].to_dict('records')
        return []
    except Exception as e:
        print(f"Anomaly detection failed: {str(e)}")
        return []

# ===== 7. DASHBOARD & API =====
app = Flask(__name__)

@app.route("/dashboard")
def dashboard():
    """Generate security dashboard"""
    try:
        logs = es.search(index="security_logs", size=1000)["hits"]["hits"]
        if not logs:
            return "No logs available"

        df = pd.DataFrame([log["_source"] for log in logs])

        # Generate visualizations
        fig1 = px.histogram(df, x="source_ip", title="Top Attack Sources")
        fig2 = px.pie(df, names="event", title="Event Distribution")

        return f"""
        <html>
            <body>
                <h1>Security Dashboard</h1>
                {fig1.to_html(full_html=False)}
                {fig2.to_html(full_html=False)}
            </body>
        </html>
        """
    except Exception as e:
        return f"Error generating dashboard: {str(e)}"

@app.route("/ingest", methods=["POST"])
def ingest_api():
    """API endpoint for log ingestion"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        if ingest_log("json", json.dumps(data)):
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Failed to ingest log"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/search", methods=["POST"])
def search_api():
    """Search logs"""
    try:
        query = request.json.get("query", "")
        results = es.search(
            index="security_logs",
            body={"query": {"query_string": {"query": query}}},
            size=100
        )
        return jsonify(results["hits"]["hits"])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== 8. MAIN EXECUTION =====
if __name__ == "__main__":
    print("""
    ███████╗██╗███████╗███╗   ███╗
    ██╔════╝██║██╔════╝████╗ ████║
    ███████╗██║█████╗  ██╔████╔██║
    ╚════██║██║██╔══╝  ██║╚██╔╝██║
    ███████║██║███████╗██║ ╚═╝ ██║
    ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝
    """)
    print("Starting SIEM Engine...")

    # Start Flask in a separate thread
    from threading import Thread
    flask_thread = Thread(target=lambda: app.run(host="0.0.0.0", port=5000, threaded=True))
    flask_thread.daemon = True
    flask_thread.start()

    # Start Kafka consumer
    print("Listening for logs...")
    stream_logs()
