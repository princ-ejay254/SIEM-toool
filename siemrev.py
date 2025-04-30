#!/usr/bin/env python3
#######################
### SIEM CORE ENGINE ###
### BY ENG.JK ###
#######################

import os
import re
import json
import smtplib
import socket
import time
from datetime import datetime, timedelta
from kafka import KafkaProducer, KafkaConsumer
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from flask import Flask, jsonify, request, Response
import pandas as pd
import plotly.express as px
from sklearn.ensemble import IsolationForest
from threading import Thread, Lock
import logging
from dotenv import load_dotenv
import requests
import hashlib
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
#from siem_core import stream_logs
# Add this near the top with other imports
from flask import Flask, jsonify, request, Response, redirect, url_for, flash
import os
from dotenv import load_dotenv

# Load environment variables (add right after imports)
load_dotenv()

# Initialize Flask app (find where app = Flask(__name__) is defined)
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Add this verification check right after
if not app.secret_key:
    raise ValueError("No SECRET_KEY configured. Please set it in .env file")

# Your admin configuration (add this with other configs)
ADMINS = {
    os.getenv('ADMIN_USERNAME', 'admin'): {
        "password_hash": generate_password_hash(os.getenv('ADMIN_PASSWORD')),
        "email": "admin@yourdomain.com"
    }
}

# Load environment variables
load_dotenv()

# ===== CONFIGURATION =====
ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
KAFKA_HOST = os.getenv("KAFKA_HOST", "localhost:9092")
ALERT_EMAIL = os.getenv("ALERT_EMAIL", "katumangaaustine@gmail.com")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "katumangajayson@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "oujbnbeyxyahqano")
from dotenv import load_dotenv
load_dotenv()
print("SMTP User:", os.getenv("SMTP_USER"))
# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='siem.log'
)
logger = logging.getLogger('SIEM')

# ===== DATA STORES =====
# In-memory store for real-time dashboard updates
recent_alerts = []
alert_lock = Lock()

# ===== ELASTICSEARCH CONNECTION =====
es = Elasticsearch([ES_HOST], request_timeout=30)

search = Search(using=es, index="security_logs")
# Create index if not exists
if not es.indices.exists(index="security_logs"):
    es.indices.create(
        index="security_logs",
        body={
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"},
                    "severity": {"type": "keyword"},
                    "event": {"type": "keyword"},
                    "message": {"type": "text"}
                }
            }
        }
    )

# ===== KAFKA CONNECTION =====
producer = KafkaProducer(
    bootstrap_servers=[KAFKA_HOST],
    value_serializer=lambda v: json.dumps(v).encode('utf-8'),
    api_version=(2, 8, 0)
)

consumer = KafkaConsumer(
    "security_logs",
    bootstrap_servers=[KAFKA_HOST],
    auto_offset_reset='earliest',
    group_id='siem-group',
    api_version=(2, 8, 0)
)

# ===== CORE FUNCTIONS =====
def ingest_log(log_source, log_data):
    """Ingest logs from various sources with validation"""
    try:
        if log_source == "syslog":
            parsed = [parse_syslog(log_data)]
        elif log_source == "json":
            try:
                # Handle different input types
                if isinstance(log_data, str):
                    data = json.loads(log_data)
                else:
                    data = log_data

                # Handle both direct array and wrapped formats
                if isinstance(data, dict):
                    parsed = data.get('logs', [data])
                else:
                    parsed = data if isinstance(data, list) else [data]

            except json.JSONDecodeError:
                logger.error("Invalid JSON format")
                return False
        else:  # CSV
            try:
                # Handle both file paths and string data
                if isinstance(log_data, str) and '\n' in log_data:
                    # CSV string data
                    from io import StringIO
                    parsed = pd.read_csv(StringIO(log_data)).to_dict(orient="records")
                else:
                    # Assume file path or file-like object
                    parsed = pd.read_csv(log_data).to_dict(orient="records")
            except Exception as e:
                logger.error(f"CSV parsing error: {str(e)}")
                return False

        # Process parsed entries
        successful_ingestions = 0
        for entry in parsed:
            # Skip if entry is None or empty
            if not entry:
                continue

            # Validate required fields
            if not validate_log_entry(entry):
                continue

            # Add metadata
            if "timestamp" not in entry:
                entry["timestamp"] = datetime.now().isoformat()

            # Generate a unique ID for the log entry
            entry_hash = hashlib.md5(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            entry["log_id"] = entry_hash

            try:
                # Index in Elasticsearch
                es.index(index="security_logs", body=entry)

                # Send to Kafka
                producer.send("security_logs", value=entry)
                successful_ingestions += 1
            except Exception as e:
                logger.error(f"Failed to store log entry: {str(e)}")

        return successful_ingestions > 0
    except Exception as e:
        logger.error(f"Error ingesting log: {str(e)}", exc_info=True)
        return False
def stream_logs():
    """Process logs from Kafka in real-time"""
    logger.info("Starting log stream processor")
    for msg in consumer:
        try:
            log = json.loads(msg.value.decode('utf-8'))
            detect_threats(log)
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")

def validate_log_entry(entry):
    """Validate log entry structure"""
    required_fields = ['event', 'source_ip']
    if "message" not in entry:
        entry["message"] = f"Auto-generated log for event '{entry['event']}'"
    for field in required_fields:
        if field not in entry:
            logger.warning(f"Log entry missing required field: {field}")
            return False
    return True

def parse_syslog(log):
    """Parse RFC 5424 syslog messages with enhanced parsing"""
    pattern = r'<(\d+)>(\d+) (\S+) (\S+) (\S+) (\S+) (.*)'
    match = re.match(pattern, log)
    if not match:
        logger.warning(f"Failed to parse syslog message: {log}")
        return {
            "message": log,
            "timestamp": datetime.now().isoformat(),
            "event": "unparsed_syslog"
        }

    return {
        "priority": match.group(1),
        "timestamp": datetime.now().isoformat(),
        "host": match.group(3),
        "app": match.group(4),
        "message": match.group(7),
        "event": "syslog_message"
    }

# ===== SECURITY FUNCTIONS =====
RULES = [
    {
        "name": "SSH Bruteforce",
        "condition": lambda log: log.get('event') == 'ssh_failed' and log.get('count', 0) > 5,
        "severity": "high",
        "description": "Multiple failed SSH login attempts from a single source"
    },
    {
        "name": "Port Scan Detected",
        "condition": lambda log: log.get('event') == 'port_scan' and log.get('ports_scanned', 0) > 10,
        "severity": "medium",
        "description": "Scanning of multiple ports from a single IP"
    },
    {
        "name": "Unauthorized Access Attempt",
        "condition": lambda log: log.get('event') == 'access_denied' and log.get('resource', '').startswith('/admin'),
        "severity": "high",
        "description": "Attempt to access restricted admin area"
    },
    {
        "name": "Data Exfiltration Attempt",
        "condition": lambda log: log.get('bytes_out', 0) > 1000000,  # 1MB
        "severity": "critical",
        "description": "Large amount of data being transferred out"
    },
    {
    "name": "Basic Port Scan",
    "condition": lambda log: (
        log.get('event') == 'connection_attempt'
        and log.get('dst_port') is not None
        and int(log.get('dst_port')) > 5  # Threshold
    ),
    "severity": "medium",
    "description": "Multiple ports scanned from one IP"
    }
]

def detect_threats(log):
    """Evaluate log against security rules without using eval()"""
    for rule in RULES:
        try:
            if rule["condition"](log):
                alert = {
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": log.get("source_ip", "unknown"),
                    "message": log.get("message", ""),
                    "details": rule["description"],
                    "log_data": log
                }

                with alert_lock:
                    if len(recent_alerts) >= 100:  # Keep only 100 most recent alerts
                        recent_alerts.pop(0)
                    recent_alerts.append(alert)

                trigger_alert(rule, log)
        except Exception as e:
            logger.error(f"Error evaluating rule {rule['name']}: {str(e)}")

def trigger_alert(rule, log):
    """Send alerts via multiple channels with improved formatting"""
    alert_id = hashlib.md5(f"{rule['name']}{datetime.now().isoformat()}".encode()).hexdigest()

    alert_msg = f"""
    🚨 SIEM ALERT [{alert_id}] 🚨
    Rule: {rule['name']}
    Severity: {rule['severity'].upper()}
    Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Source IP: {log.get('source_ip', 'N/A')}
    Host: {log.get('host', 'N/A')}
    Description: {rule.get('description', 'No description')}

    Log Details:
    {json.dumps(log, indent=2)}
    """

    # Email Alert
    if SMTP_USER and SMTP_PASS:
        try:
            subject = f"SIEM Alert: {rule['name']} (Severity: {rule['severity']})"
            message = f"Subject: {subject}\n\n{alert_msg}"

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(SMTP_USER, ALERT_EMAIL, message.encode('utf-8'))
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")

    # Slack Alert
    if SLACK_WEBHOOK and not SLACK_WEBHOOK.startswith("https://hooks.slack.com/services/XXX"):
        try:
            color = {
                "critical": "#ff0000",
                "high": "#ff5e00",
                "medium": "#ffbb00",
                "low": "#00aaff"
            }.get(rule["severity"], "#cccccc")

            slack_msg = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"SIEM Alert: {rule['name']}",
                        "fields": [
                            {"title": "Severity", "value": rule["severity"], "short": True},
                            {"title": "Source IP", "value": log.get("source_ip", "N/A"), "short": True},
                            {"title": "Timestamp", "value": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "short": True},
                            {"title": "Description", "value": rule.get("description", "")},
                            {"title": "Alert ID", "value": alert_id}
                        ],
                        "text": f"```{json.dumps(log, indent=2)}```",
                        "footer": "SIEM Alert System"
                    }
                ]
            }
            requests.post(SLACK_WEBHOOK, json=slack_msg, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}")
def detect_network_scans():
    # Get recent connections
    results = es.search(
        index="security_logs",
        body={
            "size": 0,
            "query": {"term": {"event": "connection_attempt"}},
            "aggs": {
                "scanners": {
                    "terms": {"field": "src_ip.keyword"},
                    "aggs": {"port_count": {"cardinality": {"field": "dst_port"}}}
                }
            }
        }
    )

    # Trigger alerts
    for scanner in results['aggregations']['scanners']['buckets']:
        if scanner['port_count']['value'] > 5:  # Threshold
            trigger_alert({
                "rule": "Network Scan Detected",
                "src_ip": scanner['key'],
                "ports_scanned": scanner['port_count']['value']
            })

def detect_anomalies():
    """Enhanced anomaly detection with more features"""
    try:
        # Get logs from last 24 hours
        time_range = {"range": {"timestamp": {"gte": "now-1d/d"}}}
        logs = es.search(index="security_logs",body={"size": 1000, "query": {"match_all": {}}})["hits"]["hits"]
        if not logs:
            return []

        df = pd.DataFrame([log["_source"] for log in logs])

        # Feature engineering
        numeric_cols = []
        for col in ['login_count', 'bytes_transferred', 'duration', 'count', 'ports_scanned']:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
                numeric_cols.append(col)

        if not numeric_cols or len(df) < 20:
            return []

        # Train Isolation Forest
        clf = IsolationForest(contamination=0.05, random_state=42)
        features = df[numeric_cols].dropna()

        if len(features) > 0:
            anomalies = clf.fit_predict(features)
            anomaly_records = features[anomalies == -1]

            # Add context to anomalies
            anomaly_records = df.loc[anomaly_records.index].to_dict('records')

            # Create alerts for anomalies
            for anomaly in anomaly_records:
                alert = {
                    "rule": "Anomaly Detected",
                    "severity": "high",
                    "timestamp": datetime.now().isoformat(),
                    "source_ip": anomaly.get("source_ip", "unknown"),
                    "message": "Unusual behavior pattern detected",
                    "details": f"Anomaly in features: {numeric_cols}",
                    "log_data": anomaly
                }

                with alert_lock:
                    if len(recent_alerts) >= 100:
                        recent_alerts.pop(0)
                    recent_alerts.append(alert)

            return anomaly_records
        return []
    except Exception as e:
        logger.error(f"Anomaly detection failed: {str(e)}")
        return []
def send_email(subject, body, to_email=None):
    """Enhanced email sending function with better error handling"""
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        logger.warning("Email not configured - missing SMTP parameters")
        return False

    to_email = to_email or ALERT_EMAIL
    message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.ehlo()
            if SMTP_PORT == 587:
                server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to_email, message.encode('utf-8'))
        logger.info(f"Email sent successfully to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return False
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

def send_html_email(subject, html_content, to_email=None):
    """Send HTML formatted emails"""
    if not all([SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        return False

    to_email = to_email or ALERT_EMAIL
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(html_content, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"HTML email failed: {str(e)}")
        return False
from apscheduler.schedulers.background import BackgroundScheduler

def generate_daily_report():
    """Generate and email daily report"""
    # Get data from last 24 hours
    logs = es.search(index="security_logs", body={
        "query": {"range": {"timestamp": {"gte": "now-1d/d"}}},
        "size": 1000
    })["hits"]["hits"]

    # Generate HTML report
    html_report = """
    <html><body>
        <h1>Daily Security Report</h1>
        <p>Total events: {count}</p>
        <!-- Add more report content -->
    </body></html>
    """.format(count=len(logs))

    # Send email
    send_html_email(
        f"Daily SIEM Report - {datetime.now().date()}",
        html_report
    )

# Schedule daily at 8 AM
scheduler = BackgroundScheduler()
scheduler.add_job(generate_daily_report, 'cron', hour=8)
scheduler.start()
# ===== WEB INTERFACE =====
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-very-secret-key-here')  # Change this!

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'

# User model
class AdminUser(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return AdminUser(user_id)
@app.route("/")
def home():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard</title>
        <meta http-equiv="refresh" content="0; url=/dashboard" />
    </head>
    <body>
        <p>Redirecting to <a href="/dashboard">dashboard</a>...</p>
    </body>
    </html>
    """
# Add this test route to verify email functionality
@app.route('/test-email')
def test_email():
    if send_email("SIEM Test Email", "This is a test message from your SIEM system"):
        return "Test email sent successfully"
    return "Failed to send test email"
@app.route("/dashboard")
@login_required
def dashboard():
    try:
        # Check if index exists or has documents
        if not es.indices.exists(index="security_logs") or \
           not es.count(index="security_logs")["count"] > 0:
            return render_empty_dashboard()

        # Get data from Elasticsearch
        logs = es.search(
            index="security_logs",
            body={
                "size": 1000,
                "query": {
                    "match_all": {}
                }
            }
        )["hits"]["hits"]


        if not logs:
            return render_empty_dashboard()

        df = pd.DataFrame([log["_source"] for log in logs])

        # Generate visualizations
        threat_map = generate_threat_map(df)
        timeline = generate_timeline(df)
        threats_table = generate_threats_table(df)

        # Get stats
        stats = get_dashboard_stats(df)

        # Get recent alerts
        with alert_lock:
            alerts_to_display = recent_alerts[-20:]  # Last 20 alerts

        return render_dashboard(stats, threat_map, timeline, threats_table, alerts_to_display)

    except Exception as e:
        return render_error_page(e)

@app.route("/stream")
def stream():
    """Server-sent events for real-time updates"""
    def event_stream():
        last_count = 0
        while True:
            with alert_lock:
                current_count = len(recent_alerts)
                if current_count != last_count:
                    alert = recent_alerts[-1]
                    yield f"data: {json.dumps(alert)}\n\n"
                    last_count = current_count
            time.sleep(1)

    return Response(event_stream(), mimetype="text/event-stream")

# Helper functions for dashboard rendering
def render_empty_dashboard():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard</title>
        <style>
            body {
                background: #0f0f23;
                color: #0f0;
                font-family: monospace;
                text-align: center;
                padding: 2rem;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                border: 1px solid #0f0;
                padding: 2rem;
                box-shadow: 0 0 20px #0f0;
            }
            h1 {
                text-shadow: 0 0 5px #0f0;
            }
            .blink {
                animation: blink 1s step-end infinite;
            }
            @keyframes blink {
                from, to { opacity: 1; }
                50% { opacity: 0; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SIEM DASHBOARD</h1>
            <p>No security logs found <span class="blink">_</span></p>
            <p>Waiting for incoming data...</p>
            <p>Try sending some test logs to the /ingest endpoint</p>
        </div>
    </body>
    </html>
    """
def generate_threat_map(df):
    """Generate threat map visualization with robust size handling"""
    # Add mock geo data if missing
    if 'latitude' not in df.columns:
        df['latitude'] = [hash(ip) % 180 - 90 for ip in df.get('source_ip', '0.0.0.0')]
        df['longitude'] = [hash(ip) % 360 - 180 for ip in df.get('source_ip', '0.0.0.0')]

    # Use 'event' instead of 'severity' if severity doesn't exist
    color_column = 'severity' if 'severity' in df.columns else 'event'

    # Handle size column - default to 1 if count is missing or invalid
    if 'count' not in df.columns:
        df['size'] = 1
    else:
        # Convert count to numeric, fill NA/NaN with 1
        df['size'] = pd.to_numeric(df['count'], errors='coerce').fillna(1)
        # Ensure minimum size of 1
        df['size'] = df['size'].clip(lower=1)

    return px.scatter_geo(
        df,
        lat='latitude',
        lon='longitude',
        color=color_column,
        hover_name='source_ip',
        size='size',  # Use our cleaned size column
        projection="natural earth",
        title="<b>GLOBAL THREAT HEATMAP</b>",
        height=400
    )

def generate_timeline(df):
    """Generate threat timeline visualization with error handling"""
    try:
        if df.empty:
            return px.area(title="<b>NO DATA AVAILABLE</b>")

        # Ensure timestamp exists and is datetime
        if 'timestamp' not in df.columns:
            df['timestamp'] = datetime.now().isoformat()

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])

        # Resample with modern syntax
        timeline_df = (df.set_index('timestamp')
                      .resample('5min')
                      .size()
                      .reset_index(name='count'))

        return px.area(
            timeline_df,
            x='timestamp',
            y='count',
            title="<b>THREAT TIMELINE</b>",
            line_shape='spline',
            height=400
        )
    except Exception as e:
        logger.error(f"Timeline generation failed: {str(e)}")
        return px.area(title="<b>TIMELINE ERROR</b>")

def generate_threats_table(df):
    """Generate top threats visualization"""
    if 'event' not in df.columns:
        df['event'] = 'unknown'

    top_threats = df['event'].value_counts().reset_index()
    top_threats.columns = ['Threat Type', 'Count']

    return px.bar(
        top_threats,
        x='Threat Type',
        y='Count',
        color='Count',
        color_continuous_scale='reds',
        title="<b>TOP THREAT TYPES</b>",
        height=400
    )

def get_dashboard_stats(df):
    """Calculate dashboard statistics"""
    stats = {
        "total_events": len(df),
        "critical_alerts": len(df[df['severity'] == 'critical']),
        "high_alerts": len(df[df['severity'] == 'high']),
        "top_threat": df['event'].mode()[0] if len(df) > 0 else "None",
        "last_alert": df['timestamp'].max() if 'timestamp' in df.columns else "Unknown",
        "unique_ips": df['source_ip'].nunique() if 'source_ip' in df.columns else 0
    }
    return stats

def render_dashboard(stats, threat_map, timeline, threats_table, recent_alerts):
    """Render the complete dashboard"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard</title>
        <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        <script>
            // Real-time updates with EventSource
            if (typeof(EventSource) !== "undefined") {{
                var eventSource = new EventSource("/stream");
                eventSource.onmessage = function(e) {{
                    var alert = JSON.parse(e.data);
                    var alertsDiv = document.getElementById("recent-alerts");

                    // Add new alert to the top
                    var alertElement = document.createElement("div");
                    alertElement.className = "alert-item";
                    alertElement.innerHTML = `
                        <strong>${{alert.rule}}</strong>
                        <span class="severity ${{alert.severity}}">${{alert.severity}}</span>
                        <div>${{new Date(alert.timestamp).toLocaleString()}}</div>
                        <div>Source: ${{alert.source_ip}}</div>
                    `;

                    alertsDiv.insertBefore(alertElement, alertsDiv.firstChild);

                    // Keep only 20 alerts
                    if (alertsDiv.children.length > 20) {{
                        alertsDiv.removeChild(alertsDiv.lastChild);
                    }}

                    // Update stats
                    document.getElementById("total-events").textContent = parseInt(document.getElementById("total-events").textContent) + 1;
                    if (alert.severity === 'critical') {{
                        document.getElementById("critical-alerts").textContent =
                            parseInt(document.getElementById("critical-alerts").textContent) + 1;
                    }}
                }};
            }}
        </script>
        <style>
            :root {{
                --primary: #00ffcc;
                --secondary: #ff5555;
                --bg-dark: #0a0a1a;
                --bg-panel: rgba(0, 20, 40, 0.7);
                --text-light: #e0e0e0;
            }}

            body {{
                background-color: var(--bg-dark);
                color: var(--text-light);
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
            }}

            .dashboard-header {{
                background: linear-gradient(135deg, #001a33 0%, #000d1a 100%);
                color: white;
                padding: 1rem 2rem;
                border-bottom: 1px solid var(--primary);
                box-shadow: 0 2px 10px rgba(0,0,0,0.5);
            }}

            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 1rem;
            }}

            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }}

            .stat-card {{
                background: rgba(0, 40, 80, 0.6);
                padding: 1.5rem;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                transition: transform 0.3s ease;
            }}

            .stat-card:hover {{
                transform: translateY(-5px);
            }}

            .stat-value {{
                font-size: 2.5rem;
                font-weight: bold;
                margin: 0.5rem 0;
                color: var(--primary);
            }}

            .dashboard-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(600px, 1fr));
                gap: 1.5rem;
            }}

            .panel {{
                background: var(--bg-panel);
                border-radius: 8px;
                padding: 1rem;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}

            .panel-title {{
                color: var(--primary);
                border-bottom: 1px solid rgba(0, 255, 200, 0.3);
                padding-bottom: 0.5rem;
                margin-top: 0;
            }}

            #recent-alerts {{
                max-height: 400px;
                overflow-y: auto;
                border: 1px solid rgba(0, 255, 200, 0.3);
                border-radius: 5px;
                padding: 0.5rem;
            }}

            .alert-item {{
                padding: 0.5rem;
                margin-bottom: 0.5rem;
                background: rgba(0, 20, 40, 0.5);
                border-left: 4px solid var(--secondary);
            }}

            .severity {{
                padding: 0.2rem 0.5rem;
                border-radius: 3px;
                font-size: 0.8rem;
                font-weight: bold;
            }}

            .severity.critical {{
                background: #ff0000;
                color: white;
            }}

            .severity.high {{
                background: #ff5555;
                color: white;
            }}

            .severity.medium {{
                background: #ffaa00;
                color: black;
            }}

            .severity.low {{
                background: #00aa00;
                color: white;
            }}

            .last-updated {{
                text-align: right;
                font-size: 0.8rem;
                color: #999;
                margin-top: 1rem;
            }}
            .report-actions {{
                margin-top: 2rem;
                padding: 1rem;
                background: rgba(0, 40, 80, 0.6);
                border-radius: 8px;
            }}

            .report-buttons {{
                display: flex;
                gap: 1rem;
                margin-top: 1rem;
            }}

            .report-button {{
                padding: 0.8rem 1.5rem;
                border-radius: 4px;
                color: white;
                text-decoration: none;
                font-weight: bold;
                transition: transform 0.2s;
            }}

            .report-button.pdf {{
                background: #e74c3c;
            }}

            .report-button.csv {{
                background: #27ae60;
            }}

            .report-button:hover {{
                transform: translateY(-2px);
            }}
        </style>
    </head>
    <body>
        <div class="dashboard-header">
            <h1>SIEM SECURITY DASHBOARD</h1>
            <p>Real-time threat monitoring and analysis</p>
        </div>

        <div class="container">
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>TOTAL EVENTS</h3>
                    <div class="stat-value" id="total-events">{stats['total_events']}</div>
                    <p>Processed events</p>
                </div>
                <div class="stat-card">
                    <h3>CRITICAL ALERTS</h3>
                    <div class="stat-value" id="critical-alerts">{stats['critical_alerts']}</div>
                    <p>Require immediate action</p>
                </div>
                <div class="stat-card">
                    <h3>HIGH ALERTS</h3>
                    <div class="stat-value">{stats['high_alerts']}</div>
                    <p>Important threats</p>
                </div>
                <div class="stat-card">
                    <h3>UNIQUE SOURCES</h3>
                    <div class="stat-value">{stats['unique_ips']}</div>
                    <p>Distinct IP addresses</p>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="panel">
                    <h2 class="panel-title">THREAT MAP</h2>
                    {threat_map.to_html(full_html=False, include_plotlyjs='cdn')}
                </div>
                <div class="panel">
                    <h2 class="panel-title">THREAT TIMELINE</h2>
                    {timeline.to_html(full_html=False, include_plotlyjs='cdn')}
                </div>
                <div class="panel">
                    <h2 class="panel-title">TOP THREATS</h2>
                    {threats_table.to_html(full_html=False, include_plotlyjs='cdn')}
                </div>
                <div class="panel">
                    <h2 class="panel-title">RECENT ALERTS</h2>
                   <div id="recent-alerts">
                    {"".join(
                        f'<div class="alert-item">'
                        f'<strong>{alert["rule"]}</strong>'
                        f'<span class="severity {alert["severity"]}">{alert["severity"]}</span>'
                        f'<div>{datetime.fromisoformat(alert["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")}</div>'
                        f'<div>Source: {alert["source_ip"]}</div>'
                        f'</div>'
                        for alert in recent_alerts[::-1]
                    )}
                </div>

                </div>
            </div>
            <div class="report-actions">
                <h2 class="panel-title">GENERATE REPORTS</h2>
                <div class="report-buttons">
                    <a href="/report/pdf" class="report-button pdf">Download PDF Report</a>
                    <a href="/report/csv" class="report-button csv">Download CSV Data</a>
                </div>
            </div>
            <div class="last-updated">
                Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
    </body>
    </html>
    """

def render_error_page(error):
    """Render error page"""
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Dashboard Error</title>
        <style>
            body {{
                background: #0f0f23;
                color: #f00;
                font-family: monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .error-container {{
                max-width: 800px;
                padding: 2rem;
                border: 2px solid #f00;
                background: rgba(0,0,0,0.7);
                box-shadow: 0 0 20px #f00;
            }}
            pre {{
                white-space: pre-wrap;
                word-wrap: break-word;
            }}
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>SIEM DASHBOARD ERROR</h1>
            <p>An error occurred while generating the dashboard:</p>
            <pre>{str(error)}</pre>
            <p>Please check the server logs for more details.</p>
        </div>
    </body>
    </html>
    """
from flask import make_response
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from io import BytesIO

@app.route('/report/pdf')
@login_required
def generate_pdf_report():
    """Generate a PDF security report"""
    try:
        # Get data from Elasticsearch
        logs = es.search(index="security_logs", body={"size": 1000, "query": {"match_all": {}}})["hits"]["hits"]
        df = pd.DataFrame([log["_source"] for log in logs])

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Add title
        story.append(Paragraph("SIEM Security Report", styles['Title']))
        story.append(Spacer(1, 12))

        # Add summary statistics
        stats = get_dashboard_stats(df)
        summary_data = [
            ["Total Events", stats['total_events']],
            ["Critical Alerts", stats['critical_alerts']],
            ["High Alerts", stats['high_alerts']],
            ["Top Threat", stats['top_threat']],
            ["Unique IPs", stats['unique_ips']]
        ]
        summary_table = Table(summary_data, colWidths=[200, 100])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 12))

        # Add recent alerts
        story.append(Paragraph("Recent Alerts", styles['Heading2']))
        alert_data = [["Time", "Rule", "Severity", "Source IP"]]
        with alert_lock:
            for alert in recent_alerts[-10:]:
                alert_data.append([
                    datetime.fromisoformat(alert["timestamp"]).strftime("%Y-%m-%d %H:%M"),
                    alert["rule"],
                    alert["severity"],
                    alert["source_ip"]
                ])

        alerts_table = Table(alert_data, colWidths=[100, 200, 80, 120])
        alerts_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ]))
        story.append(alerts_table)

        # Build PDF
        doc.build(story)
        buffer.seek(0)

        # Return as downloadable file
        response = make_response(buffer.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=siem_report.pdf'
        return response

    except Exception as e:
        logger.error(f"Failed to generate PDF report: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
@app.route('/report/csv')
def generate_csv_report():
    """Generate a CSV security report"""
    try:
        # Get data from Elasticsearch
        logs = es.search(index="security_logs", body={"size": 1000, "query": {"match_all": {}}})["hits"]["hits"]
        df = pd.DataFrame([log["_source"] for log in logs])

        # Create CSV in memory
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)

        # Return as downloadable file
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=siem_report.csv'
        return response

    except Exception as e:
        logger.error(f"Failed to generate CSV report: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
# ===== API ENDPOINTS =====
@app.route("/ingest", methods=["POST"])
def ingest_api():
    """API endpoint for log ingestion"""
    try:
        content_type = request.headers.get('Content-Type')

        if content_type == 'application/json':
            data = request.get_json()
            if not data:
                return jsonify({"status": "error", "message": "No data provided"}), 400
            log_source = data.get("log_source", "json")
            log_data = data.get("log_data", data)
        else:  # Handle plain text
            log_source = "syslog"  # or auto-detect format
            log_data = request.data.decode('utf-8')

        if ingest_log(log_source, log_data):
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "Failed to ingest log"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
from apscheduler.schedulers.background import BackgroundScheduler

def send_daily_report():
    """Generate and email daily security report"""
    try:
        # Get data from last 24 hours
        logs = es.search(
            index="security_logs",
            body={
                "size": 1000,
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": "now-1d/d"
                        }
                    }
                }
            }
        )["hits"]["hits"]

        df = pd.DataFrame([log["_source"] for log in logs])
        stats = get_dashboard_stats(df)

        # Create email content
        email_content = f"""
        Daily SIEM Security Report - {datetime.now().strftime('%Y-%m-%d')}

        Summary Statistics:
        - Total Events: {stats['total_events']}
        - Critical Alerts: {stats['critical_alerts']}
        - High Alerts: {stats['high_alerts']}
        - Top Threat: {stats['top_threat']}
        - Unique IPs: {stats['unique_ips']}

        Recent Alerts:
        """

        with alert_lock:
            for alert in recent_alerts[-5:]:
                email_content += f"""
                - [{alert['severity'].upper()}] {alert['rule']}
                  Source: {alert['source_ip']}
                  Time: {datetime.fromisoformat(alert['timestamp']).strftime('%Y-%m-%d %H:%M')}
                """

        # Send email
        subject = f"Daily SIEM Report - {datetime.now().strftime('%Y-%m-%d')}"
        message = f"Subject: {subject}\n\n{email_content}"

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, ALERT_EMAIL, message.encode('utf-8'))

    except Exception as e:
        logger.error(f"Failed to send daily report: {str(e)}")

# Schedule daily reports at 8 AM
scheduler = BackgroundScheduler()
scheduler.add_job(send_daily_report, 'cron', hour=8)
scheduler.start()
@app.route('/report/custom', methods=['POST'])
def generate_custom_report():
    """Generate a report with custom parameters"""
    try:
        params = request.json
        time_range = params.get('time_range', '1d')
        report_type = params.get('type', 'pdf')

        es_query = {
            "size": 1000,
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{time_range}/d"
                    }
                }
            }
        }

        logs = es.search(index="security_logs", body=es_query)["hits"]["hits"]
        df = pd.DataFrame([log["_source"] for log in logs])

        if report_type == 'pdf':
            # Generate PDF as shown earlier
            pass
        elif report_type == 'csv':
            # Generate CSV as shown earlier
            pass
        else:
            return jsonify({"status": "error", "message": "Invalid report type"}), 400

    except Exception as e:
        logger.error(f"Failed to generate custom report: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500
@app.route("/search", methods=["POST"])
def search_api():
    """Search logs with enhanced query capabilities"""
    try:
        query = request.json.get("query", "")
        time_range = request.json.get("time_range", "1d")

        es_query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": {
                                "query": query
                            }
                        },
                        {
                            "range": {
                                "timestamp": {
                                    "gte": f"now-{time_range}/d"
                                }
                            }
                        }
                    ]
                }
            },
            "size": 100
        }

        results = es.search(index="security_logs", body=es_query)
        return jsonify(results["hits"]["hits"])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ===== MAIN EXECUTION =====
# Admin credentials (in production, store hashed passwords in a database)
ADMINS = {
    "admin": {
        "password_hash": generate_password_hash(os.getenv('ADMIN_PASSWORD', 'securepassword123')),
        "email": "admin@yourdomain.com"
    }
}

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username in ADMINS and check_password_hash(ADMINS[username]['password_hash'], password):
            user = AdminUser(username)
            login_user(user)
            logger.info(f"Admin login successful: {username}")
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('admin_dashboard'))

        logger.warning(f"Failed admin login attempt for: {username}")
        flash('Invalid credentials', 'error')

    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Admin Login</title>
        <style>
            /* Your existing CSS styles here */
            :root {
                --primary: #00ffcc;
                --secondary: #ff5555;
                --bg-dark: #0a0a1a;
                --bg-panel: rgba(0, 20, 40, 0.7);
                --text-light: #e0e0e0;
            }

            body {
                background-color: var(--bg-dark);
                color: var(--text-light);
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }

            .login-container {
                background: var(--bg-panel);
                padding: 2rem;
                border-radius: 8px;
                width: 350px;
                box-shadow: 0 4px 20px rgba(0, 255, 200, 0.1);
                border: 1px solid rgba(0, 255, 200, 0.2);
            }

            .login-header {
                text-align: center;
                margin-bottom: 2rem;
            }

            .login-header h1 {
                color: var(--primary);
                margin-bottom: 0.5rem;
            }

            .login-form input {
                width: 100%;
                padding: 12px;
                margin-bottom: 1rem;
                background: rgba(0, 10, 20, 0.5);
                border: 1px solid rgba(0, 255, 200, 0.3);
                border-radius: 4px;
                color: white;
            }

            .login-form button {
                width: 100%;
                padding: 12px;
                background: var(--primary);
                color: #001a33;
                border: none;
                border-radius: 4px;
                font-weight: bold;
                cursor: pointer;
            }

            .error-message {
                color: var(--secondary);
                text-align: center;
                margin-top: 1rem;
                height: 20px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <div class="login-header">
                <h1>SIEM Admin Portal</h1>
                <p>Security Information and Event Management</p>
            </div>

            <form class="login-form" method="post">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>

            <div class="error-message">
                <!-- Corrected Jinja2 syntax for flash messages -->
                {% with messages = get_flashed_messages() %}
                    {% if messages %}
                        {{ messages[0] }}
                    {% endif %}
                {% endwith %}
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return f'''
    <h1>Admin Dashboard</h1>
    <p>Welcome, {current_user.id}</p>
    <a href="/admin/logs">View Security Logs</a><br>
    <a href="/admin/logout">Logout</a>
    '''

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/admin/logs')
@login_required
def view_logs():
    logs = es.search(index="security_logs", body={"query": {"match_all": {}}, "size": 100})["hits"]["hits"]
    return jsonify([log["_source"] for log in logs])
@app.route('/admin/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password == confirm_password:
            ADMINS[current_user.id]['password_hash'] = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')
            return redirect(url_for('admin_dashboard'))

        flash('Passwords do not match', 'error')

    return '''
    <form method="post">
        <h2>Reset Password</h2>
        <input type="password" name="new_password" placeholder="New Password" required>
        <input type="password" name="confirm_password" placeholder="Confirm Password" required>
        <button type="submit">Update Password</button>
    </form>
    '''
if __name__ == "__main__":
    print("""
     ███████╗██╗███████╗███╗   ███╗
    ██╔════╝██║██╔════╝████╗ ████║
    ███████╗██║█████╗  ██╔████╔██║
    ╚════██║██║██╔══╝  ██║╚██╔╝██║
    ███████║██║███████╗██║ ╚═╝ ██║
    ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝
    Security Information and Event Management System
    """)

    print("Starting SIEM Engine...")

    try:
        # Start anomaly detection in background
        anomaly_thread = Thread(target=lambda: detect_anomalies(), daemon=True)
        anomaly_thread.start()

        # Start Flask in a separate thread
        flask_thread = Thread(target=lambda: app.run(
            host="0.0.0.0",
            port=5000,
            threaded=True,
            debug=False
        ))
        flask_thread.daemon = True
        flask_thread.start()

        # Start Kafka consumer
        print("Listening for logs...")
        logger.info("SIEM service started")
        stream_logs()

    except KeyboardInterrupt:
        print("\nShutting down SIEM...")
        logger.info("SIEM service stopped")
    except Exception as e:
        logger.critical(f"SIEM crashed: {str(e)}")
        raise
