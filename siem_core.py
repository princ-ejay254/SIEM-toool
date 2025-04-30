#!/usr/bin/env python3
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
from threading import Thread
import logging

# ===== CONFIGURATION =====
ES_HOST = "http://localhost:9200"
KAFKA_HOST = "localhost:9092"
ALERT_EMAIL = "katumangajayson@gmail.com"
SLACK_WEBHOOK = "https://hooks.slack.com/services/XXX"  #  webhook
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "katumangajayson@gmail.com"
SMTP_PASS = "12345678j"  # Use app-specific password

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='siem.log'
)
logger = logging.getLogger('SIEM')

# ===== ELASTICSEARCH CONNECTION =====
es = Elasticsearch([ES_HOST], request_timeout=30)

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
    """Ingest logs from various sources"""
    try:
        if log_source == "syslog":
            parsed = [parse_syslog(log_data)]
        elif log_source == "json":
            parsed = [json.loads(log_data)]
        else:  # CSV
            parsed = pd.read_csv(log_data).to_dict(orient="records")

        for entry in parsed:
            if "timestamp" not in entry:
                entry["timestamp"] = datetime.now().isoformat()
            es.index(index="security_logs", body=entry)
            producer.send("security_logs", value=entry)

        return True
    except Exception as e:
        logger.error(f"Error ingesting log: {str(e)}")
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

def stream_logs():
    """Process logs from Kafka in real-time"""
    logger.info("Starting log stream processor")
    for msg in consumer:
        try:
            log = json.loads(msg.value.decode('utf-8'))
            detect_threats(log)
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")

# ===== SECURITY FUNCTIONS =====
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
    """Evaluate log against security rules"""
    for rule in RULES:
        try:
            if eval(rule["condition"], {'log': log}):
                trigger_alert(rule, log)
        except Exception as e:
            logger.error(f"Error evaluating rule {rule['name']}: {str(e)}")

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
            server.sendmail(SMTP_USER, ALERT_EMAIL, alert_msg)
    except Exception as e:
        logger.error(f"Failed to send email alert: {str(e)}")

    # Slack Alert
    if SLACK_WEBHOOK and not SLACK_WEBHOOK.startswith("https://hooks.slack.com/services/XXX"):
        try:
            import requests
            requests.post(SLACK_WEBHOOK, json={"text": alert_msg})
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}")

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

        if len(df) < 10:
            return []

        clf = IsolationForest(contamination=0.01, random_state=42)
        features = df[['login_count', 'bytes_transferred']].dropna()
        if len(features) > 0:
            anomalies = clf.fit_predict(features)
            return features[anomalies == -1].to_dict('records')
        return []
    except Exception as e:
        logger.error(f"Anomaly detection failed: {str(e)}")
        return []
'''import geoip2.database

reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')

def get_geolocation(ip):
    try:
        response = reader.city(ip)
        return (response.location.latitude, response.location.longitude)
    except:
        return (0, 0)'''
# ===== WEB INTERFACE =====
app = Flask(__name__)

@app.route("/dashboard")
def dashboard():
    try:
        # Check if index exists
        if not es.indices.exists(index="security_logs"):
            return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>ALIEN DEFENSE DASHBOARD</title>
                <link href='https://fonts.googleapis.com/css?family=Orbitron' rel='stylesheet'>
                <link href='https://fonts.googleapis.com/css?family=Montserrat' rel='stylesheet'>
                <style>
                    body {
                        background: #0a0a1a url('https://assets.codepen.io/13471/starfield.png');
                        color: #00ffcc;
                        font-family: 'Montserrat', sans-serif;
                        text-align: center;
                        padding: 2rem 1rem;
                        margin: 0;
                        min-height: 100vh;
                        display: flex;
                        flex-direction: column;
                        justify-content: center;
                    }
                    h1, h2, h3 {
                        font-family: 'Orbitron', sans-serif;
                        text-shadow: 0 0 10px #00ffff;
                    }
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 0 1rem;
                    }
                    .alert-panel {
                        background: rgba(255, 85, 85, 0.2);
                        border: 1px solid #ff5555;
                        border-radius: 8px;
                        padding: 2rem;
                        width: 100%;
                        max-width: 800px;
                        margin: 0 auto;
                        box-shadow: 0 0 30px rgba(255, 85, 85, 0.3);
                        animation: pulse 2s infinite;
                        backdrop-filter: blur(5px);
                    }
                    @keyframes pulse {
                        0% { box-shadow: 0 0 15px rgba(255, 85, 85, 0.3); }
                        50% { box-shadow: 0 0 30px rgba(255, 85, 85, 0.5); }
                        100% { box-shadow: 0 0 15px rgba(255, 85, 85, 0.3); }
                    }
                    .status-text {
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        gap: 1rem;
                        margin: 1rem 0;
                    }
                    .loading-animation {
                        display: inline-block;
                        width: 20px;
                        height: 20px;
                        border: 3px solid rgba(0, 255, 200, 0.3);
                        border-radius: 50%;
                        border-top-color: #00ffcc;
                        animation: spin 1s ease-in-out infinite;
                    }
                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🛸 ALIEN DEFENSE DASHBOARD 👽</h1>
                    <div class="alert-panel">
                        <h2>⚠️ NO THREAT DATA FOUND ⚠️</h2>
                        <div class="status-text">
                            <div class="loading-animation"></div>
                            <span>Waiting for alien activity...</span>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """

        # Get data and process visualizations (same as before)
       # Inside your /dashboard route
        logs = es.search(
            index="security_logs",
            body={
                "size": 1000,
                "query": {
                    "match_all": {}
                }
            }
        )["hits"]["hits"]

        df = pd.DataFrame([log["_source"] for log in logs])

        # Add mock geo data if missing
        if 'latitude' not in df.columns:
            import random
            df['latitude'] = [random.uniform(-90, 90) for _ in range(len(df))]
            df['longitude'] = [random.uniform(-180, 180) for _ in range(len(df))]

        # Generate visualizations with improved config
        threat_map = px.scatter_geo(
            df,
            lat='latitude',
            lon='longitude',
            color='severity',
            hover_name='source_ip',
            size='count',
            projection="natural earth",
            title="<b>GLOBAL THREAT HEATMAP</b>",
            color_discrete_map={
                'critical': '#ff0000',
                'high': '#ff5555',
                'medium': '#ffaa00',
                'low': '#00ffcc'
            },
            height=400
        )
        threat_map.update_layout(
            geo=dict(
                landcolor='rgba(0, 30, 60, 0.7)',
                bgcolor='rgba(0,0,0,0)',
                showframe=False
            ),
            margin=dict(l=20, r=20, t=40, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            font_color="#00ffcc",
            hoverlabel=dict(
                bgcolor="#0a0a1a",
                font_size=12,
                font_family="Orbitron"
            )
        )

        timeline = px.area(
            df,
            x='timestamp',
            y='count',
            color='event',
            title="<b>THREAT TIMELINE</b>",
            line_shape='spline',
            height=400
        )
        timeline.update_layout(
            xaxis=dict(showgrid=False),
            yaxis=dict(showgrid=False),
            plot_bgcolor='rgba(0, 20, 40, 0.5)',
            paper_bgcolor='rgba(0,0,0,0)',
            font_color="#00ffcc",
            margin=dict(l=20, r=20, t=40, b=20),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )

        # Top threats table
        top_threats = df['event'].value_counts().reset_index()
        top_threats.columns = ['Threat Type', 'Count']
        threats_table = px.bar(
            top_threats,
            x='Threat Type',
            y='Count',
            color='Count',
            color_continuous_scale='reds',
            title="<b>TOP THREAT TYPES</b>",
            height=400
        )
        threats_table.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            font_color="#00ffcc",
            margin=dict(l=20, r=20, t=40, b=20),
            coloraxis_showscale=False
        )

        # Stats cards
        stats = {
            "total_events": len(df),
            "critical_alerts": len(df[df['severity'] == 'critical']),
            "top_threat": df['event'].mode()[0] if len(df) > 0 else "None",
            "last_alert": df['timestamp'].max() if 'timestamp' in df.columns else "Unknown"
        }

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ALIEN DEFENSE DASHBOARD</title>
            <link href='https://fonts.googleapis.com/css?family=Orbitron' rel='stylesheet'>
            <link href='https://fonts.googleapis.com/css?family=Montserrat' rel='stylesheet'>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
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
                    color: var(--primary);
                    font-family: 'Montserrat', sans-serif;
                    padding: 0;
                    margin: 0;
                    min-height: 100vh;
                }}

                .dashboard-header {{
                    text-align: center;
                    margin-bottom: 2rem;
                    padding: 2rem 1rem;
                    background: linear-gradient(90deg, rgba(0,0,0,0) 0%, rgba(0,255,200,0.1) 50%, rgba(0,0,0,0) 100%);
                    border-bottom: 1px solid var(--primary);
                }}

                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    padding: 0 1rem;
                }}

                .dashboard-grid {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 1.5rem;
                    margin-bottom: 2rem;
                }}

                .panel {{
                    background: var(--bg-panel);
                    border: 1px solid var(--primary);
                    border-radius: 8px;
                    padding: 1.5rem;
                    box-shadow: 0 0 15px rgba(0, 255, 200, 0.3);
                    transition: all 0.3s ease;
                    backdrop-filter: blur(5px);
                }}

                .panel:hover {{
                    box-shadow: 0 0 25px rgba(0, 255, 200, 0.5);
                    transform: translateY(-5px);
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
                    border-left: 5px solid var(--secondary);
                    box-shadow: 0 0 10px rgba(255, 85, 85, 0.3);
                    transition: all 0.3s ease;
                }}

                .stat-card:hover {{
                    transform: translateY(-3px);
                }}

                .stat-card.green {{
                    border-left-color: var(--primary);
                    box-shadow: 0 0 10px rgba(0, 255, 200, 0.3);
                }}

                .stat-card.orange {{
                    border-left-color: #ffaa00;
                    box-shadow: 0 0 10px rgba(255, 170, 0, 0.3);
                }}

                .stat-card.purple {{
                    border-left-color: #aa00ff;
                    box-shadow: 0 0 10px rgba(170, 0, 255, 0.3);
                }}

                .stat-value {{
                    font-size: 2rem;
                    font-weight: bold;
                    margin: 0.5rem 0;
                    text-shadow: 0 0 10px currentColor;
                    font-family: 'Orbitron', sans-serif;
                }}

                .alert-banner {{
                    background: linear-gradient(90deg, #ff0000 0%, #ff5555 100%);
                    padding: 1rem;
                    text-align: center;
                    border-radius: 8px;
                    margin-bottom: 2rem;
                    animation: pulse 2s infinite;
                    font-weight: bold;
                    color: white;
                }}

                @keyframes pulse {{
                    0% {{ opacity: 0.8; }}
                    50% {{ opacity: 1; }}
                    100% {{ opacity: 0.8; }}
                }}

                h1, h2, h3 {{
                    font-family: 'Orbitron', sans-serif;
                    text-shadow: 0 0 10px #00ffff;
                    margin-top: 0;
                }}

                h1 {{
                    font-size: 2.5rem;
                    margin-bottom: 0.5rem;
                }}

                h2 {{
                    font-size: 1.5rem;
                    margin-bottom: 1rem;
                }}

                .last-updated {{
                    text-align: right;
                    font-size: 0.9rem;
                    color: #00aaaa;
                }}

                #log-stream {{
                    height: 400px;
                    overflow-y: auto;
                    background: rgba(0,0,0,0.3);
                    padding: 1rem;
                    border-radius: 5px;
                    font-family: monospace;
                    color: var(--text-light);
                }}

                #log-stream div {{
                    margin-bottom: 0.5rem;
                    border-bottom: 1px solid #003366;
                    padding-bottom: 0.5rem;
                }}

                @media (max-width: 768px) {{
                    .dashboard-header {{
                        padding: 1rem;
                    }}

                    h1 {{
                        font-size: 2rem;
                    }}

                    .stat-value {{
                        font-size: 1.5rem;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="dashboard-header">
                <div class="container">
                    <h1>🛸 ALIEN DEFENSE COMMAND CENTER 👽</h1>
                    <div>Real-time threat monitoring and analysis</div>
                    <div class="last-updated">Last updated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} UTC</div>
                </div>
            </div>

            <div class="container">
                {f'<div class="alert-banner">🚨 CRITICAL ALERT: {stats["critical_alerts"]} ACTIVE THREATS DETECTED 🚨</div>' if stats["critical_alerts"] > 0 else ''}

                <div class="stats-grid">
                    <div class="stat-card green">
                        <h3>TOTAL EVENTS</h3>
                        <div class="stat-value">{stats['total_events']}</div>
                        <div>since system startup</div>
                    </div>
                    <div class="stat-card orange">
                        <h3>ACTIVE THREATS</h3>
                        <div class="stat-value">{stats['critical_alerts']}</div>
                        <div>requiring immediate action</div>
                    </div>
                    <div class="stat-card">
                        <h3>PRIMARY THREAT</h3>
                        <div class="stat-value">{stats['top_threat'].upper()}</div>
                        <div>most frequent event type</div>
                    </div>
                    <div class="stat-card purple">
                        <h3>LAST DETECTION</h3>
                        <div class="stat-value">{stats['last_alert']}</div>
                        <div>most recent alert</div>
                    </div>
                </div>

                <div class="dashboard-grid">
                    <div class="panel">
                        <h2>🌍 GLOBAL THREAT HEATMAP</h2>
                        {threat_map.to_html(full_html=False, include_plotlyjs='cdn')}
                    </div>
                    <div class="panel">
                        <h2>⏱️ THREAT ACTIVITY TIMELINE</h2>
                        {timeline.to_html(full_html=False, include_plotlyjs='cdn')}
                    </div>
                    <div class="panel">
                        <h2>🔥 TOP THREAT TYPES</h2>
                        {threats_table.to_html(full_html=False, include_plotlyjs='cdn')}
                    </div>
                    <div class="panel">
                        <h2>⚡ REAL-TIME LOG STREAM</h2>
                        <div id="log-stream" aria-live="polite">
                            {''.join(f'<div>{log["_source"].get("message", str(log["_source"]))}</div>' for log in logs[-20:])}
                        </div>
                    </div>
                </div>
            </div>

            <script>
                // Auto-refresh every 30 seconds
                setTimeout(function(){{
                    window.location.reload();
                }}, 30000);

                // Smooth scroll for log stream
                const logStream = document.getElementById('log-stream');
                if (logStream) {{
                    logStream.scrollTop = logStream.scrollHeight;
                }}
            </script>
        </body>
        </html>
        """
    except Exception as e:
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>ALIEN DEFENSE DASHBOARD ERROR</title>
            <link href='https://fonts.googleapis.com/css?family=Orbitron' rel='stylesheet'>
            <link href='https://fonts.googleapis.com/css?family=Montserrat' rel='stylesheet'>
            <style>
                body {{
                    background: #0a0a1a url('https://assets.codepen.io/13471/starfield.png');
                    color: #ff5555;
                    font-family: 'Montserrat', sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    margin: 0;
                    padding: 2rem;
                }}
                .error-container {{
                    max-width: 800px;
                    background: rgba(0, 0, 0, 0.8);
                    border: 2px solid #ff0000;
                    border-radius: 10px;
                    padding: 2rem;
                    box-shadow: 0 0 30px rgba(255, 0, 0, 0.5);
                    text-align: center;
                }}
                h1 {{
                    font-family: 'Orbitron', sans-serif;
                    color: #ff0000;
                    text-shadow: 0 0 10px #ff0000;
                }}
                pre {{
                    background: rgba(255, 0, 0, 0.1);
                    padding: 1rem;
                    border-radius: 5px;
                    overflow-x: auto;
                    text-align: left;
                }}
                .alien-icon {{
                    font-size: 3rem;
                    margin-bottom: 1rem;
                    animation: float 3s ease-in-out infinite;
                }}
                @keyframes float {{
                    0% {{ transform: translateY(0); }}
                    50% {{ transform: translateY(-10px); }}
                    100% {{ transform: translateY(0); }}
                }}
            </style>
        </head>
        <body>
            <div class="error-container">
                <div class="alien-icon">👽</div>
                <h1>⚠️ ALIEN INTERFERENCE DETECTED ⚠️</h1>
                <p>Dashboard systems compromised. Emergency protocols engaged.</p>
                <pre>{str(e)}</pre>
                <p>Please try refreshing the page or contact your system administrator.</p>
            </div>
        </body>
        </html>
        """


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

# ===== MAIN EXECUTION =====
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

    try:
        # Start Flask in a separate thread
        flask_thread = Thread(target=lambda: app.run(host="0.0.0.0", port=5000, threaded=True))
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
