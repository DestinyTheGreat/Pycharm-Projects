import streamlit as st
import os
import re
import requests
import platform
import subprocess
import json
import nmap
import pandas as pd
import joblib
import plotly.express as px
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from scapy.all import sniff, IP
from fpdf import FPDF
import zipfile
from io import BytesIO

# Constants
LOG_FILE = "scan_logs.txt"
SHODAN_API_KEY = st.secrets.get("SHODAN_API_KEY", "LIo6dGocBGHFpuf98zuxDybk1BxKUpB7")
OPENVAS_API_URL = "http://localhost:9392"
OPENVAS_CREDS = st.secrets.get("OPENVAS", {"username": "admin", "password": "admin"})
KAGGLE_DATASET_URL = "https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15/download?datasetVersionNumber=1"
DATASET_PATH = "data/unsw-nb15/"
TRAIN_DATA_FILE = DATASET_PATH + "UNSW_NB15_training-set.csv"
TEST_DATA_FILE = DATASET_PATH + "UNSW_NB15_testing-set.csv"
MODEL_PATH = "models/unsw_model.pkl"
SCAN_HISTORY_FILE = "data/scan_history.csv"

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = {"data": {}, "metadata": {}}
if 'logs' not in st.session_state:
    st.session_state.logs = ""
if 'anomaly_model' not in st.session_state:
    st.session_state.anomaly_model = None
if 'traffic_data' not in st.session_state:
    st.session_state.traffic_data = pd.DataFrame(columns=["timestamp", "source", "destination", "protocol"])
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = pd.DataFrame(columns=["timestamp", "target", "scan_type", "findings"])
if 'stop_monitor' not in st.session_state:
    st.session_state.stop_monitor = False


# Utility Functions
def init_directories():
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs(DATASET_PATH, exist_ok=True)


def download_unsw_dataset():
    """Download and extract UNSW-NB15 dataset"""
    if not os.path.exists(TRAIN_DATA_FILE) or not os.path.exists(TEST_DATA_FILE):
        try:
            st.warning("Please download the UNSW-NB15 dataset manually from Kaggle and place it in the data folder")
            st.info("Dataset available at: https://www.kaggle.com/datasets/mrwellsdavid/unsw-nb15")
            return False
        except Exception as e:
            st.error(f"Failed to download dataset: {str(e)}")
            return False
    return True


def preprocess_unsw_data():
    """Preprocess the UNSW-NB15 dataset"""
    try:
        train_df = pd.read_csv(TRAIN_DATA_FILE)
        test_df = pd.read_csv(TEST_DATA_FILE)
        df = pd.concat([train_df, test_df])

        # Preprocessing
        categorical_cols = ['proto', 'service', 'state']
        df = pd.get_dummies(df, columns=categorical_cols, drop_first=True)
        df.fillna(0, inplace=True)

        # Selected features from UNSW-NB15
        features = [
            'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
            'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
            'sinpkt', 'dinpkt', 'sjit', 'djit', 'swin', 'stcpb',
            'dtcpb', 'dwin', 'tcprtt', 'synack', 'ackdat',
            'smean', 'dmean', 'trans_depth', 'response_body_len',
            'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm', 'ct_src_dport_ltm',
            'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'is_ftp_login',
            'ct_ftp_cmd', 'ct_flw_http_mthd', 'ct_src_ltm', 'ct_srv_dst',
            'is_sm_ips_ports'
        ]
        features += [col for col in df.columns if col.startswith(tuple(categorical_cols))]
        features = [f for f in features if f in df.columns]

        X = df[features]
        y = df['label']  # 0 for normal, 1 for attack

        return X, y, features
    except Exception as e:
        st.error(f"Data preprocessing failed: {str(e)}")
        return None, None, None


def load_anomaly_model():
    """Load or train the UNSW-NB15 based anomaly detection model"""
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            st.success("Loaded pre-trained anomaly detection model")
            return model
        except:
            st.warning("Failed to load pre-trained model, retraining...")

    if not download_unsw_dataset():
        return None

    X, y, features = preprocess_unsw_data()
    if X is None:
        return None

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    with st.spinner("Training anomaly detection model (this may take several minutes)..."):
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred)

    st.text("Model Evaluation Report:")
    st.text(report)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(features, "models/unsw_features.pkl")
    joblib.dump(scaler, "models/unsw_scaler.pkl")

    st.success("Anomaly detection model trained and saved!")
    return model


def log_scan(target, scan_type, findings):
    """Log scan results to history"""
    new_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "scan_type": scan_type,
        "findings": str(findings)
    }

    if os.path.exists(SCAN_HISTORY_FILE):
        history = pd.read_csv(SCAN_HISTORY_FILE)
    else:
        history = pd.DataFrame(columns=["timestamp", "target", "scan_type", "findings"])

    history = pd.concat([history, pd.DataFrame([new_entry])], ignore_index=True)
    history.to_csv(SCAN_HISTORY_FILE, index=False)
    st.session_state.scan_history = history


# Scan Functions
def nmap_scan(target):
    """Perform Nmap scan on target"""
    try:
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments="-T4 -A -v")

        results = {
            "host": target,
            "status": scanner[target].state(),
            "protocols": list(scanner[target].all_protocols()),
            "ports": []
        }

        for proto in scanner[target].all_protocols():
            ports = scanner[target][proto].keys()
            for port in ports:
                port_info = {
                    "port": port,
                    "state": scanner[target][proto][port]["state"],
                    "service": scanner[target][proto][port]["name"],
                    "product": scanner[target][proto][port].get("product", ""),
                    "version": scanner[target][proto][port].get("version", ""),
                    "extra": scanner[target][proto][port].get("extrainfo", "")
                }
                results["ports"].append(port_info)

        return results
    except Exception as e:
        st.error(f"Nmap scan failed: {str(e)}")
        return None


def openvas_scan(target):
    """Perform OpenVAS scan on target"""
    try:
        auth_url = f"{OPENVAS_API_URL}/login"
        response = requests.post(auth_url, data=OPENVAS_CREDS)
        token = response.json()["token"]

        task_url = f"{OPENVAS_API_URL}/tasks"
        task_data = {"target": target, "name": f"Scan {target}"}
        headers = {"X-Token": token}
        response = requests.post(task_url, json=task_data, headers=headers)
        task_id = response.json()["id"]

        report_url = f"{OPENVAS_API_URL}/reports"
        report_data = {"task_id": task_id}
        response = requests.get(report_url, json=report_data, headers=headers)

        return response.json()
    except Exception as e:
        st.error(f"OpenVAS scan failed: {str(e)}")
        return None


def process_packet(packet):
    """Process network packets for real-time monitoring"""
    if IP in packet:
        new_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f"),
            "source": packet[IP].src,
            "destination": packet[IP].dst,
            "protocol": packet.sprintf("%IP.proto%")
        }

        if len(st.session_state.traffic_data) > 100:
            st.session_state.traffic_data = st.session_state.traffic_data.iloc[1:]

        st.session_state.traffic_data = pd.concat([
            st.session_state.traffic_data,
            pd.DataFrame([new_entry])
        ], ignore_index=True)


# Security Functions
def check_system_misconfigurations():
    """Check for common system misconfigurations"""
    issues = []

    try:
        if platform.system() == "Linux":
            services = subprocess.check_output(["service", "--status-all"]).decode()
            risky_services = ["telnet", "ftp", "rlogin", "rsh", "rexec"]
            for service in risky_services:
                if service in services.lower():
                    issues.append(f"Risky service running: {service}")
    except:
        pass

    try:
        if platform.system() == "Linux":
            result = subprocess.check_output(["find", "/", "-perm", "-2", "-ls"]).decode()
            if result.strip():
                issues.append("World-writable files found (security risk)")
    except:
        pass

    try:
        if platform.system() == "Linux":
            firewall_status = subprocess.check_output(["ufw", "status"]).decode()
            if "inactive" in firewall_status.lower():
                issues.append("Firewall is inactive")
    except:
        pass

    return issues if issues else ["No major misconfigurations detected"]


def lynis_scan():
    """Run Lynis system audit if available"""
    try:
        result = subprocess.check_output(["lynis", "audit", "system"], stderr=subprocess.STDOUT).decode()
        return result
    except FileNotFoundError:
        return "Lynis not installed. Please install Lynis for system auditing."
    except Exception as e:
        return f"Lynis scan failed: {str(e)}"


def weak_password_check(password):
    """Check password strength"""
    if not password:
        return "No password provided"

    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password is too short (minimum 8 characters recommended)")

    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add numbers")

    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    else:
        feedback.append("Add special characters")

    common_passwords = ["password", "123456", "qwerty", "letmein"]
    if password.lower() in common_passwords:
        score = 0
        feedback.append("Password is too common")

    if score >= 5:
        return "Strong password"
    elif score >= 3:
        return f"Moderate password. Suggestions: {', '.join(feedback)}"
    else:
        return f"Weak password. Suggestions: {', '.join(feedback)}"


# Anomaly Detection
def detect_anomalies(scan_results):
    """Detect anomalies using the UNSW-NB15 trained model"""
    anomalies = []

    if not scan_results or not st.session_state.anomaly_model:
        return anomalies

    try:
        features = joblib.load("models/unsw_features.pkl")
        scaler = joblib.load("models/unsw_scaler.pkl")

        feature_vector = np.zeros(len(features))

        if "ports" in scan_results:
            open_ports = len([p for p in scan_results["ports"] if p["state"] == "open"])
            feature_vector[features.index('spkts')] = open_ports * 10
            feature_vector[features.index('dpkts')] = open_ports * 5

            risky_ports = {21: 'ftp', 22: 'ssh', 23: 'telnet', 80: 'http', 443: 'https'}
            for port_info in scan_results["ports"]:
                if port_info["state"] == "open":
                    port = port_info["port"]
                    if port in risky_ports:
                        feature_vector[features.index(f"proto_{risky_ports[port]}")] = 1

        feature_vector = scaler.transform([feature_vector])

        prediction = st.session_state.anomaly_model.predict(feature_vector)
        proba = st.session_state.anomaly_model.predict_proba(feature_vector)

        if prediction[0] == 1:
            attack_confidence = proba[0][1]
            anomalies.append({
                "type": "Network intrusion pattern detected",
                "details": f"Model detected malicious network patterns (confidence: {attack_confidence:.2%})",
                "severity": "High" if attack_confidence > 0.8 else "Medium",
                "confidence": attack_confidence
            })

        return anomalies
    except Exception as e:
        st.error(f"Anomaly detection failed: {str(e)}")
        return []


def suggest_remediation(anomalies):
    """Generate remediation suggestions based on detected anomalies"""
    if not anomalies:
        return "No critical issues detected. System appears secure."

    actions = ["Recommended actions based on UNSW-NB15 threat intelligence:"]

    for anomaly in anomalies:
        if "Network intrusion pattern" in anomaly["type"]:
            conf = anomaly.get("confidence", 0)
            actions.append(f"- Detected potential network intrusion (confidence: {conf:.2%})")
            actions.append("  - Review firewall rules and IDS/IPS logs")
            actions.append("  - Check for unusual outbound connections")
            actions.append("  - Verify system integrity with file hashes")

            if conf > 0.8:
                actions.append("  - HIGH CONFIDENCE ALERT: Consider isolating the system")

    return "\n".join(actions)


# Reporting
def generate_report(scan_data):
    """Generate a PDF report from scan results with robust font handling"""
    pdf = FPDF()
    pdf.add_page()

    # Font configuration - try multiple fallbacks
    font_configured = False
    font_paths = [
        os.path.join("DejaVuSans.ttf"),  # Local project file
        "C:/Windows/Fonts/DejaVuSans.ttf",  # Windows standard location
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux common location
        "/Library/Fonts/DejaVuSans.ttf"  # macOS common location
    ]

    # Try to find and register DejaVu font
    for font_path in font_paths:
        try:
            if os.path.exists(font_path):
                pdf.add_font("ReportFont", "", font_path, uni=True)
                pdf.set_font("ReportFont", size=12)
                font_configured = True
                break
        except:
            continue

    # Fallback to Arial if DejaVu not found
    if not font_configured:
        try:
            pdf.set_font("Arial", size=12)
        except:
            pdf.set_font("Helvetica", size=12)  # Final fallback

    # Header
    pdf.set_font("ReportFont" if font_configured else "Arial", 'B', 16)
    pdf.cell(200, 10, txt="CyberShield Vulnerability Report", ln=1, align='C')
    pdf.set_font("ReportFont" if font_configured else "Arial", size=12)

    # Report metadata
    metadata = scan_data.get('metadata', {})
    pdf.cell(200, 10, txt=f"Scan Date: {metadata.get('timestamp', 'N/A')}", ln=1)
    pdf.cell(200, 10, txt=f"Target: {metadata.get('target', 'N/A')}", ln=1)
    pdf.cell(200, 10, txt=f"Scan Type: {metadata.get('scan_type', 'N/A')}", ln=1)
    pdf.ln(10)

    # Scan Results section
    pdf.set_font("ReportFont" if font_configured else "Arial", 'B', 14)
    pdf.cell(200, 10, txt="Scan Results", ln=1)
    pdf.set_font("ReportFont" if font_configured else "Arial", size=12)

    if metadata.get('scan_type') == "Nmap Comprehensive Scan":
        data = scan_data.get('data', {})
        pdf.cell(200, 10, txt=f"Host Status: {data.get('status', 'N/A').upper()}", ln=1)
        pdf.ln(5)

        # Port table
        pdf.set_font("ReportFont" if font_configured else "Arial", 'B', 12)
        col_widths = [30, 60, 30]  # Adjusted column widths
        pdf.cell(col_widths[0], 10, "Port", border=1)
        pdf.cell(col_widths[1], 10, "Service", border=1)
        pdf.cell(col_widths[2], 10, "State", border=1, ln=1)
        pdf.set_font("ReportFont" if font_configured else "Arial", size=10)

        for port in data.get('ports', []):
            # Handle potential missing keys
            pdf.cell(col_widths[0], 10, str(port.get('port', '')), border=1)
            pdf.cell(col_widths[1], 10, port.get('service', ''), border=1)
            pdf.cell(col_widths[2], 10, port.get('state', ''), border=1, ln=1)

    # Anomalies section
    if scan_data.get('anomalies'):
        pdf.ln(10)
        pdf.set_font("ReportFont" if font_configured else "Arial", 'B', 14)
        pdf.cell(200, 10, txt="Security Anomalies Detected", ln=1)
        pdf.set_font("ReportFont" if font_configured else "Arial", size=12)

        for anomaly in scan_data['anomalies']:
            pdf.cell(200, 10, txt=f"- {anomaly.get('type', 'Unknown')} ({anomaly.get('severity', 'N/A')})", ln=1)

    # Remediation section
    if scan_data.get('remediation'):
        pdf.ln(10)
        pdf.set_font("ReportFont" if font_configured else "Arial", 'B', 14)
        pdf.cell(200, 10, txt="Recommended Actions", ln=1)
        pdf.set_font("ReportFont" if font_configured else "Arial", size=12)
        pdf.multi_cell(0, 10, txt=scan_data['remediation'])

    # Footer
    pdf.ln(20)
    pdf.set_font("ReportFont" if font_configured else "Arial", 'I', 10)
    pdf.cell(0, 10, txt="Generated by CyberShield Vulnerability Scanner", align='C')

    # Return PDF as bytes
    try:
        return pdf.output(dest='S').encode('utf-8')
    except:
        return pdf.output(dest='S').encode('latin1')


# UI Components
def render_scan_results():
    if not st.session_state.scan_results["data"]:
        return

    results = st.session_state.scan_results["data"]
    metadata = st.session_state.scan_results["metadata"]

    st.subheader(f"Scan Results for {metadata['target']}")
    st.caption(f"Scan completed at {metadata['timestamp']} using {metadata['scan_type']}")

    if metadata["scan_type"] == "Nmap Comprehensive Scan":
        col1, col2 = st.columns(2)

        with col1:
            st.metric("Host Status", results["status"].upper())

            ports_df = pd.DataFrame(results["ports"])
            if not ports_df.empty:
                st.dataframe(
                    ports_df[["port", "state", "service"]],
                    use_container_width=True,
                    hide_index=True
                )

        with col2:
            if not ports_df.empty:
                fig = px.pie(
                    ports_df,
                    names="state",
                    title="Port Status Distribution",
                    hole=0.4
                )
                st.plotly_chart(fig, use_container_width=True)

        st.subheader("Anomaly Analysis")
        if "anomalies" in st.session_state.scan_results:
            anomalies = st.session_state.scan_results["anomalies"]
            remediation = st.session_state.scan_results["remediation"]

            col1, col2 = st.columns(2)

            with col1:
                st.metric("Anomalies Detected", len(anomalies))
                st.dataframe(pd.DataFrame(anomalies), use_container_width=True)

            with col2:
                st.text_area("Recommended Actions", remediation, height=200)

                risk_score = min(len(anomalies) * 10, 100)
                fig, ax = plt.subplots()
                ax.barh(["Risk Score"], [risk_score], color="red" if risk_score > 50 else "orange")
                ax.set_xlim(0, 100)
                st.pyplot(fig)
    else:
        st.json(results)


def render_history_tab():
    if not os.path.exists(SCAN_HISTORY_FILE):
        st.info("No scan history available yet")
        return

    history = pd.read_csv(SCAN_HISTORY_FILE)
    if history.empty:
        st.info("No scan history available yet")
        return

    st.dataframe(
        history,
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": "Time",
            "target": "Target",
            "scan_type": "Scan Type",
            "findings": "Findings"
        }
    )

    history['date'] = pd.to_datetime(history['timestamp']).dt.date
    scans_per_day = history.groupby('date').size().reset_index(name='count')

    fig = px.line(
        scans_per_day,
        x='date',
        y='count',
        title='Scan Activity Over Time',
        markers=True
    )
    st.plotly_chart(fig, use_container_width=True)


def render_realtime_monitor():
    st.subheader("Network Traffic Monitor")

    if st.button("Start Monitoring"):
        st.session_state.stop_monitor = False
        st.warning("Monitoring network traffic... (Press Stop to end)")
        sniff(prn=process_packet, store=0, stop_filter=lambda x: st.session_state.stop_monitor)

    if st.button("Stop Monitoring"):
        st.session_state.stop_monitor = True
        st.success("Monitoring stopped")

    if not st.session_state.traffic_data.empty:
        col1, col2 = st.columns(2)

        with col1:
            st.dataframe(
                st.session_state.traffic_data.tail(10),
                use_container_width=True,
                hide_index=True
            )

        with col2:
            protocol_counts = st.session_state.traffic_data['protocol'].value_counts().reset_index()
            protocol_counts.columns = ['protocol', 'count']

            fig = px.bar(
                protocol_counts,
                x='protocol',
                y='count',
                title='Protocol Distribution'
            )
            st.plotly_chart(fig, use_container_width=True)

        traffic_counts = st.session_state.traffic_data.groupby(
            pd.to_datetime(st.session_state.traffic_data['timestamp']).dt.floor('S')
        ).size().reset_index(name='count')

        fig = px.line(
            traffic_counts,
            x='timestamp',
            y='count',
            title='Traffic Volume Over Time'
        )
        st.plotly_chart(fig, use_container_width=True)


def show_model_insights():
    """Show feature importance from the trained model"""
    if not os.path.exists(MODEL_PATH):
        return

    model = joblib.load(MODEL_PATH)
    features = joblib.load("models/unsw_features.pkl")

    importances = model.feature_importances_
    indices = np.argsort(importances)[-10:]

    fig, ax = plt.subplots()
    ax.set_title('Top 10 Important Features for Anomaly Detection')
    ax.barh(range(len(indices)), importances[indices], color='b', align='center')
    ax.set_yticks(range(len(indices)))
    ax.set_yticklabels([features[i] for i in indices])
    st.pyplot(fig)


# Main App
def main():
    init_directories()

    if st.session_state.anomaly_model is None:
        with st.spinner("Loading anomaly detection model..."):
            st.session_state.anomaly_model = load_anomaly_model()

    # Custom CSS
    st.markdown("""
    <style>
        .main {padding-top: 1rem;}
        .stProgress > div > div > div > div {background-color: #1DA1F2;}
        .st-bb {background-color: transparent;}
        .st-at {background-color: #0F1116;}
        div[data-testid="stExpander"] div[role="button"] p {font-size: 1.2rem;}
    </style>
    """, unsafe_allow_html=True)

    # Sidebar
    with st.sidebar:
        st.image("https://via.placeholder.com/150x50?text=CyberShield", width=150)
        st.title("Configuration")

        scan_type = st.selectbox(
            "Scan Type",
            ["Nmap Comprehensive Scan", "OpenVAS Deep Scan"],
            index=0
        )

        st.divider()
        st.subheader("Quick Actions")

        if st.button("Check System Config"):
            with st.spinner("Checking..."):
                issues = check_system_misconfigurations()
                st.text_area("Findings", "\n".join(issues), height=150)

        if st.button("Run Lynis Audit"):
            result = lynis_scan()
            st.text_area("Lynis Results", result, height=300)

        st.divider()
        st.subheader("Password Checker")
        password = st.text_input("Test Password", type="password")
        if st.button("Check Strength"):
            result = weak_password_check(password)
            st.text_area("Result", result, height=100)

        st.divider()
        st.subheader("Model Insights")
        if st.button("Show Feature Importance"):
            show_model_insights()

    # Main Content
    st.title("🛡️ CyberShield Vulnerability Scanner")
    st.caption("Comprehensive security assessment tool with UNSW-NB15 based anomaly detection")

    tab1, tab2, tab3 = st.tabs(["Scanner", "History", "Realtime Monitor"])

    with tab1:
        with st.form("scan_form"):
            target = st.text_input(
                "Target",
                placeholder="192.168.1.1 or example.com",
                help="Enter IP address or domain to scan"
            )

            col1, col2 = st.columns(2)
            with col1:
                scan_btn = st.form_submit_button("Start Scan", type="primary")
            with col2:
                export_btn = st.form_submit_button("Export Report")

        if scan_btn and target:
            with st.spinner(f"Running {scan_type} on {target}..."):
                progress_bar = st.progress(0)

                if "Nmap" in scan_type:
                    results = nmap_scan(target)
                    scan_type_name = "Nmap Comprehensive Scan"
                else:
                    results = openvas_scan(target)
                    scan_type_name = "OpenVAS Deep Scan"

                progress_bar.progress(50)

                if results:
                    anomalies = detect_anomalies(results)
                    remediation = suggest_remediation(anomalies)

                    st.session_state.scan_results = {
                        "data": results,
                        "metadata": {
                            "target": target,
                            "scan_type": scan_type_name,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        },
                        "anomalies": anomalies,
                        "remediation": remediation
                    }

                    log_scan(target, scan_type_name, results)
                    progress_bar.progress(100)
                    st.success("Scan completed!")

        render_scan_results()

        if export_btn and st.session_state.scan_results.get("data"):
            report = generate_report(st.session_state.scan_results)
            st.download_button(
                label="Download Full Report (PDF)",
                data=report,
                file_name=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )

    with tab2:
        render_history_tab()

    with tab3:
        render_realtime_monitor()


if __name__ == "__main__":
    main()