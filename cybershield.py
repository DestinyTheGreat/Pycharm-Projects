import streamlit as st
import os
import re
import hashlib
import requests
import platform
import subprocess
import json
import nmap
import pandas as pd
import joblib
import plotly.express as px
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import time
from scapy.all import sniff, IP
from io import StringIO
import numpy as np
from datetime import datetime


# Constants
LOG_FILE = "scan_logs.txt"

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "LIo6dGocBGHFpuf98zuxDybk1BxKUpB7")
OPENVAS_API_URL = "http://localhost:9392"
OPENVAS_CREDS = st.secrets.get("OPENVAS", {"username": "admin", "password": "admin"})
KAGGLE_DATASET_PATH = "UNSW-NB15.csv"
ANOMALY_MODEL_PATH = "models/anomaly_detection_model.pkl"
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

# Configure page
st.set_page_config(
    page_title="CyberShield Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Utility functions
def init_directories():
    os.makedirs("data", exist_ok=True)
    os.makedirs("models", exist_ok=True)
    os.makedirs("reports", exist_ok=True)


def load_anomaly_model():
    if os.path.exists(ANOMALY_MODEL_PATH):
        return joblib.load(ANOMALY_MODEL_PATH)
    else:
        try:
            data = pd.read_csv(KAGGLE_DATASET_PATH)
            X = data.drop(columns=["anomaly"], errors='ignore')
            y = data.get("anomaly", np.zeros(len(data)))

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            scaler = StandardScaler()
            X_train = scaler.fit_transform(X_train)

            model = IsolationForest(
                n_estimators=150,
                max_samples='auto',
                contamination=0.05,
                random_state=42
            )
            model.fit(X_train)

            joblib.dump(model, ANOMALY_MODEL_PATH)
            return model
        except Exception as e:
            st.error(f"Failed to load anomaly detection model: {str(e)}")
            return None


def log_scan(target, scan_type, findings):
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


# Scan functions
def nmap_scan(target):
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
    if IP in packet:
        new_entry = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f"),
            "source": packet[IP].src,
            "destination": packet[IP].dst,
            "protocol": packet.sprintf("%IP.proto%")
        }

        # Limit to last 100 packets for performance
        if len(st.session_state.traffic_data) > 100:
            st.session_state.traffic_data = st.session_state.traffic_data.iloc[1:]

        st.session_state.traffic_data = pd.concat([
            st.session_state.traffic_data,
            pd.DataFrame([new_entry])
        ], ignore_index=True)


# UI Components
def render_scan_results():
    if not st.session_state.scan_results["data"]:
        return

    results = st.session_state.scan_results["data"]
    metadata = st.session_state.scan_results["metadata"]

    st.subheader(f"Scan Results for {metadata['target']}")
    st.caption(f"Scan completed at {metadata['timestamp']} using {metadata['scan_type']}")

    if metadata["scan_type"] == "Nmap":
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
            # Port status distribution
            if not ports_df.empty:
                fig = px.pie(
                    ports_df,
                    names="state",
                    title="Port Status Distribution",
                    hole=0.4
                )
                st.plotly_chart(fig, use_container_width=True)

        # Anomaly detection visualization
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

                # Generate visual risk assessment
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

    # Time series analysis
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

        # Traffic over time
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


# Main App
def check_system_misconfigurations():
    pass


def lynis_scan():
    pass


def weak_password_check(password):
    pass


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
            ["Nmap Comprehensive", "OpenVAS Deep Scan"],
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

    # Main Content
    st.title("🛡️ CyberShield Vulnerability Scanner")
    st.caption("Comprehensive security assessment tool with anomaly detection and remediation guidance")

    tab1, tab2, tab3 = st.tabs(["Scanner", "History", "Realtime Monitor"])

    with tab1:
        with st.form("scan_form"):
            target = st.text_input(
                "Target",
                placeholder="192.168.1.1 or example.com",
                help="Enter IP address or domain to scan"
            )

            col1, col2 = st.columns([3, 1])

            with col1:
                st.text_area("Scan Progress", value=st.session_state.logs, height=200)

            with col2:
                scan_action = st.form_submit_button("Start Scan")

            if scan_action:
                with st.spinner(f"Starting {scan_type} scan..."):
                    if scan_type == "Nmap Comprehensive":
                        results = nmap_scan(target)
                        st.session_state.scan_results = {
                            "data": results,
                            "metadata": {
                                "target": target,
                                "scan_type": "Nmap Comprehensive",
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                        }
                    elif scan_type == "OpenVAS Deep Scan":
                        results = openvas_scan(target)
                        st.session_state.scan_results = {
                            "data": results,
                            "metadata": {
                                "target": target,
                                "scan_type": "OpenVAS Deep Scan",
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                        }
                    log_scan(target, scan_type, results)

        render_scan_results()

    with tab2:
        render_history_tab()

    with tab3:
        render_realtime_monitor()


if __name__ == "__main__":
    main()
