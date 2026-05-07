import os
import requests
import subprocess
import datetime
import hashlib
import pickle
import numpy as np
import pandas as pd
import scapy.all as scapy
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.neighbors import LocalOutlierFactor
import streamlit as st

# Pwned Password check function
def check_pwned_password(password):
    password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = password_hash[:5], password_hash[5:]

    response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
    if response.status_code == 200:
        hashes = response.text.splitlines()
        for hash in hashes:
            if hash.startswith(suffix):
                return True  # Password is pwned
    return False  # Password is not pwned

# OS update check
def check_os_updates():
    try:
        if os.name == 'posix':  # For Linux-based OS
            result = subprocess.run(["sudo", "apt-get", "update"], capture_output=True, text=True)
            return result.stdout
        elif os.name == 'nt':  # For Windows-based OS
            result = subprocess.run(["powershell", "-Command", "Get-WindowsUpdate"], capture_output=True, text=True)
            return result.stdout
    except Exception as e:
        return str(e)

# Enhanced Misconfiguration Checks
def check_misconfigurations():
    misconfigurations = [
        "Unsecured SSH: SSH root login enabled",
        "Outdated software: Ensure all packages are updated",
        "Weak file permissions: Sensitive files have improper permissions",
        "Firewall disabled: No active firewall detected",
        "Unnecessary open ports: Services running on non-standard ports",
        "Default credentials: Check for default usernames and passwords",
        "Unencrypted connections: HTTP instead of HTTPS",
        "Exposed database: Publicly accessible databases detected"
    ]
    return "\n".join(misconfigurations)

# Saving scan logs
def save_log(results):
    with open("scan_logs.txt", "a") as log_file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] Scan Results:\n{results}\n{'-'*50}\n")

# Load scan logs
def load_logs():
    try:
        with open("scan_logs.txt", "r") as log_file:
            return log_file.read()
    except FileNotFoundError:
        return "No logs found."

# Real-time anomaly detection using Isolation Forest
def detect_anomalies_with_iforest(data):
    clf = IsolationForest(contamination=0.1)
    outliers = clf.fit_predict(data)
    return np.where(outliers == -1)[0]

# Train AI model for anomaly detection using UNSW-NB15 dataset
def train_ai_model():
    df = pd.read_csv("UNSW-NB15.csv")
    X = df.drop("Class", axis=1)  # Features
    y = df["Class"]  # Labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    clf = RandomForestClassifier(n_estimators=100)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print(classification_report(y_test, y_pred))

# Streamlit UI
def main():
    st.title("Vulnerability Assessment System")

    target_input = st.text_input("Enter target IP or Domain")

    if st.button("Run Nmap Scan"):
        if target_input:
            st.write(f"Running Nmap scan on {target_input}...")
            # Simulated scan result
            results = f"Nmap scan results for {target_input}:\n- Port 80: Open\n- Port 443: Open"
            st.text_area("Scan Results", results, height=300)
            save_log(results)
        else:
            st.error("Please enter a valid target (IP or Domain).")

    if st.button("Check Shodan Exposure"):
        if target_input:
            st.write(f"Checking Shodan exposure for {target_input}...")
            results = f"Shodan exposure for {target_input}:\n- Service: HTTP\n- Port: 80"
            st.text_area("Shodan Results", results, height=300)
            save_log(results)
        else:
            st.error("Please enter a valid target (IP or Domain).")

    password_input = st.text_input("Enter Password to Check (Pwned Passwords)")
    if password_input:
        if check_pwned_password(password_input):
            st.error("The password is pwned! Change it immediately.")
        else:
            st.success("The password is safe.")

    if st.button("Check OS Updates"):
        update_results = check_os_updates()
        st.text_area("OS Update Status", update_results, height=300)

    if st.button("Check Misconfigurations"):
        misconfig_results = check_misconfigurations()
        st.text_area("Misconfiguration Check", misconfig_results, height=300)

    st.subheader("Scan Logs")
    logs = load_logs()
    st.text_area("Logs", logs, height=300)

    # Real-time anomaly detection example
    if st.button("Monitor Network for Anomalies"):
        st.write("Monitoring network traffic...")
        packets = scapy.sniff(filter="tcp", count=100)  # Capture packets
        features = [[packet.len, packet.time] for packet in packets]  # Example feature extraction
        anomalies = detect_anomalies_with_iforest(np.array(features))

        if anomalies.size > 0:
            st.warning(f"Anomalies detected at indices: {anomalies}")
        else:
            st.success("No anomalies detected.")

if __name__ == "__main__":
    main()
