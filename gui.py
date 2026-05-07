# CyberShield - Streamlit-based Vulnerability Assessment System

import streamlit as st
import nmap
import shodan
import subprocess
import platform
import re

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

# === CONFIGURATION ===
OPENVAS_CREDS = {
    'username': 'admin',
    'password': 'admin'  # Change this to your actual OpenVAS password
}
SHODAN_API_KEY = "LIo6dGocBGHFpuf98zuxDybk1BxKUpB7"  # Replace with your Shodan API Key

# === NMAP SCAN FUNCTION ===
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
        return {"error": str(e)}

# === OPENVAS SCAN FUNCTION ===
def openvas_scan(target):
    try:
        connection = TLSConnection(hostname='localhost', port=9390)
        with Gmp(connection=connection, transform=EtreeTransform()) as gmp:
            gmp.authenticate(username=OPENVAS_CREDS['username'], password=OPENVAS_CREDS['password'])
            target_id = gmp.create_target(name=f"Scan Target {target}", hosts=[target])
            task_id = gmp.create_task(name=f"Scan {target}", target_id=target_id,
                                      config_id='daba56c8-73ec-11df-a475-002264764cea')  # Full/fast scan ID
            gmp.start_task(task_id=task_id)
            return {"status": "OpenVAS scan initiated", "task_id": task_id}
    except Exception as e:
        return {"error": str(e)}

# === SHODAN SCAN FUNCTION ===
def shodan_scan(target):
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(target)
        return {
            "ip": host['ip_str'],
            "organization": host.get('org', 'N/A'),
            "os": host.get('os', 'N/A'),
            "ports": host.get('ports', []),
            "vulnerabilities": host.get('vulns', [])
        }
    except shodan.APIError as e:
        return {"error": str(e)}

# === SYSTEM MISCONFIGURATION CHECK ===
def check_system_misconfigurations():
    issues = []
    os_type = platform.system()
    if os_type == "Linux":
        try:
            firewall_status = subprocess.check_output(['sudo', 'ufw', 'status'], text=True)
            if "inactive" in firewall_status.lower():
                issues.append("UFW firewall is inactive.")
        except Exception:
            issues.append("Failed to check UFW firewall status.")
    elif os_type == "Windows":
        try:
            firewall_status = subprocess.check_output(['netsh', 'advfirewall', 'show', 'allprofiles'], text=True)
            if "State OFF" in firewall_status:
                issues.append("Windows Firewall is off for some profiles.")
        except Exception:
            issues.append("Failed to check Windows Firewall status.")
    return issues if issues else ["No misconfigurations found."]

# === PASSWORD STRENGTH CHECK ===
def weak_password_check(password):
    if len(password) < 8:
        return False, "Password too short."
    if not re.search(r'[A-Z]', password):
        return False, "Missing uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Missing lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Missing number."
    if not re.search(r'[\W_]', password):
        return False, "Missing special character."
    return True, "Password is strong."

# === OS UPDATE CHECK ===
def check_os_updates():
    os_type = platform.system()
    updates = []
    if os_type == "Linux":
        try:
            result = subprocess.check_output(['apt', 'list', '--upgradable'], text=True)
            lines = result.strip().split('\n')[1:]
            updates.extend(lines)
        except Exception as e:
            updates.append(f"Failed to check updates: {str(e)}")
    elif os_type == "Windows":
        try:
            result = subprocess.check_output(['wmic', 'qfe', 'list'], text=True)
            updates.extend(result.strip().split('\n')[1:])
        except Exception as e:
            updates.append(f"Failed to check updates: {str(e)}")
    return updates if updates else ["No updates found."]

# === STREAMLIT UI ===
def main():
    st.set_page_config(page_title="CyberShield Vulnerability Scanner", layout="wide")
    st.title("🛡️ CyberShield - Vulnerability Assessment System")

    st.markdown("Perform vulnerability scans, system checks, and password validation.")
    target = st.text_input("🔍 Enter Target IP or Domain:")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🚀 Run Nmap Scan"):
            if target:
                st.info("Running Nmap scan...")
                results = nmap_scan(target)
                st.json(results)
            else:
                st.warning("Please enter a valid target.")

    with col2:
        if st.button("🔍 Run OpenVAS Scan"):
            if target:
                st.info("Initiating OpenVAS scan...")
                results = openvas_scan(target)
                st.json(results)
            else:
                st.warning("Please enter a valid target.")

    with col3:
        if st.button("🌐 Run Shodan Scan"):
            if target:
                st.info("Querying Shodan...")
                results = shodan_scan(target)
                st.json(results)
            else:
                st.warning("Please enter a valid target.")

    st.markdown("---")
    st.subheader("🛠️ System Misconfiguration Check")
    if st.button("🧰 Check System Misconfigurations"):
        issues = check_system_misconfigurations()
        for issue in issues:
            st.warning(issue)

    st.markdown("---")
    st.subheader("🔐 Password Strength Checker")
    password = st.text_input("Enter a password to check:", type="password")
    if password:
        is_strong, message = weak_password_check(password)
        if is_strong:
            st.success(message)
        else:
            st.error(message)

    st.markdown("---")
    st.subheader("🧾 Check OS Updates")
    if st.button("🔄 Check for System Updates"):
        updates = check_os_updates()
        for update in updates:
            st.info(update)

if __name__ == "__main__":
    main()
