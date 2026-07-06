import socket
import platform
import sys
import subprocess
import datetime
import streamlit as st

st.set_page_config(page_title="Port Scanner Tool", page_icon="🔍")

def scan_ports(start, end):
    open_ports = []
    for port in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            r = s.connect_ex(('127.0.0.1', port))
            if r == 0:
                try:
                    svc = socket.getservbyport(port)
                except:
                    svc = "unknown"
                open_ports.append((port, svc))
            s.close()
        except:
            pass
    return open_ports

def get_sys_info():
    info = {}
    info["Python version"] = platform.python_version()
    try:
        res = subprocess.run([sys.executable, "-m", "pip", "--version"], capture_output=True, text=True)
        info["pip version"] = res.stdout.split()[1] if res.stdout else "not found"
    except:
        info["pip version"] = "not found"
    info["OS"] = platform.platform()
    info["Machine type"] = platform.machine()
    return info

def check_risky_ports(open_ports):
    risky = {
        21: "FTP is not encrypted",
        23: "Telnet sends data as plain text",
        80: "HTTP has no encryption, use HTTPS",
        110: "POP3 email has no encryption",
        143: "IMAP email has no encryption",
        3306: "MySQL database is exposed",
        5432: "PostgreSQL database is exposed",
        6379: "Redis has no auth by default",
        27017: "MongoDB has no auth by default",
        3389: "RDP is a common attack target",
        22: "SSH open - make sure password login is off",
    }
    found = []
    for port, svc in open_ports:
        if port in risky:
            found.append((port, svc, risky[port]))
    return found

def make_report(open_ports, sysinfo, risky_found):
    now = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    txt = []
    txt.append("SCAN REPORT")
    txt.append(f"Date: {now}")
    txt.append("Target: my computer (localhost)")
    txt.append("")
    txt.append("--- Open Ports ---")
    if open_ports:
        for port, svc in open_ports:
            txt.append(f"port {port} - {svc}")
    else:
        txt.append("none found")
    txt.append("")
    txt.append("--- System Info ---")
    for k, v in sysinfo.items():
        txt.append(f"{k}: {v}")
    txt.append("")
    txt.append("--- Warnings ---")
    if risky_found:
        for port, svc, reason in risky_found:
            txt.append(f"port {port} ({svc}): {reason}")
    else:
        txt.append("no warnings")
    txt.append("")
    total_risk = "low" if len(risky_found) == 0 else "medium" if len(risky_found) < 3 else "high"
    txt.append(f"overall risk: {total_risk}")
    return "\n".join(txt)


# ---- UI starts here ----

st.title("Network Vulnerability Scanner")
st.write("This tool scans your computer for open ports and checks for common vulnerabilities.")
st.write("---")

st.subheader("Settings")
start_port = st.number_input("start port", min_value=1, max_value=65535, value=1)
end_port = st.number_input("end port", min_value=1, max_value=65535, value=1024)
st.write(f"will scan ports {int(start_port)} to {int(end_port)}")

if "results" not in st.session_state:
    st.session_state.results = None

if st.button("start scan"):
    st.write("scanning... please wait")
    with st.spinner("this might take a while depending on port range"):
        open_ports = scan_ports(int(start_port), int(end_port))
        sysinfo = get_sys_info()
        risky_found = check_risky_ports(open_ports)
        report = make_report(open_ports, sysinfo, risky_found)
        st.session_state.results = {
            "open_ports": open_ports,
            "sysinfo": sysinfo,
            "risky_found": risky_found,
            "report": report
        }

if st.session_state.results:
    r = st.session_state.results
    open_ports = r["open_ports"]
    sysinfo = r["sysinfo"]
    risky_found = r["risky_found"]
    report = r["report"]

    st.write("---")
    st.subheader("Results")

    col1, col2 = st.columns(2)
    col1.metric("open ports", len(open_ports))
    col2.metric("warnings", len(risky_found))

    st.write("")
    st.write("**open ports found:**")
    if open_ports:
        for port, svc in open_ports:
            st.write(f"- port {port} ({svc})")
    else:
        st.write("no open ports found")

    st.write("")
    st.write("**warnings:**")
    if risky_found:
        for port, svc, reason in risky_found:
            st.warning(f"port {port} ({svc}) - {reason}")
    else:
        st.success("no issues found")

    st.write("")
    st.write("**system info:**")
    for k, v in sysinfo.items():
        st.write(f"{k}: {v}")

    st.write("---")
    st.write("**full report:**")
    st.text(report)
    st.download_button(
        "download report",
        data=report,
        file_name="scan_report.txt",
        mime="text/plain"
    )