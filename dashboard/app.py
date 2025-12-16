"""
AI-Powered IDS Dashboard 
"""

import streamlit as st
import pandas as pd
import os
import json
import re
from time import sleep

# Paths
BASE_DIR = os.path.dirname(__file__)
DATA_FILE = os.path.join(BASE_DIR, "..", "data", "captured_packets.csv")
ALERT_LOG = os.path.join(BASE_DIR, "..", "data", "alerts.log")

# Page config
st.set_page_config(page_title="AI-Powered IDS Dashboard", layout="wide")
st.title("AI-Powered IDS/IPS")

# Green divider under title
st.markdown("<hr style='border: 2px solid #00ff00; border-radius: 5px;'>", unsafe_allow_html=True)

# Load data
def load_traffic():
    if os.path.exists(DATA_FILE):
        return pd.read_csv(DATA_FILE)
    return pd.DataFrame()

def load_alerts():
    if os.path.exists(ALERT_LOG):
        with open(ALERT_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return lines[-20:][::-1]  # newest first, max 20
    return []

traffic_df = load_traffic()
alerts = load_alerts()

# Main layout — two columns
col_left, col_right = st.columns(2)

# LEFT COLUMN: Live Traffic 
with col_left:
    st.header("Live Network Traffic")

    # Header + packet counter on the same line
    total_packets = len(traffic_df)
    st.subheader(f"Total Packets Captured: **{total_packets:,}**")

    # Last 20 packets
    if not traffic_df.empty:
        st.write("**Latest Packets**")
        display_df = traffic_df.tail(20).copy()
        display_df = display_df[["timestamp", "src_ip", "dst_ip", "protocol", "packet_length"]]
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        # Green line chart — packet size over time
        st.write("**Packet Size Trend**")
        chart_data = traffic_df['packet_length'].tail(100).reset_index(drop=True)
        st.line_chart(chart_data, use_container_width=True, color="#00ff00")
    else:
        st.info("Waiting for captured traffic...")

#  RIGHT COLUMN: Security Alerts 
with col_right:
    st.header("Security Alerts")

    if alerts:
        for alert in alerts:
            if any(kw in alert.upper() for kw in ["ATTACK", "ALERT", "SUSPICIOUS"]):
                st.error(alert.strip())
            else:
                st.warning(alert.strip())
    else:
        st.success("No suspicious activity detected")

#  SIDEBAR: Threat Intelligence (AbuseIPDB + GeoIP) 
st.sidebar.header("Threat Intelligence")

abuse_info = None
for line in alerts:
    if "AbuseIPDB" in line:
        try:
            data_str = line.split("AbuseIPDB:", 1)[1].strip()
            abuse_info = json.loads(data_str.replace("'", '"'))
            break
        except:
            continue

if abuse_info:
    # Extract all data fields
    ip = abuse_info.get("ipAddress", "N/A")
    score = abuse_info.get("abuseConfidenceScore", 0)
    country = abuse_info.get("countryCode", "Unknown")
    reports = abuse_info.get("totalReports", 0)
    domain = abuse_info.get("domain", "N/A")           
    usage = abuse_info.get("usageType", "N/A")         
    last_seen = abuse_info.get("lastReportedAt", "N/A") 

    st.sidebar.markdown("### Last Detected Threat Details")
    
    # Use metric for the main score
    st.sidebar.metric("Abuse Confidence Score", f"{score}/100")

    # Display full details
    st.sidebar.markdown(f"""
    - **IP Address:** `{ip}`
    - **Country:** {country}
    - **ISP / Domain:** {domain}
    - **Usage Type:** {usage}
    - **Total Reports:** {reports}
    - **Last Reported:** {last_seen}
    """)
# Status indicators
    if score >= 50:
        st.sidebar.error("IP blocked")
    elif score > 0:
        st.sidebar.warning("Suspicious Activity Detected")
    else:
        st.sidebar.success(" IP seems clean")

else:
    st.sidebar.info("No recent threat data found in logs.")



# Optional GeoIP2 lookup
try:
    import geoip2.database
    GEOIP_DB = os.path.join(BASE_DIR, "..", "data", "GeoLite2-City.mmdb")
    if os.path.exists(GEOIP_DB) and alerts:
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", alerts[0])
        if match:
            ip = match.group(1)
            reader = geoip2.database.Reader(GEOIP_DB)
            response = reader.city(ip)
            st.sidebar.write("**Location**")
            st.sidebar.write(f"IP: {ip}")
            st.sidebar.write(f"Country: {response.country.name or 'Unknown'}")
            st.sidebar.write(f"City: {response.city.name or 'Unknown'}")
            reader.close()
except:
    pass

# Footer
st.caption("AI-Powered IDS\IPS © 2025")