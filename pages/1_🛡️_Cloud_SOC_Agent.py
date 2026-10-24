import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from google import genai

# --- AUTHENTICATION GATE ---
if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.warning("🔒 Please log in on the Home page first to access this application.")
    st.stop()

st.set_page_config(page_title="Enterprise Cloud SOC Agent", layout="wide")

# --- CUSTOM CSS STYLING ---
st.markdown("""
    <style>
    .metric-card { background-color: #1e293b; padding: 15px; border-radius: 8px; border-left: 4px solid #3b82f6; }
    .critical-alert { background-color: #451a03; padding: 12px; border-radius: 6px; border-left: 4px solid #ef4444; margin-bottom: 10px; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Enterprise Autonomous Cloud SOC & AI Response Agent")
st.markdown("Advanced SIEM telemetry pipeline, unsupervised ML anomaly detection, and automated incident response orchestration.")

# --- INITIALIZE SESSION STATE FOR AUDIT LOG ---
if 'mitigated_ips' not in st.session_state:
    st.session_state.mitigated_ips = []

# --- LOAD & PROCESS DATA ---
@st.cache_data
def load_soc_data():
    np.random.seed(42)
    n_rows = 1200
    
    ips = [f"192.168.1.{i}" for i in range(1, 20)] + ["45.33.32.156", "185.220.101.5", "198.51.100.42"]
    statuses = [200, 200, 200, 404, 401, 500, 403]
    
    data = []
    base_time = datetime.now() - timedelta(hours=3)
    
    for _ in range(n_rows):
        timestamp = base_time + timedelta(seconds=np.random.randint(0, 10800))
        ip = np.random.choice(ips, p=[0.05]*19 + [0.015, 0.015, 0.02])
        status = np.random.choice(statuses, p=[0.6, 0.1, 0.1, 0.1, 0.05, 0.02, 0.03])
        
        if ip in ["45.33.32.156", "185.220.101.5", "198.51.100.42"]:
            failed_logins = np.random.randint(8, 30)
            payload_bytes = np.random.randint(6000, 30000)
        else:
            failed_logins = np.random.randint(0, 3)
            payload_bytes = np.random.randint(200, 1500)
            
        data.append({
            "timestamp": str(timestamp),
            "ip_address": ip,
            "status_code": status,
            "failed_logins": failed_logins,
            "payload_bytes": payload_bytes
        })
        
    df = pd.DataFrame(data)
    
    # Aggregation
    aggregated = df.groupby('ip_address').agg(
        total_requests=('status_code', 'count'),
        failed_login_count=('failed_logins', 'sum'),
        avg_payload_size=('payload_bytes', 'mean'),
        unauthorized_attempts=('status_code', lambda x: ((x == 401) | (x == 403)).sum())
    ).reset_index()
    
    # Threat Intel Mock Lookup
    threat_intel_db = {
        "45.33.32.156": "Known Botnet / C2 Server",
        "185.220.101.5": "Tor Exit Node / Scanner",
        "198.51.100.42": "Suspicious Autonomous ASN"
    }
    aggregated['threat_intel'] = aggregated['ip_address'].map(threat_intel_db).fillna("Clean / Unlisted")
    
    # ML Model (Isolation Forest)
    model_features = aggregated[['total_requests', 'failed_login_count', 'avg_payload_size', 'unauthorized_attempts']]
    iso = IsolationForest(contamination=0.12, random_state=42)
    aggregated['anomaly_score'] = iso.fit_predict(model_features)
    
    return df, aggregated

with st.spinner("Analyzing telemetry streams and executing Isolation Forest models..."):
    raw_df, analyzed_df = load_soc_data()

# --- SOC AGENT PLAYBOOK LOGIC ---
def soc_agent_recommendation(row):
    if row['ip_address'] in st.session_state.mitigated_ips:
        return "🔒 MITIGATED: IP isolated and traffic dropped via automated firewall policy."
    elif row['anomaly_score'] == -1 or row['threat_intel'] != "Clean / Unlisted":
        if row['failed_login_count'] > 15:
            return "🔴 CRITICAL: Brute-Force Attack Pattern. Action: Block IP at Edge Firewall & Force Password Reset."
        else:
            return "🟠 HIGH: Anomalous Data Exfiltration / Reconnaissance. Action: Rate-Limit & Route to Sandbox."
    else:
        return "🟢 NORMAL: Traffic compliant with baseline policies."

analyzed_df['agent_recommendation'] = analyzed_df.apply(soc_agent_recommendation, axis=1)

# --- UI METRICS BAR ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Telemetry Logs", len(raw_df))
col2.metric("Active Monitored IPs", len(analyzed_df))
col3.metric("AI Flagged Anomalies", int((analyzed_df['anomaly_score'] == -1).sum()))
col4.metric("Mitigated Threats", len(st.session_state.mitigated_ips))

st.divider()

# --- MAIN DASHBOARD LAYOUT ---
left_col, right_col = st.columns([1.2, 1])

with left_col:
    st.subheader("🔍 Aggregated IP Behavior & Threat Intel")
    st.dataframe(analyzed_df[['ip_address', 'total_requests', 'failed_login_count', 'threat_intel', 'anomaly_score']], use_container_width=True)

with right_col:
    st.subheader("🤖 Autonomous SOC Incident Response Console")
    threats_only = analyzed_df[(analyzed_df['anomaly_score'] == -1) | (analyzed_df['threat_intel'] != "Clean / Unlisted")]
    
    for _, row in threats_only.iterrows():
        ip = row['ip_address']
        is_mitigated = ip in st.session_state.mitigated_ips
        
        with st.container():
            st.markdown(f"**IP Target:** `{ip}` | **Intel:** {row['threat_intel']}")
            st.write(row['agent_recommendation'])
            
            if not is_mitigated:
                if st.button(f"⚡ Execute Playbook: Isolate {ip}", key=f"btn_{ip}"):
                    st.session_state.mitigated_ips.append(ip)
                    st.rerun()
            else:
                st.success(f"Successfully remediated {ip}")
            st.markdown("---")

st.divider()

# --- ADVANCED ANALYTICS SECTION ---
bottom_left, bottom_right = st.columns(2)

with bottom_left:
    st.subheader("📊 Traffic Anomaly Cluster Map")
    st.scatter_chart(
        analyzed_df, 
        x='total_requests', 
        y='failed_login_count',
        color='anomaly_score'
    )

with bottom_right:
    st.subheader("📋 Compliance & Incident Export")
    st.markdown("Generate a certified audit log report of all detected anomalies and automated response playbooks for SecOps compliance.")
    
    csv_data = analyzed_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Download Certified Security Audit Report (CSV)",
        data=csv_data,
        file_name=f"soc_incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime='text/csv'
    )

st.divider()

# --- GOOGLE AI STUDIO GEMINI INTEGRATION ---
st.subheader("🤖 Gemini AI Security Operations Analyst")
st.markdown("Powered by Google AI Studio, this module synthesizes live telemetry anomalies into an executive incident report.")

gemini_api_key = st.text_input("Enter your Google AI Studio API Key", type="password")

if gemini_api_key:
    if st.button("Generate AI Incident Briefing"):
        with st.spinner("Consulting Gemini Security Model..."):
            try:
                client = genai.Client(api_key=gemini_api_key)
                threats_summary = analyzed_df[analyzed_df['anomaly_score'] == -1][['ip_address', 'total_requests', 'failed_login_count', 'threat_intel']].to_string()
                
                prompt = f"""
                You are an elite Cloud Security Architect and Incident Commander. 
                Analyze the following anomalous IP behaviors detected by our SIEM telemetry pipeline:
                
                {threats_summary}
                
                Provide a professional 3-bullet point executive summary detailing the potential attack vectors (e.g., brute force, botnets) and recommended containment strategy.
                """
                
                response = client.models.generate_content(
                    model='gemini-3.8-flash',
                    contents=prompt,
                    )
                
                st.success("Analysis Complete")
                st.markdown(response.text)
                
            except Exception as e:
                st.error(f"Error connecting to Gemini API: {e}")
else:
    st.info("💡 Enter your Google AI Studio API key above to unlock live Gemini-powered threat briefings.")