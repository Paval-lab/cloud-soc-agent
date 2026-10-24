import streamlit as st

st.set_page_config(page_title="Multi-App Portfolio Portal", layout="wide")

# Set your access password here
PORTAL_PASSWORD = "admin"

# Initialize session state for authentication
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

def login_form():
    st.title("🔐 Enterprise Web Portal")
    st.markdown("Please enter the password to unlock the application suite.")
    
    with st.form("login_form"):
        password_input = st.text_input("Password", type="password")
        submit_button = st.form_submit_button("Authenticate")
        
        if submit_button:
            if password_input == PORTAL_PASSWORD:
                st.session_state["authenticated"] = True
                st.success("Access Granted! Select a tool from the sidebar navigation.")
                st.rerun()
            else:
                st.error("Incorrect password. Please try again.")

# Authentication Check
if not st.session_state["authenticated"]:
    login_form()
    st.stop()  # Stops execution here if not authenticated

# --- HOME PAGE CONTENT AFTER LOGIN ---
st.title("🌐 Multi-Tool Security & AI Portal")
st.success("Authenticated Session Active")

st.markdown("""
Welcome to the unified application hub! Use the sidebar menu on the left to navigate between different tools:

1. **🛡️ Cloud SOC Intrusion Detection Agent:** Real-time log telemetry processing, unsupervised ML anomaly detection (`IsolationForest`), and interactive incident response playbooks.
2. **📊 Data Analytics & AI Predictor:** Secondary analytics tool for exploratory data analysis and insight generation.
""")

col1, col2 = st.columns(2)
with col1:
    if st.button("🔒 Lock Portal / Log Out"):
        st.session_state["authenticated"] = False
        st.rerun()
    