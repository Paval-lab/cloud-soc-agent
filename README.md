# 🛡️ Autonomous Cloud SOC & Intrusion Detection Agent

A real-time security operations center (SOC) dashboard and automated incident response agent built with Python, Streamlit, and Scikit-learn.

## 🚀 Features
- **Simulated Cloud Telemetry Ingestion:** Generates and processes high-volume access logs with IP addresses, HTTP status codes, and payload sizes.
- **Unsupervised Anomaly Detection:** Utilizes an `IsolationForest` machine learning model to isolate high-risk behavior patterns (brute-force attacks, data exfiltration) from normal traffic.
- **Autonomous SOC Agent Playbook Logic:** Automatically evaluates threat severity and issues real-time mitigation recommendations (e.g., firewall block rules, account lockouts, rate limiting).
- **Interactive UI Dashboard:** Built using Streamlit for live metrics tracking, anomaly cluster mapping, and security alert feeds.

## 🛠️ Tech Stack
- **Language:** Python
- **Libraries:** Pandas, NumPy, Scikit-Learn
- **Dashboard UI:** Streamlit

## ⚙️ Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/soc-intrusion-agent.git](https://github.com/YOUR_USERNAME/soc-intrusion-agent.git)
   cd soc-intrusion-agent