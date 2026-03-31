# EchoTrace-AutoShield 🛡️

**A Hybrid AI-Driven Cybersecurity Framework** that uses Random Forest + LSTM models to predict and prevent cyberattacks in real time.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange?logo=tensorflow)
![scikit-learn](https://img.shields.io/badge/scikit--learn-Latest-yellow?logo=scikit-learn)

---

## 🎯 Overview

EchoTrace-AutoShield is a **dual-web architecture** cybersecurity platform featuring:

- **Command Center** (Port 8000) — Real-time AI monitoring dashboard that displays threat detection, intrusion feeds, and blocked sessions
- **Target Application** (Port 8080) — A simulated enterprise portal ("SecureNet Portal") protected by the AI engine
- **Hybrid ML Engine** — Combines Random Forest (60%) + LSTM (40%) for robust threat classification
- **Network Sniffer** — Live packet capture and analysis using Scapy

## 🏗️ Architecture

```
┌─────────────────────┐     ┌──────────────────────────┐
│  Target App (8080)  │────▶│  Command Center API (8000)│
│  SecureNet Portal   │     │  EchoTrace-AutoShield     │
│  - Login            │     │  - /analyze (ML inference) │
│  - Dashboard        │     │  - /trigger (attack sim)   │
│  - Attack Sim       │     │  - /alerts (real-time)     │
└─────────────────────┘     └────────────┬─────────────┘
                                         │
┌─────────────────────┐                  │
│  Network Sniffer    │──────────────────┘
│  sniffer.py         │  (live packet features)
└─────────────────────┘
                            ┌──────────────────────┐
                            │   Hybrid AI Model     │
                            │  Random Forest + LSTM │
                            │  5 Classes: Normal,   │
                            │  DoS, Probe, R2L, U2R │
                            └──────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/EchoTrace-AutoShield.git
cd EchoTrace-AutoShield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Train the AI Models

```bash
python main.py --train
```

### Launch the System

```bash
# Terminal 1 — Command Center (AI Dashboard)
python api.py
# → http://localhost:8000

# Terminal 2 — Target Application
python target_app.py
# → http://localhost:8080

# Terminal 3 (Optional) — Network Sniffer
python sniffer.py
```

### Demo Credentials (Target App)

| Username  | Password   |
|-----------|-----------|
| admin     | admin123  |
| analyst   | cyber456  |
| demo      | demo      |

## 📂 Project Structure

```
EchoTrace-AutoShield/
├── api.py                  # FastAPI Command Center (port 8000)
├── target_app.py           # Target web app (port 8080)
├── hybrid_model.py         # RF + LSTM hybrid model
├── sniffer.py              # Live packet sniffer
├── main.py                 # CLI (train / predict)
├── requirements.txt        # Dependencies
├── data/
│   └── sample_data.csv     # Training data
├── models/
│   ├── rf_model.pkl        # Trained Random Forest
│   ├── lstm_model.keras    # Trained LSTM
│   └── scaler.pkl          # StandardScaler
├── static/                 # Command Center frontend
│   ├── index.html
│   ├── styles.css
│   └── script.js
└── static_target/          # Target App frontend
    ├── login.html
    ├── dashboard.html
    ├── blocked.html
    └── target_styles.css
```

## 🧠 How the AI Works

1. **Random Forest** — Classifies individual traffic samples using 4 network features
2. **LSTM** — Analyzes temporal sequences (sliding window of 5 packets) for pattern-based detection
3. **Hybrid Prediction** — Weighted ensemble: `0.6 × RF + 0.4 × LSTM`
4. **Attack Classes**: Normal, DoS, Probe, R2L (Remote to Local), U2R (User to Root)

## 🔒 Attack Simulation

The Target App includes a **Penetration Test Panel** with simulated attacks:
- 💥 **DoS Attack** — Flood the server with traffic
- 🔍 **Probe Attack** — Scan for vulnerabilities
- 📡 **R2L Attack** — Remote to local intrusion
- 👑 **U2R Attack** — Privilege escalation

When an attack is triggered, the AI engine detects it in real-time and:
1. Logs the alert on the Command Center dashboard
2. Terminates the attacker's session
3. Blocks further access

## 📜 License

This project is for **educational and research purposes**.

## 🤝 Contributors

Built as part of a cybersecurity research initiative.
