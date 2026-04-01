# EchoTrace-AutoShield

**AI-Driven Cybersecurity Framework** — Hybrid Random Forest + LSTM + Action Decision Network for real-time intrusion detection and automated threat response.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange?logo=tensorflow)
![scikit-learn](https://img.shields.io/badge/scikit--learn-Latest-yellow?logo=scikit-learn)

---

## Overview

EchoTrace-AutoShield is a **fully AI-driven** cybersecurity platform with 3 trained neural networks:

| Model | Role | Accuracy |
|---|---|---|
| **Random Forest** | Attack classification (5 classes) | ~99% |
| **LSTM** | Temporal attack pattern detection | 100% |
| **Action Decision Network** | Decides PASS/ALERT/BLOCK | ~97% |

**No hardcoded if-else thresholds** — every detection and action decision is made by trained AI models.

### Key Features
- **NSL-KDD Dataset** — Trained on 125,973 real network traffic samples with 122 features
- **3-Model Pipeline** — RF + LSTM → Action Network (all AI-driven)
- **Windows Firewall Integration** — Real OS-level IP blocking via `netsh advfirewall`
- **Dual-Web Architecture** — Command Center + Target App
- **Real-Time Dashboard** — Live threat visualization with per-model probability bars

## Architecture

```
┌─────────────────────┐     ┌──────────────────────────────┐
│  Target App (8080)  │────▶│  Command Center API (8000)    │
│  SecureNet Portal   │     │  EchoTrace-AutoShield         │
│  - Login            │     │  - /trigger (attack sim)      │
│  - Dashboard        │     │  - /analyze (live inference)  │
│  - Attack Sim Panel │     │  - /alerts (real-time feed)   │
└─────────────────────┘     │  - /firewall/* (fw mgmt)     │
                            └──────────────┬───────────────┘
                                           │
┌─────────────────────┐                    ▼
│  Network Sniffer    │     ┌──────────────────────────────┐
│  sniffer.py         │────▶│   3-Model AI Pipeline         │
└─────────────────────┘     │                              │
                            │  1. Random Forest (60%)       │
                            │  2. LSTM Network (40%)        │
                            │  3. Action Decision Network   │
                            │                              │
                            │  Input: 122 NSL-KDD features  │
                            │  Output: Attack type + Action  │
                            └──────────────┬───────────────┘
                                           │
                            ┌──────────────▼───────────────┐
                            │  Windows Firewall (netsh)     │
                            │  Real IP blocking when AI     │
                            │  decides BLOCK                │
                            └──────────────────────────────┘
```

## Quick Start

### Prerequisites
- Python 3.10+
- Windows (for firewall integration)

### Installation

```bash
git clone https://github.com/Saravana-kumar369/EchoTrace-AutoShield.git
cd EchoTrace-AutoShield

python -m venv venv
venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

### Prepare Dataset & Train Models

```bash
# Step 1: Preprocess NSL-KDD dataset
python preprocess_nslkdd.py

# Step 2: Train all 3 AI models
python main.py --train

# Step 3: Test predictions
python main.py --predict
```

### Launch the System

```bash
# Terminal 1 — Command Center (run as Administrator for firewall)
python api.py
# → http://localhost:8000

# Terminal 2 — Target Application
python target_app.py
# → http://localhost:8080

# Terminal 3 (Optional) — Network Sniffer
python sniffer.py
```

### Demo Credentials

| Username | Password |
|----------|----------|
| admin | admin123 |
| analyst | cyber456 |
| demo | demo |

## Project Structure

```
EchoTrace-AutoShield/
├── api.py                  # Command Center API (port 8000)
├── target_app.py           # Target web app (port 8080)
├── hybrid_model.py         # 3-model AI pipeline (RF + LSTM + Action)
├── firewall.py             # Windows Firewall integration
├── sniffer.py              # Live packet sniffer
├── main.py                 # CLI (--train / --predict)
├── preprocess_nslkdd.py    # NSL-KDD preprocessing
├── generate_dataset.py     # Synthetic dataset generator (legacy)
├── requirements.txt        # Dependencies
├── data/
│   ├── KDDTrain+.txt       # NSL-KDD training data (125K samples)
│   ├── KDDTest+.txt        # NSL-KDD test data (22K samples)
│   ├── nsl_kdd_train.csv   # Preprocessed training data
│   ├── sample_data.csv     # Active training data
│   └── feature_stats.npz   # Per-class feature distributions
├── models/
│   ├── rf_model.pkl        # Trained Random Forest
│   ├── lstm_model.keras    # Trained LSTM
│   ├── action_model.keras  # Trained Action Decision Network
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

## How the AI Works

### Full Pipeline (Zero If-Else)

1. **Traffic arrives** → 122 NSL-KDD features extracted
2. **Random Forest (60%)** → Classifies attack type from features
3. **LSTM (40%)** → Detects temporal attack patterns from 5-packet sequences
4. **Hybrid Ensemble** → `0.6 × RF + 0.4 × LSTM` probabilities combined
5. **Action Decision Network** → Takes 17 inputs (RF probs + LSTM probs + combined + class + confidence) → Outputs PASS/ALERT/BLOCK
6. **Firewall** → If BLOCK, creates real Windows Firewall rule via `netsh`

### Attack Classes (NSL-KDD)

| Class | Examples | Typical Action |
|---|---|---|
| **Normal** | Regular traffic | PASS |
| **DoS** | Neptune, Smurf, Back, Teardrop | BLOCK |
| **Probe** | Portsweep, IPsweep, Nmap, Satan | BLOCK/ALERT |
| **R2L** | Guess_passwd, FTP_write, Warezclient | BLOCK |
| **U2R** | Buffer_overflow, Rootkit, Loadmodule | BLOCK |

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/trigger` | POST | Simulate an attack (AI classifies + decides action) |
| `/analyze` | POST | Analyze real traffic features |
| `/alerts` | GET | Get all alerts |
| `/blocked_list` | GET | Get blocked sessions |
| `/firewall/status` | GET | Check firewall integration status |
| `/firewall/unblock/{ip}` | POST | Unblock a specific IP |
| `/firewall/unblock_all` | POST | Remove all firewall blocks |

## License

This project is for **educational and research purposes**.

## Contributors

Built as part of a cybersecurity research initiative.
