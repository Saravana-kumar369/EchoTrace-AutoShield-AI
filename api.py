from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from hybrid_model import load_saved, hybrid_predict
import numpy as np
import uvicorn
import time
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="EchoTrace-AutoShield Command Center")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Global state
rf, lstm, scaler = None, None, None
latest_alerts = []
blocked_sessions = {}  # session_token -> block info

@app.on_event("startup")
async def startup_event():
    global rf, lstm, scaler
    try:
        rf, lstm, scaler = load_saved()
        print("Models loaded successfully.")
    except Exception as e:
        print(f"Error loading models: {e}. Please run 'python main.py --train' first.")

class TrafficPayload(BaseModel):
    sample: List[float]
    sequence: List[List[float]]

class AttackPayload(BaseModel):
    attack_type: str
    session_token: str
    username: str
    ip_address: str

@app.get("/", response_class=HTMLResponse)
def read_root():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.post("/trigger")
def trigger_attack(payload: AttackPayload):
    alert_info = {
        "label": payload.attack_type,
        "confidence": 0.99,
        "action": "BLOCK",
        "timestamp": time.time(),
        "ip_address": payload.ip_address,
        "username": payload.username,
        "session_token": payload.session_token,
        "simulated": True
    }
    latest_alerts.insert(0, alert_info)
    if len(latest_alerts) > 100:
        latest_alerts.pop()

    # Block this session
    blocked_sessions[payload.session_token] = {
        "blocked_at": time.time(),
        "reason": payload.attack_type,
        "username": payload.username,
        "ip_address": payload.ip_address
    }

    return {"status": "success", "alert": alert_info}

@app.get("/check_blocked/{session_token}")
def check_blocked(session_token: str):
    if session_token in blocked_sessions:
        return {
            "blocked": True,
            "reason": blocked_sessions[session_token]["reason"],
            "blocked_at": blocked_sessions[session_token]["blocked_at"]
        }
    return {"blocked": False}

@app.get("/alerts")
def get_alerts():
    return {"alerts": latest_alerts, "blocked_sessions": len(blocked_sessions)}

@app.get("/blocked_list")
def get_blocked_list():
    return {"blocked": blocked_sessions}

@app.post("/analyze")
def analyze_traffic(payload: TrafficPayload):
    global rf, lstm, scaler
    if rf is None or lstm is None or scaler is None:
        return {"error": "Models not loaded. Train models first."}

    sample_np = np.array(payload.sample)
    sequence_np = np.array(payload.sequence)

    try:
        label, confidence = hybrid_predict(rf, lstm, scaler, sample_np, sequence_np)

        action = "PASS"
        if label != "Normal" and confidence >= 0.8:
            action = "BLOCK"
        elif label != "Normal":
            action = "ALERT"

        alert_info = {
            "label": label,
            "confidence": float(confidence),
            "action": action,
            "timestamp": time.time(),
            "ip_address": "auto-detected",
            "username": "sniffer",
            "session_token": "N/A",
            "simulated": False
        }

        if action != "PASS":
            latest_alerts.insert(0, alert_info)
            if len(latest_alerts) > 100:
                latest_alerts.pop()

        return alert_info
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
