from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from hybrid_model import load_saved, hybrid_predict, generate_attack_traffic, action_map
import firewall
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
rf, lstm, scaler, action_model = None, None, None, None
latest_alerts = []
blocked_sessions = {}  # session_token -> block info
blocked_users = {}     # username -> {blocked_at, expires_at, reason, ...}
blocked_ips = {}       # ip_address -> {blocked_at, expires_at, reason, ...}
BLOCK_DURATION = 300   # 5 minutes default block duration (seconds)
firewall_enabled = False

@app.on_event("startup")
async def startup_event():
    global rf, lstm, scaler, action_model
    try:
        rf, lstm, scaler, action_model = load_saved()
        print("All models loaded successfully.")
        if action_model:
            print("  Action Decision Network: LOADED (AI-driven actions)")
        else:
            print("  Action Decision Network: NOT FOUND (using fallback)")
        
        # Check firewall privileges
        global firewall_enabled
        firewall_enabled = firewall.check_admin()
        if firewall_enabled:
            print("  Windows Firewall: READY (admin privileges detected)")
        else:
            print("  Windows Firewall: DISABLED (no admin privileges - run as Administrator to enable)")
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
    """
    Full AI pipeline — zero if-else decisions:
      1. Generate realistic attack traffic features
      2. RF + LSTM classify the attack type
      3. Action Decision Network decides PASS/ALERT/BLOCK
    
    Every decision is made by a trained model.
    """
    global rf, lstm, scaler, action_model
    
    if rf is None or lstm is None or scaler is None:
        return {"error": "Models not loaded. Train models first."}
    
    # Generate realistic attack traffic
    sample, sequence = generate_attack_traffic(payload.attack_type)
    
    # Full AI pipeline: classify attack + decide action
    try:
        label, confidence, action, action_conf, rf_probs, lstm_probs, action_probs = hybrid_predict(
            rf, lstm, scaler, sample, sequence, action_model
        )
    except Exception as e:
        return {"error": f"AI prediction failed: {str(e)}"}
    
    alert_info = {
        "label": label,
        "confidence": round(float(confidence), 4),
        "action": action,
        "action_confidence": round(float(action_conf), 4),
        "timestamp": time.time(),
        "ip_address": payload.ip_address,
        "username": payload.username,
        "session_token": payload.session_token,
        "simulated_attack_type": payload.attack_type,
        "ai_driven": True,
        "action_ai_driven": action_model is not None,
        "model_details": {
            "rf_probabilities": {
                "Normal": round(rf_probs[0], 4),
                "DoS": round(rf_probs[1], 4),
                "Probe": round(rf_probs[2], 4),
                "R2L": round(rf_probs[3], 4),
                "U2R": round(rf_probs[4], 4),
            },
            "lstm_probabilities": {
                "Normal": round(lstm_probs[0], 4),
                "DoS": round(lstm_probs[1], 4),
                "Probe": round(lstm_probs[2], 4),
                "R2L": round(lstm_probs[3], 4),
                "U2R": round(lstm_probs[4], 4),
            },
            "action_probabilities": {
                "PASS": round(action_probs[0], 4),
                "ALERT": round(action_probs[1], 4),
                "BLOCK": round(action_probs[2], 4),
            },
            "ensemble_weight": "RF 60% + LSTM 40%",
            "input_features": {
                "sample": [round(float(x), 4) for x in sample],
                "sequence_shape": list(sequence.shape),
            }
        }
    }
    
    latest_alerts.insert(0, alert_info)
    if len(latest_alerts) > 100:
        latest_alerts.pop()

    # Block session, user, and IP if AI decided BLOCK
    if action == "BLOCK":
        now = time.time()
        block_info = {
            "blocked_at": now,
            "expires_at": now + BLOCK_DURATION,
            "reason": label,
            "username": payload.username,
            "ip_address": payload.ip_address,
            "confidence": round(float(confidence), 4),
            "action_confidence": round(float(action_conf), 4),
            "ai_driven": True
        }
        blocked_sessions[payload.session_token] = block_info
        blocked_users[payload.username] = block_info
        blocked_ips[payload.ip_address] = block_info
        
        # Real Windows Firewall blocking
        if firewall_enabled:
            fw_result = firewall.block_ip(
                ip_address=payload.ip_address,
                reason=f"AI detected {label}",
                username=payload.username,
                attack_type=label
            )
            alert_info["firewall"] = fw_result
            if fw_result["success"]:
                print(f"  FIREWALL: Blocked IP {payload.ip_address} ({label})")
        else:
            alert_info["firewall"] = {"success": False, "message": "Firewall disabled (no admin privileges)"}

    return {"status": "success", "alert": alert_info}

@app.get("/check_blocked/{session_token}")
def check_blocked(session_token: str):
    if session_token in blocked_sessions:
        info = blocked_sessions[session_token]
        if time.time() < info["expires_at"]:
            remaining = int(info["expires_at"] - time.time())
            return {"blocked": True, "reason": info["reason"],
                    "blocked_at": info["blocked_at"], "remaining_seconds": remaining}
        else:
            del blocked_sessions[session_token]
    return {"blocked": False}

@app.get("/check_user_blocked")
def check_user_blocked(username: str = "", ip: str = ""):
    """Check if a username or IP is currently blocked. Used by target_app before login."""
    now = time.time()
    
    # Check username block
    if username and username in blocked_users:
        info = blocked_users[username]
        if now < info["expires_at"]:
            remaining = int(info["expires_at"] - now)
            return {
                "blocked": True,
                "reason": info["reason"],
                "blocked_by": "username",
                "remaining_seconds": remaining,
                "message": f"User '{username}' is blocked for {remaining}s due to {info['reason']} attack"
            }
        else:
            del blocked_users[username]
    
    # Check IP block
    if ip and ip in blocked_ips:
        info = blocked_ips[ip]
        if now < info["expires_at"]:
            remaining = int(info["expires_at"] - now)
            return {
                "blocked": True,
                "reason": info["reason"],
                "blocked_by": "ip",
                "remaining_seconds": remaining,
                "message": f"IP '{ip}' is blocked for {remaining}s due to {info['reason']} attack"
            }
        else:
            del blocked_ips[ip]
    
    return {"blocked": False}

@app.get("/alerts")
def get_alerts():
    return {"alerts": latest_alerts, "blocked_sessions": len(blocked_sessions)}

@app.get("/blocked_list")
def get_blocked_list():
    return {"blocked": blocked_sessions}

# ===== Firewall Management Endpoints =====

@app.get("/firewall/status")
def firewall_status():
    """Get Windows Firewall integration status."""
    return firewall.get_status()

@app.post("/firewall/unblock/{ip_address}")
def firewall_unblock(ip_address: str):
    """Remove a firewall block rule for an IP."""
    result = firewall.unblock_ip(ip_address)
    # Also remove from blocked sessions
    to_remove = [k for k, v in blocked_sessions.items() if v.get("ip_address") == ip_address]
    for key in to_remove:
        del blocked_sessions[key]
    result["sessions_unblocked"] = len(to_remove)
    return result

@app.post("/firewall/unblock_all")
def firewall_unblock_all():
    """Remove ALL firewall block rules and clear blocked sessions."""
    fw_result = firewall.unblock_all()
    sessions_cleared = len(blocked_sessions)
    blocked_sessions.clear()
    fw_result["sessions_cleared"] = sessions_cleared
    return fw_result

@app.post("/analyze")
def analyze_traffic(payload: TrafficPayload):
    """Analyze real traffic from the network sniffer using the full AI pipeline."""
    global rf, lstm, scaler, action_model
    if rf is None or lstm is None or scaler is None:
        return {"error": "Models not loaded. Train models first."}

    sample_np = np.array(payload.sample)
    sequence_np = np.array(payload.sequence)

    try:
        label, confidence, action, action_conf, rf_probs, lstm_probs, action_probs = hybrid_predict(
            rf, lstm, scaler, sample_np, sequence_np, action_model
        )

        alert_info = {
            "label": label,
            "confidence": round(float(confidence), 4),
            "action": action,
            "action_confidence": round(float(action_conf), 4),
            "timestamp": time.time(),
            "ip_address": "auto-detected",
            "username": "sniffer",
            "session_token": "N/A",
            "ai_driven": True,
            "action_ai_driven": action_model is not None,
            "model_details": {
                "rf_probabilities": {k: round(v, 4) for k, v in zip(
                    ["Normal","DoS","Probe","R2L","U2R"], rf_probs)},
                "lstm_probabilities": {k: round(v, 4) for k, v in zip(
                    ["Normal","DoS","Probe","R2L","U2R"], lstm_probs)},
                "action_probabilities": {
                    "PASS": round(action_probs[0], 4),
                    "ALERT": round(action_probs[1], 4),
                    "BLOCK": round(action_probs[2], 4),
                },
            }
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
