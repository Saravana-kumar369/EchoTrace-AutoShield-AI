from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests

app = FastAPI(title="SecureNet Portal")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static_target"), name="static")

AI_API = "http://127.0.0.1:8000"

# Demo user credentials
USERS = {
    "admin": "admin123",
    "analyst": "cyber456",
    "demo": "demo"
}

@app.get("/", response_class=HTMLResponse)
def login_page():
    with open("static_target/login.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_page():
    with open("static_target/dashboard.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.get("/blocked", response_class=HTMLResponse)
def blocked_page():
    with open("static_target/blocked.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.post("/auth")
def authenticate(request_body: dict, request: Request):
    username = request_body.get("username", "")
    password = request_body.get("password", "")
    
    # Check if this username or IP is blocked by the AI engine
    client_ip = request.client.host if request.client else "unknown"
    try:
        check = requests.get(
            f"{AI_API}/check_user_blocked",
            params={"username": username, "ip": client_ip},
            timeout=3
        )
        if check.status_code == 200:
            data = check.json()
            if data.get("blocked"):
                remaining = data.get("remaining_seconds", 0)
                mins = remaining // 60
                secs = remaining % 60
                return {
                    "success": False,
                    "blocked": True,
                    "remaining_seconds": remaining,
                    "message": f"Access denied. Blocked for {mins}m {secs}s due to {data.get('reason', 'threat')} detection."
                }
    except Exception:
        pass  # If AI API is down, allow login (graceful degradation)
    
    # Normal authentication
    if username in USERS and USERS[username] == password:
        import uuid
        token = str(uuid.uuid4())
        return {"success": True, "token": token, "username": username}
    return {"success": False, "message": "Invalid credentials"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
