from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="SecureNet Portal")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static_target"), name="static")

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
def authenticate(request_body: dict):
    username = request_body.get("username", "")
    password = request_body.get("password", "")
    if username in USERS and USERS[username] == password:
        import uuid
        token = str(uuid.uuid4())
        return {"success": True, "token": token, "username": username}
    return {"success": False, "message": "Invalid credentials"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
