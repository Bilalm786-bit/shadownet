"""Quick API test script"""
import urllib.request
import json

BASE = "http://localhost:8000"

def api(method, path, data=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(f"{BASE}{path}", body, headers, method=method)
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

# 1. Health check
s, d = api("GET", "/health")
print(f"[Health] {s}: {d}")

# 2. Register
s, d = api("POST", "/api/v1/auth/register", {
    "email": "test@shadownet.io", "username": "analyst", "password": "Test12345"
})
print(f"[Register] {s}: {d.get('username', d.get('detail', 'ok'))}")

# 3. Login
s, d = api("POST", "/api/v1/auth/login", {
    "username": "analyst", "password": "Test12345"
})
token = d.get("access_token", "")
print(f"[Login] {s}: token={'YES' if token else 'NO'}")

# 4. List modules
s, d = api("GET", "/api/v1/osint/modules", token=token)
print(f"[Modules] {s}: {len(d)} modules loaded")
for m in d:
    print(f"  - {m['name']}")

# 5. Dashboard stats
s, d = api("GET", "/api/v1/dashboard/stats", token=token)
print(f"[Dashboard] {s}: cases={d.get('cases',{}).get('total',0)}, targets={d.get('targets',0)}")

# 6. Create case
s, d = api("POST", "/api/v1/cases/", {"name": "Test Investigation", "description": "Testing all modules", "priority": 1}, token=token)
case_id = d.get("id", "")
print(f"[Create Case] {s}: id={case_id}")

# 7. Add target
s, d = api("POST", f"/api/v1/cases/{case_id}/targets/", {
    "target_type": "domain", "value": "example.com", "label": "Test Domain"
}, token=token)
target_id = d.get("id", "")
print(f"[Add Target] {s}: id={target_id}")

# 8. Launch scan
s, d = api("POST", "/api/v1/osint/scan", {
    "target_id": target_id, "modules": ["all"]
}, token=token)
print(f"[Launch Scan] {s}: {d.get('message','')}, modules={d.get('modules',[])}")

# 9. List alerts
s, d = api("GET", "/api/v1/alerts/", token=token)
print(f"[Alerts] {s}: {len(d)} alerts")

# 10. Darkweb search
s, d = api("GET", "/api/v1/darkweb/search?q=test", token=token)
print(f"[Darkweb] {s}: {d.get('count',0)} results")

print("\n=== ALL API TESTS COMPLETE ===")
