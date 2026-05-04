"""Test darkweb backend endpoints — updated for v2.0 API"""
import urllib.request, json, sys

BASE = 'http://localhost:8000'

# Login
try:
    req = urllib.request.Request(f'{BASE}/api/v1/auth/login',
        json.dumps({'username':'analyst','password':'Test12345'}).encode(),
        {'Content-Type':'application/json'})
    r = urllib.request.urlopen(req)
    token = json.loads(r.read())['access_token']
    print(f"[OK] Authenticated")
except Exception as e:
    print(f"[FAIL] Login failed: {e}")
    sys.exit(1)

def api_get(path):
    req = urllib.request.Request(f'{BASE}{path}')
    req.add_header('Authorization', f'Bearer {token}')
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

# 1. Test /darkweb/status
print("\n─── Dark Web Status ───")
data = api_get('/api/v1/darkweb/status')
print(f"  Engine: {data.get('engine')}")
print(f"  Tor: {data.get('tor', {}).get('connected', 'N/A')}")
print(f"  Modules: {data.get('modules_loaded', [])}")
print(f"  Sources: {len(data.get('sources', []))}")

# 2. Test /darkweb/search
for query in ['bitcoin', 'leaked database']:
    print(f"\n─── Search: '{query}' ───")
    data = api_get(f'/api/v1/darkweb/search?q={query.replace(" ","%20")}&limit=10')
    print(f"  Count: {data.get('count', 0)}")
    print(f"  Sources: {data.get('sources_checked', [])}")
    risk = data.get('risk_assessment', {})
    print(f"  Risk: {risk.get('risk_score', 0)} ({risk.get('risk_level', 'N/A')})")
    print(f"  IOCs: {risk.get('total_iocs', 0)}")
    if data.get('errors'):
        print(f"  Errors: {data['errors']}")
    for item in data.get('results', [])[:3]:
        sev = item.get('severity', 'info')
        print(f"  [{sev.upper()}] {item.get('title', 'No title')[:60]}")
        print(f"    Source: {item.get('source')} | Score: {item.get('threat_score', 0)}")

# 3. Test /darkweb/breaches
print(f"\n─── Breaches: 'adobe' ───")
data = api_get('/api/v1/darkweb/breaches?q=adobe')
print(f"  Count: {data.get('count', 0)}")
for item in data.get('results', [])[:3]:
    print(f"  - {item.get('title', '')[:60]}")

# 4. Test /darkweb/dorks
print(f"\n─── Dorks: 'example.com' ───")
data = api_get('/api/v1/darkweb/dorks?q=example.com')
print(f"  Count: {data.get('count', 0)}")

# 5. Test /darkweb/scan (module-based)
print(f"\n─── Scan Module: 'bitcoin' ───")
data = api_get('/api/v1/darkweb/scan?q=bitcoin')
print(f"  Count: {data.get('count', 0)}")
print(f"  Summary: {data.get('summary', 'N/A')}")

print("\n[DONE] All dark web endpoints tested.")
