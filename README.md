# ⬡ ShadowNet — Professional OSINT Intelligence Platform

A full-stack OSINT (Open Source Intelligence) platform for reconnaissance, dark web monitoring, and threat analysis.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend — React + TypeScript (Vite)                       │
│  Dashboard │ Investigation Hub │ Graph │ Dark Web │ Feed    │
├─────────────────────────────────────────────────────────────┤
│  API Gateway — FastAPI │ JWT Auth │ Rate Limiting │ WS      │
├──────────────┬──────────────────┬────────────────────────────┤
│ OSINT Modules│  Dark Web Engine │  Core Services             │
│ • Identity   │  • Tor Router    │  • Task Queue (Celery)     │
│ • Network    │  • Onion Crawler │  • AI Analyst (GPT-5.5)    │
│ • SOCMINT    │  • Marketplace   │  • Alert Engine            │
│ • Breach     │  • Ransomware    │  • Report Generator        │
│ • Document   │  • Threat Actor  │  • OpSec Manager           │
├──────────────┴──────────────────┴────────────────────────────┤
│  Data Layer — PostgreSQL │ Neo4j │ Elasticsearch │ MinIO     │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure — Docker/K8s │ Vault │ Audit Log │ Grafana   │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+
- Python 3.11+

### 1. Start Infrastructure Services
```bash
docker-compose up -d postgres redis neo4j elasticsearch minio
```

### 2. Start Backend API
```bash
cd backend
pip install -r requirements.txt
cp ../.env.example ../.env
uvicorn app.main:app --reload --port 8000
```

### 3. Start Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```

### 4. Open ShadowNet
- **Dashboard**: http://localhost:5173
- **API Docs**: http://localhost:8000/docs
- **Neo4j Browser**: http://localhost:7474
- **MinIO Console**: http://localhost:9001

## 📦 OSINT Modules (All Free, No API Keys)

### Identity / SOCMINT / Breach / Darkweb
| Module | Category | Capabilities |
|--------|----------|-------------|
| `identity.username_lookup` | Identity | Check 300+ platforms |
| `identity.email_validator` | Identity | MX, SMTP, pattern validation |
| `identity.phone_lookup` | Identity | Phone number parsing & OSINT |
| `document.metadata_extractor` | Document | EXIF, PDF, DOCX metadata |
| `socmint.github_recon` | SOCMINT | GitHub profile intelligence |
| `breach.google_dorker` | Breach | Google dorking for leaks |
| `darkweb.onion_search` | Dark Web | Ahmia.fi clearnet search |
| `threat.intel_lookup` | Threat Intel | Cross-reference any IOC against 10 live feeds |

### Network Reconnaissance
| Module | Capabilities |
|--------|-------------|
| `network.dns_recon` | DNS record enumeration (async) |
| `network.whois_lookup` | WHOIS registration data |
| `network.ip_geolocation` | IP geolocation & ASN |
| `network.subdomain_enum` | Subdomain discovery via crt.sh + bruteforce |
| `network.wayback_machine` | Historical snapshots & URLs |
| `network.port_scanner` | Async TCP port scanner with banners |
| `network.ssl_analyzer` | TLS cert SANs, chain, expiry, cipher |
| `network.tech_detector` | CMS / WAF / framework / JS-lib fingerprint |
| `network.web_crawler` | Crawl emails, phones, social links, sensitive paths |
| `network.shodan_free` | Free Shodan host facets |
| `recon.asn_lookup` | ASN, BGP prefix, network-operator org via BGPView |
| `recon.cdn_detector` | CDN / cloud / proxy detection (headers + CNAME + IP range) |
| `recon.reverse_ip` | Co-hosted domains via HackerTarget |
| `recon.http_fingerprint` | Status, redirect chain, body hash, favicon hash |
| `recon.robots_sitemap` | Parse robots.txt + sitemap.xml for hidden paths |
| `recon.dns_advanced` | Zone transfer (AXFR) probe, DMARC / SPF / DKIM, DNSSEC, CAA |
| `recon.tls_audit` | Qualys-style protocol & cipher audit (POODLE, TLS 1.0/1.1, weak keys, HSTS) |
| `recon.waf_detector` | Identify WAF / IPS via header + body fingerprint catalogue (25+ vendors) |
| `recon.http_methods` | Probe risky methods: TRACE, PUT, DELETE, PROPFIND, CONNECT |

### Active Enumeration
| Module | Capabilities |
|--------|-------------|
| `enumeration.directory_buster` | Async path discovery with built-in admin / backup / config wordlist |
| `enumeration.vhost_enum` | Virtual-host fuzzing via Host-header on the target IP |
| `enumeration.parameter_finder` | Harvest URL / form / JSON parameter names |
| `enumeration.js_endpoints` | Mine JS bundles for endpoints, URLs, leaked secrets |
| `enumeration.cms_enum` | Enumerate WordPress version, plugins, themes, users |
| `enumeration.s3_buckets` | Discover public S3 / GCS / Azure / DO Spaces buckets |

### Defensive Vulnerability Detection (read-only)
| Module | Capabilities |
|--------|-------------|
| `exploit.security_headers` | Mozilla-style security-header grade (A+ / F) |
| `exploit.cve_matcher` | Map detected technologies to CVEs via the public NVD 2.0 API |
| `exploit.subdomain_takeover` | Detect dangling CNAMEs against 17 SaaS fingerprints |
| `exploit.cors_misconfig` | Probe unsafe CORS reflection / null-origin / credentialed wildcard |
| `exploit.open_redirect` | Detect redirect parameters that accept external destinations |
| `exploit.reflection_probe` | Surface parameters that reflect input into HTML / JS contexts |
| `exploit.sqli_fingerprint` | Spot SQL stack-trace error strings on malformed parameters |
| `exploit.secrets_scanner` | Search public GitHub for credentials referencing the target |
| `exploit.sensitive_files` | Hand-tuned catalogue of high-signal sensitive paths (.env, /actuator/env, dump.sql, .htpasswd, kubeconfig, …) |
| `exploit.default_creds` | Locate exposed admin / management consoles with known vendor defaults (Tomcat, Jenkins, Grafana, phpMyAdmin, RabbitMQ …) |
| `exploit.host_header_injection` | Host / X-Forwarded-Host / X-Original-URL injection (cache poison, pwd-reset poison, auth bypass) |
| `exploit.jwt_analyzer` | Find + decode JWTs in HTML / JS, flag alg=none / weak HS256 / leaked claims |

> The `exploit.*` modules are **non-destructive**. They issue benign sentinels and inspect responses; they never carry live exploit payloads. Use them only against assets you own or are explicitly authorized to test.

## 🔁 Investigation Presets

| Preset | Endpoint | What it runs |
|--------|----------|-------------|
| Person | `POST /api/v1/investigate/person` | Identity + breach + SOCMINT modules |
| Network | `POST /api/v1/investigate/network` | Network recon + ASN + CDN + threat-intel |
| Website | `POST /api/v1/investigate/website` | Network recon + enumeration + exploit-surface checks |
| Exploit | `POST /api/v1/investigate/exploit` | Focused enumeration + defensive vuln detection only |
| **Vuln Scan** | `POST /api/v1/investigate/vuln-scan` | **Nessus-style unified scan** — runs the full 35+ module catalogue and returns a normalized report (findings with `id / plugin / family / title / severity / cvss / cwe / evidence / solution / references`, asset inventory, severity & family distributions, top risks, executive summary, per-module timeline) |

### Vuln-scan response shape

```json
{
  "target": "example.com",
  "duration_ms": 47230,
  "risk_score": 78,
  "executive_summary": "Vulnerability scan of example.com identified 23 findings (3 critical, 7 high, ...).",
  "asset_inventory": {
    "ip": "93.184.216.34", "asn": 15133, "asn_name": "EDGECAST",
    "cdn": ["Akamai"], "waf": [], "tls": {"protocols": ["TLSv1.3", "TLSv1.2"], "cipher": "...", "key_bits": 2048},
    "subdomains": ["..."], "open_ports": [{"port": 443, "service": "HTTPS"}], "tech": ["server:ECS"], ...
  },
  "severity_distribution": {"critical": 3, "high": 7, "medium": 9, "low": 4, "info": 0},
  "family_distribution": [{"family": "TLS / SSL", "count": 5}, ...],
  "top_risks": [{"id": "...", "plugin": "...", "title": "...", "severity": "critical", "cvss": 9.8, ...}],
  "findings": [/* full sorted list */],
  "timeline": [{"module": "...", "ms": 1240, "status": "completed", "severity": "high", "entities": 4}, ...],
  "modules_run": [...], "modules_total": 35, "errors": []
}
```

The `Vuln Scanner` page in the UI consumes this directly and renders it as a Nessus-style dashboard (severity donut, CVSS bar, family bar chart, executive-summary card, top-risks list, sortable & filterable findings table with a per-finding evidence/solution/references drawer, asset-inventory cards, and a per-module timeline). **No raw JSON is shown to the user.**

## 🛰️ Real-time Threat Intelligence

ShadowNet ships with a built-in threat-intel aggregator that pulls fresh IOCs every 10 minutes
from public feeds and pushes new indicators over a WebSocket so the dashboard updates live —
no API keys required.

| Feed | IOC type | Vendor |
|------|----------|--------|
| URLhaus | URL | abuse.ch |
| ThreatFox | IP / URL / domain / hash | abuse.ch |
| Feodo Tracker | botnet C2 IP | abuse.ch |
| OpenPhish | URL | OpenPhish |
| PhishTank | URL | PhishTank |
| CISA KEV | exploited CVE | CISA |
| NVD recent | CVE | NIST |
| AlienVault OTX | pulse | AT&T |
| GitHub Advisories | GHSA / CVE | GitHub |
| Tor exit list | IP | Tor Project |
| Spamhaus DROP/EDROP | CIDR | Spamhaus |

API endpoints under `/api/v1/threat-intel/`: `status`, `feeds`, `refresh`, `indicators`,
`lookup`, `summary`. See the **Threat Intel** page in the UI for the live dashboard.

## 🛡️ Tech Stack

- **Backend**: FastAPI, SQLAlchemy (async), Celery
- **Frontend**: React 18, TypeScript, Vite
- **Databases**: PostgreSQL, Neo4j, Elasticsearch, Redis
- **Storage**: MinIO (S3-compatible)
- **AI**: OpenAI GPT-5.5 (optional)
- **Auth**: JWT (access + refresh tokens), RBAC

## 📁 Project Structure

```
shadownet/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # REST API endpoints
│   │   ├── core/            # Config, DB, Auth, Clients
│   │   ├── darkweb/         # Tor router, Onion crawler
│   │   ├── middleware/      # Rate limiting
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── modules/         # OSINT scan modules
│   │   │   ├── identity/    # Username, email, phone
│   │   │   ├── network/     # DNS, WHOIS, IP, subdomains
│   │   │   ├── socmint/     # GitHub, social media
│   │   │   ├── breach/      # Google dorking, leak search
│   │   │   └── document/    # Metadata extraction
│   │   ├── schemas/         # Pydantic request/response
│   │   ├── services/        # AI, Scan Engine, Alerts
│   │   ├── templates/       # Report HTML templates
│   │   └── main.py          # FastAPI entry point
│   ├── alembic/             # Database migrations
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── api/             # Axios API client
│   │   ├── components/      # Sidebar, TopBar
│   │   ├── context/         # Auth context
│   │   ├── pages/           # All dashboard pages
│   │   ├── App.tsx          # Router & layout
│   │   └── index.css        # Design system
│   └── package.json
├── docker-compose.yml
└── .env.example
```

## 🧱 Adding a New OSINT Module

Every module subclasses `app.modules.base.OSINTModule` and registers itself with
the singleton `ModuleRegistry`. The orchestrator picks them up automatically.

```python
from app.modules.base import OSINTModule, ScanResult, EntityFound, ModuleRegistry


class MyNewModule(OSINTModule):
    name = "category.my_module"
    description = "what this module does"
    supported_target_types = ["domain", "ip"]
    requires_api_key = False
    rate_limit = 10

    async def scan(self, target: str, options=None) -> ScanResult:
        entities = [EntityFound(entity_type="domain", value=target, source=self.name)]
        return ScanResult(
            module=self.name, target=target, success=True,
            entities=entities, raw_data={...}, summary="...", severity="info",
        )


ModuleRegistry.register(MyNewModule())
```

Then:

1. Drop the file in `backend/app/modules/<category>/<name>.py`.
2. Add a `try/except`-guarded import block to `backend/app/modules/__init__.py`.
3. (Optional) Add the module name to `NETWORK_MODULES`, `WEBSITE_MODULES`, or
   `EXPLOIT_MODULES` in `backend/app/services/investigation_orchestrator.py` so it
   is included in the corresponding investigation preset.
4. Restart the backend — the registry rescans automatically.

## ⚠️ Legal Disclaimer

This tool is designed for **authorized security testing and OSINT research only**. Always ensure you have proper authorization before conducting any reconnaissance activities.
