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

| Module | Category | Capabilities |
|--------|----------|-------------|
| `identity.username_lookup` | Identity | Check 300+ platforms |
| `identity.email_validator` | Identity | MX, SMTP, pattern validation |
| `identity.phone_lookup` | Identity | Phone number parsing & OSINT |
| `network.dns_recon` | Network | DNS record enumeration (async) |
| `network.whois_lookup` | Network | WHOIS registration data |
| `network.ip_geolocation` | Network | IP geolocation & ASN |
| `network.subdomain_enum` | Network | Subdomain discovery |
| `network.wayback_machine` | Network | Historical snapshots |
| `document.metadata_extractor` | Document | EXIF, PDF, DOCX metadata |
| `socmint.github_recon` | SOCMINT | GitHub profile intelligence |
| `breach.google_dorker` | Breach | Google dorking for leaks |
| `darkweb.onion_search` | Dark Web | Ahmia.fi clearnet search |
| `threat.intel_lookup` | Threat Intel | Cross-reference any IOC against 10 live feeds |

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

## ⚠️ Legal Disclaimer

This tool is designed for **authorized security testing and OSINT research only**. Always ensure you have proper authorization before conducting any reconnaissance activities.
