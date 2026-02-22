# 🛡️ CyberGuard — AI-Powered Cyber Incident Defence Portal

## Product Vision

CyberGuard is a **B2B SaaS platform** designed for organizations to **detect, report, analyze, and respond** to cyber incidents — particularly social engineering, phishing, and credential theft attacks targeting service personnel and their families.

> The platform combines **human reporting** with **AI-powered threat intelligence** to provide real-time risk assessments, automated safety guidance, and a structured analyst review workflow.

---

## 🧠 Core Concepts

### 1. Incident Lifecycle

Every cyber incident flows through a structured pipeline:

```
User Reports → AI Analysis → Risk Scoring → Safety Guidance → Analyst Review → Resolution
```

| Stage | Description |
|---|---|
| **Report** | Users submit incidents via a structured form (platform, date, narrative, IOC indicators) |
| **AI Analysis** | VADER NLP analyzes tone/urgency; keyword engine scores threat level |
| **Risk Scoring** | Combined score (0–100) assigns a level: `LOW`, `MEDIUM`, or `HIGH` |
| **Threat Classification** | Auto-classified as: `Malicious Link`, `Credential Theft`, `Social Engineering`, or `Suspicious Message` |
| **Safety Guidance** | Immediate actions + preventive advice served from the Response Playbook |
| **Analyst Review** | Staff (Admin/Analyst) verify, add notes, assign final verdict |
| **Resolution** | Incident status updated: `open` → `under_review` → `resolved` / `escalated` |

---

### 2. AI-Powered Risk Engine

The risk engine is the brain of CyberGuard. It operates in two layers:

#### Layer 1: Keyword Analysis (`risk_engine.py`)
- Scans combined text (narrative + IOC indicators) for threat keywords
- **High-risk** keywords (`password`, `bank`, `otp`, `login`): +25 points each
- **Medium-risk** keywords (`urgent`, `click`, `link`): +15 points each
- **Low-risk** indicators (`newsletter`, `promotion`): -10 points each
- URL presence: +20 points
- Evidence provided: +10 points

#### Layer 2: NLP Sentiment Analysis (`ai_analysis.py`)
- Uses **VADER** (Valence Aware Dictionary and sEntiment Reasoner)
- Detects emotional pressure, fear tone, and urgency
- Strong negative/fear tone (compound ≤ -0.5): +15 points
- Mild urgency tone (-0.5 < compound < -0.2): +8 points

#### Output
- **Score**: Normalized between 0–100
- **Level**: `LOW` (≤25), `MEDIUM` (26–60), `HIGH` (61–100)
- **Reasons**: Explainable AI — every score contribution is logged

---

### 3. Threat Classification & Response Playbook

Based on the analysis, each incident is automatically classified:

| Threat Type | Trigger |
|---|---|
| **Malicious Link** | URL flagged by Safe Browsing API |
| **Credential Theft** | Keywords: `otp`, `password`, `bank`, `verify`, `login` |
| **Social Engineering** | High urgency score (>10) |
| **Suspicious Message** | Default fallback |

Each classification maps to a **Response Playbook** with:
- **Immediate Actions**: What to do right now (e.g., "Change all passwords immediately")
- **Preventive Advice**: Long-term protection (e.g., "Use a password manager")

---

### 4. Authentication & Role-Based Access Control (RBAC)

CyberGuard uses **JWT-based authentication** with three roles:

| Role | Access Level |
|---|---|
| `user` | Report incidents, view own reports, see AI analysis |
| `analyst` | All user permissions + review incidents, add notes, update status |
| `admin` | All analyst permissions + manage users, delete incidents, view system stats |

- Passwords are hashed using **Werkzeug's PBKDF2-SHA256**
- Tokens carry role claims for middleware-level access control
- Staff access is enforced via `staff_required()` and `admin_required()` decorators

---

### 5. Data Integrity & Evidence Chain

Every incident report includes a **hybrid evidence hash** computed from:
```
sha256 = SHA256(platform + incident_date + narrative + ioc_indicators)
md5    = MD5(platform + incident_date + narrative + ioc_indicators)
```

This dual-hash approach enables:
- **Tamper detection**: Any modification to the original report data is detectable via two independent algorithms
- **Forensic integrity**: Dual-algorithm evidence chain is stronger for legal/compliance purposes
- **Cross-verification**: If one algorithm is compromised, the other still provides integrity assurance
- **Verification endpoint**: `GET /incident/verify/<id>` compares stored vs. recalculated hashes for both SHA-256 and MD5

---

### 6. Incident History & Audit Trail

Every action on an incident is logged in a `history` array:

```json
{
  "action": "Review started",
  "by": "analyst_username",
  "time": "2026-02-22T12:00:00Z"
}
```

This provides a complete **audit trail** for compliance and accountability.

---

## 🏗️ Architecture Overview

```
backend/
├── app/
│   ├── __init__.py          # App Factory (Flask, CORS, JWT, MongoDB, NLTK)
│   ├── config.py            # Environment-based configuration
│   ├── extensions.py        # Shared extension instances (JWT, DB)
│   ├── constants/           # Static labels & messages (no hardcoded strings)
│   │   ├── auth_constants.py
│   │   └── incident_constants.py
│   ├── models/              # MongoDB document schemas
│   │   ├── user_model.py
│   │   └── incident_model.py
│   ├── routes/              # API endpoints (Blueprints)
│   │   ├── auth_routes.py   # /api/auth/*
│   │   ├── incident_routes.py  # /incident/*
│   │   ├── admin_routes.py  # /api/admin/*
│   │   └── test_routes.py   # Health check
│   ├── services/            # Business logic layer
│   │   ├── auth_service.py  # Login, profile retrieval
│   │   ├── risk_engine.py   # AI risk scoring
│   │   ├── ai_analysis.py   # VADER NLP analysis
│   │   └── url_checker.py   # Google Safe Browsing integration
│   └── utils/               # Cross-cutting concerns
│       ├── logger.py        # Rotating file + console logging
│       ├── error_handler.py # Global HTTP error handlers
│       ├── db_init.py       # MongoDB index initialization
│       └── security.py      # SHA-256 + MD5 hybrid hashing
├── run.py                   # Entry point
├── requirements.txt         # Lean dependency list
└── .env                     # Environment variables
```

---

## 🔑 API Endpoints Summary

### Auth (`/api/auth`)
| Method | Endpoint | Description |
|---|---|---|
| POST | `/register` | Register new user |
| POST | `/login` | Authenticate & get JWT |
| GET | `/me` | Get current user profile |
| POST | `/logout` | Logout (client-side token discard) |

### Incidents (`/incident`)
| Method | Endpoint | Description |
|---|---|---|
| POST | `/report` | Submit a new incident |
| GET | `/my-incidents` | Fetch user's own incidents |
| GET | `/analysis/<id>` | Get AI analysis for an incident |
| GET | `/verify/<id>` | Verify evidence integrity |

### Admin (`/api/admin`)
| Method | Endpoint | Description |
|---|---|---|
| GET | `/incidents/pending` | Pending review incidents |
| GET | `/incidents/high-risk` | High-risk flagged incidents |
| GET | `/incidents/all` | All incidents |
| GET | `/incident/<id>` | Incident detail |
| PUT | `/incident/<id>/start-review` | Begin analyst review |
| PUT | `/incident/<id>/review` | Submit analyst review |
| PUT | `/incident/<id>/status` | Update incident status |
| GET | `/incident/<id>/history` | View audit trail |
| GET | `/stats` | Dashboard statistics |

---

## 🔮 Technology Stack

| Layer | Technology |
|---|---|
| **Framework** | Flask 2.3 |
| **Database** | MongoDB (PyMongo) |
| **Auth** | JWT (Flask-JWT-Extended) |
| **AI/NLP** | NLTK VADER Sentiment Analysis |
| **Security** | Werkzeug PBKDF2, SHA-256 + MD5 Hybrid |
| **Threat Intel** | Google Safe Browsing API |
| **Logging** | Python `logging` + RotatingFileHandler |

---

## 🎯 Why CyberGuard?

1. **AI-First**: Every incident is automatically analyzed — no manual triage bottleneck
2. **Explainable AI**: Risk scores come with human-readable reasons
3. **Tamper-Proof**: SHA-256 + MD5 hybrid evidence hashing ensures forensic integrity
4. **Role-Based**: Clear separation between users, analysts, and admins
5. **Audit-Ready**: Full history trail for every incident action
6. **Scalable**: Stateless architecture with indexed MongoDB for horizontal scaling

---

*CyberGuard — Defending the digital frontline with AI-powered intelligence.*
