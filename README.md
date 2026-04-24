<p align="center">
  <img src="https://img.shields.io/badge/SentinelAI-WAF-6366f1?style=for-the-badge&logo=shield&logoColor=white" alt="SentinelAI" />
  <img src="https://img.shields.io/badge/Node.js-Backend-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js" />
  <img src="https://img.shields.io/badge/React-Frontend-61DAFB?style=for-the-badge&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/MongoDB-Atlas-47A248?style=for-the-badge&logo=mongodb&logoColor=white" alt="MongoDB" />
  <img src="https://img.shields.io/badge/Gemini_AI-Powered-4285F4?style=for-the-badge&logo=google&logoColor=white" alt="Gemini AI" />
</p>

# 🛡️ SentinelAI — AI-Powered Web Application Firewall

> **A full-stack, intelligent cybersecurity platform** that combines Google Gemini AI, multi-layer encoding detection, and external threat intelligence to detect, classify, and block web attacks in real-time — with a sleek React dashboard for live monitoring.

---

## 🌟 Key Highlights

- 🤖 **Dual-Engine Threat Detection** — Gemini AI + custom regex-based scoring engine working in tandem
- 🔗 **Hybrid Risk Scoring** — Combines AbuseIPDB IP reputation (60%) with local payload analysis (40%)
- 🧬 **Multi-Layer Encoding Detection** — URL encoding, double encoding, Base64, Unicode, hex, HTML entities
- 📊 **Real-Time Dashboard** — Live traffic feed, analytics charts, alerts, and attacker profiling
- 🔐 **Dual Authentication** — Local JWT + Firebase Google Sign-In
- ⚡ **Auto-Blocking** — IPs automatically blocked after repeated malicious requests

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      CLIENT REQUEST                      │
└─────────────────────┬───────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│                    SECURITY LAYERS                       │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────┐    │
│  │  Helmet   │  │  CORS    │  │  Rate Limiter      │    │
│  │ (Headers) │  │ (Origin) │  │  (100 req/15 min)  │    │
│  └──────────┘  └──────────┘  └────────────────────┘    │
└─────────────────────┬───────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  WAF MIDDLEWARE                           │
│  ┌────────────────┐  ┌───────────────────────────────┐  │
│  │ IP Blocklist   │  │  Gemini AI Classification     │  │
│  │ (Fast Reject)  │  │  SQLi | XSS | CSRF | RCE     │  │
│  └────────────────┘  └───────────────────────────────┘  │
└─────────────────────┬───────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│              THREAT DETECTION ENGINE                     │
│  ┌────────────────┐  ┌────────────────┐  ┌───────────┐ │
│  │  Encoding      │  │  Scoring       │  │ AbuseIPDB │ │
│  │  Analyzer      │  │  Engine        │  │ Hybrid    │ │
│  │  (6 decoders)  │  │  (weighted)    │  │ Risk API  │ │
│  └────────────────┘  └────────────────┘  └───────────┘ │
└─────────────────────┬───────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│  MongoDB Atlas: Logs │ Alerts │ Profiles │ Blocked IPs  │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
SentinelAI/
├── backend/
│   ├── config/               # MongoDB connection
│   ├── controllers/          # Auth, Logs, Stats, IP, Scanner, RiskScore, Profiles
│   ├── middleware/
│   │   ├── wafMiddleware.js  # Core WAF interceptor (Gemini AI)
│   │   ├── authMiddleware.js # JWT verification
│   │   ├── rateLimiter.js    # Rate limiting
│   │   └── validators.js     # Input validation (express-validator)
│   ├── models/
│   │   ├── User.js           # Users with bcrypt hashing
│   │   ├── Log.js            # Request audit trail
│   │   ├── Alert.js          # Security notifications
│   │   ├── BlockedIP.js      # IP blocklist
│   │   └── AttackerProfile.js # Behavioral profiling
│   ├── routes/               # 8 route modules
│   ├── services/
│   │   ├── geminiService.js     # Google Gemini AI integration
│   │   ├── abuseIPDBService.js  # External IP reputation
│   │   ├── ipBlockService.js    # IP management
│   │   ├── alertService.js      # Alert generation
│   │   ├── profileService.js    # Attacker profiling
│   │   └── threatDetector/      # Custom regex scoring engine
│   │       ├── index.js         # Public API (analyze, classify)
│   │       ├── scoringEngine.js # Weighted pattern matching
│   │       ├── encodingAnalyzer.js # Multi-layer decoder
│   │       └── patterns.js      # 50+ attack signatures
│   ├── tests/                # Jest + Supertest test suite
│   ├── server.js             # Express entry point
│   └── .env                  # Environment configuration
│
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Navbar.jsx       # Navigation + notification bell
    │   │   ├── StatCard.jsx     # Interactive metric cards
    │   │   └── LoadingScreen.jsx # Animated boot screen
    │   ├── context/
    │   │   └── AuthContext.jsx  # JWT + Google auth state
    │   ├── pages/
    │   │   ├── Dashboard.jsx   # Live traffic + stat cards + alerts
    │   │   ├── Analytics.jsx   # Charts (Recharts)
    │   │   ├── Logs.jsx        # Filterable request log
    │   │   ├── Scanner.jsx     # Payload testing tool
    │   │   ├── Profiles.jsx    # Attacker behavior profiles
    │   │   └── Login.jsx       # Dual auth (local + Google)
    │   ├── services/
    │   │   └── api.js          # Axios with JWT interceptor
    │   └── index.css           # Full design system (1400+ lines)
    ├── index.html
    └── vite.config.js
```

---

## 🚀 Quick Start

### Prerequisites
- **Node.js** v18+
- **MongoDB Atlas** account (or local MongoDB)
- **Google Gemini API** key ([aistudio.google.com](https://aistudio.google.com/))
- **AbuseIPDB** free API key ([abuseipdb.com](https://www.abuseipdb.com/)) — optional, for hybrid scoring

### 1. Clone the Repository
```bash
git clone https://github.com/cryptoujjwal07/SentinelAI.git
cd SentinelAI
```

### 2. Configure Environment

Create `backend/.env`:
```env
# Server
PORT=5000
NODE_ENV=development

# MongoDB
MONGODB_URI=<your-mongodb-atlas-uri>

# JWT
JWT_SECRET=<your-strong-secret-key>
JWT_EXPIRES_IN=7d

# Google Gemini AI
GEMINI_API_KEY=<your-gemini-api-key>
GEMINI_MODEL=gemini-2.0-flash

# WAF Settings
MALICIOUS_THRESHOLD=3
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Firebase (Google Sign-In)
FIREBASE_PROJECT_ID=<your-firebase-project-id>

# Frontend CORS
FRONTEND_URL=http://localhost:5173

# AbuseIPDB (optional — enables hybrid risk scoring)
ABUSEIPDB_API_KEY=<your-abuseipdb-api-key>
```

### 3. Start Backend
```bash
cd backend
npm install
npm run dev
# ✅ Server running on http://localhost:5000
```

### 4. Start Frontend
```bash
cd frontend
npm install
npm run dev
# ✅ Dashboard on http://localhost:5173
```

### 5. Create Your First Account
Register via the Dashboard UI or via API:
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@sentinelai.com","password":"Admin123!","role":"admin"}'
```

---

## 🤖 How the WAF Works

### Detection Pipeline

```
Incoming Request
    │
    ├─ 1. IP Blocklist Check ──→ Blocked? ──→ 403 Forbidden
    │
    ├─ 2. Rate Limit Check ────→ Exceeded? ─→ 429 Too Many Requests
    │
    ├─ 3. Gemini AI Analysis ──→ Sends method, path, body, headers, IP
    │                           Returns: SAFE | SUSPICIOUS | MALICIOUS
    │                           + confidence score + attack type
    │
    ├─ 4. Action:
    │     ├─ MALICIOUS → 403 blocked, log saved, strike counter++
    │     ├─ SUSPICIOUS → Warning headers, alert created, log flagged
    │     └─ SAFE → Request passes through, log saved
    │
    └─ 5. Auto-Block: 3 malicious strikes → IP permanently blocked
```

### Threat Detector (Regex Engine)

Operates independently alongside Gemini AI for the Scanner and Hybrid Risk API:

| Layer | Function |
|-------|----------|
| **Encoding Analyzer** | Decodes URL, double-URL, Unicode, hex, Base64, HTML entities |
| **Pattern Matcher** | 50+ weighted regex patterns across 13 attack categories |
| **Scoring Engine** | Weighted scoring with category-based multipliers |
| **Classifier** | Maps score → `SAFE` (0–29) / `SUSPICIOUS` (30–69) / `MALICIOUS` (70–100) |

### Hybrid Risk Scoring (AbuseIPDB Integration)

```
POST /api/risk-score
{
  "ip": "185.220.101.1",
  "payload": "%27%20OR%201%3D1%20--"
}

Response:
{
  "score": 82,
  "level": "high",
  "sources": {
    "ipReputation": 95,    ← AbuseIPDB (60% weight)
    "payloadAnalysis": 62  ← Local regex engine (40% weight)
  }
}
```

> **Fallback:** If AbuseIPDB is unavailable, uses 100% local payload scoring automatically.

---

## 📡 API Reference

### 🔐 Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | Login & receive JWT |
| POST | `/api/auth/google` | Google Sign-In (Firebase) |
| GET  | `/api/auth/me` | Get current user profile |

### 📊 Stats & Analytics
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats/overview` | Dashboard summary (counts, rates) |
| GET | `/api/stats/attack-types` | Attack type breakdown |
| GET | `/api/stats/timeline?period=24h` | Traffic over time (24h/7d/30d) |
| GET | `/api/stats/top-ips` | Top attacking IP addresses |
| GET | `/api/stats/alerts?limit=20` | Recent security alerts |
| PATCH | `/api/stats/alerts/read` | Mark alerts as read |

### 📋 Logs
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/logs` | Paginated logs with filters |
| GET | `/api/logs/recent?limit=10` | Live traffic feed |
| GET | `/api/logs/:id` | Single log detail |
| DELETE | `/api/logs/:id` | Delete log entry |
| DELETE | `/api/logs/all` | Clear all logs |

### 🚫 IP Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ip/blocked` | List all blocked IPs |
| POST | `/api/ip/block` | Manually block an IP |
| DELETE | `/api/ip/unblock/:ip` | Unblock an IP |
| GET | `/api/ip/check/:ip` | Check block status |

### 🔬 Scanner
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scanner/test` | Analyze a single payload |
| POST | `/api/scanner/bulk` | Bulk test up to 10 payloads |
| GET | `/api/scanner/samples` | Get sample attack payloads |

### 🧬 Threat Detector
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/threat-detector/analyze` | Deep payload analysis |
| GET | `/api/threat-detector/test-suite` | Run built-in test cases (23 payloads) |

### 🎯 Hybrid Risk Score
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/risk-score` | Combined IP reputation + payload analysis |

### 👤 Attacker Profiles
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/profiles` | List all attacker profiles |
| GET | `/api/profiles/:ip` | Profile details for an IP |
| GET | `/api/profiles/top-risk?limit=10` | Highest risk attackers |

---

## 🎯 Attack Detection Capabilities

| Category | Examples | Encoding Support |
|----------|----------|-----------------|
| **SQL Injection** | UNION SELECT, OR 1=1, DROP TABLE, time-based blind | URL, double, Base64, hex |
| **Cross-Site Scripting** | `<script>`, onerror, eval, document.cookie | URL, Unicode, HTML entity |
| **Command Injection** | `$(cmd)`, `` `whoami` ``, `; ls`, `&& rm -rf` | URL, double encoding |
| **Path Traversal** | `../../etc/passwd`, `%2e%2e%2f` | URL, Unicode (%uXXXX) |
| **CSRF** | Missing tokens, suspicious origins | — |
| **Defanged URLs** | `hxxps[://]`, `domain[.]com` | Bracket notation |
| **Null Byte Injection** | `%00/etc/passwd` | URL encoding |
| **Obfuscation** | String.fromCharCode, mixed encoding | JavaScript, multi-layer |

---

## 🛡️ Security Stack

| Feature | Implementation |
|---------|---------------|
| AI Threat Detection | Google Gemini 2.0 Flash |
| Regex Scoring Engine | Custom weighted pattern matcher (50+ rules) |
| External Threat Intel | AbuseIPDB API (IP reputation) |
| Rate Limiting | express-rate-limit (100 req/15 min) |
| Security Headers | helmet.js (HSTS, CSP, X-Frame) |
| IP Auto-Blocking | 3-strike threshold system |
| JWT Authentication | jsonwebtoken (7-day expiry) |
| Google Sign-In | Firebase Authentication |
| Password Security | bcryptjs (12 salt rounds) |
| Input Validation | express-validator |
| CORS Protection | Restricted to frontend URL |
| Audit Trail | Full request logging in MongoDB |
| Attacker Profiling | Rule-based behavioral classification |

---

## 🖥️ Frontend Pages

| Page | Features |
|------|----------|
| **Dashboard** | 8 interactive stat cards, live traffic table, alerts panel, notification bell |
| **Analytics** | Attack type chart, traffic timeline, top IPs visualization |
| **Logs** | Filterable/searchable request log with pagination |
| **Scanner** | Test payloads against the detection engine, bulk scanning |
| **Profiles** | Attacker behavior profiles, risk scores, attack type breakdown |
| **Login** | Local credentials + Google Sign-In, animated loading screen |

---

## 🧰 Tech Stack

| Layer | Technologies |
|-------|-------------|
| **Backend** | Node.js, Express.js, MongoDB (Mongoose), JWT |
| **AI Engine** | Google Gemini 2.0 Flash API |
| **Threat Intel** | AbuseIPDB API, Custom regex scoring engine |
| **Frontend** | React 19, Vite, Recharts, Lucide Icons |
| **Auth** | JWT + Firebase (Google Sign-In) |
| **Styling** | Custom CSS design system (dark theme, glassmorphism) |
| **Testing** | Jest, Supertest |

---

## 🧪 Testing

### Run Backend Tests
```bash
cd backend
npm test
```

### Manual Testing with cURL

**Test SQL Injection Detection:**
```bash
curl -X POST http://localhost:5000/api/scanner/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -d '{"payload": "'\'' OR 1=1 --"}'
```

**Test Hybrid Risk Score:**
```bash
curl -X POST http://localhost:5000/api/risk-score \
  -H "Content-Type: application/json" \
  -d '{"ip": "185.220.101.1", "payload": "%27%20OR%201%3D1%20--"}'
```

**Test Encoded XSS:**
```bash
curl -X POST http://localhost:5000/api/scanner/test \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <your-jwt-token>" \
  -d '{"payload": "%3Cscript%3Ealert(1)%3C/script%3E"}'
```

---

## 📄 License

This project is for educational and hackathon purposes. Built with ❤️ by Team SentinelAI.

---

<p align="center">
  <b>🛡️ SecureNet Monitoring Platform — SentinelAI</b><br/>
  <i>Intelligent. Adaptive. Real-Time.</i>
</p>
