# 🛡️ CIRS — Cybersecurity Incident Response & Protection System

CIRS started as a DBMS project (analyst incident-response dashboard). It is now a two-sided
security product:

- **A Chrome extension (Manifest V3)** for everyday internet users: scan the current website,
  understand *why* it looks risky, report it, follow the investigation, and get warned before a
  dangerous site loads.
- **An analyst web dashboard** for the security team: the original events / alerts / threats /
  vulnerabilities / analysts modules, plus a full **user-report investigation workflow**.

The existing CIRS modules and API paths were kept. Everything new is additive.

---

## 1. Architecture

```
Chrome Extension (Manifest V3)          Analyst Dashboard (HTML/CSS/JS)
  popup · side panel · warning page       login · dashboard · events · alerts
  service worker · options                user reports · incidents
        │                                        │
        └──────────── HTTPS REST (JWT) ──────────┘
                              │
                    Node.js + Express API
                    ├─ auth (users + analysts, bcrypt + JWT, RBAC)
                    ├─ scanner (transparent URL heuristics)
                    ├─ threat intelligence (Safe Browsing / VirusTotal, optional)
                    ├─ reports (user submission → alert → investigation)
                    └─ analyst modules (events, alerts, threats, vulns)
                              │
                        MySQL (cybersecurity_irs)
```

---

## 2. Repository layout

```
backend/
  server.js                     entry point (Express app + graceful shutdown)
  src/config.js                 env-driven configuration (no hardcoded secrets)
  src/db.js                     mysql2 pool, transactions, test seam
  src/app.js                    app, CORS, security headers, health, static frontend
  src/middleware/               auth (JWT/RBAC), rate limiting, validation
  src/routes/                   auth, user (extension), analyst
  src/services/                 urlAnalyzer, threatIntel, assessment
  db/migrations/                001 core schema, 002 extension schema (additive)
  scripts/migrate.js            idempotent migration runner
  scripts/seed.js               demo analyst + demo user + sample reference data
  tests/                        unit + API tests, DB-gated integration test
frontend/
  index.html                    analyst login
  pages/                        dashboard, events, alerts, reports, incidents
  js/config.js                  runtime API base resolution (no localhost in production)
  js/app.js                     API client, auth, badges, helpers
  css/main.css                  dark cyberpunk theme
extension/
  manifest.json                 Manifest V3
  src/popup/                    compact popup UI (scan, report, status)
  src/sidepanel/                personal security dashboard
  src/warning/                  interstitial warning page
  src/options/                  server URL, protection, notifications, account
  src/background/               service worker (warning redirect, notifications)
  src/lib/                      API client, storage, formatting
  icons/                        generated shield icons
docs/
  DEPLOYMENT.md                 MySQL + Render/Railway + Vercel + extension publishing
  EXTENSION-INSTALL.md          local install, usage, permissions, store checklist
scripts/package-extension.sh    builds dist/cirs-extension-v<version>.zip
tools/generate-icons.js         regenerates the PNG icons (no dependencies)
```

---

## 3. What the extension does

| Feature | Behaviour |
|---|---|
| Website security scanner | Detects the current tab's URL, extracts the domain, checks HTTPS, IP-host URLs, punycode/lookalike brands, typosquats, deep subdomains, credential keywords, obfuscation, redirects, shorteners, risky file extensions and suspicious TLDs |
| Verdicts | `SAFE` / `SUSPICIOUS` / `DANGEROUS` / `UNKNOWN`, each with a 0–100 risk score and plain-language reasons |
| Phishing risk | Explainable weighted indicators; the extension lists what was found and why it matters |
| Threat intelligence | Google Safe Browsing and/or VirusTotal, **only if the server has API keys**. A malicious reputation hit forces `DANGEROUS` |
| Reporting | One click "Report website" → reference ID such as `CIRS-261116-A1B2C3`; stored in MySQL with a linked security event and alert |
| Notifications | Dangerous site detected, suspicious site detected, site you previously reported still suspicious, report status updates; deduplicated per domain |
| Personal dashboard | Side panel with scans, suspicious sites, reports, open reports, threat categories, recent activity, notifications, protection toggles |
| Warning interstitial | Shown before a site that *you scanned and that was flagged dangerous* loads again; requires an explicit acknowledgement to continue |
| Privacy | Only the URL you scan/report is sent to your own CIRS server. No page content, forms, cookies, tokens or browsing history. No content scripts |

### Verdict semantics (honest by design)

| Verdict | Meaning |
|---|---|
| `DANGEROUS` | A configured threat-intelligence provider returned a malicious result |
| `SUSPICIOUS` | Heuristic score ≥ 40, or a provider returned "suspicious" |
| `SAFE` | Heuristics clean **and** a configured provider explicitly reports no known threat. Never a guarantee |
| `UNKNOWN` | Not enough information — e.g. heuristics clean but no reputation source configured |

The UI always says which mode produced the result (`heuristic-only` vs `reputation-assisted`) and
states that CIRS is not an antivirus. It never claims a site is safe just because nothing matched.

---

## 4. Quick start (local)

### 4.1 Database

Requires MySQL 8 (or MariaDB 10.5+).

```bash
cd backend
cp .env.example .env          # fill DB_* and JWT_SECRET
npm ci
npm run migrate               # creates DB + tables, additive, keeps existing rows
npm run seed                  # demo analyst + extension user (prints generated passwords)
```

`npm run seed` reads `SEED_ANALYST_EMAIL`, `SEED_ANALYST_PASSWORD`, `SEED_USER_EMAIL`,
`SEED_USER_PASSWORD`. Missing passwords are generated and printed once — no password is
hardcoded in the repository.

### 4.2 Backend

```bash
cd backend
npm start                     # http://localhost:3000
curl http://localhost:3000/api/health
```

The API also serves `frontend/` when `SERVE_FRONTEND=true` (default).

### 4.3 Analyst dashboard

Open `http://localhost:3000/` → sign in with the seeded analyst account.

### 4.4 Extension

```bash
bash scripts/package-extension.sh   # optional zip for sharing
```

1. `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select `extension/`.
2. Open the CIRS popup → enter your server URL (`http://localhost:3000/api`) → **Connect**.
3. Create an account or sign in → scan the current website.

Full instructions: [docs/EXTENSION-INSTALL.md](docs/EXTENSION-INSTALL.md).

---

## 5. Environment variables

See [backend/.env.example](backend/.env.example). Essentials:

| Variable | Purpose |
|---|---|
| `NODE_ENV` | `production` enforces a mandatory `JWT_SECRET` |
| `PORT` | API port (default 3000) |
| `DB_HOST` `DB_PORT` `DB_USER` `DB_PASSWORD` `DB_NAME` | MySQL connection |
| `DB_SSL` `DB_SSL_VERIFY` | TLS for hosted MySQL |
| `JWT_SECRET` | Signing key — generate with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| `JWT_USER_EXPIRY` / `JWT_ANALYST_EXPIRY` | Token lifetimes (`7d` / `8h` by default) |
| `CORS_ORIGINS` | Comma-separated dashboard origins; `chrome-extension://…` origins are always allowed |
| `SAFE_BROWSING_API_KEY` | Optional Google Safe Browsing key |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal v3 key |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | Reputation cache (default 900) |
| `SCAN_RATE_LIMIT_PER_MINUTE`, `REPORT_RATE_LIMIT_PER_HOUR`, `LOGIN_RATE_LIMIT` | Abuse protection |

---

## 6. API reference

All responses are JSON. Send `Authorization: Bearer <token>`. `401` = missing/expired token,
`403` = wrong role, `429` = rate limited.

**Public**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | DB + schema + threat-intel readiness |
| GET | `/api/scan/providers` | Which reputation providers are configured |
| POST | `/api/users/register` | Extension user registration |
| POST | `/api/users/login` | Extension user login |
| POST | `/api/analyst/login` (alias `/api/login`) | Analyst login |

**Extension user (`role: user`)**

| Method | Path | Purpose |
|---|---|---|
| GET/PATCH | `/api/users/me` | Profile / notification preference |
| POST | `/api/users/password` | Change password |
| POST | `/api/scan` | Assess a URL, store scan history |
| POST | `/api/reports` | Submit a report (server re-assesses; duplicate-protected for 24 h) |
| GET | `/api/reports` | Own reports |
| GET | `/api/reports/:reference` | Own report detail |
| GET | `/api/user/stats` | Personal dashboard totals, categories, activity |
| GET | `/api/user/scans` | Scan history |
| GET | `/api/user/notifications` | Notifications |
| PATCH/POST | `/api/user/notifications/:id/read`, `/read-all` | Mark read |

**Analyst (`role: analyst`)**

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/analyst/me` | Current analyst |
| GET | `/api/dashboard/stats` | Events, alerts, threats, vulns, user reports |
| GET/POST/DELETE | `/api/events`, `/api/events/:id` | Security events |
| GET/POST | `/api/alerts` | Alerts |
| PATCH | `/api/alerts/:id/status` | Update alert status |
| GET | `/api/threats`, `/api/vulnerabilities`, `/api/analysts` | Reference data |
| GET/POST | `/api/mitigations` | Mitigation actions |
| GET | `/api/analyst/reports` | All user reports (status/verdict/search filters) |
| GET | `/api/analyst/reports/:reference` | Report + linked event + alert |
| PATCH | `/api/analyst/reports/:reference/status` | Investigation status + notes (notifies the reporter) |

Existing paths from the original project (`/api/login`, `/api/events`, `/api/alerts`,
`/api/threats`, `/api/vulnerabilities`, `/api/analysts`, `/api/dashboard/stats`) are unchanged.

---

## 7. Investigation workflow

```
User submits report (extension)
  → server re-scans the URL and stores WebsiteReport
  → creates a SecurityEvent (severity from verdict)
  → raises an Alert for SUSPICIOUS / DANGEROUS reports
  → notifies the user ("Report submitted")
Analyst opens Reports → Investigate
  → Submitted → Under Review → Investigating → Confirmed Threat / False Positive / Resolved
  → linked event + alert are updated (Confirmed Threat ⇒ alert In Progress, False Positive/Resolved ⇒ alert closed)
  → the reporter gets a notification and sees the new status in the extension
```

---

## 8. Security model

- bcrypt password hashing (10 rounds); no plaintext or demo passwords in code.
- JWT with issuer/audience validation, separate expirations and a `role` claim.
- Role-based authorisation: extension users cannot reach analyst endpoints and vice versa.
- All SQL is parameterised through `mysql2`; no string concatenation of user input.
- Input validation/limits for emails, passwords (8–72 chars, letter + number), URLs (http/https only),
  text fields and enum values; 64 KB JSON body cap.
- Rate limiting on login, scanning and reporting.
- CORS allow-list plus extension origins; security headers (`nosniff`, `DENY`, `no-referrer`).
- Secrets only in `.env`; the extension never contains database or API credentials.
- Threat-intel calls go from the server to the provider. Only the scanned URL is sent — never history.
- `GET /api/health` exposes readiness, not secrets.

---

## 9. Testing

```bash
cd backend
npm test                  # unit + API tests (no MySQL needed)
npm run test:integration  # full journey against a real MySQL (skips if unreachable)
```

Covered by `npm test`:

- URL heuristics (lookalikes, typosquats, IP hosts, userinfo tricks, HTTP, ports, TLDs)
- verdict rules (`SAFE` only with reputation confirmation, malicious always wins, errors degrade honestly)
- Safe Browsing + VirusTotal response mapping and provider failure handling
- validation (schemes, passwords, emails), JWT expiry, role separation, route shadowing
- scan response + scan-history persistence, duplicate-report rejection
- report → event → alert → notification creation
- analyst status update + reporter notification + alert sync
- health endpoint and JSON 404s

`npm run test:integration` performs the full real journey (register, login, scan, report, analyst
review, status update, user sees status, cross-account isolation) and **skips** when MySQL is not
available rather than pretending to pass.

Verified in development against **MariaDB 11.4** (MySQL-compatible): `npm run migrate`,
`npm run seed`, the 30-test unit/API suite, the integration journey, and an additional API walk-through
(scan → report → duplicate rejection → analyst investigation → mitigation action → reporter
notification → role boundaries) all passed on a live database.

---

## 10. Deployment

Full instructions: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

- **Database:** cloud MySQL (Aiven, PlanetScale, Railway…), then `npm run migrate` / `npm run seed`.
- **Backend:** Render or Railway, root `backend`, `npm ci && npm start`.
- **Dashboard:** Vercel, root `frontend` (static). Set the API URL as described in the deployment doc.
- **Extension:** unpacked locally now; `scripts/package-extension.sh` produces the Web Store zip.

---

## 11. Known limitations

- Heuristic scoring is pattern matching, **not** a commercial phishing engine. Expect false
  positives on unusual-but-legitimate domains and false negatives on brand-new phishing sites.
- The interstitial only triggers for sites **this user already scanned** and that were flagged
  `DANGEROUS` (or provider-confirmed `SUSPICIOUS`) during the session. CIRS does not proxy or
  inspect every page, does not block uncertain results, and provides no content scripts.
- Reputation results are cached in process memory (single instance). A multi-instance deployment
  should move the cache and rate limits to Redis.
- VirusTotal's public API reports only URLs it already knows; unknown URLs return `unknown`,
  which is surfaced as such.
- No email delivery is configured; report updates appear in the extension dashboard.

---

*CIRS — K.R. Mangalam University DBMS project, extended into a browser-extension security product.*
*Student: Pratham Sharma · Roll: 2401010229*
