# CIRS Deployment Guide

Target setup:

```
Chrome Extension  ──HTTPS──▶  Backend (Render / Railway)  ──▶  Cloud MySQL
Analyst Dashboard ──HTTPS──▶              │
   (Vercel)                               └──▶ Google Safe Browsing / VirusTotal (optional)
```

Nothing in the production path depends on `localhost`.

---

## 1. Cloud MySQL

Any managed MySQL 8 / MariaDB 10.5+ works (Aiven, PlanetScale, Railway MySQL, DigitalOcean).
Create the database and note: host, port, user, password, database name, and whether TLS is required.

```bash
cd backend
cp .env.example .env
# point DB_* at the cloud instance
DB_HOST=...
DB_PORT=3306
DB_USER=...
DB_PASSWORD=...
DB_NAME=cybersecurity_irs
DB_SSL=true
DB_SSL_VERIFY=true

npm ci
npm run migrate     # additive: creates missing tables/columns, keeps existing rows
npm run seed        # optional demo accounts; set SEED_* passwords or read the generated ones
```

`npm run migrate` is safe to re-run. It never drops tables and never deletes records.

Verify:

```bash
mysql -h <host> -u <user> -p cybersecurity_irs -e "SHOW TABLES; SELECT COUNT(*) FROM WebsiteReport;"
```

Expected tables: `Analyst, SecurityEvent, Alert, Threat, Vulnerability, User, WebsiteReport,
ScanHistory, UserNotification, MitigationAction, SchemaMigration`.

---

## 2. Backend on Render

1. **New → Web Service** → connect the repository.
2. **Root Directory:** `backend`
3. **Build Command:** `npm ci`
4. **Start Command:** `npm start`
5. **Health Check Path:** `/api/health`
6. Add environment variables:

| Key | Value |
|---|---|
| `NODE_ENV` | `production` |
| `JWT_SECRET` | 48 random bytes (`node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`) |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | cloud MySQL |
| `DB_SSL` | `true` when the provider requires TLS |
| `CORS_ORIGINS` | `https://your-dashboard.vercel.app` |
| `TRUST_PROXY` | `true` |
| `SERVE_FRONTEND` | `false` if the dashboard is on Vercel (leave `true` to serve it from the API) |
| `SAFE_BROWSING_API_KEY` | optional |
| `VIRUSTOTAL_API_KEY` | optional |

Deploy, then confirm:

```bash
curl https://your-api.onrender.com/api/health
# {"status":"ok","database":{"connected":true,"schema":{"ready":true,...}},...}
```

If `status` is `degraded`, a migration has not run or a table is missing — the `missing` array names it.

### Railway alternative

Same variables; root `backend`; start `npm start`. Add the MySQL plugin and copy its connection
details into `DB_*`. Set `DB_SSL=true` if required.

---

## 3. Analyst dashboard on Vercel

The dashboard is static HTML/CSS/JS (no build step).

1. **New Project** → import the repository.
2. **Root Directory:** `frontend`
3. **Framework Preset:** Other
4. **Build Command:** empty
5. **Output Directory:** `.` (or leave blank)
6. Deploy.

Point it at the API — choose one:

- **Recommended:** edit the `<meta name="cirs-api-base" content="">` tag in `frontend/index.html`
  to `content="https://your-api.onrender.com/api"`.
- Or set the `PRODUCTION_API_BASE` constant at the top of `frontend/js/config.js`.
- Or, without a rebuild: open the deployed site with `?api=https://your-api.onrender.com/api`
  (stored in `localStorage` for that browser) — convenient for a one-off demo.

Then set the backend's `CORS_ORIGINS` to the exact Vercel URL and redeploy the backend.

Sign in at `https://your-dashboard.vercel.app/` with the seeded analyst credentials.

---

## 4. Threat intelligence (optional)

Without keys CIRS runs heuristic-only scans and labels every result as such.

### Google Safe Browsing

1. Google Cloud Console → create/select a project.
2. **APIs & Services → Library → Safe Browsing API → Enable**.
3. **Credentials → Create credentials → API key**; restrict it to the Safe Browsing API.
4. Set `SAFE_BROWSING_API_KEY` on the backend and restart.

### VirusTotal

1. Create a VirusTotal account → **API Key** in your profile.
2. Set `VIRUSTOTAL_API_KEY` on the backend and restart.

The public VirusTotal API has a low quota (≈4 requests/minute). CIRS caches results
(`THREAT_INTEL_CACHE_TTL_SECONDS`) and enforces `THREAT_INTEL_MIN_INTERVAL_MS` between calls.
Check what is active:

```bash
curl https://your-api.onrender.com/api/scan/providers
```

Only the specific URL being scanned is sent to a provider — never a browsing history.

---

## 5. Browser extension distribution

**Local / demo:** load `extension/` unpacked (see [EXTENSION-INSTALL.md](EXTENSION-INSTALL.md)).
Each install enters the deployed API URL once in the popup or Settings.

**Chrome Web Store:**

```bash
bash scripts/package-extension.sh
# dist/cirs-extension-v2.0.0.zip
```

Upload the zip at <https://chrome.google.com/webstore/devconsole>, complete the listing
(single purpose, screenshots, privacy policy URL, permission justifications in
[EXTENSION-INSTALL.md](EXTENSION-INSTALL.md)), and submit for review.

After the extension is published, its ID changes from the unpacked one. The backend already accepts
any `chrome-extension://` origin, so no CORS change is needed. If you later pin the extension ID,
add it to `CORS_ORIGINS` as `chrome-extension://<id>` for extra tightness.

---

## 6. Post-deployment checklist

1. `GET /api/health` → `status: ok`, `database.connected: true`, `schema.ready: true`.
2. Analyst login on the Vercel URL succeeds; dashboard loads statistics.
3. Extension: connect to the deployed API, register an account, scan
   `http://paypal-secure-login.xyz/verify` → expect `SUSPICIOUS` with lookalike reasons.
4. Report it → reference ID returned; the report appears in **User Reports** on the dashboard.
5. Analyst sets **Confirmed Threat** → the extension's Reports tab shows the new status and the
   Alerts tab shows the notification.
6. Invalid login returns 401; an expired token returns 401 `TOKEN_EXPIRED`; no token returns 401;
   a user token on an analyst endpoint returns 403.
7. `GET /api/scan/providers` reflects whether reputation lookups are active.

---

## 7. Operational notes

- **Rate limits and the reputation cache are in process memory.** On more than one instance, move
  both to Redis (or pin a single instance) so limits stay effective.
- **Rotate `JWT_SECRET`** to sign every session out; users simply sign in again.
- **Backups:** enable automated backups on the managed MySQL.
- **Logs:** the backend logs method/path/status per API call and never logs passwords or tokens.
- **Free-tier cold starts:** Render free instances sleep; the extension shows an offline state and a
  retry works once the service wakes.
- **TLS:** always use `https://` for the API in production. The extension accepts `http://` only for
  local development.
