# CIRS Browser Extension — Install & Usage

The extension checks the website you are on for phishing and scam indicators, lets you report it,
and shows the security team's investigation result. It talks only to your CIRS server.

---

## 1. Install (Developer Mode / unpacked)

1. Start the backend and make sure `GET http://localhost:3000/api/health` responds.
2. Open `chrome://extensions` in Chrome (116 or newer).
3. Turn on **Developer mode** (top-right).
4. Click **Load unpacked** and select the `extension/` folder of this repository.
5. The CIRS shield appears in the toolbar. Pin it for quick access.

> After changing extension files, press the reload icon on the CIRS card in `chrome://extensions`.
> Changes to the service worker require that reload; pages only need reopening.

---

## 2. First run

1. Click the toolbar icon → **Connect to CIRS**.
2. Enter your server URL, e.g. `http://localhost:3000/api` (development) or
   `https://your-cirs-api.onrender.com/api` (production).
3. Chrome asks for permission to contact **that server only** → Allow.
4. Choose **Create account** (name, email, password ≥ 8 chars with a letter and a number) or
   **Sign in** with an existing CIRS user account.

Analyst accounts are separate and sign in on the web dashboard, not in the extension.

---

## 3. Using it

| Action | Where |
|---|---|
| Scan the current website | Popup → **Scan this website** |
| See the verdict, risk score and reasons | Popup result card (expand "Show all reasons") |
| Report the website | Popup → **Report website** → choose a category, add an optional description → **Submit report** |
| Copy the report reference | Shown after submission, e.g. `CIRS-261116-7F3A2C` |
| Follow your reports and the analyst's status | Popup → **Security history**, or the side panel → **Reports** |
| Personal dashboard (scans, risk categories, activity, notifications) | Popup → **⤢**, or right-click the icon → *Open side panel* |
| Protection and notification settings | Popup → **⚙** (Settings page) |
| Warning page | Appears automatically before a website **you scanned and that came back dangerous** loads again |

The warning page shows the URL, risk score, reasons and recommended action. Options:

- **← Go back to safety** — leaves the site.
- **View risk details** — expands the indicators.
- **Continue to this website** — only enabled after ticking *"I understand the risk…"*.

Sites with `UNKNOWN` results are **not** blocked or intercepted; CIRS only warns about confirmed
high-risk results.

---

## 4. Permissions and what they are used for

| Permission | Why |
|---|---|
| `storage` | Save the server URL, session token, settings and local scan cache |
| `tabs` | Read the current tab's URL so you can scan it, and redirect a tab to the warning page |
| `notifications` | Desktop alerts for dangerous/suspicious sites and report updates |
| `sidePanel` | Personal security dashboard |
| `alarms` | Housekeeping of the notification-dedup log |
| `optional_host_permissions` (`https://*/*`, `http://*/*`) | Requested **only** for the one CIRS server you configure, so the extension can call its API |

The extension has **no content scripts**, does not read page contents, and does not request access to
the websites you visit. It only knows the URL Chrome displays in the address bar.

---

## 5. Packaging for the Chrome Web Store

```bash
bash scripts/package-extension.sh
# dist/cirs-extension-v2.0.0.zip
```

Upload that zip at <https://chrome.google.com/webstore/devconsole> and complete:

- **Single purpose:** "Helps a user check the security of the website they are on, report suspicious
  sites to their CIRS security team, and follow the investigation result."
- **Permission justifications** — reuse the table in section 4.
- **Remote code:** none (all JavaScript ships in the package; data comes from the CIRS REST API).
- **Data usage:** disclose that the email, password hash, scanned URLs, reports and notifications are
  stored on the user's own CIRS server; no browsing history; no data sold; no ads.
- **Privacy policy URL** — publish one that matches section 6.
- **Screenshots** — popup with a scan result, warning page, side-panel dashboard, report confirmation.

Bump `version` in `extension/manifest.json` before each upload.

---

## 6. Privacy summary

Collected and stored on your CIRS server:

- account: name, email, bcrypt password hash, sign-in timestamps;
- the URLs you explicitly scan or report, the resulting verdict, score and reasons;
- reports (URL, category, optional description, status, analyst notes);
- notifications generated for you.

Never collected: page content, form values, passwords, cookies, authentication tokens, private
messages, downloads or full browsing history. No third-party analytics.

Threat-intelligence lookups (when the server has keys) send **only the scanned URL** to Google
Safe Browsing and/or VirusTotal.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| "Connect the extension to your CIRS server" | Open Settings, save the server URL and allow access |
| "Offline" in the footer | Check the API URL, that the backend is running, and the network/proxy |
| Browser blocks the API call (CORS) | The backend allows `chrome-extension://` origins automatically; verify the URL ends in `/api` and the backend is reachable |
| "Your session expired" | Sign in again; analyst tokens last 8 h, user tokens 7 days by default |
| Scan returns `UNKNOWN` | No threat-intelligence key is configured on the server. That is expected and labelled heuristic-only |
| Warning page does not appear | The site must have been scanned and flagged dangerous by this extension; also check Settings → *Warn before high-risk websites load* |
| Changes to code not applied | Reload the extension on `chrome://extensions` |
| Report rejected as duplicate | The same user reported that URL within 24 h; the existing reference is shown |

---

## 8. Regenerating icons

```bash
node tools/generate-icons.js
```

Writes `extension/icons/icon{16,32,48,128}.png` (shield + check mark) with no external dependencies.
