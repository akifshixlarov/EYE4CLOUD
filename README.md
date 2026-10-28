# Azure Misconfiguration Scanner

A lightweight CSPM (Cloud Security Posture Management) tool that looks for the
most common configuration mistakes in an Azure environment. It runs read-only
(with the Reader role). Results are shown in an interactive Streamlit
dashboard: a 0-100 "posture score", a severity-coloured findings table, and
trend/diff comparison between scans.

## What this project does

| # | Check | Resource | Severity | CIS Azure Benchmark (v2.1.0) |
|---|-------|----------|----------|-------------------------------|
| 1 | Is Public Blob Access enabled? | Storage Account | High | 3.7 |
| 2 | Is Secure Transfer (HTTPS-only) enforced? | Storage Account | Medium | 3.1 |
| 3 | Is SSH(22)/RDP(3389) open from 0.0.0.0/0? | Network Security Group | High | 6.1 (RDP) / 6.2 (SSH) |
| 4 | Is Soft Delete enabled? | Key Vault | High | 8.5 |
| 5 | Is Purge Protection enabled? | Key Vault | High | 8.5 |
| 6 | Is the minimum TLS version below 1.2? | Storage Account | Medium | 3.15 |
| 7 | Are disks encrypted with a Customer Managed Key? | Virtual Machine | Medium | 7.2 |
| 8 | Is the VM attached directly to a public IP? | Virtual Machine | Medium | N/A |

Each finding comes with concrete remediation advice (and, where possible, a
ready-to-use `az cli` command). A user can mark a finding as "accepted risk"
(with a reason) to exclude it from the score calculation.

## Why this is not a copy of existing tools (ScoutSuite, Prowler)

The goal of this project is not to "invent" a new CSPM tool, but to understand
the internals of existing tools (ScoutSuite, Prowler, etc.) and build a
lightweight, extensible version focused on Azure. What is different:

- **Posture Score** — a weighted 0-100 score for every scan (`core/scoring.py`)
- **Scan history and diff** — results are stored as JSON and two scans are
  compared automatically for "new / resolved" issues (`core/diff.py`) —
  tools that produce a static HTML report don't have this
- **Live Streamlit dashboard** — not a static file, but an app that runs
  in real time with a "Start new scan" button

## Architecture

```
azure-scanner/
├── core/
│   ├── auth.py            # Microsoft sign-in (device code) / Service Principal / AzureCliCredential
│   ├── scanner.py         # runs all checks, writes JSON
│   ├── scoring.py         # 0-100 posture score
│   ├── diff.py            # comparison between scans, trend
│   ├── history.py         # scan history: list/load/delete files
│   ├── remediation.py     # "how to fix" for every check + ready az cli command
│   ├── exceptions.py      # "Accepted Risk" - accepted findings
│   ├── notifications.py   # Telegram / Teams / Slack notification (optional)
│   ├── scheduler.py       # background scheduled scans configured from the dashboard
│   ├── settings.py        # dashboard-saved settings (results/settings.json)
│   ├── security.py        # public mode, input validation, redaction, rate limits
│   └── dashboard_auth.py  # password protection for the dashboard (optional)
├── checks/
│   ├── storage_checks.py
│   ├── nsg_checks.py
│   ├── keyvault_checks.py
│   └── vm_checks.py           # disk CMK encryption, direct public IP
├── ui/                    # Streamlit components (connect panel, automation panel, charts, export, demo data)
├── scripts/
│   ├── scheduled_scan.py  # headless scan (Task Scheduler / cron / CI)
│   └── hash_password.py   # creates a bcrypt hash for the dashboard password
├── results/               # every scan is written here as scan_<timestamp>.json
│                          # + accepted_risks.json, settings.json
├── logs/                  # log of scheduled scans
├── .streamlit/config.toml # custom theme
└── app.py                 # Streamlit UI (4 tabs: Overview/Findings/History/
                           #                Accepted Risks)
```

Data flow: `checks/*.py` → `core/scanner.py` (merges, saves) →
`core/scoring.py` + `core/diff.py` (analysis) → `app.py` (display).

## Installation

### 1. Local run

```bash
git clone <repo-url>
cd azure-scanner
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

streamlit run app.py
```

`http://localhost:8501` opens in the browser. A `.env` file is optional — you
can connect directly from the dashboard (see below).

### 2. Connect from the dashboard

The **"Connect to Azure"** section in the left panel offers two sign-in methods:

**Sign in with Microsoft (recommended)** — no app registration or secret needed:
1. Enter your **Subscription ID(s)** (comma-separated, max 3).
2. Click **"🔐 Sign in with Microsoft"**.
3. A device code is shown — open `https://microsoft.com/devicelogin`, enter the
   code and sign in with your Microsoft account.
4. Once signed in, start the scan. The account needs the **Reader** role on the
   subscription.

**Service Principal (advanced)** — for automation or when device code sign-in
is not possible:
- **Tenant ID**, **Client ID** (App ID), **Client Secret** (masked input) and
  **Subscription ID(s)**.

Create a read-only Service Principal like this:

```bash
az ad sp create-for-rbac --name "azure-scanner-sp" \
  --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

This returns `appId` (client_id), `password` (client_secret) and `tenant`.
**Note:** only give the SP the `Reader` role — this tool performs no
write/change operations, it only reads.

#### Security guarantees
- **In-memory only:** credentials and tokens are kept only in the active Streamlit browser session (`st.session_state`).
- **Zero disk footprint:** Azure credentials and tokens are never written to disk, the `.env` file, the `results/` folder, server logs, JSON exports or URL parameters. (Exception, local mode only: a Telegram bot token you save in the Automation panel is stored in `results/settings.json` — see [Notifications](#notifications-telegram--teams--slack-optional).)
- **Error masking:** when an Azure SDK or authentication error occurs, error messages never include credential details.
- **One-click wipe:** the "🔌 Disconnect / Clear" button removes credentials from the session immediately.
- **Priority:** dashboard input > system `.env` file > active `az login` session.
- **Rule of thumb:** always use an account or Service Principal with only the **Reader** role (ideally on a test subscription).

### 3. `.env` file (optional)

```bash
cp .env.example .env
# fill in your own Service Principal values
```

### 4. Demo Mode (safe preview)

To show every dashboard feature without any Azure account or credentials:
- Turn on the **"🎮 Demo Mode (Safe Preview)"** toggle in the left panel.
- Realistic fake (mock) resources and findings load immediately.
- Ideal for public links or customer demos without risking a real cloud environment.

### 5. Public Mode (`PUBLIC_MODE=true` — multi-user public mode)

When the tool is deployed publicly (for example, so that unknown visitors on the
internet can connect their own Azure accounts), `PUBLIC_MODE=true` must be set
in the `.env` file or the container environment.

Security barriers in this mode:
- **Server credentials blocked:** the server's `AZURE_*` values from `.env` and `az login` are blocked entirely; the server's own identity is never used for visitor scans.
- **Full session isolation (memory only):** sign-in tokens, Tenant ID, Client ID, Client Secret and scan results are kept only in that session's RAM (`st.session_state`). No file is written to disk (`results/`, `logs/`, etc.). Previous visitors' scan files are never shown to anyone.
- **Automatic secret wipe:**
  - After 15 minutes of inactivity, all credentials and input fields (`input_*`) are deleted automatically.
  - Credentials are deleted as soon as a scan completes (unless "Stay connected after the scan" is ticked).
  - The Disconnect button clears all text buffers.
- **Strict input validation:** Tenant ID, Client ID and Subscription IDs are validated against a strict GUID regex (`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`). At most 3 subscriptions are allowed per session.
- **Anti-abuse and rate limiting:**
  - Per session, at most 5 connection tests / sign-in attempts and 3 scans per 10 minutes.
  - A global semaphore caps the number of scans running in parallel across the whole server (max 2).
  - If the dashboard password is enabled, exponential lockout applies after 3 failed attempts.
- **Leak prevention:**
  - All error messages and logs pass through `redact()`; secrets, Bearer tokens and JWTs are masked.
  - Azure SDK, urllib3 and MSAL log levels are raised to `WARNING` (HTTP bodies are not logged).
  - The Streamlit config sets `client.showErrorDetails = "none"` and `server.enableXsrfProtection = true`.

### 6. Run with Docker

```bash
docker build -t azure-scanner .
docker run -p 8501:8501 --env-file .env -v $(pwd)/results:/app/results azure-scanner
```

`-v $(pwd)/results:/app/results` matters — otherwise the scan history is lost
when the container restarts.

## Read-only check (terminal)

To test just the backend without the UI:

```bash
python -m core.scanner
```

## Running the tests

```bash
python -m pytest -q
```

`tests/test_credentials.py` covers session isolation, public mode and secret
redaction; `tests/test_automation.py` covers the scheduler, Telegram
notifications and settings-file permissions. No Azure or Telegram access is
needed — the SDK and HTTP calls are mocked.

## Scanning several subscriptions (optional)

Give a comma-separated list in `.env` (or in the dashboard) — each subscription
is scanned separately, the results are merged, and every finding records which
subscription it came from:

```bash
AZURE_SUBSCRIPTION_IDS=<sub-1-id>,<sub-2-id>
```

If left empty, the single `AZURE_SUBSCRIPTION_ID` is used (default behaviour).
The `Reader` role is needed on every subscription.

**Limitation:** findings are identified by the `(category, resource, check)`
triple — if two subscriptions have a resource with the same name, the diff and
"accepted risks" will treat them as the same finding.

## Dashboard password protection (optional)

**This is not production-grade authentication** — it is only for local
demos/presentations: a single user, a password stored in `.env`, no role model,
and Streamlit itself does not terminate HTTPS. For an internet-facing setup use
a reverse proxy + a proper identity provider instead.

First create a hash for the password:

```bash
python scripts/hash_password.py
```

Then add it to `.env`:

```bash
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD_HASH=<hash from above>
DASHBOARD_COOKIE_KEY=<random key>
```

`DASHBOARD_COOKIE_KEY` is **required** — the session cookie is signed with it.
If it is empty the dashboard will not open (a default key would be visible in
the repo and would allow bypassing the login screen). To generate one:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

If both are empty, the dashboard opens without a password (default behaviour).
A plain password (`DASHBOARD_PASSWORD`) also works, but then bcrypt is
recomputed on every page refresh — the hash variant is both faster and safer.

## Notifications: Telegram / Teams / Slack (optional)

When a scan finishes (manual or scheduled), a short summary (posture score,
total findings, new/resolved findings) is sent to every configured channel.

### Telegram (from the dashboard)

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy its token.
2. Send your bot any message (or add it to a group/channel), then get the chat
   ID (e.g. from @userinfobot; group IDs start with `-100`).
3. In the sidebar open **🤖 Automation → 📨 Telegram notifications**, turn it on,
   enter the token and chat ID, click **📤 Send test**, then **💾 Save**.

The token is saved in `results/settings.json` (git-ignored, `chmod 600`) and is
never shown back in the browser — leave the field empty to keep the saved one.
`TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` in `.env` also work (e.g. for the
cron script); dashboard settings take precedence when enabled.

### Teams / Slack (from `.env`)

```bash
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
# or
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

If nothing is configured, the notification step is skipped entirely — scan behaviour
does not change. If a network error occurs, the notification is quietly
dropped; the scan result has already been written to `results/`.

## Scheduled (automatic) scan

### From the dashboard

In the sidebar open **🤖 Automation → ⏰ Scheduled scan**, turn it on, pick
**Daily at a fixed time (UTC)** or **Every N hours**, optionally enter
Subscription ID(s), and click **💾 Save**. The next/last run and its status are
shown in the same panel; results appear in the scan history as
`scan_scheduled_<timestamp>.json`.

- Scheduled scans run with the **server's** credentials (`.env` Service
  Principal, or the `az login` session of the user running Streamlit) —
  dashboard sign-ins are session-only and are never stored for background use.
- The scheduler runs inside the Streamlit server process: it starts with the
  first page load after the server starts, and only runs while the server is up.
  A run missed while the server was down happens once on the next start.
- Not available with `PUBLIC_MODE=true`.
- **Security:** anyone who can open the dashboard can change the schedule and
  the Telegram target. If the app is reachable from other machines, enable
  [dashboard password protection](#dashboard-password-protection-optional).

### From the command line (cron / Task Scheduler / CI)

`scripts/scheduled_scan.py` runs a full scan without the UI, writes the result
to `results/` and appends a one-line summary to `logs/scheduled_scan.log`.
It returns exit code `0` on success and `1` on error.

```bash
python scripts/scheduled_scan.py
```

### Daily scan with Windows Task Scheduler

To run every day at 09:00 (adjust the paths):

```powershell
schtasks /create /tn "AzureScanner-Daily" /sc daily /st 09:00 ^
  /tr "C:\path\to\azure-scanner\venv\Scripts\python.exe C:\path\to\azure-scanner\scripts\scheduled_scan.py"
```

Check / delete:

```powershell
schtasks /query /tn "AzureScanner-Daily"
schtasks /run   /tn "AzureScanner-Daily"
schtasks /delete /tn "AzureScanner-Daily" /f
```

**Note:** Task Scheduler usually starts from a different working directory —
the script accounts for this (`.env` and paths are resolved from the project
root). However, in `AzureCliCredential` mode the `az login` session must be
active for that user; on a server/CI a Service Principal is more reliable.

### With GitHub Actions (alternative)

For example as `.github/workflows/scheduled-scan.yml`:

```yaml
name: Scheduled Azure Scan
on:
  schedule:
    - cron: "0 6 * * *"   # every day at 06:00 UTC
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - run: python scripts/scheduled_scan.py
        env:
          AZURE_SUBSCRIPTION_ID: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
          AZURE_TENANT_ID: ${{ secrets.AZURE_TENANT_ID }}
          AZURE_CLIENT_ID: ${{ secrets.AZURE_CLIENT_ID }}
          AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
      - uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: results/
```

**Note:** GitHub Actions has no `az login` session and cannot do interactive
Microsoft sign-in, so a Service Principal is required (App Registration
permission is needed in the tenant).

## Limitations

- Only the Reader role at subscription level is needed
- Currently limited to 4 Azure resource types (Storage, NSG, Key Vault, VM) —
  to extend it, adding a new module to the `checks/` folder is enough (keeping
  the same `{"category", "resource", "resource_group", "check", "issue",
  "severity", "compliance"}` format)
- The score methodology is a simple weighted deduction model, not academic risk
  modelling — the goal is to prioritise findings
- The VM disk encryption check only looks at Disk Encryption Set (SSE + CMK) —
  a VM encrypted with Azure Disk Encryption (ADE) may be wrongly flagged
- "Sign in with Microsoft" uses the `organizations` endpoint — personal
  Microsoft accounts and guest users may need the Service Principal method
