# EYE4CLOUD — Security Audit Report (Hardened v2)

> **Date:** 2026-10-25  
> **Target:** EYE4CLOUD (Azure Cloud Security Posture Management Scanner)  
> **Branch:** `feature/public-hardening`  
> **Audit Type:** Public-Facing Security Architecture & Penetration Defense Audit  
> **Status:** PASSED (All blocker architectural risks resolved)  

---

## Executive Summary

This audit assesses the readiness of EYE4CLOUD to be hosted on a **public-facing URL** where untrusted visitors can enter their own Azure credentials.

### Overall Verdict: **SAFE FOR PUBLIC DEPLOYMENT (under PUBLIC_MODE=true)**

- **Session Isolation (PASSED):** The module-level global variable `_runtime_credentials` has been **completely eliminated**. Credentials and SDK client instances are constructed strictly within session scope and passed as explicit arguments.
- **Diskless Public Execution (PASSED):** Under `PUBLIC_MODE=true`, scan results and accepted risks are held **strictly in session memory** (`st.session_state`). No visitor data is written to `results/` on disk.
- **Server Credential Protection (PASSED):** When `PUBLIC_MODE=true`, all server-side environment variables (`AZURE_*`) and local Azure CLI login sessions are completely ignored and blocked with `PermissionError`.
- **Abuse & DOS Protection (PASSED):** A global scan semaphore caps concurrent scans to 2 simultaneous executions; session-level rate limiters block flood attacks; strict GUID validation prevents injection; and an inactivity timeout purges secrets after 15 minutes.

---

## 1. Before vs. After Hardening Comparison

| Security Dimension | Initial State (`feature/dashboard-v2`) | Hardened State (`feature/public-hardening`) | Verdict |
|---|---|---|---|
| **Module-level Global State** | **RISKY:** `core.auth._runtime_credentials` was process-global; concurrent users could overwrite or read each other's credentials. | **SAFE:** `_runtime_credentials` removed. All credentials passed explicitly as parameters into `get_clients()`, `run_scan()`, and `execute_parallel_scan()`. | **RESOLVED** |
| **Cross-Session Scan Isolation** | **RISKY:** `list_session_scans()` had a fallback to show all `scan_*.json` files to new sessions. | **SAFE:** In public mode, scans exist ONLY in `st.session_state["session_scans"]`. Disk writes disabled; legacy fallback removed. | **RESOLVED** |
| **Accepted Risks Isolation** | **RISKY:** Shared `results/accepted_risks.json` on disk was read/written by all visitors. | **SAFE:** In-memory store `st.session_state["accepted_risks_store"]` used per session. Zero disk touches in public mode. | **RESOLVED** |
| **Server Credential Leakage** | **RISKY:** If visitor entered no credentials, scanner could fall back to server `.env` or `az cli`. | **SAFE:** Under `PUBLIC_MODE=true`, server env credentials and `az cli` are completely blocked; raises `PermissionError`. | **RESOLVED** |
| **Widget Memory Cleanup** | **RISKY:** Disconnect cleared `azure_creds`, but left widget buffer keys (`input_client_secret`) in memory. | **SAFE:** `wipe_session_credentials()` explicitly pops all input widget keys and overwrites memory references. | **RESOLVED** |
| **Input Validation** | **RISKY:** Inputs accepted arbitrary strings with no GUID checks. | **SAFE:** Strict regex GUID validation (8-4-4-4-12 hex) for Tenant, Client, and Sub IDs. Max 3 subscriptions, secret length bounded (8–128). | **RESOLVED** |
| **Abuse & DOS Prevention** | **NONE:** Unlimited concurrent scans and connection tests were possible. | **SAFE:** Global semaphore limits simultaneous scans to 2. Per-session rate limiter enforces max 5 tests and 3 scans per 10 minutes. | **RESOLVED** |
| **Auto-Expiration** | **NONE:** Credentials remained in memory until the server restarted or session timed out. | **SAFE:** Auto-clear after 15 minutes of inactivity; auto-clear immediately after scan finishes (unless "Keep connected" is opted into). | **RESOLVED** |
| **Central Redaction** | **PARTIAL:** Handled ad-hoc in error try/catch blocks. | **SAFE:** Central `core.security.redact()` masks secrets, Bearer tokens, and JWTs from log lines and exceptions. | **RESOLVED** |
| **Streamlit Configuration** | **DEFAULT:** Debug details and toolbar were visible to visitors. | **SAFE:** `.streamlit/config.toml` sets `client.showErrorDetails = "none"`, `toolbarMode = "viewer"`, `enableXsrfProtection = true`. | **RESOLVED** |
| **Dashboard Brute-Force** | **NONE:** Unlimited login attempts allowed against `core/dashboard_auth.py`. | **SAFE:** Exponential lockout delay enforced after 3 failed attempts (up to 300s). | **RESOLVED** |

---

## 2. Complete Credential Lifecycle Trace (Hardened)

The table below traces each credential from user input to disposal under `PUBLIC_MODE=true`:

| Step | Action | Files & Line Numbers | Values Involved | Storage Medium |
|---|---|---|---|---|
| **1. Consent** | Visitor must check the Reader-only & non-critical test confirmation checkbox. | [ui/auth_panel.py:58-69](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/auth_panel.py#L58-L69) | User consent boolean | In-memory session state |
| **2. UI Input** | User enters credentials into validated fields (`max_chars` bounded, password masked). | [ui/auth_panel.py:84-128](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/auth_panel.py#L84-L128) | `tenant_id`, `client_id`, `client_secret`, `subscription_ids` | Browser DOM & Streamlit widget buffer |
| **3. Strict Validation** | Input validated against GUID regex and length bounds before any network call. | [core/security.py:46-99](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/security.py#L46-L99) | `tenant_id`, `client_id`, `client_secret`, `subscription_ids` | Memory only |
| **4. Rate Check** | Session rate limiter checks 10-minute operation quota. | [core/security.py:126-147](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/security.py#L126-L147) | Operation timestamp | `st.session_state["rate_limits"]` |
| **5. Ephemeral Credential** | `_build_credential(credentials)` builds `ClientSecretCredential` strictly for this call. | [core/auth.py:59-80](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/auth.py#L59-L80) | `tenant_id`, `client_id`, `client_secret` | Ephemeral `ClientSecretCredential` object |
| **6. Token Exchange** | Azure SDK queries Microsoft Entra ID token endpoint via HTTPS POST. | `azure.identity.ClientSecretCredential` | `tenant_id`, `client_id`, `client_secret` | TLS-encrypted socket to `login.microsoftonline.com` |
| **7. Concurrency Gate** | `GLOBAL_SCAN_SEMAPHORE.acquire(blocking=False)` checks server capacity. | [ui/scanner_runner.py:61-66](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/scanner_runner.py#L61-L66) | Thread lock | Process-level Semaphore |
| **8. In-Memory Skan Store** | Findings aggregated into session state; disk save skipped in public mode. | [ui/scanner_runner.py:117-124](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/scanner_runner.py#L117-L124) | Scan findings & `subscription_ids` only | `st.session_state["session_scans"]` |
| **9. Post-Scan Auto-Wipe** | If `keep_connected` is False (default), credentials are wiped immediately. | [ui/scanner_runner.py:133-136](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/scanner_runner.py#L133-L136) | Clears `azure_creds` and widget keys | Memory flushed |
| **10. Inactivity Expire** | If user is idle for >15 minutes, credentials auto-purge on next interaction. | [core/security.py:150-164](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/security.py#L150-L164) | Memory purge | `wipe_session_credentials()` executed |

---

## 3. Detailed Answers with Evidence

### a. Is it stored only in memory or written anywhere?
- **Evidence:** [ui/auth_panel.py:139](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/auth_panel.py#L139), [core/security.py:167-195](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/security.py#L167-L195).
- **Answer:** **EXCLUSIVELY IN MEMORY.** Credentials exist only within the visitor's `st.session_state["azure_creds"]` and are cleared by `wipe_session_credentials()`.

### b. Is it written to disk?
- **Evidence:** [core/scanner.py:75-77](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/scanner.py#L75-L77), [ui/scanner_runner.py:117-124, 142-146](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/ui/scanner_runner.py#L117-L146), [core/exceptions.py:28-33](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/exceptions.py#L28-L33).
- **Answer:** **NO.**
  - `.env`: Never written to.
  - `results/*.json`: When `PUBLIC_MODE=true`, `_save_result()` and `save_session_scan()` are short-circuited and write nothing to disk.
  - `logs/`: No dashboard logger writes to disk.
  - `accepted_risks.json`: In public mode, all accepted risks are held in `st.session_state["accepted_risks_store"]`.
  - Cache files / Temp files / Streamlit cache: None are used.

### c. Can it appear in logs, print statements, tracebacks, exception messages, or UI?
- **Evidence:** [app.py:13-16](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/app.py#L13-L16), [core/security.py:102-123](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/security.py#L102-L123), [core/auth.py:183-203](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/auth.py#L183-L203), [.streamlit/config.toml:11-13](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/.streamlit/config.toml#L11-L13).
- **Answer:** **NO.**
  - Central `redact()` scrubs secrets and tokens before logging.
  - Loggers for `"azure"`, `"urllib3"`, `"msal"`, and `"azure.identity"` are set to `WARNING`, preventing HTTP request/response header/body dumps.
  - Streamlit config sets `client.showErrorDetails = "none"` so raw tracebacks are never shown to visitors.

### d. Is it ever included in URLs, query params, cookies, or webhook notifications?
- **Evidence:** [core/dashboard_auth.py:23](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/dashboard_auth.py#L23), [core/scanner.py:111-114](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/scanner.py#L111-L114).
- **Answer:** **NO.**
  - URLs / Query params: `st.query_params` is never set with credentials.
  - Cookies: The only cookie is `azure_scanner_auth` for dashboard password protection.
  - Webhooks: In `PUBLIC_MODE=true`, `_notify()` is completely disabled.

### e. Outbound Network Destinations
Every outbound network call in the project:

| Destination Host | Protocol / Method | Triggered by | Purpose | Azure Credentials Included? |
|---|---|---|---|---|
| `login.microsoftonline.com` | HTTPS POST | `ClientSecretCredential` | OAuth2 Token exchange | **YES** (Standard Microsoft Entra ID auth) |
| `management.azure.com` | HTTPS GET | `azure-mgmt-*` | Read-only resource audits | **NO secrets** (Bearer token only) |
| `api.osv.dev` | HTTPS POST | [checks/dependency_checks.py:70](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/checks/dependency_checks.py#L70) | PyPI package vulnerability lookup | **NO** (Only package names/versions) |

### f. Cross-User / Cross-Session Sharing
- **Evidence:** [core/auth.py:48-80](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/core/auth.py#L48-L80), [tests/test_credentials.py:54-118](file:///e:/Main%20Programs/dell/Projects/EYE4CLOUD/tests/test_credentials.py#L54-L118).
- **Answer:** **COMPLETELY ISOLATED.**
  - Module-level `_runtime_credentials` has been removed.
  - Session A's credentials are never accessible to Session B.
  - Session B never sees Session A's findings, scans, or accepted risks.

### g. Credential Lifetime and Lifecycle Events
- **Browser Refresh (F5):** Persists in `st.session_state` of that specific visitor's browser session.
- **Tab Close:** Disconnects websocket; Streamlit garbage-collects session state after timeout.
- **Session Inactivity (>15 min):** Automatically purged by `check_inactivity()`.
- **Post-Scan:** Wiped immediately if "Keep connected" is unchecked (default).
- **Disconnect Button:** Wipes credentials, widget inputs, and memory references via `wipe_session_credentials()`.

---

## 4. Inherent Limits (What This Audit CANNOT Prove)

1. **Client-Side Host Compromise:** If a visitor's browser has malicious extensions or their operating system has keyloggers, inputs can be captured before reaching the HTTPS boundary.
2. **Reverse Proxy / TLS Termination:** Streamlit binds to HTTP on port 8501. In a public deployment, you **must** place it behind a reverse proxy (e.g., Caddy, NGINX, Azure Front Door, or Cloudflare) with valid HTTPS/TLS certificates.
3. **Azure RBAC Misconfiguration:** The scanner cannot prevent a user from entering credentials for an overly privileged (e.g., Owner/Contributor) Service Principal. The dashboard UI actively warns users to use Reader-only.

---

## 5. Deployment Checklist: Before Going Public

- [ ] **1. Set Environment Variable:**
  ```bash
  export PUBLIC_MODE=true
  ```
- [ ] **2. Verify HTTPS Termination:**
  Ensure the public domain uses HTTPS (TLS 1.2/1.3) via Cloudflare, Azure App Service, or reverse proxy. Never expose `http://` directly.
- [ ] **3. Bind to Localhost / Container Network:**
  Run Streamlit with:
  ```bash
  streamlit run app.py --server.address 127.0.0.1 --server.port 8501
  ```
- [ ] **4. Verify Tests Pass:**
  ```bash
  python -m pytest -v tests/
  ```
  Ensure all 6 tests in `tests/test_credentials.py` pass.
