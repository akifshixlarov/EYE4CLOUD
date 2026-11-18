# Azure Misconfiguration Scanner

> 🌐 *English version: [README.md](README.md)*

Azure mühitində ən çox rast gəlinən 4 konfiqurasiya səhvini axtaran, read-only
(Reader rolu ilə) işləyən yüngül CSPM (Cloud Security Posture Management)
aləti. Nəticələr interaktiv Streamlit dashboard-unda göstərilir: 0-100
"posture score", severity-yə görə rənglənmiş tapıntı cədvəli, və skanlar
arasında trend/diff müqayisəsi.

## Bu layihə nə edir

| # | Check | Resurs | Severity | CIS Azure Benchmark (v2.1.0) |
|---|-------|--------|----------|-------------------------------|
| 1 | Public Blob Access aktivdirmi? | Storage Account | High | 3.7 |
| 2 | Secure Transfer (HTTPS-only) məcburidirmi? | Storage Account | Medium | 3.1 |
| 3 | 0.0.0.0/0-dan SSH(22)/RDP(3389) açıqdırmı? | Network Security Group | High | 6.1 (RDP) / 6.2 (SSH) |
| 4 | Soft Delete aktivdirmi? | Key Vault | High | 8.5 |
| 5 | Purge Protection aktivdirmi? | Key Vault | High | 8.5 |
| 6 | Minimum TLS versiyası 1.2-dən aşağıdırmı? | Storage Account | Medium | 3.15 |
| 7 | Disk-lər Customer Managed Key ilə şifrələnibmi? | Virtual Machine | Medium | 7.2 |
| 8 | VM birbaşa public IP-yə bağlıdırmı? | Virtual Machine | Medium | N/A |
| 9 | Layihənin öz asılılıqlarında bilinən CVE varmı? (OSV.dev) | Dependency | High/Medium/Low | N/A (əhatə xaricində) |

Hər tapıntının yanında konkret remediation təklifi (və mümkünsə hazır `az
cli` əmri) göstərilir, istifadəçi bir tapıntını "bilərəkdən qəbul edirəm"
kimi işarələyib (səbəblə birlikdə) score hesablamasından çıxara bilər.

## Niyə bu layihə mövcud alətlərin (ScoutSuite, Prowler) təkrarı deyil

Bu layihənin məqsədi yeni bir CSPM aləti "icad etmək" deyil — mövcud
alətlərin (ScoutSuite, Prowler və s.) daxili məntiqini anlayıb, Azure-a
fokuslanmış, yüngül və genişlənə bilən öz versiyasını qurmaqdır. Fərqli
olan əsas hissə:

- **Posture Score** — hər skan üçün 0-100 arası çəkili bal (`core/scoring.py`)
- **Skan tarixçəsi və diff** — nəticələr JSON kimi saxlanılır, iki skan
  arasında "yeni yaranan / həll olunan" problemlər avtomatik müqayisə olunur
  (`core/diff.py`) — statik HTML report verən alətlərdə bu yoxdur
- **Canlı Streamlit dashboard** — statik fayl deyil, "Yeni skan başlat"
  düyməsi ilə real-time işləyən tətbiq

## Arxitektura

```
eye4cloud/
├── core/
│   ├── auth.py              # Service Principal / AzureCliCredential autentifikasiyası
│   ├── scanner.py           # bütün check-ləri işə salır, JSON-a yazır
│   ├── scoring.py           # 0-100 posture score hesablaması
│   ├── diff.py              # skanlar arası müqayisə, trend
│   ├── history.py           # skan tarixçəsi: faylları sadalamaq/yükləmək/silmək
│   ├── remediation.py       # hər check üçün "necə düzəldilir" + hazır az cli əmri
│   ├── exceptions.py        # "Accepted Risk" - qəbul edilmiş tapıntılar
│   ├── notifications.py     # Teams/Slack webhook bildirişi (opsional)
│   └── dashboard_auth.py    # dashboard-a parol qoruması (opsional)
├── checks/
│   ├── storage_checks.py
│   ├── nsg_checks.py
│   ├── keyvault_checks.py
│   ├── vm_checks.py         # disk CMK şifrələməsi, birbaşa public IP
│   └── dependency_checks.py # OSV.dev ilə CVE yoxlaması (requirements.lock.txt)
├── scripts/
│   ├── scheduled_scan.py    # UI-siz skan (Task Scheduler / cron / CI üçün)
│   └── hash_password.py     # dashboard parolu üçün bcrypt hash yaradır
├── results/                 # hər skan buraya scan_<timestamp>.json kimi yazılır
│                            # + accepted_risks.json
├── logs/                    # zamanlanmış skanların log-u
├── .streamlit/config.toml   # custom theme
└── app.py                   # Streamlit UI (5 tab: Overview/Findings/History/
                             #                Dependencies/Accepted Risks)
```

Data axını: `checks/*.py` → `core/scanner.py` (birləşdirir, saxlayır) →
`core/scoring.py` + `core/diff.py` (analiz) → `app.py` (göstərir).

## Quraşdırma

### 1. Azure tərəfi — Service Principal yaratmaq

```bash
az ad sp create-for-rbac --name "azure-scanner-sp" \
  --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

Bu, `appId` (client_id), `password` (client_secret) və `tenant` verəcək.
**Diqqət:** SP-yə yalnız `Reader` rolu verilməlidir — bu alət heç bir
yazma/dəyişmə əməliyyatı etmir, yalnız oxuyur.

### 2. Lokal işə salma

```bash
git clone <repo-url>
cd eye4cloud
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# .env faylını öz Service Principal dəyərlərinlə doldur

streamlit run app.py
```

Brauzerdə `http://localhost:8501` açılacaq.

### 3. Dashboard-dan birbaşa qoşulma (v2 — .env olmadan)

Dashboard-un sol panelindəki **"Connect to Azure"** bölməsindən Service Principal məlumatlarını birbaşa daxil edə bilərsiniz:
- **Tenant ID**
- **Client ID** (App ID)
- **Client Secret** (`type="password"` ilə daxil edilir, ekranda maskalanır)
- **Subscription ID(s)** (vergüllə ayrılmış bir və ya bir neçə subscription)

#### Təhlükəsizlik Zəmanətləri:
- **Yalnız Yaddaşda:** Sirlər yalnız aktiv Streamlit sessiyasında (`st.session_state`) saxlanılır.
- **Sıfır Disk İzi:** Heç vaxt diskə, `.env`-ə, `results/`-ə, server log-larına yazılmır.
- **Xəta Maskalanması:** Credential detalları heç vaxt xəta mətnlərində əks olunmur.
- **Bir Kliklə Təmizləmə:** "Əlaqəni kəs" düyməsi credential-ları dərhal silir.
- **Avtomatik Müddətin Bitməsi:** 15 dəqiqə hərəkətsizlikdən sonra silinir.

### 4. Demo Mode (Təhlükəsiz Təqdimat Rejimi)

Sol paneldəki **"🎮 Demo Mode (Safe Preview)"** açarını aktiv edin. Heç bir Azure hesabı tələb olunmur.

### 5. Public Mode (`PUBLIC_MODE=true`)

İnternetə açıq yerləşdirildikdə `.env`-də `PUBLIC_MODE=true` təyin edin:

- Server credential-ları tamamilə bloklanır
- Ziyarətçi məlumatları yalnız RAM-da saxlanılır
- Rate limiting: 10 dəqiqədə maks 5 test + 3 skan
- Qlobal semafor: eyni anda maks 2 paralel skan
- Bütün loglar `redact()` ilə sirrlərdən təmizlənir

### 6. CVE/Dependency yoxlaması

```bash
pip freeze > requirements.lock.txt
```

Bu fayl yoxdursa, dependency check sakitcə 0 tapıntı qaytarır.

### 7. Docker ilə işə salma

```bash
docker build -t eye4cloud .
docker run -p 8501:8501 --env-file .env -v $(pwd)/results:/app/results eye4cloud
```

## Zamanlanmış (avtomatik) skan

```bash
python scripts/scheduled_scan.py
```

### Windows Task Scheduler ilə gündəlik skan

```powershell
schtasks /create /tn "EYE4CLOUD-Daily" /sc daily /st 09:00 `
  /tr "C:\path\to\venv\Scripts\python.exe C:\path\to\eye4cloud\scripts\scheduled_scan.py"
```

### GitHub Actions ilə

`.github/workflows/scheduled-scan.yml` kimi:

```yaml
name: Scheduled Azure Scan
on:
  schedule:
    - cron: "0 6 * * *"
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

## Dashboard parol qoruması (opsional)

**Bu, production-grade autentifikasiya deyil** — yalnız lokal demo üçündür.

```bash
python scripts/hash_password.py
```

`.env`-ə yaz:
```bash
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD_HASH=<hash>
DASHBOARD_COOKIE_KEY=<python -c "import secrets; print(secrets.token_hex(32))">
```

## Webhook bildirişi (opsional)

```bash
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## Məhdudiyyətlər

- Hazırda 4 Azure resurs tipi ilə məhdudlaşır (Storage, NSG, Key Vault, VM)
- VM disk şifrələmə check-i yalnız Disk Encryption Set (SSE + CMK) yoxlayır — ADE ilə şifrələnmiş VM yanlış flag edilə bilər
- Score metodologiyası sadə çəkili çıxma modelidir (High×15 + Medium×7 + Low×3)
- Tapıntı açarı `(category, resource, check)` — subscription_id daxil deyil
