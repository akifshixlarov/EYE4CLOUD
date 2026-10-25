# Azure Misconfiguration Scanner

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
azure-scanner/
├── core/
│   ├── auth.py       # Service Principal / AzureCliCredential autentifikasiyası
│   ├── scanner.py     # bütün check-ləri işə salır, JSON-a yazır
│   ├── scoring.py      # 0-100 posture score hesablaması
│   ├── diff.py           # skanlar arası müqayisə, trend
│   ├── history.py         # skan tarixçəsi: fayllları sadalamaq/yükləmək/silmək
│   ├── remediation.py      # hər check üçün "necə düzəldilir" + hazır az cli əmri
│   ├── exceptions.py        # "Accepted Risk" - qəbul edilmiş tapıntılar
│   ├── notifications.py      # Teams/Slack webhook bildirişi (opsional)
│   └── dashboard_auth.py      # dashboard-a parol qoruması (opsional)
├── checks/
│   ├── storage_checks.py
│   ├── nsg_checks.py
│   ├── keyvault_checks.py
│   ├── vm_checks.py           # disk CMK şifrələməsi, birbaşa public IP
│   └── dependency_checks.py   # OSV.dev ilə CVE yoxlaması (requirements.lock.txt)
├── scripts/
│   ├── scheduled_scan.py  # UI-siz skan (Task Scheduler / cron / CI üçün)
│   └── hash_password.py   # dashboard parolu üçün bcrypt hash yaradır
├── results/              # hər skan buraya scan_<timestamp>.json kimi yazılır
│                         # + accepted_risks.json
├── logs/                  # zamanlanmış skanların log-u
├── .streamlit/config.toml # custom theme
└── app.py                 # Streamlit UI (5 tab: Overview/Findings/History/
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
cd azure-scanner
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# .env faylını öz Service Principal dəyərlərinlə doldur

streamlit run app.py
```

Brauzerdə `http://localhost:8501` açılacaq.

### 3. Connect from Dashboard (v2 — .env olmadan birbaşa qoşulma)

Dashboard-un sol panelindəki **"Connect to Azure"** bölməsindən Service Principal məlumatlarını birbaşa daxil edə bilərsiniz:
- **Tenant ID**
- **Client ID** (App ID)
- **Client Secret** (`type="password"` ilə daxil edilir, ekranda maskalanır)
- **Subscription ID(s)** (vergüllə ayrılmış bir və ya bir neçə subscription)

#### Təhlükəsizlik Zəmanətləri (Security Guarantees):
- **Yalnız Yaddaşda (In-Memory Only):** Daxil edilən sirlər yalnız aktiv Streamlit brauzer sessiyasında (`st.session_state`) saxlanılır.
- **Sıfır Disk İzi:** Heç vaxt diskə, `.env` faylına, `results/` qovluğuna, server log-larına, JSON ixracına və ya URL parametrlərinə yazılmır.
- **Xəta Maskalanması:** Azure SDK və ya autentifikasiya xətası baş verdikdə xəta mətnlərində heç vaxt credential detalları əks olunmur.
- **Bir Kliklə Təmizləmə:** "🔌 Əlaqəni kəs / Təmizlə" düyməsi credential-ları dərhal sessiyadan silir.
- **Prioritet:** Dashboard daxiletməsi > Sistem `.env` faylı > Aktiv `az login` sessiyası.
- **Təhlükəsizlik Qaydası:** Həmişə yalnız **Reader** (oxuma) hüququ olan Service Principal istifadə edin (mümkünsə test abunəliyində).

### 4. Demo Mode (Təhlükəsiz Təqdimat Rejimi)

Heç bir Azure hesabı və ya credential olmadan dashboard-un bütün imkanlarını nümayiş etdirmək üçün:
- Sol paneldəki **"🎮 Demo Mode (Safe Preview)"** açarını aktiv edin.
- Realistik saxta (mock) resurslar və tapıntılar dərhal yüklənir.
- Public link və ya müştəri təqdimatları zamanı real bulud mühitinə təhlükə yaratmadan istifadə üçün idealdır.

### 5. Public Mode (`PUBLIC_MODE=true` — İctimai Çoxistifadəçili Rejim)

Aləti ictimaiyyətə açıq (məsələn, internet üzərindən tanımadığınız ziyarətçilərin öz Service Principal-larını daxil edə bilməsi üçün) yerləşdirdikdə `.env` faylında və ya konteyner parametrində `PUBLIC_MODE=true` mütləq təyin edilməlidir.

Bu rejimdə tətbiq edilən təhlükəsizlik baryerləri:
- **Server Credential-larının Bloklanması:** Serverdəki `.env` faylındakı `AZURE_*` parametrləri və `az login` icazələri tamamilə bloklanır; ziyarətçi skanları üçün heç vaxt serverin öz kimliyi istifadə olunmur.
- **Tam Sessiya İzolyasiyası (Memory-Only):** Ziyarətçilərin daxil etdiyi Tenant ID, Client ID, Client Secret və skan nəticələri yalnız həmin sessiyanın RAM-ında (`st.session_state`) saxlanılır. Diskə (`results/`, `logs/` və s.) heç bir fayl yazılmır. Əvvəlki ziyarətçilərin köhnə skan faylları heç kimə göstərilmir.
- **Sirrlərin Avtomatik Təmizlənməsi:**
  - 15 dəqiqə hərəkətsizlikdən sonra bütün credential-lar və daxiletmə sahələri (`input_*`) avtomatik silinir.
  - Skan tamamlandıqda credential-lar dərhal silinir ("Sessiyada saxla" seçilmədikdə).
  - Disconnect düyməsi bütün mətn buferlərini təmizləyir.
- **Sərt Giriş Validasiyası:** Tenant ID, Client ID və Subscription ID-lər ciddi GUID regex-i (`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`) ilə yoxlanılır. Bir sessiyada maksimum 3 subscription-a icazə verilir.
- **Anti-Abuse və Rate Limiting:**
  - Hər sessiya üçün 10 dəqiqə ərzində maksimum 5 əlaqə testi və 3 skan limiti.
  - Eyni anda bütün server üzrə paralel icra oluna bilən skan sayı qlobal semafor ilə məhdudlaşdırılır (maksimum 2 paralel skan).
  - Dashboard parolu aktivdirsə, 3 uğursuz cəhddən sonra eksponensial bloklanma (lockout) tətbiq olunur.
- **Məlumat Sızmalarının Qarşısının Alınması:**
  - Bütün xəta mesajları və loqlar `redact()` funksiyasından keçirilir; secret, Bearer token və JWT-lər maskalanır.
  - Azure SDK, urllib3 və MSAL loq səviyyələri `WARNING`-ə qaldırılmışdır (HTTP body-lər loglanmır).
  - Streamlit konfiqurasiyasında `client.showErrorDetails = "none"` və `server.enableXsrfProtection = true` aktivdir.


### 6. CVE/Dependency check üçün əlavə addım

OSV.dev sorğusu dəqiq versiya tələb edir, `requirements.txt`-də isə `>=` işlədilib. Ona görə bu check-in işləməsi üçün əvvəlcə dəqiq versiyalı fayl yaradılmalıdır:

```bash
pip freeze > requirements.lock.txt
```

Bu fayl yoxdursa, dependency check sakitcə 0 tapıntı qaytarır (xəta vermir).

### 7. Docker ilə işə salma

```bash
docker build -t azure-scanner .
docker run -p 8501:8501 --env-file .env -v $(pwd)/results:/app/results azure-scanner
```

`-v $(pwd)/results:/app/results` vacibdir — əks halda konteyner
yenidən başladıqda skan tarixçəsi itir.

## Yalnız oxumaq üçün yoxlama (terminal)

UI olmadan sadəcə backend-i test etmək üçün:

```bash
python -m core.scanner
```

## Bir neçə subscription skan etmək (opsional)

`.env`-də vergüllə ayrılmış siyahı ver — hər subscription ayrıca skan olunur,
nəticələr birləşdirilir və hər tapıntıda hansı subscription-dan gəldiyi qeyd
edilir:

```bash
AZURE_SUBSCRIPTION_IDS=<sub-1-id>,<sub-2-id>
```

Boş qoyulsa, tək `AZURE_SUBSCRIPTION_ID` istifadə olunur (defolt davranış).
Hər subscription üçün `Reader` rolu lazımdır.

**Məhdudiyyət:** tapıntılar `(kateqoriya, resurs, check)` üçlüyü ilə
tanınır — iki subscription-da eyni adlı resurs olarsa, diff və "qəbul edilmiş
risklər" onları eyni tapıntı kimi görəcək.

## Dashboard parol qoruması (opsional)

**Bu, production-grade autentifikasiya deyil** — yalnız lokal demo/təqdimat
üçündür: tək istifadəçi, `.env`-də saxlanan parol, rol modeli yoxdur və
Streamlit özü HTTPS terminasiyası etmir. İnternetə açılan quruluşda bunun
əvəzinə reverse proxy + normal identity provider istifadə edilməlidir.

Əvvəlcə parol üçün hash yarat:

```bash
python scripts/hash_password.py
```

Sonra `.env`-ə yaz:

```bash
DASHBOARD_USERNAME=admin
DASHBOARD_PASSWORD_HASH=<yuxarıdakı hash>
DASHBOARD_COOKIE_KEY=<təsadüfi açar>
```

`DASHBOARD_COOKIE_KEY` **məcburidir** — sessiya cookie-si onunla imzalanır.
Boş qalarsa dashboard açılmır (defolt açar repoda görünən olardı və giriş
ekranını keçməyə imkan verərdi). Yaratmaq üçün:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Hər ikisi boş olarsa dashboard parolsuz açılır (defolt davranış). Açıq parol
(`DASHBOARD_PASSWORD`) da işləyir, amma o halda hər səhifə yenilənməsində
bcrypt yenidən hesablanır — hash variantı həm daha sürətli, həm daha təhlükəsizdir.

## Webhook bildirişi (opsional)

Skan bitəndə Teams və ya Slack-ə qısa xülasə (posture score, ümumi tapıntı
sayı, yeni/həll olunan tapıntılar) göndərilə bilər. `.env`-də URL təyin et:

```bash
TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
# və ya
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Hər ikisi boş olarsa bildiriş mərhələsi tamamilə atlanır — skan davranışı
dəyişmir. Şəbəkə xətası baş verərsə bildiriş sakitcə buraxılır, skan
nəticəsi onsuz da `results/`-ə yazılıb.

## Zamanlanmış (avtomatik) skan

`scripts/scheduled_scan.py` UI olmadan tam skan icra edir, nəticəni
`results/`-ə yazır və `logs/scheduled_scan.log`-a bir sətirlik xülasə əlavə
edir. Uğurda `0`, xətada `1` exit kodu qaytarır.

```bash
python scripts/scheduled_scan.py
```

### Windows Task Scheduler ilə gündəlik skan

Hər gün saat 09:00-da işə salmaq üçün (yolları özünə uyğunlaşdır):

```powershell
schtasks /create /tn "AzureScanner-Daily" /sc daily /st 09:00 ^
  /tr "C:\path\to\azure-scanner\venv\Scripts\python.exe C:\path\to\azure-scanner\scripts\scheduled_scan.py"
```

Yoxlamaq / silmək:

```powershell
schtasks /query /tn "AzureScanner-Daily"
schtasks /run   /tn "AzureScanner-Daily"
schtasks /delete /tn "AzureScanner-Daily" /f
```

**Qeyd:** Task Scheduler adətən fərqli iş qovluğundan işə salır — skript
bunu nəzərə alır (`.env` və yollar layihə kökünə görə tapılır). Lakin
`AzureCliCredential` rejimində `az login` sessiyası həmin istifadəçi üçün
aktiv olmalıdır; server/CI mühitində Service Principal daha etibarlıdır.

### GitHub Actions ilə (alternativ)

`.github/workflows/scheduled-scan.yml` kimi:

```yaml
name: Scheduled Azure Scan
on:
  schedule:
    - cron: "0 6 * * *"   # hər gün 06:00 UTC
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

**Diqqət:** GitHub Actions-da `az login` sessiyası olmadığı üçün Service
Principal məcburidir (tenant-da App Registration icazəsi tələb olunur).

## Məhdudiyyətlər

- Yalnız subscription səviyyəsində Reader roluna ehtiyac var
- Hazırda 4 Azure resurs tipi ilə məhdudlaşır (Storage, NSG, Key Vault, VM) —
  genişlənmə üçün `checks/` qovluğuna yeni modul əlavə etmək kifayətdir (eyni
  `{"category", "resource", "resource_group", "check", "issue", "severity",
  "compliance"}` formatını saxlamaqla)
- Score metodologiyası sadə çəkili çıxma modelidir, akademik risk
  modelləşdirməsi deyil — məqsəd tapıntıları prioritetləşdirməkdir
- VM disk şifrələmə check-i yalnız Disk Encryption Set (SSE + CMK) yoxlayır —
  Azure Disk Encryption (ADE) ilə şifrələnmiş VM yanlış olaraq flag edilə bilər
- Yalnız bir subscription skan olunur (multi-subscription dəstəyi yoxdur)
