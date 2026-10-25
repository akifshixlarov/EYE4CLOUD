"""
ui/demo_data.py

Realistik saxta (demo) tapıntılar və skan məlumatları.
Heç bir Azure hesabı tələb etmədən dashboard-un bütün imkanlarını
(gauge, donut, diff, trend, filtrlər, remediation) təhlükəsiz nümayiş etdirmək üçündür.
"""

from datetime import datetime, timezone, timedelta

_NOW = datetime.now(timezone.utc)
_YESTERDAY = _NOW - timedelta(days=1)
_TWO_DAYS_AGO = _NOW - timedelta(days=2)

DEMO_SCAN_PREVIOUS = {
    "scan_time": _YESTERDAY.isoformat(),
    "subscription_ids": ["demo-sub-production-01", "demo-sub-analytics-02"],
    "total_findings": 7,
    "findings": [
        {
            "category": "Storage Account",
            "resource": "stprodeuwest001",
            "resource_group": "rg-production-eu",
            "check": "Secure transfer (HTTPS) tələb olunmalıdır",
            "issue": "Storage account HTTP sorğularına icazə verir, şifrələnməmiş trafik mümkündür",
            "severity": "High",
            "compliance": "CIS 3.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Storage Account",
            "resource": "stoldbackup99",
            "resource_group": "rg-backup-archive",
            "check": "Minimum TLS versiyası 1.2 olmalıdır",
            "issue": "TLS versiyası 1.0/1.1-ə icazə verir",
            "severity": "Medium",
            "compliance": "CIS 3.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Network Security Group",
            "resource": "nsg-backend-prod",
            "resource_group": "rg-production-eu",
            "check": "SSH (port 22) internetə açıq olmamalıdır",
            "issue": "0.0.0.0/0 (hər kəs) üçün port 22-yə inbound icazə verilib",
            "severity": "High",
            "compliance": "CIS 6.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Network Security Group",
            "resource": "nsg-dmz-gateway",
            "resource_group": "rg-network-hub",
            "check": "RDP (port 3389) internetə açıq olmamalıdır",
            "issue": "Internet mənbəyindən 3389 portuna birbaşa icazə qaydası var",
            "severity": "High",
            "compliance": "CIS 6.1",
            "subscription_id": "demo-sub-analytics-02",
        },
        {
            "category": "Key Vault",
            "resource": "kv-shared-secrets",
            "resource_group": "rg-security-core",
            "check": "Soft-delete aktiv olmalıdır",
            "issue": "Təsadüfən silinən açar və sirlər dərhal itə bilər (purged)",
            "severity": "Medium",
            "compliance": "CIS 8.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Virtual Machine",
            "resource": "vm-legacy-app",
            "resource_group": "rg-legacy-apps",
            "check": "Managed disk şifrələnməsi yoxlanılmalıdır",
            "issue": "Disk platform default key ilə şifrələnib, CMK tələb olunur",
            "severity": "Low",
            "compliance": "CIS 7.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Dependency",
            "resource": "urllib3==1.26.4",
            "resource_group": "N/A",
            "check": "PyPI zəifliyi (CVE)",
            "issue": "CVE-2021-33503: ReDoS vulnerability in Catastrophic backtracking",
            "severity": "Medium",
            "compliance": "N/A",
            "subscription_id": "N/A",
        },
    ],
}

DEMO_SCAN_LATEST = {
    "scan_time": _NOW.isoformat(),
    "subscription_ids": ["demo-sub-production-01", "demo-sub-analytics-02"],
    "total_findings": 6,
    "findings": [
        {
            "category": "Storage Account",
            "resource": "stprodeuwest001",
            "resource_group": "rg-production-eu",
            "check": "Secure transfer (HTTPS) tələb olunmalıdır",
            "issue": "Storage account HTTP sorğularına icazə verir, şifrələnməmiş trafik mümkündür",
            "severity": "High",
            "compliance": "CIS 3.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Storage Account",
            "resource": "stdevdatalake02",
            "resource_group": "rg-analytics-dev",
            "check": "İctimai blob oxuma icazəsi (public access) bağlı olmalıdır",
            "issue": "Anonim istifadəçilər blob məlumatlarını birbaşa internetdən oxuya bilər",
            "severity": "High",
            "compliance": "CIS 3.5",
            "subscription_id": "demo-sub-analytics-02",
        },
        {
            "category": "Network Security Group",
            "resource": "nsg-backend-prod",
            "resource_group": "rg-production-eu",
            "check": "SSH (port 22) internetə açıq olmamalıdır",
            "issue": "0.0.0.0/0 (hər kəs) üçün port 22-yə inbound icazə verilib",
            "severity": "High",
            "compliance": "CIS 6.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Key Vault",
            "resource": "kv-shared-secrets",
            "resource_group": "rg-security-core",
            "check": "Soft-delete aktiv olmalıdır",
            "issue": "Təsadüfən silinən açar və sirlər dərhal itə bilər (purged)",
            "severity": "Medium",
            "compliance": "CIS 8.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Key Vault",
            "resource": "kv-shared-secrets",
            "resource_group": "rg-security-core",
            "check": "Purge protection aktiv olmalıdır",
            "issue": "Zərərli və ya təsadüfi silinmələrə qarşı qorunma müddəti yoxdur",
            "severity": "Medium",
            "compliance": "CIS 8.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Dependency",
            "resource": "requests==2.25.1",
            "resource_group": "N/A",
            "check": "PyPI zəifliyi (CVE)",
            "issue": "GHSA-j8r2-6x86-q33q: Unintended leak of Proxy-Authorization header",
            "severity": "Medium",
            "compliance": "N/A",
            "subscription_id": "N/A",
        },
    ],
}


def get_demo_scans() -> list[dict]:
    """Demo skanların xronoloji siyahısını qaytarır."""
    return [DEMO_SCAN_PREVIOUS, DEMO_SCAN_LATEST]
