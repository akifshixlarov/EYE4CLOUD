"""
ui/demo_data.py

Realistic fake (demo) findings and scan data.
Used to safely showcase every dashboard feature
(gauge, donut, diff, trend, filters, remediation) without any Azure account.
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
            "check": "Secure transfer (HTTPS) should be required",
            "issue": "Storage account allows HTTP requests; unencrypted traffic is possible",
            "severity": "High",
            "compliance": "CIS 3.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Storage Account",
            "resource": "stoldbackup99",
            "resource_group": "rg-backup-archive",
            "check": "Minimum TLS version should be 1.2",
            "issue": "TLS version allows 1.0/1.1",
            "severity": "Medium",
            "compliance": "CIS 3.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Network Security Group",
            "resource": "nsg-backend-prod",
            "resource_group": "rg-production-eu",
            "check": "SSH (port 22) should not be open to the internet",
            "issue": "Inbound access to port 22 is allowed from 0.0.0.0/0 (anyone)",
            "severity": "High",
            "compliance": "CIS 6.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Network Security Group",
            "resource": "nsg-dmz-gateway",
            "resource_group": "rg-network-hub",
            "check": "RDP (port 3389) should not be open to the internet",
            "issue": "A rule allows direct access to port 3389 from the Internet",
            "severity": "High",
            "compliance": "CIS 6.1",
            "subscription_id": "demo-sub-analytics-02",
        },
        {
            "category": "Key Vault",
            "resource": "kv-shared-secrets",
            "resource_group": "rg-security-core",
            "check": "Soft-delete should be enabled",
            "issue": "Accidentally deleted keys and secrets can be lost immediately (purged)",
            "severity": "Medium",
            "compliance": "CIS 8.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Virtual Machine",
            "resource": "vm-legacy-app",
            "resource_group": "rg-legacy-apps",
            "check": "Managed disk encryption should be reviewed",
            "issue": "Disk is encrypted with the platform default key; CMK is required",
            "severity": "Low",
            "compliance": "CIS 7.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Dependency",
            "resource": "urllib3==1.26.4",
            "resource_group": "N/A",
            "check": "PyPI vulnerability (CVE)",
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
            "check": "Secure transfer (HTTPS) should be required",
            "issue": "Storage account allows HTTP requests; unencrypted traffic is possible",
            "severity": "High",
            "compliance": "CIS 3.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Storage Account",
            "resource": "stdevdatalake02",
            "resource_group": "rg-analytics-dev",
            "check": "Public blob read access should be disabled",
            "issue": "Anonymous users can read blob data directly from the internet",
            "severity": "High",
            "compliance": "CIS 3.5",
            "subscription_id": "demo-sub-analytics-02",
        },
        {
            "category": "Network Security Group",
            "resource": "nsg-backend-prod",
            "resource_group": "rg-production-eu",
            "check": "SSH (port 22) should not be open to the internet",
            "issue": "Inbound access to port 22 is allowed from 0.0.0.0/0 (anyone)",
            "severity": "High",
            "compliance": "CIS 6.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Key Vault",
            "resource": "kv-shared-secrets",
            "resource_group": "rg-security-core",
            "check": "Soft-delete should be enabled",
            "issue": "Accidentally deleted keys and secrets can be lost immediately (purged)",
            "severity": "Medium",
            "compliance": "CIS 8.1",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Key Vault",
            "resource": "kv-shared-secrets",
            "resource_group": "rg-security-core",
            "check": "Purge protection should be enabled",
            "issue": "No retention protection against malicious or accidental deletion",
            "severity": "Medium",
            "compliance": "CIS 8.2",
            "subscription_id": "demo-sub-production-01",
        },
        {
            "category": "Dependency",
            "resource": "requests==2.25.1",
            "resource_group": "N/A",
            "check": "PyPI vulnerability (CVE)",
            "issue": "GHSA-j8r2-6x86-q33q: Unintended leak of Proxy-Authorization header",
            "severity": "Medium",
            "compliance": "N/A",
            "subscription_id": "N/A",
        },
    ],
}


def get_demo_scans() -> list[dict]:
    """Returns the demo scans in chronological order."""
    return [DEMO_SCAN_PREVIOUS, DEMO_SCAN_LATEST]
