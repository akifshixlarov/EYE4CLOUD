# CLAUDE.md

Azure CSPM scanner (Streamlit). Read-only: everything must work with the **Reader** role.
Full user docs are in `README.md`.

## Conventions for checks
- One module per service in `checks/`, exposing `run_all_<x>_checks(clients) -> list[dict]`,
  registered once in `CHECK_MODULES` (`core/scanner.py`; the UI reuses it).
- Finding format (do not break - saved scan JSONs and the accepted-risk key depend on it):
  `{"category", "resource", "resource_group", "check", "issue", "severity", "compliance"}`;
  the scanner adds `"subscription_id"`. Issue text in English. Severity: High / Medium / Low.
- `(category, resource, check)` identifies a finding across scans - one finding per key.
  Child resources use `"parent/child"` as resource (e.g. SQL `"server/db"`).
- `compliance`: a CIS Azure Foundations ID only when verified, otherwise `"N/A"`.
- Every check ID needs an entry in `core/remediation.py` (advice + `az` command with
  `{resource}` / `{resource_group}` / `{server}` / `{database}` placeholders).
- New categories go into the default set in `core/scoring.py` (card shows 100/100 when clean).
- Defensive: wrap per-resource SDK calls (`HttpResponseError`) so one failure skips only that
  resource. A whole-module failure is caught by the scanner and recorded in `result["errors"]`.
- Tests in `tests/` use fake SDK objects (SimpleNamespace / MagicMock) - never real Azure.
  Run: `python -m pytest -q`.

## Checks

| Check ID | Category | Severity | Compliance |
|---|---|---|---|
| public_blob_access | Storage Account | High | CIS Azure 3.7 |
| secure_transfer | Storage Account | Medium | CIS Azure 3.1 |
| minimum_tls_version | Storage Account | Medium | CIS Azure 3.15 |
| open_management_port | Network Security Group | High | CIS Azure 6.1 / 6.2 |
| soft_delete | Key Vault | High | CIS Azure 8.5 |
| purge_protection | Key Vault | High | CIS Azure 8.5 |
| disk_cmk_encryption | Virtual Machine | Medium | CIS Azure 7.2 |
| vm_public_ip | Virtual Machine | Medium | N/A (no CIS equivalent) |
| sql_firewall_open_to_internet | Azure SQL | High | N/A - to verify |
| sql_allow_azure_services | Azure SQL | Medium | N/A - to verify |
| sql_public_network_access | Azure SQL | Medium | N/A - to verify |
| sql_min_tls | Azure SQL | Medium | N/A - to verify |
| sql_no_entra_admin | Azure SQL | Medium | N/A - to verify |
| sql_auditing_disabled | Azure SQL | Medium | N/A - to verify |
| sql_tde_disabled | Azure SQL | High | N/A - to verify |

## Status (branch `feature/more-checks`)
- [x] Task 1 - Azure SQL checks
- [ ] Task 2 - NSG: database / SMB / WinRM ports, any-any rules
- [ ] Task 3 - Public network access for Storage and Key Vault
- [ ] Task 4 - IAM (owners, wildcard custom roles, direct user assignments)
- [ ] Test-environment scripts (`scripts/create_test_resources.sh` / `delete_...`)
