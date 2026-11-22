# Contributing to EYE4CLOUD

Thank you for your interest in improving EYE4CLOUD! Contributions from the security and cloud engineering community are welcome.

---

## Code of Conduct & Principles

1. **Read-Only by Design:** EYE4CLOUD is strictly a non-intrusive auditor. Every scanner check must work with standard Azure **Reader** role permissions. Write or mutate operations against target subscriptions are strictly forbidden.
2. **Defensive Error Handling:** Never let a failure in one resource or module crash the entire scan. Wrap individual SDK calls (e.g. handling `HttpResponseError`) so that permission errors or unregistered resource providers are recorded gracefully.
3. **Mocked Testing:** Unit tests in `tests/` must use mock objects (`unittest.mock.MagicMock`). Never make live network or authentication calls during automated testing.

---

## Adding a New Security Check

Adding support for a new Azure check is straightforward. Follow these steps:

### 1. Create or Update Check Module in `checks/`
Each service has its own module in `checks/` (e.g., `checks/storage_checks.py`, `checks/sql_checks.py`).

Your check function accepts an `AzureClients` object and returns a list of dictionaries adhering strictly to the **Finding Contract**:

```python
{
    "category":       "Service Name",      # e.g., "Key Vault", "Azure SQL"
    "resource":       "resource-name",     # For child resources use "parent/child"
    "resource_group": "rg-name",
    "check":          "unique_check_id",   # Snake_case unique identifier
    "issue":          "Clear description of the misconfiguration in English",
    "severity":       "High",              # "High", "Medium", or "Low"
    "compliance":     "CIS Azure 8.5",     # CIS Benchmark ID or "N/A"
}
```

The scanner automatically appends `"subscription_id"` to each finding upon collection.

### 2. Register Module in `core/scanner.py`
Add your check runner function to `CHECK_MODULES` in `core/scanner.py`:

```python
CHECK_MODULES = [
    ("Storage Account", run_all_storage_checks),
    ("Network Security Group", run_all_nsg_checks),
    ("Key Vault", run_all_keyvault_checks),
    ("Virtual Machine", run_all_vm_checks),
    ("Azure SQL", run_all_sql_checks),
    # Add new module runner here
]
```

### 3. Add Remediation Guidance in `core/remediation.py`
Add your check's `check_id` to the `REMEDIATION` dictionary with human-readable advice and a templated Azure CLI command:

```python
"my_new_check_id": {
    "advice": "Clear explanation of how to remediate the issue.",
    "command": "az <service> update --name {resource} --resource-group {resource_group} --setting true",
},
```

Placeholders available: `{resource}`, `{resource_group}`, `{server}`, `{database}`.

### 4. Ensure Category is in `core/scoring.py`
If introducing a new Azure category, ensure it is registered in `all_categories` in `core/scoring.py` so the category posture card displays `100/100` when clean.

---

## Running the Test Suite

Before submitting a pull request, verify that all tests pass:

```bash
# Run all unit tests
pytest -v

# Run with concise output
pytest -q
```

All new checks must include corresponding unit tests in `tests/` using mocked SDK responses.

---

## Pull Request Process

1. Fork the repository and create a feature branch (`git checkout -b feature/my-new-check`).
2. Commit your changes with clear, semantic commit messages (e.g., `feat(checks): add AKS cluster private endpoint check`).
3. Ensure CI workflows pass on GitHub Actions.
4. Submit a Pull Request targeting the `main` branch with a description of the security check and relevant CIS Benchmark references.
