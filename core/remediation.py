"""
core/remediation.py

Stores "how to fix" advice and (where possible) a concrete Azure CLI/pip
command for each check ID. Deliberately not written into the finding dict -
it is looked up at display time (from `app.py`) via `get_remediation()`, so
older saved `results/scan_*.json` files are covered retroactively
as well.
"""

REMEDIATION = {
    "public_blob_access": {
        "advice": "Disable Public Blob Access on the Storage Account - "
                  "containers should be reachable only via Shared Access Signature (SAS) or "
                  "authentication.",
        "command": "az storage account update --name {resource} "
                   "--resource-group {resource_group} "
                   "--allow-blob-public-access false",
    },
    "secure_transfer": {
        "advice": "Enforce Secure Transfer (HTTPS-only) so that traffic "
                  "never travels over an unencrypted channel.",
        "command": "az storage account update --name {resource} "
                   "--resource-group {resource_group} "
                   "--https-only true",
    },
    "minimum_tls_version": {
        "advice": "Raise the Storage Account minimum TLS version to 1.2 - "
                  "TLS 1.0/1.1 are deprecated and have known weaknesses.",
        "command": "az storage account update --name {resource} "
                   "--resource-group {resource_group} "
                   "--min-tls-version TLS1_2",
    },
    "disk_cmk_encryption": {
        "advice": "Encrypt disks with a Customer Managed Key (CMK) - "
                  "first create a Disk Encryption Set, then attach it to the "
                  "disk. (The disk is already encrypted with a platform key; CMK "
                  "gives you control over key management.)",
        "command": "az vm encryption enable --name {resource} "
                   "--resource-group {resource_group} "
                   "--disk-encryption-keyvault <keyvault-name>",
    },
    "vm_public_ip": {
        "advice": "Do not expose the VM directly to the internet - remove the "
                  "public IP and route access through Azure Bastion, VPN or a "
                  "Load Balancer/NAT Gateway.",
        "command": "az network nic ip-config update --name <ipconfig-name> "
                   "--nic-name <nic-name> --resource-group {resource_group} "
                   "--remove publicIpAddress",
    },
    "open_management_port": {
        "advice": "Delete the NSG rule or restrict the source to a specific trusted "
                  "IP/CIDR - reach management ports via Azure Bastion/VPN, "
                  "not directly from the internet.",
        "command": "az network nsg rule update --nsg-name {resource} "
                   "--resource-group {resource_group} "
                   "--name <rule-name> --source-address-prefixes <trusted-ip>",
    },
    "soft_delete": {
        "advice": "Enable Soft Delete on the Key Vault so that deleted "
                  "secrets/keys/certificates can be recovered.",
        "command": "az keyvault update --name {resource} "
                   "--resource-group {resource_group} "
                   "--enable-soft-delete true",
    },
    "purge_protection": {
        "advice": "Enable Purge Protection so the vault cannot be permanently "
                  "deleted before the retention period ends.",
        "command": "az keyvault update --name {resource} "
                   "--resource-group {resource_group} "
                   "--enable-purge-protection true",
    },
    "sql_firewall_open_to_internet": {
        "advice": "Delete the firewall rule that opens the server to every IP address and "
                  "allow only specific trusted IPs/CIDRs (or use a Private Endpoint).",
        "command": "az sql server firewall-rule delete --server {resource} "
                   "--resource-group {resource_group} --name <rule-name>",
    },
    "sql_allow_azure_services": {
        "advice": "Turn off 'Allow Azure services and resources to access this server' - it "
                  "admits traffic from any Azure subscription, not only yours. Use VNet rules "
                  "or Private Endpoints instead.",
        "command": "az sql server firewall-rule delete --server {resource} "
                   "--resource-group {resource_group} --name AllowAllWindowsAzureIps",
    },
    "sql_public_network_access": {
        "advice": "Disable public network access and connect through a Private Endpoint.",
        "command": "az sql server update --name {resource} "
                   "--resource-group {resource_group} --enable-public-network false",
    },
    "sql_min_tls": {
        "advice": "Require TLS 1.2 or newer for client connections.",
        "command": "az sql server update --name {resource} "
                   "--resource-group {resource_group} --minimal-tls-version 1.2",
    },
    "sql_no_entra_admin": {
        "advice": "Configure a Microsoft Entra administrator (preferably a group) so logins "
                  "use central identity management and MFA.",
        "command": "az sql server ad-admin create --server-name {resource} "
                   "--resource-group {resource_group} "
                   "--display-name <group-name> --object-id <group-object-id>",
    },
    "sql_auditing_disabled": {
        "advice": "Enable server-level auditing and send the logs to a Storage Account or "
                  "Log Analytics workspace.",
        "command": "az sql server audit-policy update --name {resource} "
                   "--resource-group {resource_group} --state Enabled "
                   "--lats Enabled --lawri <log-analytics-workspace-resource-id>",
    },
    "sql_tde_disabled": {
        "advice": "Enable Transparent Data Encryption on the database.",
        "command": "az sql db tde set --server {server} --database {database} "
                   "--resource-group {resource_group} --status Enabled",
    },
}

DEFAULT_ADVICE = "No specific remediation advice has been written for this check yet."


def get_remediation(finding: dict) -> dict:
    """
    Returns the remediation text + (if any) a ready-made command for a finding.
    `{resource}`/`{resource_group}` placeholders are replaced with the finding's
    own fields. For an unknown check ID a default text is
    returned - it does not raise, so old/unknown checks don't break the UI.
    """
    check_id = finding.get("check")
    entry = REMEDIATION.get(check_id)

    if entry is None:
        return {"advice": DEFAULT_ADVICE, "command": None}

    resource = finding.get("resource", "<resource>")
    resource_group = finding.get("resource_group", "<resource-group>")
    # Child resources are named "parent/child" (e.g. SQL "server/db")
    server, _, database = resource.partition("/")

    command = entry["command"].format(
        resource=resource, resource_group=resource_group, server=server, database=database
    )

    return {"advice": entry["advice"], "command": command}
