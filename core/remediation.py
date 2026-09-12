"""
core/remediation.py

Hər check ID-si üçün "necə düzəldilir" məsləhəti və (mümkünsə) konkret
Azure CLI/pip əmrini saxlayır. Bilərəkdən finding dict-inin özünə yazılmır -
göstərmə zamanı (`app.py`-dan) `get_remediation()` ilə lookup edilir, ona
görə köhnə saxlanmış `results/scan_*.json` faylları da retroaktiv əhatə
olunur.
"""

REMEDIATION = {
    "public_blob_access": {
        "advice": "Storage Account-da Public Blob Access-i deaktiv edin - "
                  "container-lər yalnız Shared Access Signature (SAS) və ya "
                  "autentifikasiya ilə əlçatan olsun.",
        "command": "az storage account update --name {resource} "
                   "--resource-group {resource_group} "
                   "--allow-blob-public-access false",
    },
    "secure_transfer": {
        "advice": "Secure Transfer (HTTPS-only) məcburi edin ki, trafik "
                  "açıq (şifrəsiz) kanalla getməsin.",
        "command": "az storage account update --name {resource} "
                   "--resource-group {resource_group} "
                   "--https-only true",
    },
    "minimum_tls_version": {
        "advice": "Storage Account-un minimum TLS versiyasını 1.2-yə qaldırın - "
                  "TLS 1.0/1.1 köhnəlmiş sayılır və bilinən zəiflikləri var.",
        "command": "az storage account update --name {resource} "
                   "--resource-group {resource_group} "
                   "--min-tls-version TLS1_2",
    },
    "disk_cmk_encryption": {
        "advice": "Disk-ləri Customer Managed Key (CMK) ilə şifrələyin - "
                  "əvvəlcə Disk Encryption Set yaradın, sonra onu disk-ə "
                  "bağlayın. (Disk artıq platform açarı ilə şifrəlidir, CMK "
                  "açar idarəsini sizə verir.)",
        "command": "az vm encryption enable --name {resource} "
                   "--resource-group {resource_group} "
                   "--disk-encryption-keyvault <keyvault-name>",
    },
    "vm_public_ip": {
        "advice": "VM-i birbaşa internetə açmayın - public IP-ni silin və girişi "
                  "Azure Bastion, VPN və ya Load Balancer/NAT Gateway üzərindən "
                  "təşkil edin.",
        "command": "az network nic ip-config update --name <ipconfig-name> "
                   "--nic-name <nic-name> --resource-group {resource_group} "
                   "--remove publicIpAddress",
    },
    "open_management_port": {
        "advice": "NSG qaydasını silin və ya source-u konkret etibarlı "
                  "IP/CIDR-ə məhdudlaşdırın - idarəetmə portlarına birbaşa "
                  "internetdən deyil, Azure Bastion/VPN üzərindən girin.",
        "command": "az network nsg rule update --nsg-name {resource} "
                   "--resource-group {resource_group} "
                   "--name <rule-name> --source-address-prefixes <trusted-ip>",
    },
    "soft_delete": {
        "advice": "Key Vault-da Soft Delete-i aktiv edin ki, silinən "
                  "secret/key/certificate-lar bərpa oluna bilsin.",
        "command": "az keyvault update --name {resource} "
                   "--resource-group {resource_group} "
                   "--enable-soft-delete true",
    },
    "purge_protection": {
        "advice": "Purge Protection-ı aktiv edin ki, vault saxlama müddəti "
                  "bitmədən həmişəlik silinə bilməsin.",
        "command": "az keyvault update --name {resource} "
                   "--resource-group {resource_group} "
                   "--enable-purge-protection true",
    },
    "known_vulnerability": {
        "advice": "Paketi OSV.dev-in bildirdiyi düzəliş versiyasına (və ya "
                  "daha yenisinə) yüksəldin, sonra requirements.lock.txt-i "
                  "yenidən yaradın (`pip freeze > requirements.lock.txt`).",
        "command": "pip install --upgrade {resource}",
    },
}

DEFAULT_ADVICE = "Bu check üçün konkret remediation təklifi hələ yazılmayıb."


def get_remediation(finding: dict) -> dict:
    """
    Bir finding üçün remediation mətnini + (varsa) hazır əmri qaytarır.
    `{resource}`/`{resource_group}` placeholder-ləri finding-in öz
    sahələri ilə əvəz olunur. Naməlum check ID-si üçün defolt mətn
    qaytarılır - xəta atmır ki, köhnə/naməlum check-lər UI-ni sındırmasın.
    """
    check_id = finding.get("check")
    entry = REMEDIATION.get(check_id)

    if entry is None:
        return {"advice": DEFAULT_ADVICE, "command": None}

    resource = finding.get("resource", "<resource>")
    resource_group = finding.get("resource_group", "<resource-group>")

    if check_id == "known_vulnerability":
        # resource "paket==versiya" formatındadır - pip install ucun sade paket adi lazimdir
        resource = resource.split("==")[0]

    command = entry["command"].format(resource=resource, resource_group=resource_group)

    return {"advice": entry["advice"], "command": command}
