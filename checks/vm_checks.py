"""
checks/vm_checks.py

Virtual Machine-ler uzerinde 2 check:
  1) Disk-ler Customer Managed Key (CMK) ile sifrelenibmi?
  2) VM birbasa public IP-ye baglidirmi?

Qeyd (disk encryption): Azure managed disk-ler heminki platform-managed key
(PMK) ile "at rest" sifrelenir - yeni "hec sifrelenmeyib" veziyyeti yoxdur.
CIS Azure 7.2 mehz CMK isteyir, ona gore burada disk-e Disk Encryption Set
(CMK) baglanib-baglanmadigini yoxlayiriq. Mehdudiyyet: bu usul Azure Disk
Encryption (ADE, BitLocker/dm-crypt) ile sifrelenmis VM-i CMK saymir -
ADE ayri mexanizmdir ve VM extension-larindan oxunmalidir.

Qeyd (public IP): VM obyekti yalniz NIC-lerin ID-sini verir, ona gore her
NIC ucun network client-den ayrica sorgu gonderilir.
"""

from azure.core.exceptions import HttpResponseError

from core.auth import AzureClients


def _finding(vm_name: str, resource_group: str, check: str,
             issue: str, severity: str, compliance: str) -> dict:
    return {
        "category": "Virtual Machine",
        "resource": vm_name,
        "resource_group": resource_group,
        "check": check,
        "issue": issue,
        "severity": severity,
        "compliance": compliance,
    }


def _managed_disks(vm) -> list[tuple[str, object]]:
    """
    VM-in butun managed disk-lerini (ad, managed_disk obyekti) kimi qaytarir -
    OS disk + data disk-ler. Managed olmayan (kohne "unmanaged") disk-ler
    atlanir, cunki onlarda disk encryption set anlayisi yoxdur.
    """
    disks = []
    storage_profile = vm.storage_profile

    os_disk = storage_profile.os_disk
    if os_disk and os_disk.managed_disk:
        disks.append((os_disk.name or "os-disk", os_disk.managed_disk))

    for data_disk in storage_profile.data_disks or []:
        if data_disk.managed_disk:
            disks.append((data_disk.name or f"data-disk-{data_disk.lun}", data_disk.managed_disk))

    return disks


def check_disk_encryption(clients: AzureClients) -> list[dict]:
    """
    Her VM-in disk-lerinde Disk Encryption Set (CMK) olub-olmadigini yoxlayir.
    Bagli deyilse, disk yalniz platform-managed key ile sifrelenib demekdir.
    """
    findings = []

    for vm in clients.compute.virtual_machines.list_all():
        resource_group = vm.id.split("/")[4]

        unencrypted = [
            disk_name for disk_name, managed_disk in _managed_disks(vm)
            if managed_disk.disk_encryption_set is None
        ]

        if unencrypted:
            findings.append(_finding(
                vm_name=vm.name,
                resource_group=resource_group,
                check="disk_cmk_encryption",
                issue=f"Disk(s) {', '.join(unencrypted)} are not encrypted with a "
                      "Customer Managed Key - only the platform-managed key is used",
                severity="Medium",
                # CIS Microsoft Azure Foundations Benchmark v2.1.0
                compliance="CIS Azure 7.2",
            ))

    return findings


def check_public_ip(clients: AzureClients) -> list[dict]:
    """
    VM-in NIC-lerinden hec birinde public IP olmamalidir - birbasa internete
    acilan VM hucum sethini genislendirir (Bastion/Load Balancer/NAT tovsiye olunur).
    """
    findings = []

    for vm in clients.compute.virtual_machines.list_all():
        resource_group = vm.id.split("/")[4]
        public_nics = []

        for nic_ref in (vm.network_profile.network_interfaces if vm.network_profile else []):
            # nic_ref yalniz ARM id verir - tam obyekt ucun ayrica sorgu lazimdir
            nic_rg = nic_ref.id.split("/")[4]
            nic_name = nic_ref.id.split("/")[-1]
            nic = clients.network.network_interfaces.get(nic_rg, nic_name)

            has_public_ip = any(
                ip_config.public_ip_address is not None
                for ip_config in (nic.ip_configurations or [])
            )
            if has_public_ip:
                public_nics.append(nic_name)

        if public_nics:
            findings.append(_finding(
                vm_name=vm.name,
                resource_group=resource_group,
                check="vm_public_ip",
                issue=f"NIC(s) {', '.join(public_nics)} have a public IP - the VM is "
                      "directly reachable from the internet",
                severity="Medium",
                # CIS Azure Foundations bu veziyyeti ayrica control kimi saymir
                compliance="N/A (CIS Azure Foundations-da birbaşa qarşılığı yoxdur)",
            ))

    return findings


def run_all_vm_checks(clients: AzureClients) -> list[dict]:
    """
    Subscription-da Microsoft.Compute provider-i qeydiyyatdan kecmeyibse
    (VM hec vaxt yaradilmayibsa bu adi haldir) Azure xeta qaytarir - o zaman
    VM check-leri sadece bos siyahi verir, butun skan dayanmir.
    """
    try:
        return check_disk_encryption(clients) + check_public_ip(clients)
    except HttpResponseError:
        return []
