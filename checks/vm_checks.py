"""
checks/vm_checks.py

2 checks on Virtual Machines:
  1) Are disks encrypted with a Customer Managed Key (CMK)?
  2) Is the VM attached directly to a public IP?

Note (disk encryption): Azure managed disks are always encrypted at rest with a
platform-managed key (PMK) - so an "unencrypted" state does not exist.
CIS Azure 7.2 specifically requires CMK, so here we check whether a Disk Encryption Set
(CMK) is attached to the disk. Limitation: this method does not count a VM encrypted
with Azure Disk Encryption (ADE, BitLocker/dm-crypt) as CMK -
ADE is a separate mechanism and must be read from the VM extensions.

Note (public IP): the VM object only provides NIC IDs, so a separate
request is sent to the network client for each NIC.
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
    Returns all managed disks of the VM as (name, managed_disk object) -
    OS disk + data disks. Non-managed (legacy "unmanaged") disks
    are skipped, since the disk encryption set concept does not apply to them.
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
    Checks whether each VM's disks have a Disk Encryption Set (CMK).
    If not attached, the disk is encrypted only with a platform-managed key.
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
    None of the VM's NICs should have a public IP - a VM exposed directly to the
    internet widens the attack surface (Bastion/Load Balancer/NAT is recommended).
    """
    findings = []

    for vm in clients.compute.virtual_machines.list_all():
        resource_group = vm.id.split("/")[4]
        public_nics = []

        for nic_ref in (vm.network_profile.network_interfaces if vm.network_profile else []):
            # nic_ref only gives the ARM id - a separate request is needed for the full object
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
                # CIS Azure Foundations does not count this as a separate control
                compliance="N/A (no direct equivalent in CIS Azure Foundations)",
            ))

    return findings


def run_all_vm_checks(clients: AzureClients) -> list[dict]:
    """
    If the Microsoft.Compute provider is not registered in the subscription
    (normal if no VM was ever created), Azure returns an error - in that case
    the VM checks just return an empty list and the whole scan does not stop.
    """
    try:
        return check_disk_encryption(clients) + check_public_ip(clients)
    except HttpResponseError:
        return []
