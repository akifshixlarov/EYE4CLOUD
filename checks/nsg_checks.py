"""
checks/nsg_checks.py

Check on NSG (Network Security Group) rules:
  - Inbound, Allow rule
  - Source 0.0.0.0/0 / "*" / "Internet" / "Any" (i.e. the whole internet)
  - Destination port 22 (SSH) or 3389 (RDP) - a single port, a range, or "*"

Note: Azure also returns the default (auto-created) NSG rules.
To exclude them we don't look at default_security_rules, only at security_rules
(rules the user added themselves) - because
the default rules are Azure's own protection, not a human mistake.
"""

from core.auth import AzureClients

RISKY_PORTS = {"22", "3389"}
OPEN_SOURCE_PREFIXES = {"*", "0.0.0.0/0", "internet", "any"}


def _compliance_for_port(port: str) -> str:
    """
    In CIS Microsoft Azure Foundations Benchmark v2.1.0, RDP and SSH are separate
    controls (6.1 / 6.2). If the port is "*", both are open.
    """
    if port == "3389":
        return "CIS Azure 6.1"
    if port == "22":
        return "CIS Azure 6.2"
    return "CIS Azure 6.1, 6.2"


def _finding(nsg_name: str, resource_group: str, rule_name: str,
             port: str, source: str) -> dict:
    return {
        "category": "Network Security Group",
        "resource": nsg_name,
        "resource_group": resource_group,
        "check": "open_management_port",
        "issue": f"Rule '{rule_name}' allows inbound access from {source} "
                 f"to port {port} (SSH/RDP) - management port exposed to the internet",
        "severity": "High",
        "compliance": _compliance_for_port(port),
    }


def _port_matches_risky(port_range: str) -> str | None:
    """
    A destination_port_range value can be a single number ("22"), a range ("20-30")
    or "*". If it covers one of the risky ports, this function
    returns that port, otherwise None.
    """
    if port_range == "*":
        return "*"

    if "-" in port_range:
        try:
            start, end = port_range.split("-")
            start, end = int(start), int(end)
        except ValueError:
            return None
        for risky in RISKY_PORTS:
            if start <= int(risky) <= end:
                return risky
        return None

    return port_range if port_range in RISKY_PORTS else None


def _source_is_open(source_prefix: str) -> bool:
    return source_prefix.strip().lower() in OPEN_SOURCE_PREFIXES


def check_open_management_ports(clients: AzureClients) -> list[dict]:
    findings = []

    for nsg in clients.network.network_security_groups.list_all():
        resource_group = nsg.id.split("/")[4]

        for rule in nsg.security_rules or []:
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue

            # Some rules have a single source_address_prefix, others
            # source_address_prefixes (a list) - we check both
            sources = []
            if rule.source_address_prefix:
                sources.append(rule.source_address_prefix)
            if rule.source_address_prefixes:
                sources.extend(rule.source_address_prefixes)

            if not any(_source_is_open(s) for s in sources):
                continue

            # Likewise, the port can be a single field or several
            port_ranges = []
            if rule.destination_port_range:
                port_ranges.append(rule.destination_port_range)
            if rule.destination_port_ranges:
                port_ranges.extend(rule.destination_port_ranges)

            for port_range in port_ranges:
                matched_port = _port_matches_risky(port_range)
                if matched_port:
                    findings.append(_finding(
                        nsg_name=nsg.name,
                        resource_group=resource_group,
                        rule_name=rule.name,
                        port=matched_port,
                        source=sources[0] if sources else "unknown",
                    ))

    return findings


def run_all_nsg_checks(clients: AzureClients) -> list[dict]:
    return check_open_management_ports(clients)
