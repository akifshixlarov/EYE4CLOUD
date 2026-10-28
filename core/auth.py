"""
core/auth.py

Azure authentication and creation of SDK management clients.

SECURITY LOGIC:
- No module-level global variables (global state).
- All credentials are passed to functions as explicit parameters (`credentials: dict | None`).
- Client and credential objects are never shared between sessions.
- With PUBLIC_MODE=true, server `.env` values and `az cli` are COMPLETELY ignored.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from azure.identity import ClientSecretCredential, AzureCliCredential, DeviceCodeCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.compute import ComputeManagementClient

try:
    from azure.mgmt.resource import ResourceManagementClient
except ImportError:
    ResourceManagementClient = None

from core.security import is_public_mode, redact

load_dotenv()

ARM_SCOPE = "https://management.azure.com/.default"
DEVICE_CODE_TIMEOUT_SECONDS = 300


@dataclass
class AzureClients:
    subscription_id: str
    storage: StorageManagementClient
    network: NetworkManagementClient
    keyvault: KeyVaultManagementClient
    compute: ComputeManagementClient


def has_env_credentials() -> bool:
    """Are environment variable (Service Principal) credentials configured?"""
    if is_public_mode():
        return False
    return bool(
        os.getenv("AZURE_TENANT_ID")
        and os.getenv("AZURE_CLIENT_ID")
        and os.getenv("AZURE_CLIENT_SECRET")
    )


def get_credential_source(credentials: dict | None = None) -> str:
    """Reports which credential source is currently in use."""
    if credentials:
        return "dashboard"
    if is_public_mode():
        return "none"
    if has_env_credentials():
        return "environment"
    return "azure_cli"


def _build_credential(credentials: dict | None = None):
    """
    Builds the credential object.
    Uses ONLY the passed credentials or (in non-public mode) the server environment.
    """
    # 1) Explicit session data was provided
    if credentials and isinstance(credentials, dict):
        # "Sign in with Microsoft" — an already authenticated DeviceCodeCredential
        if credentials.get("credential") is not None:
            return credentials["credential"]
        tenant_id = credentials.get("tenant_id")
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")
        if tenant_id and client_id and client_secret:
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

    # 2) In Public Mode, server credentials are strictly forbidden
    if is_public_mode():
        raise PermissionError(
            "Using server credentials is forbidden in Public mode. "
            "Please sign in or enter your Service Principal details."
        )

    # 3) .env fallback in non-public (local) mode
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    # 4) Azure CLI fallback in non-public (local) mode
    try:
        return AzureCliCredential()
    except Exception:
        raise EnvironmentError(
            "No credentials for authentication were found: no entered credentials, "
            "no Service Principal (.env), and no active 'az login' session."
        )


def sign_in_with_device_code(prompt_callback) -> DeviceCodeCredential:
    """
    Device code sign-in with a Microsoft account (no app registration required).
    prompt_callback(verification_uri, user_code, expires_on) shows the code in the UI.
    Blocks until the user finishes signing in; the token stays only in the credential object's memory.
    """
    credential = DeviceCodeCredential(
        prompt_callback=prompt_callback,
        timeout=DEVICE_CODE_TIMEOUT_SECONDS,
    )
    credential.authenticate(scopes=[ARM_SCOPE])
    return credential


def list_subscription_ids(credentials: dict | None = None) -> list[str]:
    """List of subscription IDs to scan."""
    if credentials and credentials.get("subscription_ids"):
        return credentials["subscription_ids"]

    if is_public_mode():
        raise PermissionError(
            "No Subscription ID was provided in public mode."
        )

    # Non-public (local) fallback
    multi = os.getenv("AZURE_SUBSCRIPTION_IDS")
    if multi:
        ids = [s.strip() for s in multi.split(",") if s.strip()]
        if ids:
            return ids

    single = os.getenv("AZURE_SUBSCRIPTION_ID")
    if single:
        return [single]

    raise EnvironmentError(
        "Subscription ID not found. Enter it in the dashboard or "
        "set AZURE_SUBSCRIPTION_ID in the .env file."
    )


def get_clients(subscription_id: str | None = None, credentials: dict | None = None) -> AzureClients:
    """Returns isolated SDK clients for the given subscription and credentials."""
    if subscription_id is None:
        subscription_id = list_subscription_ids(credentials)[0]

    credential = _build_credential(credentials)

    return AzureClients(
        subscription_id=subscription_id,
        storage=StorageManagementClient(credential, subscription_id),
        network=NetworkManagementClient(credential, subscription_id),
        keyvault=KeyVaultManagementClient(credential, subscription_id),
        compute=ComputeManagementClient(credential, subscription_id),
    )


def test_connection(subscription_id: str, credentials: dict | None = None) -> tuple[bool, str]:
    """
    Harmless read-only connection test.
    Error messages never include credential details (they are redacted).
    """
    secret = credentials.get("client_secret", "") if credentials else ""
    try:
        credential = _build_credential(credentials)
        if ResourceManagementClient is not None:
            resource_client = ResourceManagementClient(credential, subscription_id)
            rg_list = list(resource_client.resource_groups.list())
            return True, f"Connection successful! {len(rg_list)} resource groups found."
        else:
            storage_client = StorageManagementClient(credential, subscription_id)
            accounts = list(storage_client.storage_accounts.list())
            return True, f"Connection successful! {len(accounts)} storage accounts read."
    except Exception as e:
        clean_err = redact(str(e), [secret])
        # Only give the user a safe, generic message
        return False, (
            "Could not connect to Azure. Check your sign-in details and "
            "Subscription ID. The account needs the Reader role on the subscription."
        )