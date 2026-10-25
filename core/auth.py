"""
core/auth.py

Azure autentifikasiyası və SDK management client-lərinin yaradılması.

TƏHLÜKƏSİZLİK MƏNTİQİ:
- Heç bir modul-səviyyəli qlobal dəyişən (global state) yoxdur.
- Bütün credential-lar funksiyalara eksplisit parametr kimi ötürülür (`credentials: dict | None`).
- Client və credential obyektləri sessiyalar arasında heç vaxt paylaşılmır.
- PUBLIC_MODE=true olduqda server `.env` dəyərləri və `az cli` TAMAMİLƏ nəzərə alınmır.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from azure.identity import ClientSecretCredential, AzureCliCredential
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


@dataclass
class AzureClients:
    subscription_id: str
    storage: StorageManagementClient
    network: NetworkManagementClient
    keyvault: KeyVaultManagementClient
    compute: ComputeManagementClient


def has_env_credentials() -> bool:
    """Environment variable (Service Principal) konfiqurasiya edilibmi?"""
    if is_public_mode():
        return False
    return bool(
        os.getenv("AZURE_TENANT_ID")
        and os.getenv("AZURE_CLIENT_ID")
        and os.getenv("AZURE_CLIENT_SECRET")
    )


def get_credential_source(credentials: dict | None = None) -> str:
    """Hazırda hansı credential mənbəyinin istifadə olunduğunu bildirir."""
    if credentials:
        return "dashboard"
    if is_public_mode():
        return "none"
    if has_env_credentials():
        return "environment"
    return "azure_cli"


def _build_credential(credentials: dict | None = None):
    """
    Credential obyekti qurur.
    YALNIZ ötürülən credentials və ya (non-public rejimdə) server mühitindən istifadə edir.
    """
    # 1) Eksplisit sessiya məlumatı verilibsə
    if credentials and isinstance(credentials, dict):
        tenant_id = credentials.get("tenant_id")
        client_id = credentials.get("client_id")
        client_secret = credentials.get("client_secret")
        if tenant_id and client_id and client_secret:
            return ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

    # 2) Public Mode aktivdirsə, server credential-ları qəti qadağandır
    if is_public_mode():
        raise PermissionError(
            "Açıq (Public) rejimdə server credential-larının istifadəsi qadağandır. "
            "Zəhmət olmasa Service Principal məlumatlarınızı daxil edin."
        )

    # 3) Qeyri-ictimai (local) rejimdə .env fallback-i
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    # 4) Qeyri-ictimai (local) rejimdə Azure CLI fallback-i
    try:
        return AzureCliCredential()
    except Exception:
        raise EnvironmentError(
            "Autentifikasiya üçün nə daxil edilmiş credential, nə Service "
            "Principal (.env), nə də aktiv 'az login' sessiyası tapıldı."
        )


def list_subscription_ids(credentials: dict | None = None) -> list[str]:
    """Skan ediləcək subscription ID-lərinin siyahısı."""
    if credentials and credentials.get("subscription_ids"):
        return credentials["subscription_ids"]

    if is_public_mode():
        raise PermissionError(
            "Açıq rejimdə heç bir Subscription ID təqdim edilməyib."
        )

    # Qeyri-ictimai (local) fallback
    multi = os.getenv("AZURE_SUBSCRIPTION_IDS")
    if multi:
        ids = [s.strip() for s in multi.split(",") if s.strip()]
        if ids:
            return ids

    single = os.getenv("AZURE_SUBSCRIPTION_ID")
    if single:
        return [single]

    raise EnvironmentError(
        "Subscription ID tapılmadı. Dashboard-dan daxil edin və ya "
        ".env faylında AZURE_SUBSCRIPTION_ID təyin edin."
    )


def get_clients(subscription_id: str | None = None, credentials: dict | None = None) -> AzureClients:
    """Verilən subscription və credentials üçün izolə edilmiş SDK client-lərini qaytarır."""
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
    Zərərsiz read-only əlaqə testi.
    Xəta mesajında heç vaxt credential detalları əks olunmur (redact edilir).
    """
    secret = credentials.get("client_secret", "") if credentials else ""
    try:
        credential = _build_credential(credentials)
        if ResourceManagementClient is not None:
            resource_client = ResourceManagementClient(credential, subscription_id)
            rg_list = list(resource_client.resource_groups.list())
            return True, f"Bağlantı uğurlu! {len(rg_list)} resource group aşkarlandı."
        else:
            storage_client = StorageManagementClient(credential, subscription_id)
            accounts = list(storage_client.storage_accounts.list())
            return True, f"Bağlantı uğurlu! {len(accounts)} storage account oxundu."
    except Exception as e:
        clean_err = redact(str(e), [secret])
        # İstifadəçiyə yalnız təhlükəsiz ümumi mesaj veririk
        return False, (
            "Azure-a qoşulmaq mümkün olmadı. Tenant ID, Client ID, "
            "Client Secret və Subscription ID-ni yoxlayın. "
            "Service Principal-ın Reader rolu olmalıdır."
        )