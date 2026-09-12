"""
core/auth.py

Autentifikasiya olub, her check modulunun ehtiyaci olan Azure management
client-lerini qaytarir.

Iki auth rejimi dstekleniyi:
  1) Service Principal (.env-de tenant/client/secret varsa)
  2) Azure CLI session (yoxdursa, `az login` sessiyasindan istifade edir)

Bir ve ya bir nece subscription dstekleniyi - bax: list_subscription_ids().
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv
from azure.identity import ClientSecretCredential, AzureCliCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.compute import ComputeManagementClient

load_dotenv()


@dataclass
class AzureClients:
    subscription_id: str
    storage: StorageManagementClient
    network: NetworkManagementClient
    keyvault: KeyVaultManagementClient
    compute: ComputeManagementClient


def _build_credential():
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    if tenant_id and client_id and client_secret:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    try:
        return AzureCliCredential()
    except Exception as e:
        raise EnvironmentError(
            "Autentifikasiya ucun ne Service Principal, ne de aktiv "
            f"'az login' sessiyasi tapildi. Terminal-da `az login` edin. ({e})"
        )


def list_subscription_ids() -> list[str]:
    """
    Skan edilecek subscription-larin siyahisi.

    AZURE_SUBSCRIPTION_IDS (vergulle ayrilmis) verilibse hamisi skan olunur;
    yoxdursa tek AZURE_SUBSCRIPTION_ID istifade olunur (kohne davranis).
    """
    multi = os.getenv("AZURE_SUBSCRIPTION_IDS")
    if multi:
        ids = [s.strip() for s in multi.split(",") if s.strip()]
        if ids:
            return ids

    single = os.getenv("AZURE_SUBSCRIPTION_ID")
    if single:
        return [single]

    raise EnvironmentError(
        ".env faylinda AZURE_SUBSCRIPTION_ID (ve ya AZURE_SUBSCRIPTION_IDS) tapilmadi."
    )


def get_clients(subscription_id: str | None = None) -> AzureClients:
    """
    Verilen subscription ucun SDK client-lerini qaytarir. subscription_id
    verilmezse, siyahidaki birinci subscription goturulur.
    """
    if subscription_id is None:
        subscription_id = list_subscription_ids()[0]

    credential = _build_credential()

    return AzureClients(
        subscription_id=subscription_id,
        storage=StorageManagementClient(credential, subscription_id),
        network=NetworkManagementClient(credential, subscription_id),
        keyvault=KeyVaultManagementClient(credential, subscription_id),
        compute=ComputeManagementClient(credential, subscription_id),
    )