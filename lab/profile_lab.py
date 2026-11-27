"""Perfila hosts del inventario con el perfilador real (AsyncSshTransport, L1).

Uso: python lab/profile_lab.py [host_id ...]   (desde la raíz; por defecto, las víctimas)

Requiere el código de L1 (`AsyncSshTransport`) y haber ejecutado antes lab/register_lab.py.
Guarda cada perfil en `inventario.db` e imprime el JSON resultante.
"""

import asyncio
import sys
from ipaddress import IPv4Address
from pathlib import Path

from register_lab import open_inventory
from sqlmodel import create_engine

from securization.inventario import Inventory
from securization.perfilador import (
    AsyncSshTransport,
    HostProfileStore,
    ProfilingError,
    orchestrate_profiling,
)


async def profile(inventory: Inventory, store: HostProfileStore, host_id: str) -> None:
    host = inventory.get_host(host_id)
    transport = AsyncSshTransport(
        host.address, host.ssh_port, host.ssh_user, inventory.get_ssh_secret(host_id)
    )
    try:
        perfil = await orchestrate_profiling(
            host_id=host_id,
            address=IPv4Address(host.address),
            os_family=host.os_family,
            transport=transport,
            store=store,
        )
        print(perfil.model_dump_json(indent=2))
    except ProfilingError as error:
        print(f"{host_id}: ERROR {error}")


async def main() -> None:
    root = Path.cwd()
    inventory = open_inventory(root)
    store = HostProfileStore(create_engine(f"sqlite:///{root / 'inventario.db'}"))
    for host_id in sys.argv[1:] or ["victima-01", "victima-02"]:
        await profile(inventory, store, host_id)


if __name__ == "__main__":
    asyncio.run(main())
