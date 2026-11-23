"""Da de alta los hosts del laboratorio en el inventario y verifica SSH con lo guardado.

Uso: python lab/register_lab.py   (desde la raíz del repositorio)

Usa `inventario.db` y la clave Fernet de `securization.key` (ambos ignorados por git); si
la clave no existe, la genera. Registra cada host por su IP de labnet y puerto 22.
Nunca imprime contraseñas.
"""

import asyncio
from pathlib import Path

import asyncssh
from _credenciales import load_lab_hosts
from sqlmodel import create_engine

from securization.inventario import CredentialVault, HostAlreadyRegisteredError, Inventory


def open_inventory(root: Path) -> Inventory:
    fichero_clave = root / "securization.key"
    if not fichero_clave.exists():
        fichero_clave.write_bytes(CredentialVault.generate_key())
        print("Clave Fernet nueva generada en securization.key")
    vault = CredentialVault(fichero_clave.read_bytes().strip())
    return Inventory(create_engine(f"sqlite:///{root / 'inventario.db'}"), vault)


async def verify(inventory: Inventory, host_id: str) -> str:
    host = inventory.get_host(host_id)
    try:
        async with asyncssh.connect(
            host.address,
            port=host.ssh_port,
            username=host.ssh_user,
            password=inventory.get_ssh_secret(host_id),
            known_hosts=None,
            connect_timeout=10,
        ) as conn:
            r = await conn.run("hostname", check=True)
            return f"{host_id} @ {host.address}:{host.ssh_port} -> SSH OK ({str(r.stdout).strip()})"
    except (OSError, asyncssh.Error) as error:
        return f"{host_id} @ {host.address}: ERROR {type(error).__name__}"


async def main() -> None:
    root = Path.cwd()
    inventory = open_inventory(root)
    for h in load_lab_hosts(root):
        try:
            inventory.add_host(
                host_id=h.host_id, address=h.labnet_ip, ssh_user=h.user, ssh_secret=h.password
            )
            print(f"alta: {h.host_id} {h.labnet_ip}")
        except HostAlreadyRegisteredError:
            print(f"ya registrado: {h.host_id}")
    hosts = inventory.list_hosts()
    print(*(await asyncio.gather(*(verify(inventory, h.host_id) for h in hosts))), sep="\n")


if __name__ == "__main__":
    asyncio.run(main())
