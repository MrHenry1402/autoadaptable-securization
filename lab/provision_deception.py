"""Prepara deception-central para alojar señuelos OpenCanary en contenedores (L3).

Uso: python lab/provision_deception.py   (desde la raíz del repositorio)

Idempotente. Deja:
- Docker instalado y el usuario `lab` en el grupo `docker` (el desplegador lanza los
  contenedores por SSH sin sudo).
- `enp0s8` (labnet) en modo promiscuo de forma persistente. Además de `allow-all` en el
  NIC2 de VirtualBox, la e1000 del invitado tiene que aceptar el unicast dirigido a las
  MAC de los contenedores macvlan: sin esto el ARP resuelve, pero ICMP y TCP no llegan.
- La red Docker `labnet-decoys` (macvlan sobre `enp0s8`, 10.0.0.0/24).
- La imagen oficial de OpenCanary fijada por digest.

Nunca imprime contraseñas.
"""

import asyncio
from pathlib import Path

import asyncssh
from _credenciales import LabHost, load_lab_hosts
from set_static_ip import run_sudo

HOST_ID = "deception-central"
IMAGE = "thinkst/opencanary@sha256:479c2cf42bbaed8d298d12be0a67da5099cc20ee1dcbc336d84b05251d1d22b6"
NETWORK = "labnet-decoys"

_INTERFACES = """# Gestionado por lab/provision_deception.py
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

auto enp0s8
iface enp0s8 inet static
    address 10.0.0.5
    netmask 255.255.255.0
    up ip link set enp0s8 promisc on
"""


async def ejecutar(conn: asyncssh.SSHClientConnection, host: LabHost) -> None:
    async def paso(nombre: str, argv: list[str], entrada: str = "", tolerar: bool = False) -> int:
        estado = await run_sudo(conn, host.password, argv, entrada)
        print(f"[{HOST_ID}] {nombre}: exit={estado}")
        if estado != 0 and not tolerar:
            raise SystemExit(f"[{HOST_ID}] falló el paso: {nombre}")
        return estado or 0

    await paso("apt update", ["apt-get", "update", "-q"])
    await paso(
        "instalar docker.io",
        ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "-q", "docker.io"],
    )
    await paso("grupo docker", ["usermod", "-aG", "docker", host.user])
    await paso("interfaces (promisc persistente)", ["tee", "/etc/network/interfaces"], _INTERFACES)
    await paso("promisc ahora", ["ip", "link", "set", "enp0s8", "promisc", "on"])
    existe = await paso("red existente", ["docker", "network", "inspect", NETWORK], tolerar=True)
    if existe != 0:
        await paso(
            "crear red macvlan",
            [
                "docker",
                "network",
                "create",
                "-d",
                "macvlan",
                "--subnet",
                "10.0.0.0/24",
                "-o",
                "parent=enp0s8",
                NETWORK,
            ],
        )
    await paso("imagen OpenCanary", ["docker", "pull", "-q", IMAGE])


async def main() -> None:
    host = next(h for h in load_lab_hosts(Path.cwd()) if h.host_id == HOST_ID)
    async with asyncssh.connect(
        "127.0.0.1",
        port=host.nat_port,
        username=host.user,
        password=host.password,
        known_hosts=None,
    ) as conn:
        await ejecutar(conn, host)


if __name__ == "__main__":
    asyncio.run(main())
