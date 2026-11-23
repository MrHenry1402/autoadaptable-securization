"""Fija la IP estática de labnet en una VM del laboratorio recién aprovisionada.

Uso: python lab/set_static_ip.py <host_id>   (desde la raíz del repositorio)

Toma usuario, contraseña, puerto NAT e IP de `lab-credentials.local.txt`. Añade un bloque
`iface ... inet static` a /etc/network/interfaces para la única interfaz sin IP (el NIC2
de labnet) y la levanta con ifup. Nunca imprime la contraseña.
"""

import asyncio
import shlex
import sys
from pathlib import Path

import asyncssh
from _credenciales import LabHost, load_lab_hosts


async def run_sudo(
    conn: asyncssh.SSHClientConnection, password: str, argv: list[str], stdin_extra: str = ""
) -> int | None:
    proceso = await conn.create_process(shlex.join(["sudo", "-S", *argv]))
    proceso.stdin.write(password + "\n" + stdin_extra)
    proceso.stdin.write_eof()
    await proceso.wait()
    return proceso.exit_status


async def set_static_ip(host: LabHost) -> None:
    async with asyncssh.connect(
        "127.0.0.1",
        port=host.nat_port,
        username=host.user,
        password=host.password,
        known_hosts=None,
    ) as conn:
        salida = await conn.run("ip -br addr show", check=True)
        interfaz = None
        for linea in str(salida.stdout).splitlines():
            partes = linea.split()
            if not partes or partes[0] == "lo":
                continue
            if not any("/" in p and p[0].isdigit() for p in partes[2:]):
                interfaz = partes[0]
                break
        if interfaz is None:
            print(f"[{host.host_id}] no hay ninguna interfaz sin IP; nada que hacer")
            return
        bloque = (
            f"\nauto {interfaz}\niface {interfaz} inet static\n"
            f"    address {host.labnet_ip}\n    netmask 255.255.255.0\n"
        )
        tee = await run_sudo(conn, host.password, ["tee", "-a", "/etc/network/interfaces"], bloque)
        ifup = await run_sudo(conn, host.password, ["ifup", interfaz])
        print(f"[{host.host_id}] {interfaz} -> {host.labnet_ip} (tee={tee}, ifup={ifup})")
        verif = await conn.run(shlex.join(["ip", "-br", "addr", "show", interfaz]))
        print(f"[{host.host_id}] {str(verif.stdout).strip()}")


def main() -> None:
    hosts = {h.host_id: h for h in load_lab_hosts(Path.cwd())}
    if len(sys.argv) != 2 or sys.argv[1] not in hosts:
        sys.exit(f"uso: python lab/set_static_ip.py <{'|'.join(hosts)}>")
    asyncio.run(set_static_ip(hosts[sys.argv[1]]))


if __name__ == "__main__":
    main()
