"""Comprueba SSH (por NAT), IP de labnet y ping cruzado entre las VMs del laboratorio.

Uso: python lab/check_lab.py   (desde la raíz del repositorio)
Nunca imprime contraseñas.
"""

import asyncio
import shlex
from pathlib import Path

import asyncssh
from _credenciales import LabHost, load_lab_hosts


async def check(host: LabHost, todas: list[str]) -> str:
    try:
        async with asyncssh.connect(
            "127.0.0.1",
            port=host.nat_port,
            username=host.user,
            password=host.password,
            known_hosts=None,
            connect_timeout=10,
        ) as conn:
            lineas = [f"== {host.host_id}"]
            r = await conn.run("hostname; uptime -p; ip -4 -o addr show | awk '{print $2, $4}'")
            lineas.append(str(r.stdout).strip())
            for otra in todas:
                if otra != host.labnet_ip:
                    p = await conn.run(shlex.join(["ping", "-c1", "-W2", otra]))
                    lineas.append(f"ping {otra}: {'ok' if p.exit_status == 0 else 'FALLO'}")
            return "\n".join(lineas)
    except (OSError, asyncssh.Error) as error:
        return f"== {host.host_id}: ERROR {type(error).__name__}: {error}"


async def main() -> None:
    hosts = load_lab_hosts(Path.cwd())
    ips = [h.labnet_ip for h in hosts]
    print("\n".join(await asyncio.gather(*(check(h, ips) for h in hosts))))


if __name__ == "__main__":
    asyncio.run(main())
