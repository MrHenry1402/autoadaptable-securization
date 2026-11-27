"""Prueba del laboratorio: servicios reales de las víctimas y Docker/macvlan en deception-central.

Uso: python lab_proof.py <repo>. Nunca imprime contraseñas.
"""

import asyncio
import sys
from pathlib import Path

import asyncssh

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "lab"))
from _credenciales import load_lab_hosts  # noqa: E402

COMANDOS = {
    "victima-01": [
        "grep PRETTY_NAME /etc/os-release",
        "systemctl is-active ssh nginx mariadb",
        "ss -tlnH | awk '{print $4}' | sort -u",
    ],
    "victima-02": [
        "grep PRETTY_NAME /etc/os-release",
        "systemctl is-active ssh vsftpd redis-server",
        "ss -tlnH | awk '{print $4}' | sort -u",
    ],
    "deception-central": [
        "grep PRETTY_NAME /etc/os-release",
        "docker --version",
        "docker network inspect labnet-decoys --format 'red {{.Name}}: driver {{.Driver}}, "
        'padre {{index .Options "parent"}}, subred {{(index .IPAM.Config 0).Subnet}}\'',
        "ip -br link show enp0s8",
        "docker ps -a --format '{{.Names}}  {{.Image}}  {{.Status}}'",
    ],
}


async def main() -> None:
    hosts = {h.host_id: h for h in load_lab_hosts(root)}
    for host_id, comandos in COMANDOS.items():
        h = hosts[host_id]
        async with asyncssh.connect(
            h.labnet_ip, username=h.user, password=h.password, known_hosts=None
        ) as c:
            print(f"== {host_id} ({h.labnet_ip})")
            for cmd in comandos:
                r = await c.run(cmd)
                print(f"$ {cmd}\n{r.stdout}{r.stderr}".rstrip() + "\n")


asyncio.run(main())
