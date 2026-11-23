"""Instala en las víctimas del laboratorio los servicios reales que la herramienta perfilará.

Uso: python lab/provision_services.py [host_id ...]   (desde la raíz; por defecto, ambas)

Cada víctima tiene un papel distinto, con servicios que OpenCanary sabe emular, para que
los señuelos y la comparación H2 vs H4 no se reduzcan a copiar un único sshd:

- victima-01, servidor web con base de datos: nginx (80/tcp) y MariaDB (3306/tcp).
- victima-02, servidor de ficheros y caché: vsftpd (21/tcp) y Redis (6379/tcp).

Es idempotente: los ficheros de configuración se sobrescriben (no se anexan) y apt no
reinstala lo que ya está. Los servicios escuchan en todas las interfaces porque labnet es
una red Host-Only aislada. Nunca imprime contraseñas.
"""

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
from _credenciales import LabHost, load_lab_hosts
from set_static_ip import run_sudo


@dataclass(frozen=True)
class Rol:
    paquetes: list[str]
    ficheros: dict[str, str] = field(default_factory=dict)
    comandos: list[list[str]] = field(default_factory=list)
    servicios: list[str] = field(default_factory=list)


_INDEX_INTRANET = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>Intranet</title></head>
<body><h1>Intranet</h1><p>Portal interno. Acceso restringido al personal.</p></body></html>
"""

ROLES: dict[str, Rol] = {
    "victima-01": Rol(
        paquetes=["nginx", "mariadb-server"],
        ficheros={
            "/etc/mysql/mariadb.conf.d/60-lab.cnf": "[mysqld]\nbind-address = 0.0.0.0\n",
            "/var/www/html/index.html": _INDEX_INTRANET,
        },
        servicios=["nginx", "mariadb"],
    ),
    "victima-02": Rol(
        paquetes=["vsftpd", "redis-server"],
        comandos=[["sed", "-i", "-E", "s/^bind .*/bind 0.0.0.0/", "/etc/redis/redis.conf"]],
        servicios=["vsftpd", "redis-server"],
    ),
}


async def provision(host: LabHost, rol: Rol) -> None:
    async with asyncssh.connect(
        "127.0.0.1",
        port=host.nat_port,
        username=host.user,
        password=host.password,
        known_hosts=None,
    ) as conn:
        pw = host.password
        pasos: list[tuple[str, list[str], str]] = [
            ("apt update", ["apt-get", "update", "-q"], ""),
            (
                "apt install",
                [
                    "env",
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "install",
                    "-y",
                    "-q",
                    *rol.paquetes,
                ],
                "",
            ),
        ]
        pasos += [
            (f"escribir {ruta}", ["tee", ruta], texto) for ruta, texto in rol.ficheros.items()
        ]
        pasos += [(" ".join(c), c, "") for c in rol.comandos]
        pasos += [(f"reiniciar {s}", ["systemctl", "restart", s], "") for s in rol.servicios]
        for nombre, argv, entrada in pasos:
            estado = await run_sudo(conn, pw, argv, entrada)
            print(f"[{host.host_id}] {nombre}: exit={estado}")
            if estado != 0:
                raise SystemExit(f"[{host.host_id}] falló el paso: {nombre}")
        salida = await conn.run("ss -tln", check=True)
        print(f"[{host.host_id}] puertos en escucha:\n{str(salida.stdout).strip()}")


async def main() -> None:
    hosts = {h.host_id: h for h in load_lab_hosts(Path.cwd())}
    objetivos = sys.argv[1:] or list(ROLES)
    for host_id in objetivos:
        if host_id not in ROLES or host_id not in hosts:
            sys.exit(f"host sin rol definido o sin credenciales: {host_id}")
    await asyncio.gather(*(provision(hosts[h], ROLES[h]) for h in objetivos))


if __name__ == "__main__":
    asyncio.run(main())
