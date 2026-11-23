"""Lectura de `lab-credentials.local.txt` (ignorado por git) para los scripts del laboratorio.

Formato de cada línea: `<host_id> <usuario> <contraseña> puerto_nat=<n> ip_labnet=<ip> ...`
"""

import re
from dataclasses import dataclass
from pathlib import Path

FICHERO = "lab-credentials.local.txt"
_PUERTO_RE = re.compile(r"puerto_nat=(\d+)")
_IP_RE = re.compile(r"ip_labnet=([\d.]+)")


@dataclass(frozen=True)
class LabHost:
    host_id: str
    user: str
    password: str
    nat_port: int
    labnet_ip: str


def load_lab_hosts(repo_root: Path) -> list[LabHost]:
    """Devuelve los hosts del fichero de credenciales local, ignorando líneas incompletas."""
    hosts = []
    for linea in (repo_root / FICHERO).read_text(encoding="utf-8-sig").splitlines():
        partes = linea.split()
        puerto = _PUERTO_RE.search(linea)
        ip = _IP_RE.search(linea)
        if len(partes) < 3 or puerto is None or ip is None:
            continue
        hosts.append(LabHost(partes[0], partes[1], partes[2], int(puerto.group(1)), ip.group(1)))
    return hosts
