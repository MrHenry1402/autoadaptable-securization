"""Parsers de la salida de los comandos de `LinuxProfiler`.

Reciben texto y devuelven modelos, sin hacer E/S. Toda la salida de un host se trata como no
confiable: se descartan los caracteres de control y se limita la longitud de los valores.
"""

import re
import shlex
from collections.abc import Sequence
from ipaddress import ip_address

from securization.modelos import ServiceInfo
from securization.parsing import ParseError, has_control_chars, sanitize_text

# Comandos remotos fijos; se ejecutan como lista de argumentos, nunca construidos a mano.
OS_RELEASE_CMD: tuple[str, ...] = ("cat", "/etc/os-release")
SS_CMD: tuple[str, ...] = ("ss", "-tlnp")
LS_ROOT_CMD: tuple[str, ...] = ("ls", "-1Ap", "/")
# dpkg-query interpreta \t y \n del formato; shlex.join lo entrecomilla para el shell remoto.
DPKG_CMD: tuple[str, ...] = ("dpkg-query", "-W", r"-f=${Package}\t${Version}\n")

# Paquetes de servicio cuya versión exacta sirve para que el señuelo anuncie la misma (H4).
SERVICE_PACKAGES: frozenset[str] = frozenset(
    {
        "apache2",
        "mariadb-server",
        "mysql-server",
        "nginx",
        "openssh-server",
        "postgresql",
        "redis-server",
        "vsftpd",
    }
)
_DEBIAN_VERSION_RE = re.compile(r"[0-9][A-Za-z0-9.+~:-]{0,63}")

__all__ = [
    "DPKG_CMD",
    "LS_ROOT_CMD",
    "OS_RELEASE_CMD",
    "SERVICE_PACKAGES",
    "SS_CMD",
    "ParseError",
    "parse_dpkg_query",
    "parse_os_release",
    "parse_ss_listening",
    "parse_top_level_dirs",
    "to_command_line",
]

_MAX_DIR_NAME_LEN = 255
_UNKNOWN_PROCESS = "unknown"
_VIRTUAL_DIRS = frozenset({"proc", "sys", "dev", "run", "lost+found"})
_PROCESS_RE = re.compile(r'users:\(\("([^"]*)"')


def to_command_line(argv: Sequence[str]) -> str:
    """Convierte una lista de argumentos en la línea que pide asyncssh, escapando cada uno."""
    return shlex.join(argv)


def parse_dpkg_query(text: str) -> dict[str, str]:
    """Versión instalada de los paquetes de servicio, a partir de `DPKG_CMD`.

    Solo guarda los de `SERVICE_PACKAGES` y con una versión con forma de versión Debian;
    cualquier otra línea se ignora (la salida del host no es confiable).
    """
    paquetes: dict[str, str] = {}
    for linea in text.splitlines():
        nombre, sep, version = linea.partition("\t")
        if sep and nombre in SERVICE_PACKAGES and _DEBIAN_VERSION_RE.fullmatch(version):
            paquetes[nombre] = version
    return paquetes


def parse_os_release(text: str) -> str:
    """Devuelve el nombre del SO a partir de `/etc/os-release`."""
    valores: dict[str, str] = {}
    for linea in text.splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#"):
            continue
        clave, sep, valor = linea.partition("=")
        if not sep:
            continue
        valor = valor.strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "\"'":
            valor = valor[1:-1]
        valores[clave.strip()] = valor

    nombre = valores.get("PRETTY_NAME")
    if not nombre:
        base = valores.get("NAME")
        if base:
            version = valores.get("VERSION_ID")
            nombre = f"{base} {version}" if version else base
    resultado = sanitize_text(nombre).strip() if nombre else ""
    if not resultado:
        raise ParseError("/etc/os-release no contiene PRETTY_NAME ni NAME")
    return resultado


def parse_ss_listening(text: str) -> list[ServiceInfo]:
    """Servicios TCP expuestos (no solo loopback) a partir de `ss -tlnp`, sin duplicados."""
    por_puerto: dict[int, str] = {}
    for linea in text.splitlines():
        campos = linea.split()
        if len(campos) < 5 or campos[0] != "LISTEN":
            continue
        direccion, sep, puerto_txt = campos[3].rpartition(":")
        if not sep or not puerto_txt.isdecimal():
            continue
        puerto = int(puerto_txt)
        if not 1 <= puerto <= 65535:
            continue
        host = direccion.strip("[]").split("%")[0]
        if host not in ("", "*"):
            try:
                if ip_address(host).is_loopback:
                    continue
            except ValueError:
                continue
        coincidencia = _PROCESS_RE.search(linea)
        nombre = sanitize_text(coincidencia.group(1)) if coincidencia else ""
        nombre = nombre or _UNKNOWN_PROCESS
        if por_puerto.get(puerto, _UNKNOWN_PROCESS) == _UNKNOWN_PROCESS:
            por_puerto[puerto] = nombre
    return [
        ServiceInfo(port=puerto, protocol="tcp", name=nombre)
        for puerto, nombre in sorted(por_puerto.items())
    ]


def parse_top_level_dirs(text: str) -> list[str]:
    """Directorios de primer nivel de `/` a partir de `ls -1Ap /`, ordenados."""
    dirs: set[str] = set()
    for linea in text.splitlines():
        if not linea.endswith("/"):
            continue
        nombre = linea[:-1]
        if (
            not nombre
            or "/" in nombre
            or nombre in (".", "..")
            or len(nombre) > _MAX_DIR_NAME_LEN
            or has_control_chars(nombre)
            or nombre in _VIRTUAL_DIRS
        ):
            continue
        dirs.add(f"/{nombre}")
    return sorted(dirs)
