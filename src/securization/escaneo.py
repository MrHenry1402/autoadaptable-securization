"""Escaneo con nmap: comandos fijos, parseo de la salida XML, IPs libres y ejecución real.

La construcción de comandos y el parseo de XML son puros, sin E/S, probados con salidas de
ejemplo (`tests/fixtures/nmap/`). La E/S real de verdad (lanzar `nmap`) va detrás de la
interfaz `ProcessRunner` (L2): una implementación falsa en los tests y `AsyncNmapRunner`
(subprocess real, nunca shell) para cuando haya laboratorio — mismo patrón que `SshTransport`
en `perfilador.py`. El XML se lee siempre con `defusedxml` y se trata como no confiable.
"""

import asyncio
from collections.abc import Iterable, Sequence
from ipaddress import IPv4Address, IPv4Network
from typing import Protocol, runtime_checkable

# Solo se usa para anotar tipos; el XML se parsea siempre con defusedxml.
from xml.etree.ElementTree import Element  # nosec B405

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError as XmlParseError
from defusedxml.ElementTree import fromstring

from securization.modelos import Fingerprint, OsMatch, ServiceInfo
from securization.parsing import ParseError, sanitize_text


class NmapScanError(Exception):
    """Fallo al escanear un host: el proceso de nmap falló o su salida no es interpretable."""

_MIN_PREFIX = 16
_BANNER_SCRIPTS = ("banner", "http-server-header")
_UNKNOWN_SERVICE = "unknown"


# --- Comandos ---------------------------------------------------------------


def _parse_address(address: str | IPv4Address) -> IPv4Address:
    try:
        return IPv4Address(address)
    except ValueError:
        raise ValueError(f"address inválida: {address!r}") from None


def _parse_network(network: str) -> IPv4Network:
    try:
        red = IPv4Network(network)
    except ValueError:
        raise ValueError(f"network inválida: {network!r}") from None
    if red.prefixlen < _MIN_PREFIX:
        raise ValueError(f"network demasiado grande (mínimo /{_MIN_PREFIX}): {network!r}")
    return red


def build_scan_command(address: str | IPv4Address) -> tuple[str, ...]:
    """Comando para huella de un único host (`-sV -O`) con salida XML por stdout."""
    return ("nmap", "-sV", "-O", "-oX", "-", str(_parse_address(address)))


def build_ping_sweep_command(network: str) -> tuple[str, ...]:
    """Comando de barrido de hosts vivos (`-sn`) sobre una red, con salida XML por stdout."""
    return ("nmap", "-sn", "-oX", "-", str(_parse_network(network)))


# --- Parseo de XML ----------------------------------------------------------


def _load_nmaprun(xml_text: str) -> Element:
    try:
        raiz = fromstring(xml_text)
    except (XmlParseError, DefusedXmlException, ValueError) as error:
        raise ParseError(f"Salida de nmap no válida: {type(error).__name__}") from None
    if raiz.tag != "nmaprun":
        raise ParseError("La salida de nmap no tiene la raíz <nmaprun>")
    return raiz


def _host_address(host: Element) -> IPv4Address | None:
    """IPv4 de un host que está `up`; `None` si está caído o no tiene dirección IPv4."""
    estado = host.find("status")
    if estado is None or estado.get("state") != "up":
        return None
    for direccion in host.findall("address"):
        if direccion.get("addrtype") == "ipv4":
            try:
                return IPv4Address(direccion.get("addr", ""))
            except ValueError:
                return None
    return None


def _optional_text(valor: str | None) -> str | None:
    if valor is None:
        return None
    return sanitize_text(valor) or None


def _parse_service(puerto: Element) -> ServiceInfo | None:
    estado = puerto.find("state")
    if estado is None or estado.get("state") != "open":
        return None
    protocolo = puerto.get("protocol")
    identificador = puerto.get("portid", "")
    if protocolo not in ("tcp", "udp") or not identificador.isdecimal():
        return None
    numero = int(identificador)
    if not 1 <= numero <= 65535:
        return None

    servicio = puerto.find("service")
    nombre = _UNKNOWN_SERVICE
    producto = version = extrainfo = None
    if servicio is not None:
        nombre = _optional_text(servicio.get("name")) or _UNKNOWN_SERVICE
        producto = _optional_text(servicio.get("product"))
        version = _optional_text(servicio.get("version"))
        extrainfo = _optional_text(servicio.get("extrainfo"))

    banner = None
    for script in puerto.findall("script"):
        if script.get("id") in _BANNER_SCRIPTS:
            banner = _optional_text(script.get("output"))
            if banner:
                break

    return ServiceInfo(
        port=numero,
        protocol=protocolo,
        name=nombre,
        banner=banner,
        product=producto,
        version=version,
        extrainfo=extrainfo,
    )


def _parse_os_matches(host: Element) -> list[OsMatch]:
    coincidencias: list[OsMatch] = []
    for elemento in host.findall("os/osmatch"):
        precision = elemento.get("accuracy", "")
        if not precision.isdecimal() or int(precision) > 100:
            continue
        nombre = sanitize_text(elemento.get("name", ""))
        if not nombre:
            continue
        clase = elemento.find("osclass")
        familia = _optional_text(clase.get("osfamily")) if clase is not None else None
        coincidencias.append(OsMatch(name=nombre, accuracy=int(precision), os_family=familia))
    return sorted(coincidencias, key=lambda m: m.accuracy, reverse=True)


def parse_nmap_xml(xml_text: str) -> list[Fingerprint]:
    """Huellas de los hosts vivos de una salida `nmap -oX`, ordenadas por dirección."""
    huellas: list[Fingerprint] = []
    for host in _load_nmaprun(xml_text).findall("host"):
        direccion = _host_address(host)
        if direccion is None:
            continue
        servicios = [
            servicio
            for puerto in host.findall("ports/port")
            if (servicio := _parse_service(puerto)) is not None
        ]
        servicios.sort(key=lambda s: (s.port, s.protocol))
        huellas.append(
            Fingerprint(
                address=direccion,
                os_matches=_parse_os_matches(host),
                services=servicios,
            )
        )
    return sorted(huellas, key=lambda h: h.address)


def parse_alive_hosts(xml_text: str) -> list[IPv4Address]:
    """Direcciones IPv4 vivas de un barrido `nmap -sn -oX`, ordenadas."""
    vivas = (_host_address(host) for host in _load_nmaprun(xml_text).findall("host"))
    return sorted(direccion for direccion in vivas if direccion is not None)


# --- Ejecución real (L2) -----------------------------------------------------


@runtime_checkable
class ProcessRunner(Protocol):
    """Ejecuta un comando (lista de argumentos) y devuelve su salida estándar.

    Mismo contrato que `SshTransport` en `perfilador.py`, para que todo el proyecto use una
    sola forma de abstraer "ejecutar un comando externo y darme el stdout".
    """

    async def run(self, argv: Sequence[str]) -> str:
        """Ejecuta el comando (lista de argumentos) y devuelve su salida estándar."""
        ...


class AsyncNmapRunner:
    """Implementación real de `ProcessRunner`: lanza el proceso sin shell (L2)."""

    async def run(self, argv: Sequence[str]) -> str:
        proceso = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proceso.communicate()
        if proceso.returncode != 0:
            error = sanitize_text(stderr.decode(errors="replace").strip())
            raise NmapScanError(
                f"nmap terminó con código {proceso.returncode}: {error}"
            )
        return stdout.decode(errors="replace")


async def scan_host(address: IPv4Address, runner: ProcessRunner) -> Fingerprint:
    """Escanea un host con `nmap -sV -O` y devuelve su huella.

    Falla con `NmapScanError` si el proceso falla, si la salida no es XML de nmap
    interpretable, o si la dirección pedida no aparece entre los hosts vivos (nunca
    devuelve la huella de otro host por error).
    """
    comando = build_scan_command(address)
    try:
        salida = await runner.run(comando)
    except NmapScanError:
        raise
    except Exception as error:
        raise NmapScanError(f"fallo al ejecutar nmap contra {address}: {error}") from error
    try:
        huellas = parse_nmap_xml(salida)
    except ParseError as error:
        raise NmapScanError(f"salida de nmap no interpretable para {address}: {error}") from error
    for huella in huellas:
        if huella.address == address:
            return huella
    raise NmapScanError(f"{address} no aparece entre los hosts vivos del escaneo")


# --- IPs libres -------------------------------------------------------------


def find_free_ips(
    network: str,
    used: Iterable[str | IPv4Address],
    limit: int = 64,
) -> list[IPv4Address]:
    """Primeras IPs libres de la red, excluyendo red, broadcast y las direcciones usadas."""
    red = _parse_network(network)
    ocupadas: set[IPv4Address] = set()
    for direccion in used:
        try:
            ocupadas.add(IPv4Address(direccion))
        except ValueError:
            raise ValueError(f"used contiene una dirección inválida: {direccion!r}") from None

    libres: list[IPv4Address] = []
    for candidata in red.hosts():
        if len(libres) >= limit:
            break
        if candidata not in ocupadas:
            libres.append(candidata)
    return libres
