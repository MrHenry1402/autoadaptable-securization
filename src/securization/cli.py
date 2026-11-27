"""CLI `securization` (H6): el flujo completo de la herramienta desde una terminal.

    securization hosts add|list          alta (contraseña con getpass) y listado
    securization profile HOST            perfil por SSH + huella nmap del host real
    securization name HOST               propuesta de hostname con el LLM local (Ollama)
    securization campaign HOST ...       campaña H2 + bucle de verificación H4 + plan
    securization approve CAMPAÑA         aprobación manual del operador
    securization deploy CAMPAÑA          planta breadcrumbs y despliega el señuelo
    securization events collect|list     alertas reales de los señuelos
    securization dashboard               dashboard web (FastAPI)

Configuración por variables de entorno: SECURIZATION_DB (inventario.db),
SECURIZATION_KEY_FILE (securization.key; o la clave en SECURIZATION_KEY),
SECURIZATION_DECEPTION_HOST (deception-central) y SECURIZATION_DECOY_DIR (/home/lab/decoys).

Solo orquesta lo que ya hacen los módulos (`operaciones.py`): no construye ningún comando con
texto del LLM y el despliegue definitivo exige el plan aprobado (`deploy_decoy`). Las
operaciones largas pintan una barra de progreso en la salida de error.
"""

import argparse
import asyncio
import ipaddress
import os
import socket
import sys
from collections.abc import Sequence
from getpass import getpass
from ipaddress import IPv4Address
from pathlib import Path

from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.desplegador import (
    AsyncSftpTransport,
    DeploymentPlanStore,
    PlausibilityThresholdError,
    approve_plan,
)
from securization.escaneo import AsyncNmapRunner
from securization.eventos import EventStore
from securization.generador import CollisionError, propose_decoy_hostname
from securization.inventario import CredentialVault, HostNotFoundError, Inventory
from securization.llm import OllamaClient
from securization.operaciones import (
    BarraTerminal,
    PlanNoAprobadoError,
    crear_campana,
    desplegar,
    perfilar,
    recoger_alertas,
)
from securization.perfilador import AsyncSshTransport, HostProfileStore


class Runtime:
    """Base de datos, clave y fábricas de transportes reales; los tests la sustituyen."""

    decoy_startup_s: float = 10

    def __init__(
        self,
        *,
        db_path: Path,
        key_path: Path,
        deception_host: str = "deception-central",
        decoy_config_dir: str = "/home/lab/decoys",
    ) -> None:
        if key_path.exists():
            clave = key_path.read_bytes().strip()
        elif os.environ.get("SECURIZATION_KEY"):
            clave = os.environ["SECURIZATION_KEY"].encode()
        else:
            raise SystemExit(
                f"Falta la clave Fernet: no existe {key_path} ni la variable SECURIZATION_KEY"
            )
        self.engine: Engine = create_engine(f"sqlite:///{db_path}")
        self.vault = CredentialVault(clave)
        self.deception_host = deception_host
        self.decoy_config_dir = decoy_config_dir
        self.runner = AsyncNmapRunner()

    @classmethod
    def from_env(cls) -> "Runtime":
        return cls(
            db_path=Path(os.environ.get("SECURIZATION_DB", "inventario.db")),
            key_path=Path(os.environ.get("SECURIZATION_KEY_FILE", "securization.key")),
            deception_host=os.environ.get("SECURIZATION_DECEPTION_HOST", "deception-central"),
            decoy_config_dir=os.environ.get("SECURIZATION_DECOY_DIR", "/home/lab/decoys"),
        )

    @property
    def inventory(self) -> Inventory:
        return Inventory(self.engine, self.vault)

    def ssh(self, host_id: str) -> AsyncSshTransport:  # pragma: no cover - E/S real
        h = self.inventory.get_host(host_id)
        secreto = self.inventory.get_ssh_secret(host_id)
        return AsyncSshTransport(h.address, h.ssh_port, h.ssh_user, secreto)

    def sftp(self, host_id: str) -> AsyncSftpTransport:  # pragma: no cover - E/S real
        h = self.inventory.get_host(host_id)
        secreto = self.inventory.get_ssh_secret(host_id)
        return AsyncSftpTransport(h.address, h.ssh_port, h.ssh_user, secreto)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securization", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    hosts = sub.add_parser("hosts", help="inventario de hosts gestionados")
    hosts_sub = hosts.add_subparsers(dest="action", required=True)
    hosts_sub.add_parser("list")
    alta = hosts_sub.add_parser("add", help="la contraseña SSH se pide por teclado")
    alta.add_argument("host_id")
    alta.add_argument("address", type=IPv4Address)
    alta.add_argument("--user", required=True)
    alta.add_argument("--port", type=int, default=22)

    perfil = sub.add_parser("profile", help="perfil SSH + huella nmap")
    perfil.add_argument("host_id")

    nombre = sub.add_parser("name", help="hostname del señuelo propuesto por el LLM local")
    nombre.add_argument("host_id")
    nombre.add_argument("--model", default="qwen3:8b")

    campana = sub.add_parser("campaign", help="campaña + bucle de verificación + plan")
    campana.add_argument("host_id")
    campana.add_argument("--decoy-node", required=True)
    campana.add_argument("--decoy-ip", required=True, type=IPv4Address)
    campana.add_argument("--max-attempts", type=int, default=3)

    aprobar = sub.add_parser("approve", help="aprobación manual del plan")
    aprobar.add_argument("campaign_id")

    desplegar_ = sub.add_parser("deploy", help="planta breadcrumbs y despliega el señuelo")
    desplegar_.add_argument("campaign_id")

    eventos = sub.add_parser("events", help="alertas de los señuelos")
    eventos.add_argument("action", choices=("collect", "list"))

    dash = sub.add_parser("dashboard", help="dashboard web")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8000)
    dash.add_argument(
        "--acciones",
        action="store_true",
        help="permite lanzar operaciones desde el dashboard aunque no escuche solo en local",
    )
    return parser


def _print(texto: str = "") -> None:
    print(texto, flush=True)


def _barra() -> BarraTerminal:
    return BarraTerminal(lambda linea: print(linea, file=sys.stderr, flush=True))


async def _hosts(args: argparse.Namespace, rt: Runtime) -> None:
    if args.action == "add":
        secreto = getpass(f"Contraseña SSH de {args.user}@{args.host_id}: ")
        rt.inventory.add_host(
            host_id=args.host_id,
            address=str(args.address),
            ssh_user=args.user,
            ssh_secret=secreto,
            ssh_port=args.port,
        )
        _print(f"Alta: {args.host_id} ({args.address}), credencial cifrada en el inventario")
        return
    for h in rt.inventory.list_hosts():
        acceso = f"{h.ssh_user}@{h.address}:{h.ssh_port}"
        _print(f"{h.host_id:<20} {h.address:<15} {acceso:<28} {h.os_family}")


async def _profile(args: argparse.Namespace, rt: Runtime) -> None:  # pragma: no cover
    perfil = await perfilar(rt, args.host_id, _barra())
    _print(f"{perfil.host_id} - {perfil.os_name}")
    for s in perfil.services:
        _print(f"  {s.port}/{s.protocol} {s.name} {s.product or ''} {s.version or ''}".rstrip())
    for paquete, version in sorted(perfil.packages.items()):
        _print(f"  paquete {paquete} {version}")


async def _name(args: argparse.Namespace, rt: Runtime) -> None:  # pragma: no cover
    perfil = HostProfileStore(rt.engine).load(args.host_id)
    identidad, calidad = await propose_decoy_hostname(perfil, OllamaClient(args.model))
    _print(f"Hostname propuesto: {identidad.hostname} (calidad: {calidad})")


async def _campaign(args: argparse.Namespace, rt: Runtime) -> None:
    try:
        resultado = await crear_campana(
            rt,
            args.host_id,
            decoy_node=args.decoy_node,
            decoy_ip=args.decoy_ip,
            max_attempts=args.max_attempts,
            informe=_barra(),
        )
    except CollisionError as error:
        raise SystemExit(
            f"{args.host_id}: {error}; el fichero ya existe en el host y la herramienta "
            "nunca sobrescribe ficheros reales"
        ) from None
    for intento in resultado.verificacion.attempts:
        _print(f"Intento {intento.attempt}: {intento.report.score}/{intento.report.threshold}")
        for diferencia in intento.report.differences:
            _print(f"    - {diferencia}")
    plan = resultado.plan
    parada = resultado.verificacion.stop_reason
    _print(f"Parada: {parada}. Plan {plan.campaign_id} guardado SIN aprobar.")
    _print(f"Breadcrumbs previstos: {', '.join(a.path for a in plan.actions)}")


async def _approve(args: argparse.Namespace, rt: Runtime) -> None:
    planes = DeploymentPlanStore(rt.engine)
    try:
        plan = approve_plan(planes.load(args.campaign_id))
    except PlausibilityThresholdError as error:
        raise SystemExit(str(error)) from None
    planes.save(plan)
    _print(f"{plan.campaign_id} aprobado ({plan.plausibility_score}/{plan.plausibility_threshold})")


async def _deploy(args: argparse.Namespace, rt: Runtime) -> None:
    try:
        nombre = await desplegar(rt, args.campaign_id, _barra())
    except PlanNoAprobadoError:
        raise SystemExit(
            f"{args.campaign_id}: el plan no está aprobado; usa `securization approve`"
        ) from None
    plan = DeploymentPlanStore(rt.engine).load(args.campaign_id)
    _print(f"Plantados {len(plan.actions)} breadcrumbs en {plan.host_id}; señuelo {nombre}")


async def _events(args: argparse.Namespace, rt: Runtime) -> None:
    if args.action == "collect":
        for campaign_id, nuevas in (await recoger_alertas(rt, _barra())).items():
            _print(f"{campaign_id}: {nuevas} nuevas")
        return
    for e in EventStore(rt.engine).list_recent():
        marca = f"breadcrumb {e.breadcrumb_service}" if e.breadcrumb_service else ""
        _print(
            f"{e.timestamp:%Y-%m-%d %H:%M:%S} {e.campaign_id:<22} {e.node_id:<10} "
            f"{e.src_host:<15} :{e.dst_port:<5} {e.logtype:<6} {marca}"
        )


_COMMANDS = {
    "hosts": _hosts,
    "profile": _profile,
    "name": _name,
    "campaign": _campaign,
    "approve": _approve,
    "deploy": _deploy,
    "events": _events,
}


async def run_command(args: argparse.Namespace, rt: Runtime) -> None:
    """Ejecuta un subcomando (salvo `dashboard`, que arranca su propio servidor)."""
    await _COMMANDS[args.command](args, rt)


def ip_local_hacia(destino: str) -> str | None:
    """IP local que usaría esta máquina para llegar a `destino` (sin enviar ningún paquete).

    Es la dirección desde la que la herramienta escanea sus trampas; el dashboard la usa para
    no presentar esos escaneos de verificación como si fueran un intruso.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((destino, 9))  # UDP: connect() solo elige ruta, no envía nada
            return str(s.getsockname()[0])
    except OSError:
        return None


def acciones_permitidas(host: str, forzar: bool) -> bool:
    """El dashboard solo lanza operaciones si escucha en local, salvo que se fuerce."""
    try:
        return forzar or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return forzar or host == "localhost"


def main(argv: Sequence[str] | None = None) -> None:  # pragma: no cover - punto de entrada
    args = build_parser().parse_args(argv)
    rt = Runtime.from_env()
    if args.command == "dashboard":
        import uvicorn

        from securization.dashboard import create_app

        entorno = rt if acciones_permitidas(args.host, args.acciones) else None
        propias: frozenset[str] = frozenset()
        try:
            propia = ip_local_hacia(rt.inventory.get_host(rt.deception_host).address)
            propias = frozenset({propia}) if propia else frozenset()
        except HostNotFoundError:
            pass
        app = create_app(rt.engine, rt.vault, entorno=entorno, ips_propias=propias)
        uvicorn.run(app, host=args.host, port=args.port)
        return
    asyncio.run(run_command(args, rt))


if __name__ == "__main__":  # pragma: no cover
    main()
