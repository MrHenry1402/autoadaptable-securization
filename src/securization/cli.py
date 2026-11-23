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

Solo orquesta lo que ya hacen los módulos: no construye ningún comando con texto del LLM y
el despliegue definitivo exige el plan aprobado (`deploy_decoy`).
"""

import argparse
import asyncio
import os
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
    build_deployment_plan,
    deploy_decoy,
    plant_breadcrumbs,
    start_decoy,
)
from securization.escaneo import AsyncNmapRunner, enrich_profile, profile_tcp_ports, scan_host
from securization.eventos import EventStore, collect_opencanary_events, fetch_decoy_log
from securization.generador import (
    Campaign,
    CampaignStore,
    CollisionError,
    DecoyConfig,
    build_campaign,
    propose_decoy_hostname,
)
from securization.inventario import CredentialVault, Inventory
from securization.llm import OllamaClient
from securization.modelos import Fingerprint, HostProfile
from securization.orquestador import VerificationResultStore, run_verification_loop
from securization.perfilador import AsyncSshTransport, HostProfileStore, orchestrate_profiling

_HOME_CMD = ("sh", "-c", 'getent passwd "$(id -un)" | cut -d: -f6')
_DECOY_STARTUP_S = 10


class Runtime:
    """Base de datos, clave y fábricas de transportes reales; los tests la sustituyen."""

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

    desplegar = sub.add_parser("deploy", help="planta breadcrumbs y despliega el señuelo")
    desplegar.add_argument("campaign_id")

    eventos = sub.add_parser("events", help="alertas de los señuelos")
    eventos.add_argument("action", choices=("collect", "list"))

    dash = sub.add_parser("dashboard", help="dashboard web")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8000)
    return parser


def _print(texto: str = "") -> None:
    print(texto, flush=True)


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
    host = rt.inventory.get_host(args.host_id)
    store = HostProfileStore(rt.engine)
    perfil = await orchestrate_profiling(
        host_id=host.host_id,
        address=IPv4Address(host.address),
        os_family=host.os_family,
        transport=rt.ssh(host.host_id),
        store=store,
    )
    real = await scan_host(perfil.address, rt.runner, ports=profile_tcp_ports(perfil))
    perfil = enrich_profile(perfil, real)
    store.save(perfil)
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
    perfil = HostProfileStore(rt.engine).load(args.host_id)
    ssh_host = rt.ssh(args.host_id)
    home = (await ssh_host.run(_HOME_CMD)).strip()
    conocidas = [f"{home}/{n}" for n in (await ssh_host.run(("ls", "-A", home))).split()]
    try:
        campana = build_campaign(
            perfil,
            campaign_id=f"campana-{args.host_id}",
            decoy_node_id=args.decoy_node,
            decoy_address=args.decoy_ip,
            home_dir=home,
            known_paths=conocidas,
        )
    except CollisionError as error:
        raise SystemExit(
            f"{args.host_id}: {error}; el fichero ya existe en el host y la herramienta "
            "nunca sobrescribe ficheros reales"
        ) from None
    await _verify_and_plan(args, rt, perfil, campana, conocidas)  # pragma: no cover


async def _verify_and_plan(  # pragma: no cover - E/S real: contenedores y nmap
    args: argparse.Namespace,
    rt: Runtime,
    perfil: HostProfile,
    campana: Campaign,
    conocidas: list[str],
) -> None:
    puertos = profile_tcp_ports(perfil)
    real = await scan_host(perfil.address, rt.runner, ports=puertos)
    ssh_dc, sftp_dc = rt.ssh(rt.deception_host), rt.sftp(rt.deception_host)

    async def arrancar(decoy: DecoyConfig) -> None:
        await start_decoy(decoy, sftp=sftp_dc, ssh=ssh_dc, config_dir=rt.decoy_config_dir)

    async def escanear(decoy: DecoyConfig) -> Fingerprint:
        await asyncio.sleep(_DECOY_STARTUP_S)
        return await scan_host(decoy.address, rt.runner, ports=puertos)

    resultado = await run_verification_loop(
        perfil, real, campana, start=arrancar, scan=escanear, max_attempts=args.max_attempts
    )
    plan = build_deployment_plan(resultado.campaign, resultado.report, known_paths=conocidas)
    CampaignStore(rt.engine).save(resultado.campaign)
    DeploymentPlanStore(rt.engine).save(plan)
    VerificationResultStore(rt.engine).save(resultado)
    for intento in resultado.attempts:
        _print(f"Intento {intento.attempt}: {intento.report.score}/{intento.report.threshold}")
        for diferencia in intento.report.differences:
            _print(f"    - {diferencia}")
    _print(f"Parada: {resultado.stop_reason}. Plan {plan.campaign_id} guardado SIN aprobar.")
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
    plan = DeploymentPlanStore(rt.engine).load(args.campaign_id)
    if not plan.ready_to_deploy:
        raise SystemExit(
            f"{plan.campaign_id}: el plan no está aprobado; usa `securization approve`"
        )
    campana = CampaignStore(rt.engine).load(args.campaign_id)  # pragma: no cover
    await plant_breadcrumbs(plan, rt.sftp(plan.host_id))  # pragma: no cover
    nombre = await deploy_decoy(  # pragma: no cover
        plan,
        campana,
        sftp=rt.sftp(rt.deception_host),
        ssh=rt.ssh(rt.deception_host),
        config_dir=rt.decoy_config_dir,
    )
    _print(f"Plantados {len(plan.actions)} breadcrumbs en {plan.host_id}; señuelo {nombre}")


async def _events(args: argparse.Namespace, rt: Runtime) -> None:
    store = EventStore(rt.engine)
    if args.action == "collect":
        campanas = CampaignStore(rt.engine).list_all()
        ssh = rt.ssh(rt.deception_host)
        for campana in campanas:
            log = await fetch_decoy_log(campana.decoy.node_id, ssh)
            nuevas = store.add_new(collect_opencanary_events(log, campanas))
            _print(f"{campana.campaign_id}: {nuevas} nuevas")
        return
    for e in store.list_recent():
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


def main(argv: Sequence[str] | None = None) -> None:  # pragma: no cover - punto de entrada
    args = build_parser().parse_args(argv)
    rt = Runtime.from_env()
    if args.command == "dashboard":
        import uvicorn

        from securization.dashboard import create_app

        uvicorn.run(create_app(rt.engine, rt.vault), host=args.host, port=args.port)
        return
    asyncio.run(run_command(args, rt))


if __name__ == "__main__":  # pragma: no cover
    main()
