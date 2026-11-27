"""Operaciones de la herramienta con informe de progreso (CLI y dashboard).

Cada operación es la misma secuencia determinista que ya hacía la CLI (perfilar, generar y
verificar la campaña, desplegar, recoger alertas), pero avisando a un `Informe` de cada paso
con un porcentaje y una frase en lenguaje llano. La terminal lo pinta como una barra de texto
y el dashboard como una barra de carga.

El progreso no cambia lo que se ejecuta: los comandos siguen siendo listas de argumentos
fijas, el despliegue sigue exigiendo el plan aprobado y nada se construye con texto del LLM.
"""

import asyncio
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Address
from typing import Literal, Protocol

from sqlalchemy import Engine

from securization.desplegador import (
    DeploymentPlan,
    DeploymentPlanStore,
    SftpTransport,
    build_deployment_plan,
    deploy_decoy,
    plant_breadcrumbs,
    start_decoy,
)
from securization.escaneo import ProcessRunner, enrich_profile, profile_tcp_ports, scan_host
from securization.eventos import EventStore, collect_opencanary_events, fetch_decoy_log
from securization.generador import CampaignStore, DecoyConfig, build_campaign
from securization.inventario import Inventory
from securization.modelos import Fingerprint, HostProfile
from securization.orquestador import (
    VerificationResult,
    VerificationResultStore,
    run_verification_loop,
)
from securization.perfilador import HostProfileStore, SshTransport, orchestrate_profiling

_HOME_CMD = ("sh", "-c", 'getent passwd "$(id -un)" | cut -d: -f6')

Informe = Callable[[int, str], None]
"""Recibe (porcentaje 0-100, frase de lo que se está haciendo)."""


def sin_informe(_porcentaje: int, _mensaje: str) -> None:
    """Informe que no hace nada (para llamadas sin barra de progreso)."""


class Entorno(Protocol):
    """Lo que necesitan las operaciones: base de datos, inventario y transportes reales."""

    @property
    def engine(self) -> Engine: ...

    @property
    def deception_host(self) -> str: ...

    @property
    def decoy_config_dir(self) -> str: ...

    @property
    def runner(self) -> ProcessRunner: ...

    @property
    def decoy_startup_s(self) -> float: ...

    @property
    def inventory(self) -> Inventory: ...

    def ssh(self, host_id: str) -> SshTransport: ...

    def sftp(self, host_id: str) -> SftpTransport: ...


async def perfilar(entorno: Entorno, host_id: str, informe: Informe = sin_informe) -> HostProfile:
    """Perfil por SSH + huella nmap de un equipo dado de alta."""
    host = entorno.inventory.get_host(host_id)
    informe(10, f"Conectando por SSH con {host_id} para ver su sistema y servicios")
    store = HostProfileStore(entorno.engine)
    perfil = await orchestrate_profiling(
        host_id=host.host_id,
        address=IPv4Address(host.address),
        os_family=host.os_family,
        transport=entorno.ssh(host.host_id),
        store=store,
    )
    informe(45, f"Escaneando {host.address} con nmap para copiar sus versiones exactas")
    real = await scan_host(perfil.address, entorno.runner, ports=profile_tcp_ports(perfil))
    perfil = enrich_profile(perfil, real)
    store.save(perfil)
    informe(100, f"Perfil guardado: {perfil.os_name}, {len(perfil.services)} servicios")
    return perfil


@dataclass(frozen=True)
class ResultadoCampana:
    verificacion: VerificationResult
    plan: DeploymentPlan


async def crear_campana(
    entorno: Entorno,
    host_id: str,
    *,
    decoy_node: str,
    decoy_ip: IPv4Address,
    max_attempts: int = 3,
    informe: Informe = sin_informe,
) -> ResultadoCampana:
    """Genera la trampa, la verifica contra el equipo real (bucle H4) y deja el plan sin aprobar."""
    informe(3, f"Leyendo el perfil guardado de {host_id}")
    perfil = HostProfileStore(entorno.engine).load(host_id)
    ssh_host = entorno.ssh(host_id)
    informe(8, f"Revisando qué ficheros hay ya en {host_id} para no pisar ninguno")
    home = (await ssh_host.run(_HOME_CMD)).strip()
    conocidas = [f"{home}/{n}" for n in (await ssh_host.run(("ls", "-A", home))).split()]
    campana = build_campaign(
        perfil,
        campaign_id=f"campana-{host_id}",
        decoy_node_id=decoy_node,
        decoy_address=decoy_ip,
        home_dir=home,
        known_paths=conocidas,
    )
    puertos = profile_tcp_ports(perfil)
    informe(15, f"Escaneando el equipo real {perfil.address} para tener con qué comparar")
    real = await scan_host(perfil.address, entorno.runner, ports=puertos)
    ssh_dc, sftp_dc = entorno.ssh(entorno.deception_host), entorno.sftp(entorno.deception_host)
    tramo = 75 / max_attempts
    intento = 0

    async def arrancar(decoy: DecoyConfig) -> None:
        nonlocal intento
        intento += 1
        base = 20 + tramo * (intento - 1)
        informe(
            int(base), f"Intento {intento}: arrancando la trampa {decoy.node_id} en {decoy.address}"
        )
        await start_decoy(decoy, sftp=sftp_dc, ssh=ssh_dc, config_dir=entorno.decoy_config_dir)

    async def escanear(decoy: DecoyConfig) -> Fingerprint:
        base = 20 + tramo * (intento - 1)
        informe(int(base + tramo / 3), f"Intento {intento}: esperando a que la trampa esté lista")
        await asyncio.sleep(entorno.decoy_startup_s)
        informe(
            int(base + 2 * tramo / 3),
            f"Intento {intento}: escaneando la trampa como lo haría un atacante",
        )
        return await scan_host(decoy.address, entorno.runner, ports=puertos)

    resultado = await run_verification_loop(
        perfil, real, campana, start=arrancar, scan=escanear, max_attempts=max_attempts
    )
    plan = build_deployment_plan(resultado.campaign, resultado.report, known_paths=conocidas)
    CampaignStore(entorno.engine).save(resultado.campaign)
    DeploymentPlanStore(entorno.engine).save(plan)
    VerificationResultStore(entorno.engine).save(resultado)
    informe(
        100,
        f"Parecido con el equipo real: {resultado.report.score}/{resultado.report.threshold}. "
        "Falta tu aprobación.",
    )
    return ResultadoCampana(resultado, plan)


class PlanNoAprobadoError(Exception):
    """Se ha pedido desplegar una campaña cuyo plan no está aprobado."""


async def desplegar(entorno: Entorno, campaign_id: str, informe: Informe = sin_informe) -> str:
    """Planta los cebos y arranca la trampa definitiva; exige el plan aprobado."""
    informe(5, "Comprobando que la campaña está aprobada")
    plan = DeploymentPlanStore(entorno.engine).load(campaign_id)
    if not plan.ready_to_deploy:
        raise PlanNoAprobadoError(
            f"{plan.campaign_id}: el plan no está aprobado; apruébalo antes de desplegar"
        )
    campana = CampaignStore(entorno.engine).load(campaign_id)
    informe(30, f"Dejando {len(plan.actions)} ficheros cebo en {plan.host_id}")
    await plant_breadcrumbs(plan, entorno.sftp(plan.host_id))
    informe(65, f"Arrancando la trampa {campana.decoy.node_id} en {campana.decoy.address}")
    nombre = await deploy_decoy(
        plan,
        campana,
        sftp=entorno.sftp(entorno.deception_host),
        ssh=entorno.ssh(entorno.deception_host),
        config_dir=entorno.decoy_config_dir,
    )
    DeploymentPlanStore(entorno.engine).save(
        plan.model_copy(update={"deployed_at": datetime.now(UTC)})
    )
    informe(100, f"Desplegado: {len(plan.actions)} cebos en {plan.host_id} y trampa {nombre}")
    return nombre


async def recoger_alertas(entorno: Entorno, informe: Informe = sin_informe) -> dict[str, int]:
    """Lee el registro de cada trampa y guarda las alertas nuevas; devuelve nuevas por campaña."""
    store = EventStore(entorno.engine)
    campanas = CampaignStore(entorno.engine).list_all()
    nuevas: dict[str, int] = {}
    if not campanas:
        informe(100, "No hay trampas de las que recoger alertas")
        return nuevas
    ssh = entorno.ssh(entorno.deception_host)
    for i, campana in enumerate(campanas):
        informe(
            int(100 * i / len(campanas)),
            f"Leyendo las alertas de la trampa {campana.decoy.node_id}",
        )
        log = await fetch_decoy_log(campana.decoy.node_id, ssh)
        nuevas[campana.campaign_id] = store.add_new(collect_opencanary_events(log, campanas))
    informe(100, f"{sum(nuevas.values())} alertas nuevas")
    return nuevas


# --- Trabajos en segundo plano (dashboard) ----------------------------------------------


@dataclass
class Trabajo:
    """Una operación lanzada desde el dashboard y su progreso."""

    id: str
    titulo: str
    porcentaje: int = 0
    mensaje: str = "Preparando…"
    estado: Literal["en curso", "hecho", "error"] = "en curso"
    pasos: list[str] = field(default_factory=list)
    enlace: str | None = None
    inicio: datetime = field(default_factory=lambda: datetime.now(UTC))

    def informar(self, porcentaje: int, mensaje: str) -> None:
        self.porcentaje = max(self.porcentaje, min(porcentaje, 100))
        if self.mensaje and self.mensaje != mensaje and self.mensaje != "Preparando…":
            self.pasos.append(self.mensaje)
        self.mensaje = mensaje

    def terminar(self, mensaje: str, enlace: str | None = None) -> None:
        self.informar(100, mensaje)
        self.estado = "hecho"
        self.enlace = enlace

    def fallar(self, mensaje: str) -> None:
        self.mensaje = mensaje
        self.estado = "error"


class Trabajos:
    """Registro en memoria de las operaciones lanzadas desde el dashboard."""

    def __init__(self) -> None:
        self._trabajos: dict[str, Trabajo] = {}

    def nuevo(self, titulo: str) -> Trabajo:
        trabajo = Trabajo(id=uuid.uuid4().hex[:12], titulo=titulo)
        self._trabajos[trabajo.id] = trabajo
        return trabajo

    def get(self, trabajo_id: str) -> Trabajo | None:
        return self._trabajos.get(trabajo_id)

    def en_curso(self) -> list[Trabajo]:
        return [t for t in self._trabajos.values() if t.estado == "en curso"]


# --- Barra de progreso de la terminal ------------------------------------------------------


class BarraTerminal:
    """Pinta el progreso como `[██████░░░░]  60 % Escaneando…`, una línea por paso."""

    def __init__(self, escribir: Callable[[str], None], ancho: int = 24) -> None:
        self._escribir = escribir
        self._ancho = ancho

    def __call__(self, porcentaje: int, mensaje: str) -> None:
        llenos = round(self._ancho * porcentaje / 100)
        barra = "█" * llenos + "░" * (self._ancho - llenos)
        self._escribir(f"[{barra}] {porcentaje:3d} % {mensaje}")
