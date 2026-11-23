"""Plantado de breadcrumbs por SFTP y arranque de deception hosts en contenedores.

La sesión S9 cubre la parte sin E/S: construir un `DeploymentPlan` a partir de una
`Campaign` ya generada (S6) y de su `PlausibilityReport` (S7), en modo simulación.

El plantado real por SFTP (L4, parte que no depende del laboratorio encendido) va detrás
de la interfaz `SftpTransport`, mismo patrón que `SshTransport` en `perfilador.py` y
`ProcessRunner` en `escaneo.py`: una implementación falsa en los tests y la real
(`AsyncSftpTransport`, sobre asyncssh) para cuando haya laboratorio. `plant_breadcrumbs`
nunca sobrescribe un fichero existente: además de la comprobación de colisiones ya hecha
al construir el plan (`build_deployment_plan`), `AsyncSftpTransport` abre cada fichero en
modo `x` (creación exclusiva SFTP), que falla en el propio servidor si la ruta ya existe,
en vez de fiarse solo de la comprobación hecha en el momento de construir el plan.

Los deception hosts (L3) son contenedores OpenCanary en deception-central, en la red macvlan
del laboratorio, con IP y MAC propias. Se lanzan por SSH (`docker`, siempre como lista de
argumentos validados) y su config se sube por SFTP. Hay dos entradas: `start_decoy`, el
arranque que necesita el bucle de verificación para escanear el señuelo dentro del
laboratorio, y `deploy_decoy`, el despliegue definitivo.

Ningún señuelo se despliega sin superar el umbral de plausibilidad (S7) ni sin aprobación
manual explícita del operador: `approve_plan` es la única forma de marcar un plan como
aprobado, y `plant_breadcrumbs` y `deploy_decoy` exigen `ready_to_deploy` antes de tocar
nada real.
"""

import contextlib
import hashlib
import re
from collections.abc import Iterable
from typing import Protocol, runtime_checkable

import asyncssh
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine
from sqlmodel import Field as SqlField
from sqlmodel import Session, SQLModel, select

from securization.generador import (
    Campaign,
    DecoyConfig,
    check_collisions,
    render_opencanary_conf,
)
from securization.modelos import PlausibilityReport
from securization.perfilador import SshTransport


class PlausibilityThresholdError(Exception):
    """El informe de plausibilidad no supera el umbral: el plan no se puede aprobar."""


class DeploymentPlanNotFoundError(Exception):
    """No hay un plan de despliegue guardado con ese `campaign_id`."""


class DeploymentNotReadyError(Exception):
    """El plan no está listo para desplegar (`ready_to_deploy` es falso): no se toca nada real."""


class BreadcrumbAlreadyExistsError(Exception):
    """Ya existe un fichero en esa ruta del host real: nunca se sobrescribe."""


class DeploymentAction(BaseModel):
    """Una acción concreta del plan: plantar un breadcrumb en una ruta."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    content: str
    mode: int


class DeploymentPlan(BaseModel):
    """Plan de despliegue de una campaña, en modo simulación hasta que se aprueba a mano."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    host_id: str
    actions: list[DeploymentAction]
    plausibility_score: int
    plausibility_threshold: int
    differences: list[str] = Field(default_factory=list)
    approved: bool = False

    @property
    def ready_to_deploy(self) -> bool:
        """Listo para desplegar solo si está aprobado y superó el umbral de plausibilidad."""
        return self.approved and self.plausibility_score >= self.plausibility_threshold


def build_deployment_plan(
    campaign: Campaign,
    plausibility: PlausibilityReport,
    known_paths: Iterable[str] = (),
) -> DeploymentPlan:
    """Construye el plan de despliegue de una campaña, sin tocar nada real todavía.

    Comprueba colisiones de ruta antes de devolver el plan, para que nunca se llegue a
    aprobar uno que sobrescribiría un fichero existente. El plan se crea siempre sin
    aprobar, aunque el señuelo ya supere el umbral: eso permite revisarlo antes de decidir.
    """
    check_collisions(campaign.breadcrumbs, known_paths)
    actions = [
        DeploymentAction(path=breadcrumb.path, content=breadcrumb.content, mode=breadcrumb.mode)
        for breadcrumb in campaign.breadcrumbs
    ]
    return DeploymentPlan(
        campaign_id=campaign.campaign_id,
        host_id=campaign.host_id,
        actions=actions,
        plausibility_score=plausibility.score,
        plausibility_threshold=plausibility.threshold,
        differences=plausibility.differences,
    )


def approve_plan(plan: DeploymentPlan) -> DeploymentPlan:
    """Aprueba el plan a mano; falla si el señuelo no superó el umbral de plausibilidad."""
    if plan.plausibility_score < plan.plausibility_threshold:
        raise PlausibilityThresholdError(
            f"{plan.campaign_id}: puntuación {plan.plausibility_score} por debajo del "
            f"umbral {plan.plausibility_threshold}, no se puede aprobar"
        )
    return plan.model_copy(update={"approved": True})


@runtime_checkable
class SftpTransport(Protocol):
    """Planta un fichero en el host real; la implementación real llega con el laboratorio."""

    async def write_file(self, path: str, content: str, mode: int) -> None:
        """Crea el fichero en `path` con `content` y los permisos `mode`.

        Debe fallar (no sobrescribir en silencio) si ya existe un fichero en esa ruta.
        """
        ...


class AsyncSftpTransport:
    """Implementación real de `SftpTransport` sobre asyncssh (L4).

    Igual que `AsyncSshTransport` (L1), no se fía de ningún `known_hosts`: las VMs del
    laboratorio se recrean con claves de host distintas en cada reinstalación.
    """

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password

    async def write_file(self, path: str, content: str, mode: int) -> None:
        async with (
            asyncssh.connect(
                self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                known_hosts=None,
            ) as conn,
            conn.start_sftp_client() as sftp,
        ):
            try:
                async with sftp.open(path, "x") as fichero:
                    await fichero.write(content)
            except asyncssh.SFTPError as error:
                if error.code == asyncssh.FX_FILE_ALREADY_EXISTS:
                    raise BreadcrumbAlreadyExistsError(path) from error
                raise
            await sftp.chmod(path, mode)


async def plant_breadcrumbs(plan: DeploymentPlan, transport: SftpTransport) -> None:
    """Planta de verdad los breadcrumbs del plan por SFTP.

    Exige `ready_to_deploy` (aprobado y por encima del umbral de plausibilidad): nunca se
    despliega un plan a medio aprobar. Si un breadcrumb falla (por ejemplo porque ya existe
    esa ruta), se interrumpe de inmediato: los breadcrumbs anteriores de este plan ya se
    quedan plantados, no hay una forma de "deshacer" un SFTP a medio terminar.
    """
    if not plan.ready_to_deploy:
        raise DeploymentNotReadyError(
            f"{plan.campaign_id}: el plan no está listo para desplegar (ready_to_deploy=False)"
        )
    for accion in plan.actions:
        await transport.write_file(accion.path, accion.content, accion.mode)


# --- Deception hosts en contenedores OpenCanary (L3) -----------------------------

DEFAULT_DECOY_NETWORK = "labnet-decoys"
DEFAULT_DECOY_IMAGE = (
    "thinkst/opencanary@sha256:479c2cf42bbaed8d298d12be0a67da5099cc20ee1dcbc336d84b05251d1d22b6"
)
_CONTAINER_CONF = "/etc/opencanaryd/opencanary.conf"
# OUI de VirtualBox: la MAC por defecto de Docker (02:42:...) delata el contenedor ante
# cualquiera que mire la tabla ARP o el escaneo nmap desde la misma red.
_DECOY_OUI = "08:00:27"
_NODE_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_REMOTE_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]*")


def decoy_container_name(node_id: str) -> str:
    """Nombre del contenedor de un señuelo; valida `node_id` (llega a argumentos de docker)."""
    if not _NODE_ID_RE.fullmatch(node_id):
        raise ValueError(f"node_id inválido: {node_id!r} (minúsculas, dígitos y guiones)")
    return f"decoy-{node_id}"


def decoy_mac(node_id: str) -> str:
    """MAC determinista del señuelo con el OUI de VirtualBox, derivada de `node_id`."""
    resumen = hashlib.sha256(node_id.encode()).digest()[:3]
    return ":".join([_DECOY_OUI, *(f"{byte:02x}" for byte in resumen)])


def _validate_remote_path(path: str, campo: str) -> str:
    if not _REMOTE_PATH_RE.fullmatch(path) or ".." in path.split("/"):
        raise ValueError(f"{campo} inválido: {path!r} (ruta absoluta sin '..' ni espacios)")
    return path


def decoy_config_path(config_dir: str, node_id: str, conf: str) -> str:
    """Ruta del config en deception-central, distinta para cada contenido.

    El SFTP crea en modo exclusivo (nunca sobrescribe), así que cada ajuste del señuelo en
    el bucle de verificación va a un fichero nuevo; el mismo contenido, al mismo fichero.
    """
    directorio = _validate_remote_path(config_dir, "config_dir").rstrip("/")
    resumen = hashlib.sha256(conf.encode()).hexdigest()[:12]
    return f"{directorio}/{decoy_container_name(node_id).removeprefix('decoy-')}-{resumen}.conf"


def build_decoy_run_command(
    decoy: DecoyConfig,
    *,
    config_path: str,
    network: str = DEFAULT_DECOY_NETWORK,
    image: str = DEFAULT_DECOY_IMAGE,
) -> tuple[str, ...]:
    """`docker run` del señuelo: IP y MAC propias en la red macvlan, config de solo lectura."""
    nombre = decoy_container_name(decoy.node_id)
    ruta = _validate_remote_path(config_path, "config_path")
    return (
        "docker",
        "run",
        "-d",
        "--name",
        nombre,
        "--network",
        network,
        "--ip",
        str(decoy.address),
        "--mac-address",
        decoy_mac(decoy.node_id),
        "--hostname",
        decoy.node_id,
        "-v",
        f"{ruta}:{_CONTAINER_CONF}:ro",
        image,
    )


def build_decoy_remove_command(node_id: str) -> tuple[str, ...]:
    """`docker rm -f` del señuelo (no falla si el contenedor no existe)."""
    return ("docker", "rm", "-f", decoy_container_name(node_id))


async def start_decoy(
    decoy: DecoyConfig,
    *,
    sftp: SftpTransport,
    ssh: SshTransport,
    config_dir: str,
    network: str = DEFAULT_DECOY_NETWORK,
    image: str = DEFAULT_DECOY_IMAGE,
) -> str:
    """Arranca (o relanza) el señuelo en deception-central y devuelve el nombre del contenedor.

    Es el arranque que necesita el bucle de verificación para poder escanear el señuelo en
    el laboratorio; el despliegue definitivo, con aprobación, es `deploy_decoy`. Renderiza
    y valida el config antes de tocar nada, lo sube por SFTP y sustituye el contenedor.
    """
    conf = render_opencanary_conf(decoy.opencanary_config)
    ruta = decoy_config_path(config_dir, decoy.node_id, conf)
    comando = build_decoy_run_command(decoy, config_path=ruta, network=network, image=image)
    await ssh.run(("mkdir", "-p", config_dir))
    # La ruta lleva el hash del contenido: si ya existe, es este mismo config.
    with contextlib.suppress(BreadcrumbAlreadyExistsError):
        await sftp.write_file(ruta, conf, 0o644)
    await ssh.run(build_decoy_remove_command(decoy.node_id))
    await ssh.run(comando)
    return decoy_container_name(decoy.node_id)


async def stop_decoy(node_id: str, *, ssh: SshTransport) -> None:
    """Para y borra el contenedor del señuelo."""
    await ssh.run(build_decoy_remove_command(node_id))


async def deploy_decoy(
    plan: DeploymentPlan,
    campaign: Campaign,
    *,
    sftp: SftpTransport,
    ssh: SshTransport,
    config_dir: str,
    network: str = DEFAULT_DECOY_NETWORK,
    image: str = DEFAULT_DECOY_IMAGE,
) -> str:
    """Despliegue definitivo del señuelo de una campaña: exige el plan aprobado.

    Igual que `plant_breadcrumbs`, no toca nada si el plan no está aprobado y por encima
    del umbral de plausibilidad, ni si el plan es de otra campaña.
    """
    if plan.campaign_id != campaign.campaign_id:
        raise ValueError(
            f"el plan es de campaign_id={plan.campaign_id!r}, no de {campaign.campaign_id!r}"
        )
    if not plan.ready_to_deploy:
        raise DeploymentNotReadyError(
            f"{plan.campaign_id}: el plan no está listo para desplegar (ready_to_deploy=False)"
        )
    return await start_decoy(
        campaign.decoy, sftp=sftp, ssh=ssh, config_dir=config_dir, network=network, image=image
    )


class _DeploymentPlanRecord(SQLModel, table=True):
    """Fila con el `DeploymentPlan` completo, serializado en JSON."""

    __tablename__ = "deployment_plan"

    campaign_id: str = SqlField(primary_key=True)
    plan_json: str


class DeploymentPlanStore:
    """Guarda y recupera planes de despliegue en la base de datos, para el dashboard (S13)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        SQLModel.metadata.create_all(engine)

    def save(self, plan: DeploymentPlan) -> None:
        """Guarda el plan; si ya había uno con ese `campaign_id`, lo sustituye."""
        payload = plan.model_dump_json()
        with Session(self._engine) as session:
            registro = session.get(_DeploymentPlanRecord, plan.campaign_id)
            if registro is None:
                registro = _DeploymentPlanRecord(campaign_id=plan.campaign_id, plan_json=payload)
            else:
                registro.plan_json = payload
            session.add(registro)
            session.commit()

    def load(self, campaign_id: str) -> DeploymentPlan:
        """Recupera el plan guardado o falla con un error claro."""
        with Session(self._engine) as session:
            registro = session.get(_DeploymentPlanRecord, campaign_id)
        if registro is None:
            raise DeploymentPlanNotFoundError(campaign_id)
        return DeploymentPlan.model_validate_json(registro.plan_json)

    def list_all(self) -> list[DeploymentPlan]:
        """Todos los planes de despliegue guardados."""
        with Session(self._engine) as session:
            registros = session.exec(select(_DeploymentPlanRecord)).all()
        return [DeploymentPlan.model_validate_json(registro.plan_json) for registro in registros]
