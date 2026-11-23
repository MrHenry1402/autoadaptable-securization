"""Eventos: parseo de logs de OpenCanary y accesos a breadcrumbs, correlación por campaña.

El esquema de log usado aquí (
ode_id`, `src_host`, `src_port`, `dst_host`, `dst_port`,
`logtype`, `local_time`, `logdata`) está comprobado (L3) contra alertas reales de
OpenCanary 0.9.10 en el laboratorio (`tests/fixtures/opencanary/alertas_reales.jsonl`).

Cada línea de log se trata como no confiable (S2/S3): se parsea con cuidado y cualquier
campo que falte o no tenga el tipo esperado produce un `ParseError`, nunca un evento a
medias ni un valor inventado. La correlación por campaña (`CampaignIndex`) solo necesita
las campañas ya generadas (S6): el
ode_id` del señuelo identifica de qué campaña viene
una alerta de OpenCanary, y el `host_id` identifica de qué campaña viene un acceso a un
breadcrumb plantado en el host real.
"""

import hashlib
import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from ipaddress import IPv4Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, func
from sqlmodel import Field as SqlField
from sqlmodel import Session, SQLModel, col, select

from securization.desplegador import decoy_container_name
from securization.generador import Campaign, DecoyConfig, breadcrumb_credentials
from securization.parsing import ParseError
from securization.perfilador import SshTransport

__all__ = [
    "BreadcrumbAccessEvent",
    "CampaignIndex",
    "CollectedEvent",
    "CorrelatedEvent",
    "EventStore",
    "OpenCanaryEvent",
    "ParseError",
    "UnknownCampaignError",
    "breadcrumb_service_used",
    "collect_opencanary_events",
    "fetch_decoy_log",
    "parse_opencanary_log",
]


class OpenCanaryEvent(BaseModel):
    """Una alerta de OpenCanary ya parseada."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    src_host: IPv4Address
    src_port: int = Field(ge=1, le=65535)
    dst_host: IPv4Address
    dst_port: int = Field(ge=1, le=65535)
    logtype: int
    timestamp: datetime
    logdata: dict[str, str] = Field(default_factory=dict)


def parse_opencanary_log(line: str) -> OpenCanaryEvent:
    """Parsea una línea de log JSON de OpenCanary; falla con `ParseError` si no es válida."""
    texto = line.strip()
    if not texto:
        raise ParseError("línea de log vacía")
    try:
        datos = json.loads(texto)
    except json.JSONDecodeError as error:
        raise ParseError(f"línea de log no es JSON válido: {error}") from None
    if not isinstance(datos, dict):
        raise ParseError("línea de log no es un objeto JSON")
    try:
        return OpenCanaryEvent(
            node_id=datos["node_id"],
            src_host=datos["src_host"],
            src_port=datos["src_port"],
            dst_host=datos["dst_host"],
            dst_port=datos["dst_port"],
            logtype=datos["logtype"],
            timestamp=datos["local_time"],
            logdata=datos.get("logdata", {}),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ParseError(f"línea de log de OpenCanary incompleta o inválida: {error}") from None


class BreadcrumbAccessEvent(BaseModel):
    """Acceso detectado a un breadcrumb ya plantado en un host real.

    El mecanismo de detección (auditd, inotify, un watcher propio) es responsabilidad de
    una sesión con laboratorio (L4); este modelo solo representa el evento ya detectado.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str
    path: str
    timestamp: datetime


class CorrelatedEvent(BaseModel):
    """Un evento (de OpenCanary o de un breadcrumb) ya vinculado a su campaña.

    `source_host` solo se rellena para eventos de OpenCanary (de dónde vino la conexión);
    un acceso a un breadcrumb no tiene una IP de origen de red asociada.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    host_id: str
    event_type: Literal["opencanary", "breadcrumb_access"]
    summary: str
    timestamp: datetime
    source_host: IPv4Address | None = None


# logtype de OpenCanary 0.9.10 que registra credenciales -> servicio (comprobado en L4).
_CREDENTIAL_LOGTYPES: dict[int, str] = {
    2000: "ftp",
    3001: "http",
    4002: "ssh",
    8001: "mysql",
    17001: "redis",
}


def breadcrumb_service_used(event: OpenCanaryEvent, decoy: DecoyConfig) -> str | None:
    """Servicio cuyo breadcrumb se usó en la alerta del señuelo, o None.

    Compara las credenciales registradas por OpenCanary con las que ofrecen los
    breadcrumbs de ese señuelo (`breadcrumb_credentials`). MySQL se reconoce solo por el
    usuario, porque OpenCanary registra la contraseña cifrada con el reto del protocolo.
    """
    servicio = _CREDENTIAL_LOGTYPES.get(event.logtype)
    if event.node_id != decoy.node_id or servicio is None:
        return None
    credencial = breadcrumb_credentials(decoy).get(servicio)
    if credencial is None:
        return None
    datos = event.logdata
    if servicio == "redis":
        usada = (
            datos.get("CMD", "").upper() == "AUTH"
            and credencial.password in datos.get("ARGS", "").split()
        )
    elif servicio == "mysql":
        usada = datos.get("USERNAME") == credencial.username
    else:
        usada = (
            datos.get("USERNAME") == credencial.username
            and datos.get("PASSWORD") == credencial.password
        )
    return servicio if usada else None


class UnknownCampaignError(Exception):
    """El evento no corresponde a ninguna campaña conocida (
    ode_id` o `host_id`)."""


class CampaignIndex:
    """Índice de campañas para correlacionar eventos por
    ode_id` del señuelo o `host_id`."""

    def __init__(self, campaigns: list[Campaign]) -> None:
        self._by_node_id = {c.decoy.node_id: c for c in campaigns}
        self._by_host_id = {c.host_id: c for c in campaigns}

    def correlate_opencanary_event(self, event: OpenCanaryEvent) -> CorrelatedEvent:
        """Vincula una alerta de OpenCanary a la campaña de su señuelo (
        ode_id`)."""
        campaign = self._by_node_id.get(event.node_id)
        if campaign is None:
            raise UnknownCampaignError(f"node_id desconocido: {event.node_id}")
        resumen = f"logtype {event.logtype} desde {event.src_host}:{event.src_port}"
        if event.logdata:
            pares = ", ".join(f"{clave}={valor}" for clave, valor in sorted(event.logdata.items()))
            resumen += f" ({pares})"
        return CorrelatedEvent(
            campaign_id=campaign.campaign_id,
            host_id=campaign.host_id,
            event_type="opencanary",
            summary=resumen,
            timestamp=event.timestamp,
            source_host=event.src_host,
        )

    def correlate_breadcrumb_access(self, event: BreadcrumbAccessEvent) -> CorrelatedEvent:
        """Vincula un acceso a un breadcrumb a la campaña del host real (`host_id`)."""
        campaign = self._by_host_id.get(event.host_id)
        if campaign is None:
            raise UnknownCampaignError(f"host_id sin campaña conocida: {event.host_id}")
        return CorrelatedEvent(
            campaign_id=campaign.campaign_id,
            host_id=campaign.host_id,
            event_type="breadcrumb_access",
            summary=f"acceso a breadcrumb {event.path}",
            timestamp=event.timestamp,
        )


# --- Recogida y almacenamiento de alertas reales de los señuelos (H6) ---------------

_DECOY_LOG = "/var/tmp/opencanary.log"  # noqa: S108 - ruta dentro del contenedor OpenCanary
_STARTUP_LOGTYPES = frozenset({1001})


class CollectedEvent(BaseModel):
    """Alerta de un señuelo ya correlacionada con su campaña, lista para guardar."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_key: str
    campaign_id: str
    host_id: str
    node_id: str
    logtype: int
    src_host: str
    dst_port: int
    timestamp: datetime
    summary: str
    breadcrumb_service: str | None = None


def collect_opencanary_events(log_text: str, campaigns: Sequence[Campaign]) -> list[CollectedEvent]:
    """Eventos de campaña a partir del log de uno o varios señuelos.

    Ignora líneas no válidas, los mensajes de arranque de OpenCanary y las alertas de
    señuelos que no pertenecen a ninguna campaña. Cada evento lleva una clave estable (el
    hash de su línea), para que releer el log entero no duplique nada al guardarlo.
    """
    por_nodo = {c.decoy.node_id: c for c in campaigns}
    indice = CampaignIndex(list(campaigns))
    eventos: list[CollectedEvent] = []
    for linea in log_text.splitlines():
        try:
            evento = parse_opencanary_log(linea)
        except ParseError:
            continue
        campana = por_nodo.get(evento.node_id)
        if campana is None or evento.logtype in _STARTUP_LOGTYPES:
            continue
        correlado = indice.correlate_opencanary_event(evento)
        eventos.append(
            CollectedEvent(
                event_key=hashlib.sha256(linea.strip().encode()).hexdigest(),
                campaign_id=correlado.campaign_id,
                host_id=correlado.host_id,
                node_id=evento.node_id,
                logtype=evento.logtype,
                src_host=str(evento.src_host),
                dst_port=evento.dst_port,
                timestamp=evento.timestamp,
                summary=correlado.summary,
                breadcrumb_service=breadcrumb_service_used(evento, campana.decoy),
            )
        )
    return eventos


async def fetch_decoy_log(node_id: str, ssh: SshTransport) -> str:
    """Lee por SSH el log de OpenCanary del contenedor del señuelo."""
    return await ssh.run(("docker", "exec", decoy_container_name(node_id), "cat", _DECOY_LOG))


class _EventRecord(SQLModel, table=True):
    """Fila con un evento de campaña ya correlacionado."""

    __tablename__ = "campaign_event"

    event_key: str = SqlField(primary_key=True)
    campaign_id: str = SqlField(index=True)
    # Texto ISO 8601: se ordena igual que la fecha y no exige zona horaria (los logs de
    # OpenCanary no la llevan).
    timestamp: str = SqlField(index=True)
    breadcrumb_service: str | None = None
    payload_json: str


class EventStore:
    """Guarda los eventos de campaña en la base de datos común, sin duplicados."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        SQLModel.metadata.create_all(engine)

    def add_new(self, events: Iterable[CollectedEvent]) -> int:
        """Guarda los eventos que aún no estaban; devuelve cuántos eran nuevos."""
        nuevos = 0
        with Session(self._engine) as session:
            for evento in events:
                if session.get(_EventRecord, evento.event_key) is not None:
                    continue
                session.add(
                    _EventRecord(
                        event_key=evento.event_key,
                        campaign_id=evento.campaign_id,
                        timestamp=evento.timestamp.isoformat(),
                        breadcrumb_service=evento.breadcrumb_service,
                        payload_json=evento.model_dump_json(),
                    )
                )
                nuevos += 1
            session.commit()
        return nuevos

    def list_recent(self, limit: int = 100) -> list[CollectedEvent]:
        """Eventos más recientes primero."""
        with Session(self._engine) as session:
            filas = session.exec(
                select(_EventRecord).order_by(col(_EventRecord.timestamp).desc()).limit(limit)
            ).all()
        return [CollectedEvent.model_validate_json(f.payload_json) for f in filas]

    def count_by_campaign(self) -> dict[str, int]:
        with Session(self._engine) as session:
            filas = session.exec(
                select(_EventRecord.campaign_id, func.count()).group_by(_EventRecord.campaign_id)
            ).all()
        return dict(filas)

    def count_breadcrumb_uses(self) -> dict[str, int]:
        with Session(self._engine) as session:
            filas = session.exec(
                select(_EventRecord.campaign_id, func.count())
                .where(col(_EventRecord.breadcrumb_service).is_not(None))
                .group_by(_EventRecord.campaign_id)
            ).all()
        return dict(filas)
