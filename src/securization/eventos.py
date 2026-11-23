"""Eventos: parseo de logs de OpenCanary y accesos a breadcrumbs, correlación por campaña.

Aviso: el esquema de log usado aquí (`node_id`, `src_host`, `src_port`, `dst_host`,
`dst_port`, `logtype`, `local_time`, `logdata`) está tomado de la documentación pública de
OpenCanary y no se ha comprobado contra una instalación real. Antes de usarlo de verdad
(L3), hay que verificarlo contra los logs que genere el OpenCanary del laboratorio.

Cada línea de log se trata como no confiable (S2/S3): se parsea con cuidado y cualquier
campo que falte o no tenga el tipo esperado produce un `ParseError`, nunca un evento a
medias ni un valor inventado. La correlación por campaña (`CampaignIndex`) solo necesita
las campañas ya generadas (S6): el `node_id` del señuelo identifica de qué campaña viene
una alerta de OpenCanary, y el `host_id` identifica de qué campaña viene un acceso a un
breadcrumb plantado en el host real.
"""

import json
from datetime import datetime
from ipaddress import IPv4Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from securization.generador import Campaign
from securization.parsing import ParseError

__all__ = [
    "BreadcrumbAccessEvent",
    "CampaignIndex",
    "CorrelatedEvent",
    "OpenCanaryEvent",
    "ParseError",
    "UnknownCampaignError",
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


class UnknownCampaignError(Exception):
    """El evento no corresponde a ninguna campaña conocida (`node_id` o `host_id`)."""


class CampaignIndex:
    """Índice de campañas para correlacionar eventos por `node_id` del señuelo o `host_id`."""

    def __init__(self, campaigns: list[Campaign]) -> None:
        self._by_node_id = {c.decoy.node_id: c for c in campaigns}
        self._by_host_id = {c.host_id: c for c in campaigns}

    def correlate_opencanary_event(self, event: OpenCanaryEvent) -> CorrelatedEvent:
        """Vincula una alerta de OpenCanary a la campaña de su señuelo (`node_id`)."""
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
