"""Respuesta: modos observación, contención y escalado para un evento correlacionado.

Decide qué hacer ante un `CorrelatedEvent` (S10) según el modo de respuesta configurado
para su campaña. En contención, construye la regla de nftables que bloquearía la IP de
origen como lista de argumentos fija (CLAUDE.md: nunca `shell=True` ni texto concatenado).

Este módulo **no ejecuta nada**: solo decide y construye el comando. Ejecutarlo de verdad
contra un host registrado necesita el transporte SSH real (L1) y queda para otra sesión;
mezclar "decidir" con "ejecutar" en una sola función haría más difícil revisar línea a
línea el único sitio que de verdad toca el cortafuegos del host, como exige CLAUDE.md.
"""

from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import BaseModel, ConfigDict

from securization.eventos import CorrelatedEvent


class ResponseMode(StrEnum):
    """Modo de respuesta configurado para una campaña."""

    OBSERVATION = "observacion"
    CONTAINMENT = "contencion"
    ESCALATION = "escalado"


class ResponseAction(BaseModel):
    """Acción decidida para un evento: el modo aplicado y, en contención, el comando."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    mode: ResponseMode
    summary: str
    command: tuple[str, ...] | None = None


def build_nftables_block_rule(source_ip: IPv4Address, *, chain: str = "input") -> tuple[str, ...]:
    """Regla de nftables, como lista de argumentos, para bloquear una IP de origen.

    Añade una regla a una cadena que ya debe existir en el firewall del host registrado;
    crear o gestionar la tabla/cadena en sí queda fuera de esta sesión. Cada argumento es
    un elemento propio de la lista, nunca texto concatenado a mano.
    """
    return (
        "nft",
        "add",
        "rule",
        "inet",
        "filter",
        chain,
        "ip",
        "saddr",
        str(source_ip),
        "drop",
    )


def decide_response(event: CorrelatedEvent, mode: ResponseMode) -> ResponseAction:
    """Decide la acción de respuesta para un evento ya correlacionado con su campaña.

    En modo contención hace falta `event.source_host` (solo lo tienen los eventos de
    OpenCanary, no los accesos a breadcrumbs) para construir la regla; si no está, falla
    con un error claro en vez de bloquear una IP que no se conoce.
    """
    if mode is ResponseMode.CONTAINMENT:
        if event.source_host is None:
            raise ValueError(
                f"{event.campaign_id}: modo contención sin IP de origen, no se puede "
                "construir la regla de nftables"
            )
        comando = build_nftables_block_rule(event.source_host)
        return ResponseAction(
            campaign_id=event.campaign_id,
            mode=mode,
            summary=f"contención: bloqueando {event.source_host}",
            command=comando,
        )

    if mode is ResponseMode.ESCALATION:
        resumen = f"escalado para revisión manual: {event.summary}"
    else:
        resumen = f"observado: {event.summary}"
    return ResponseAction(campaign_id=event.campaign_id, mode=mode, summary=resumen)
