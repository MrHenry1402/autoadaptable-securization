"""Tests de `respuesta`: decide la acción (observación, contención, escalado) de un evento.

No ejecuta nada: construye la decisión y, en contención, el comando de nftables como lista
de argumentos. Ejecutarlo de verdad contra un host registrado es trabajo de otra sesión
(necesita el transporte SSH real, L1), fuera del alcance de S11.
"""

from datetime import datetime
from ipaddress import IPv4Address

import pytest

from securization.eventos import CorrelatedEvent
from securization.respuesta import (
    ResponseAction,
    ResponseMode,
    build_nftables_block_rule,
    decide_response,
)

EVENTO_OPENCANARY = CorrelatedEvent(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    event_type="opencanary",
    summary="logtype 4002 desde 10.0.0.20:54321",
    timestamp=datetime(2026, 11, 19, 12, 0, 0),
    source_host=IPv4Address("10.0.0.20"),
)

EVENTO_BREADCRUMB = CorrelatedEvent(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    event_type="breadcrumb_access",
    summary="acceso a breadcrumb /root/.env",
    timestamp=datetime(2026, 11, 19, 12, 0, 0),
)


# --- build_nftables_block_rule -------------------------------------------------


def test_build_nftables_block_rule_es_una_lista_de_argumentos() -> None:
    regla = build_nftables_block_rule(IPv4Address("10.0.0.20"))
    assert isinstance(regla, tuple)
    assert all(isinstance(a, str) for a in regla)


def test_build_nftables_block_rule_incluye_la_ip_como_argumento_propio() -> None:
    regla = build_nftables_block_rule(IPv4Address("10.0.0.20"))
    assert "10.0.0.20" in regla
    # nunca concatenada con otro texto dentro del mismo argumento
    assert all(arg == "10.0.0.20" or "10.0.0.20" not in arg for arg in regla)


def test_build_nftables_block_rule_empieza_por_nft() -> None:
    assert build_nftables_block_rule(IPv4Address("10.0.0.20"))[0] == "nft"


def test_build_nftables_block_rule_admite_una_cadena_distinta() -> None:
    regla = build_nftables_block_rule(IPv4Address("10.0.0.20"), chain="deception")
    assert "deception" in regla


# --- decide_response: observación y escalado -----------------------------------


def test_decide_response_observacion_no_lleva_comando() -> None:
    accion = decide_response(EVENTO_OPENCANARY, ResponseMode.OBSERVATION)
    assert accion.mode is ResponseMode.OBSERVATION
    assert accion.command is None
    assert accion.campaign_id == "campana-victima-01"


def test_decide_response_escalado_no_lleva_comando() -> None:
    accion = decide_response(EVENTO_OPENCANARY, ResponseMode.ESCALATION)
    assert accion.mode is ResponseMode.ESCALATION
    assert accion.command is None


def test_decide_response_observacion_funciona_sin_source_host() -> None:
    # Un acceso a breadcrumb no tiene IP de origen; observación y escalado no la necesitan.
    accion = decide_response(EVENTO_BREADCRUMB, ResponseMode.OBSERVATION)
    assert accion.command is None


# --- decide_response: contención ------------------------------------------------


def test_decide_response_contencion_genera_el_comando_de_nftables() -> None:
    accion = decide_response(EVENTO_OPENCANARY, ResponseMode.CONTAINMENT)
    assert accion.mode is ResponseMode.CONTAINMENT
    assert accion.command is not None
    assert "10.0.0.20" in accion.command


def test_decide_response_contencion_sin_source_host_falla() -> None:
    # Nunca se bloquea "algo" a ciegas: sin IP de origen, falla con un error claro.
    with pytest.raises(ValueError, match="origen"):
        decide_response(EVENTO_BREADCRUMB, ResponseMode.CONTAINMENT)


# --- Modelo ----------------------------------------------------------------------


def test_response_action_rechaza_campos_extra() -> None:
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        ResponseAction.model_validate(
            {
                "campaign_id": "c",
                "mode": "observacion",
                "summary": "s",
                "command": None,
                "extra": "no",
            }
        )
