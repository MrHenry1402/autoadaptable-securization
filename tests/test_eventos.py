"""Tests de `eventos`: parseo de logs de OpenCanary y correlación por campaña.

La entrada (una línea de log) se trata como no confiable: nunca se asume que es JSON
válido ni que tiene los campos esperados. El esquema de los logs de OpenCanary usado aquí
está tomado de su documentación pública, no verificado contra una instalación real (L3).
"""

from datetime import datetime
from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from securization.eventos import (
    BreadcrumbAccessEvent,
    CampaignIndex,
    OpenCanaryEvent,
    ParseError,
    UnknownCampaignError,
    parse_opencanary_log,
)
from securization.generador import Campaign, DecoyConfig

LINEA_SSH = (
    '{"node_id": "victima-01-decoy", "src_host": "10.0.0.20", "src_port": 54321, '
    '"dst_host": "10.0.0.50", "dst_port": 22, "logtype": 4002, '
    '"local_time": "2026-11-19 12:00:00.000000", '
    '"logdata": {"USERNAME": "admin", "PASSWORD": "1234"}}'
)

CAMPAIGN = Campaign(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    decoy=DecoyConfig(
        node_id="victima-01-decoy",
        address=IPv4Address("10.0.0.50"),
        opencanary_config={"device.node_id": "victima-01-decoy"},
    ),
    breadcrumbs=[],
)


# --- parse_opencanary_log -----------------------------------------------------


def test_parse_opencanary_log_campos_basicos() -> None:
    evento = parse_opencanary_log(LINEA_SSH)
    assert evento.node_id == "victima-01-decoy"
    assert evento.src_host == IPv4Address("10.0.0.20")
    assert evento.src_port == 54321
    assert evento.dst_host == IPv4Address("10.0.0.50")
    assert evento.dst_port == 22
    assert evento.logtype == 4002
    assert evento.timestamp == datetime(2026, 11, 19, 12, 0, 0)


def test_parse_opencanary_log_conserva_logdata() -> None:
    evento = parse_opencanary_log(LINEA_SSH)
    assert evento.logdata == {"USERNAME": "admin", "PASSWORD": "1234"}


def test_parse_opencanary_log_sin_logdata_queda_vacio() -> None:
    linea = (
        '{"node_id": "n", "src_host": "10.0.0.20", "src_port": 1, "dst_host": "10.0.0.50", '
        '"dst_port": 22, "logtype": 4002, "local_time": "2026-11-19 12:00:00.000000"}'
    )
    assert parse_opencanary_log(linea).logdata == {}


@pytest.mark.parametrize(
    "linea",
    [
        "",
        "   ",
        "esto no es json",
        "[]",
        "{}",
        '{"node_id": "n"}',
        (
            '{"node_id": "n", "src_host": "no-es-una-ip", "src_port": 1, '
            '"dst_host": "10.0.0.50", "dst_port": 22, "logtype": 4002, '
            '"local_time": "2026-11-19 12:00:00.000000"}'
        ),
    ],
)
def test_parse_opencanary_log_entradas_invalidas_fallan(linea: str) -> None:
    with pytest.raises(ParseError):
        parse_opencanary_log(linea)


# --- CampaignIndex: OpenCanary -------------------------------------------------


def test_correlate_opencanary_event_encuentra_la_campana() -> None:
    indice = CampaignIndex([CAMPAIGN])
    evento = parse_opencanary_log(LINEA_SSH)
    correlado = indice.correlate_opencanary_event(evento)
    assert correlado.campaign_id == "campana-victima-01"
    assert correlado.host_id == "victima-01"
    assert correlado.event_type == "opencanary"


def test_correlate_opencanary_event_sin_logdata_el_resumen_no_lleva_parentesis() -> None:
    indice = CampaignIndex([CAMPAIGN])
    evento = OpenCanaryEvent(
        node_id="victima-01-decoy",
        src_host=IPv4Address("10.0.0.20"),
        src_port=1,
        dst_host=IPv4Address("10.0.0.50"),
        dst_port=22,
        logtype=4002,
        timestamp=datetime(2026, 11, 19, 12, 0, 0),
    )
    correlado = indice.correlate_opencanary_event(evento)
    assert "(" not in correlado.summary


def test_correlate_opencanary_event_conserva_el_source_host() -> None:
    indice = CampaignIndex([CAMPAIGN])
    correlado = indice.correlate_opencanary_event(parse_opencanary_log(LINEA_SSH))
    assert correlado.source_host == IPv4Address("10.0.0.20")


def test_correlate_breadcrumb_access_no_tiene_source_host() -> None:
    indice = CampaignIndex([CAMPAIGN])
    evento = BreadcrumbAccessEvent(
        host_id="victima-01", path="/root/.env", timestamp=datetime(2026, 11, 19, 12, 0, 0)
    )
    assert indice.correlate_breadcrumb_access(evento).source_host is None


def test_correlate_opencanary_event_el_resumen_incluye_el_origen() -> None:
    indice = CampaignIndex([CAMPAIGN])
    correlado = indice.correlate_opencanary_event(parse_opencanary_log(LINEA_SSH))
    assert "10.0.0.20" in correlado.summary
    assert "4002" in correlado.summary


def test_correlate_opencanary_event_node_id_desconocido_falla() -> None:
    indice = CampaignIndex([CAMPAIGN])
    evento = OpenCanaryEvent(
        node_id="no-registrado",
        src_host=IPv4Address("10.0.0.20"),
        src_port=1,
        dst_host=IPv4Address("10.0.0.99"),
        dst_port=22,
        logtype=4002,
        timestamp=datetime(2026, 11, 19, 12, 0, 0),
    )
    with pytest.raises(UnknownCampaignError, match="no-registrado"):
        indice.correlate_opencanary_event(evento)


# --- CampaignIndex: breadcrumbs -------------------------------------------------


def test_correlate_breadcrumb_access_encuentra_la_campana() -> None:
    indice = CampaignIndex([CAMPAIGN])
    evento = BreadcrumbAccessEvent(
        host_id="victima-01", path="/root/.env", timestamp=datetime(2026, 11, 19, 12, 0, 0)
    )
    correlado = indice.correlate_breadcrumb_access(evento)
    assert correlado.campaign_id == "campana-victima-01"
    assert correlado.event_type == "breadcrumb_access"
    assert "/root/.env" in correlado.summary


def test_correlate_breadcrumb_access_host_desconocido_falla() -> None:
    indice = CampaignIndex([CAMPAIGN])
    evento = BreadcrumbAccessEvent(
        host_id="victima-99", path="/root/.env", timestamp=datetime(2026, 11, 19, 12, 0, 0)
    )
    with pytest.raises(UnknownCampaignError, match="victima-99"):
        indice.correlate_breadcrumb_access(evento)


# --- Modelos ---------------------------------------------------------------------


def test_open_canary_event_rechaza_campos_extra() -> None:
    with pytest.raises(ValidationError):
        OpenCanaryEvent.model_validate(
            {
                "node_id": "n",
                "src_host": "10.0.0.20",
                "src_port": 1,
                "dst_host": "10.0.0.50",
                "dst_port": 22,
                "logtype": 4002,
                "timestamp": datetime(2026, 11, 19, 12, 0, 0),
                "extra": "no",
            }
        )
