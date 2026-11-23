"""Tests de `eventos`: parseo de logs de OpenCanary y correlación por campaña.

La entrada (una línea de log) se trata como no confiable: nunca se asume que es JSON
válido ni que tiene los campos esperados. El esquema de los logs de OpenCanary está
comprobado (L3) con alertas reales del laboratorio en `fixtures/opencanary/`.
"""

import json
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path

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

# Alertas reales de OpenCanary 0.9.10 (señuelo de victima-02 en el laboratorio, L3):
# conexión y login SSH (4000, 4001, 4002), login FTP (2000) y comandos Redis (17001).
ALERTAS_REALES = (
    (Path(__file__).parent / "fixtures" / "opencanary" / "alertas_reales.jsonl")
    .read_text(encoding="utf-8")
    .splitlines()
)


def test_parse_opencanary_log_interpreta_todas_las_alertas_reales() -> None:
    eventos = [parse_opencanary_log(linea) for linea in ALERTAS_REALES]
    assert {e.logtype for e in eventos} == {2000, 4000, 4001, 4002, 17001}
    assert all(e.node_id == "spike-v02" for e in eventos)
    assert all(e.src_host == IPv4Address("10.0.0.1") for e in eventos)
    assert all(e.dst_host == IPv4Address("10.0.0.50") for e in eventos)


def test_parse_opencanary_log_alerta_real_de_login_ssh() -> None:
    linea = next(lin for lin in ALERTAS_REALES if json.loads(lin)["logtype"] == 4002)
    evento = parse_opencanary_log(linea)
    assert evento.dst_port == 22
    assert evento.logdata["USERNAME"] == "root"
    assert evento.logdata["LOCALVERSION"] == "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4"


def test_parse_opencanary_log_alerta_real_de_login_ftp() -> None:
    linea = next(lin for lin in ALERTAS_REALES if json.loads(lin)["logtype"] == 2000)
    evento = parse_opencanary_log(linea)
    assert evento.dst_port == 21
    assert evento.logdata["USERNAME"] == "admin"


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
