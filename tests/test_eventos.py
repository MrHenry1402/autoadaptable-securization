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
    breadcrumb_service_used,
    parse_opencanary_log,
)
from securization.generador import Campaign, DecoyConfig, breadcrumb_credentials

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


# --- breadcrumb_service_used (L4): atribuir una alerta al breadcrumb usado ---------

SENUELO_FICHEROS = DecoyConfig(
    node_id="files-02",
    address=IPv4Address("10.0.0.51"),
    opencanary_config={
        "device.node_id": "files-02",
        "ftp.enabled": True,
        "ftp.port": 21,
        "ssh.enabled": True,
        "ssh.port": 22,
        "redis.enabled": True,
        "redis.port": 6379,
    },
)
SENUELO_WEB = DecoyConfig(
    node_id="web-01",
    address=IPv4Address("10.0.0.50"),
    opencanary_config={
        "device.node_id": "web-01",
        "http.enabled": True,
        "http.port": 80,
        "mysql.enabled": True,
        "mysql.port": 3306,
    },
)

# Alertas reales lanzadas desde las víctimas con credenciales de prueba (no de breadcrumb):
# MySQL 8001, HTTP 3001, Redis 17001 y FTP 2000.
ALERTAS_CREDENCIALES = (
    (Path(__file__).parent / "fixtures" / "opencanary" / "alertas_credenciales.jsonl")
    .read_text(encoding="utf-8")
    .splitlines()
)


def _alerta(node_id: str, logtype: int, dst_port: int, **logdata: str) -> OpenCanaryEvent:
    return OpenCanaryEvent(
        node_id=node_id,
        src_host=IPv4Address("10.0.0.11"),
        src_port=40000,
        dst_host=IPv4Address("10.0.0.51"),
        dst_port=dst_port,
        logtype=logtype,
        timestamp=datetime(2026, 11, 23, 3, 0),
        logdata=logdata,
    )


def test_alertas_reales_de_credenciales_se_interpretan_y_vienen_de_las_victimas() -> None:
    eventos = [parse_opencanary_log(linea) for linea in ALERTAS_CREDENCIALES]
    assert {e.logtype for e in eventos} == {2000, 3001, 8001, 17001}
    assert {e.src_host for e in eventos} == {IPv4Address("10.0.0.10"), IPv4Address("10.0.0.11")}


def test_alertas_reales_con_credenciales_de_prueba_no_se_atribuyen_a_un_breadcrumb() -> None:
    senuelos = {"web-01": SENUELO_WEB, "files-02": SENUELO_FICHEROS}
    for linea in ALERTAS_CREDENCIALES:
        evento = parse_opencanary_log(linea)
        assert breadcrumb_service_used(evento, senuelos[evento.node_id]) is None


def test_login_ftp_con_la_credencial_del_breadcrumb() -> None:
    cred = breadcrumb_credentials(SENUELO_FICHEROS)["ftp"]
    evento = _alerta("files-02", 2000, 21, USERNAME=cred.username, PASSWORD=cred.password)
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) == "ftp"


def test_login_ssh_con_la_credencial_del_breadcrumb() -> None:
    cred = breadcrumb_credentials(SENUELO_FICHEROS)["ssh"]
    evento = _alerta("files-02", 4002, 22, USERNAME=cred.username, PASSWORD=cred.password)
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) == "ssh"


def test_login_con_usuario_del_breadcrumb_pero_otra_clave_no_cuenta() -> None:
    cred = breadcrumb_credentials(SENUELO_FICHEROS)["ftp"]
    evento = _alerta("files-02", 2000, 21, USERNAME=cred.username, PASSWORD="otra")
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) is None


def test_auth_de_redis_con_la_clave_del_breadcrumb() -> None:
    clave = breadcrumb_credentials(SENUELO_FICHEROS)["redis"].password
    evento = _alerta("files-02", 17001, 6379, CMD="AUTH", ARGS=clave)
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) == "redis"


def test_auth_de_redis_con_usuario_y_clave_del_breadcrumb() -> None:
    clave = breadcrumb_credentials(SENUELO_FICHEROS)["redis"].password
    evento = _alerta("files-02", 17001, 6379, CMD="AUTH", ARGS=f"default {clave}")
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) == "redis"


def test_comando_de_redis_que_no_es_auth_no_cuenta() -> None:
    clave = breadcrumb_credentials(SENUELO_FICHEROS)["redis"].password
    evento = _alerta("files-02", 17001, 6379, CMD="GET", ARGS=clave)
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) is None


def test_mysql_se_atribuye_por_usuario_porque_la_clave_llega_cifrada() -> None:
    cred = breadcrumb_credentials(SENUELO_WEB)["mysql"]
    evento = _alerta("web-01", 8001, 3306, USERNAME=cred.username, PASSWORD="40e8ca56")
    assert breadcrumb_service_used(evento, SENUELO_WEB) == "mysql"


def test_login_http_con_la_credencial_del_breadcrumb() -> None:
    cred = breadcrumb_credentials(SENUELO_WEB)["http"]
    evento = _alerta("web-01", 3001, 80, USERNAME=cred.username, PASSWORD=cred.password)
    assert breadcrumb_service_used(evento, SENUELO_WEB) == "http"


def test_alerta_de_otro_senuelo_no_se_atribuye() -> None:
    cred = breadcrumb_credentials(SENUELO_FICHEROS)["ftp"]
    evento = _alerta("web-01", 2000, 21, USERNAME=cred.username, PASSWORD=cred.password)
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) is None


def test_servicio_que_el_senuelo_no_tiene_activo_no_se_atribuye() -> None:
    evento = _alerta("files-02", 8001, 3306, USERNAME="app_svc", PASSWORD="x")
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) is None


def test_logtype_sin_credenciales_no_se_atribuye() -> None:
    evento = _alerta("files-02", 4000, 22, SESSION="1")
    assert breadcrumb_service_used(evento, SENUELO_FICHEROS) is None


# Alertas reales de L4: un "atacante" en cada víctima lee los breadcrumbs plantados y usa
# sus credenciales contra el señuelo (.my.cnf, .env, .netrc). Incluye el fallo real de
# `redis-cli -u`, que OpenCanary no sabe interpretar ("invalid bulk length").
ALERTAS_BREADCRUMBS = (
    (Path(__file__).parent / "fixtures" / "opencanary" / "alertas_breadcrumbs.jsonl")
    .read_text(encoding="utf-8")
    .splitlines()
)


def test_alertas_reales_de_breadcrumbs_se_atribuyen_a_su_servicio() -> None:
    senuelos = {"web-01": SENUELO_WEB, "files-02": SENUELO_FICHEROS}
    usados = [
        breadcrumb_service_used(evento, senuelos[evento.node_id])
        for evento in map(parse_opencanary_log, ALERTAS_BREADCRUMBS)
    ]
    assert usados == ["mysql", "http", "ftp", None, "redis", None, "redis"]


def test_alertas_reales_de_breadcrumbs_vienen_de_la_victima_de_su_campana() -> None:
    origen = {"web-01": IPv4Address("10.0.0.10"), "files-02": IPv4Address("10.0.0.11")}
    for evento in map(parse_opencanary_log, ALERTAS_BREADCRUMBS):
        assert evento.src_host == origen[evento.node_id]
