"""Tests de la recogida y el almacenamiento de alertas reales de los señuelos (H6).

`collect_opencanary_events` convierte el log de un señuelo en eventos ya correlacionados con
su campaña (y con el breadcrumb usado, si lo hay); `EventStore` los guarda sin duplicados
aunque el log se vuelva a leer entero; `fetch_decoy_log` lo trae del contenedor por SSH.
"""

from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.eventos import (
    EventStore,
    collect_opencanary_events,
    fetch_decoy_log,
)
from securization.generador import Campaign, DecoyConfig

FIXTURES = Path(__file__).parent / "fixtures" / "opencanary"
LOG_BREADCRUMBS = (FIXTURES / "alertas_breadcrumbs.jsonl").read_text(encoding="utf-8")

WEB = Campaign(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    decoy=DecoyConfig(
        node_id="web-01",
        address=IPv4Address("10.0.0.50"),
        opencanary_config={
            "device.node_id": "web-01",
            "http.enabled": True,
            "http.port": 80,
            "mysql.enabled": True,
            "mysql.port": 3306,
        },
    ),
    breadcrumbs=[],
)
FILES = Campaign(
    campaign_id="campana-victima-02",
    host_id="victima-02",
    decoy=DecoyConfig(
        node_id="files-02",
        address=IPv4Address("10.0.0.51"),
        opencanary_config={
            "device.node_id": "files-02",
            "ftp.enabled": True,
            "ftp.port": 21,
            "redis.enabled": True,
            "redis.port": 6379,
        },
    ),
    breadcrumbs=[],
)
ARRANQUE = (
    '{"dst_host": "", "dst_port": -1, "local_time": "2026-11-23 02:14:40.595073", '
    '"logdata": {"msg": {"logdata": "Canary running!!!"}}, "logtype": 1001, '
    '"node_id": "web-01", "src_host": "", "src_port": -1}'
)


def test_convierte_las_alertas_reales_en_eventos_de_su_campana() -> None:
    eventos = collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES])
    assert len(eventos) == 7
    assert {e.campaign_id for e in eventos} == {"campana-victima-01", "campana-victima-02"}
    assert [e.breadcrumb_service for e in eventos] == [
        "mysql",
        "http",
        "ftp",
        None,
        "redis",
        None,
        "redis",
    ]


def test_cada_evento_lleva_origen_destino_y_resumen() -> None:
    (primero, *_) = collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES])
    assert primero.src_host == "10.0.0.10"
    assert primero.dst_port == 3306
    assert primero.node_id == "web-01"
    assert primero.host_id == "victima-01"
    assert "8001" in primero.summary


def test_ignora_lineas_de_arranque_basura_y_senuelos_desconocidos() -> None:
    otro = LOG_BREADCRUMBS.splitlines()[0].replace('"web-01"', '"desconocido"')
    log = "\n".join([ARRANQUE, "basura", "", otro])
    assert collect_opencanary_events(log, [WEB, FILES]) == []


def test_la_clave_de_un_evento_es_estable_y_distinta_por_linea() -> None:
    a = collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES])
    b = collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES])
    assert [e.event_key for e in a] == [e.event_key for e in b]
    assert len({e.event_key for e in a}) == len(a)


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path / 'eventos.db'}")


def test_event_store_guarda_sin_duplicar_al_releer_el_log(engine: Engine) -> None:
    store = EventStore(engine)
    eventos = collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES])
    assert store.add_new(eventos) == 7
    assert store.add_new(eventos) == 0
    assert len(store.list_recent()) == 7


def test_event_store_lista_los_mas_recientes_primero(engine: Engine) -> None:
    store = EventStore(engine)
    store.add_new(collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES]))
    recientes = store.list_recent(limit=3)
    assert len(recientes) == 3
    assert recientes[0].timestamp >= recientes[-1].timestamp


def test_event_store_cuenta_por_campana_y_breadcrumbs_usados(engine: Engine) -> None:
    store = EventStore(engine)
    store.add_new(collect_opencanary_events(LOG_BREADCRUMBS, [WEB, FILES]))
    assert store.count_by_campaign() == {"campana-victima-01": 2, "campana-victima-02": 5}
    assert store.count_breadcrumb_uses() == {"campana-victima-01": 2, "campana-victima-02": 3}


class FakeSsh:
    def __init__(self, salida: str = "") -> None:
        self.calls: list[tuple[str, ...]] = []
        self._salida = salida

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        return self._salida


async def test_fetch_decoy_log_lee_el_log_del_contenedor_por_ssh() -> None:
    ssh = FakeSsh(salida=LOG_BREADCRUMBS)
    assert await fetch_decoy_log("web-01", ssh) == LOG_BREADCRUMBS
    assert ssh.calls == [("docker", "exec", "decoy-web-01", "cat", "/var/tmp/opencanary.log")]  # noqa: S108


async def test_fetch_decoy_log_valida_el_node_id() -> None:
    with pytest.raises(ValueError, match="node_id"):
        await fetch_decoy_log("web-01; rm -rf /", FakeSsh())
