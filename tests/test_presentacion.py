"""Tests de `presentacion.py`: lenguaje llano y diagrama de red del dashboard."""

from datetime import datetime
from ipaddress import IPv4Address

from securization.desplegador import approve_plan, build_deployment_plan
from securization.eventos import CollectedEvent
from securization.generador import Campaign, DecoyConfig
from securization.inventario import Host
from securization.modelos import OsFamily, PlausibilityReport
from securization.presentacion import (
    construir_mapa,
    describir_alerta,
    estado_trampa,
    nombre_servicio,
    pasos_flujo,
)


def evento(logtype: int, breadcrumb: str | None = None, src: str = "10.0.0.20") -> CollectedEvent:
    return CollectedEvent(
        event_key=f"k{logtype}{breadcrumb}{src}",
        campaign_id="campana-victima-01",
        host_id="victima-01",
        node_id="web-01",
        logtype=logtype,
        src_host=src,
        dst_port=3306,
        timestamp=datetime(2026, 11, 27, 18, 55),
        summary="",
        breadcrumb_service=breadcrumb,
    )


CAMPANA = Campaign(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    decoy=DecoyConfig(
        node_id="web-01",
        address=IPv4Address("10.0.0.50"),
        opencanary_config={"device.node_id": "web-01", "ssh.enabled": True, "ssh.port": 22},
    ),
    breadcrumbs=[],
)


def host(host_id: str, ip: str) -> Host:
    return Host(
        host_id=host_id, address=ip, ssh_user="lab", os_family=OsFamily.LINUX, ssh_secret_token="x"
    )


def reporte(score: int) -> PlausibilityReport:
    return PlausibilityReport(score=score, threshold=90, passed=score >= 90, differences=[])


# --- Alertas -----------------------------------------------------------------------------


def test_uso_de_breadcrumb_es_alerta_alta_y_lo_explica() -> None:
    a = describir_alerta(evento(8001, "mysql"))
    assert a.gravedad == "alta"
    assert "contraseña-cebo" in a.titulo
    assert "MySQL" in a.titulo
    assert "victima-01" in a.detalle
    assert "10.0.0.20" in a.detalle


def test_intento_de_login_es_alerta_media() -> None:
    a = describir_alerta(evento(4002))
    assert a.gravedad == "media"
    assert "SSH" in a.titulo


def test_tipo_desconocido_no_falla() -> None:
    a = describir_alerta(evento(99999))
    assert a.gravedad == "baja"
    assert "99999" in a.titulo


def test_nombre_servicio_en_lenguaje_llano() -> None:
    assert nombre_servicio("ssh") == "Acceso remoto (SSH)"
    assert nombre_servicio("MySQL").startswith("Base de datos")
    assert nombre_servicio("rarito") == "rarito"


# --- Estado de la trampa --------------------------------------------------------------------


def test_estado_pendiente_de_aprobacion() -> None:
    plan = build_deployment_plan(CAMPANA, reporte(90))
    assert estado_trampa(plan).clase == "pendiente"


def test_estado_aprobada() -> None:
    plan = approve_plan(build_deployment_plan(CAMPANA, reporte(95)))
    assert estado_trampa(plan).clase == "ok"


def test_estado_bajo_umbral() -> None:
    plan = build_deployment_plan(CAMPANA, reporte(50))
    estado = estado_trampa(plan)
    assert estado.clase == "mal"
    assert "no se puede desplegar" in estado.explicacion


def test_estado_aprobada_bajo_umbral() -> None:
    plan = build_deployment_plan(CAMPANA, reporte(50)).model_copy(update={"approved": True})
    assert estado_trampa(plan).texto == "Aprobada sin nota suficiente"


# --- Mapa de red -----------------------------------------------------------------------------


def test_mapa_conecta_herramienta_equipo_trampa_y_atacante() -> None:
    hosts = [host("victima-01", "10.0.0.10"), host("deception-central", "10.0.0.5")]
    mapa = construir_mapa(hosts, [CAMPANA], [evento(4002), evento(8001, "mysql")])
    ids = {n.id for n in mapa.nodos}
    assert ids == {"herramienta", "real:victima-01", "senuelo:web-01", "atacante:10.0.0.20"}
    tipos = {(e.origen, e.destino, e.tipo) for e in mapa.enlaces}
    assert ("herramienta", "real:victima-01", "gestion") in tipos
    assert ("real:victima-01", "senuelo:web-01", "cebo") in tipos
    assert ("atacante:10.0.0.20", "senuelo:web-01", "ataque") in tipos


def test_mapa_no_dibuja_el_host_de_senuelos_como_equipo_real() -> None:
    mapa = construir_mapa([host("deception-central", "10.0.0.5")], [], [])
    assert [n.id for n in mapa.nodos] == ["herramienta"]
    assert mapa.nodo("herramienta").tipo == "herramienta"


def test_mapa_columnas_y_alto_crecen_con_los_nodos() -> None:
    hosts = [host(f"v{i}", f"10.0.0.{10 + i}") for i in range(4)]
    mapa = construir_mapa(hosts, [], [])
    xs = {n.tipo: n.x for n in mapa.nodos}
    assert xs["herramienta"] < xs["real"]
    assert mapa.alto >= 4 * 100


# --- Pasos del flujo ------------------------------------------------------------------------------


def test_pasos_marcan_lo_hecho() -> None:
    pasos = pasos_flujo(equipos=2, perfilados=2, campanas=1, aprobadas=0, alertas=0)
    assert [p.hecho for p in pasos] == [True, True, True, False, False, False]
    assert len(pasos) == 6


# --- La propia herramienta no es un intruso ------------------------------------------------


def test_alerta_de_la_propia_herramienta_no_es_intruso() -> None:
    a = describir_alerta(evento(4000, src="10.0.0.1"), ips_propias={"10.0.0.1"})
    assert a.gravedad == "propia"
    assert "No es un intruso" in a.detalle


def test_mapa_dibuja_la_comprobacion_y_no_un_atacante() -> None:
    hosts = [host("victima-01", "10.0.0.10")]
    mapa = construir_mapa(
        hosts, [CAMPANA], [evento(4000, src="10.0.0.1")], ips_propias={"10.0.0.1"}
    )
    assert not any(n.tipo == "atacante" for n in mapa.nodos)
    assert ("herramienta", "senuelo:web-01", "comprobacion") in {
        (e.origen, e.destino, e.tipo) for e in mapa.enlaces
    }


def test_estado_desplegada() -> None:
    plan = approve_plan(build_deployment_plan(CAMPANA, reporte(95))).model_copy(
        update={"deployed_at": datetime(2026, 11, 27, 18, 48)}
    )
    estado = estado_trampa(plan)
    assert estado.texto == "Desplegada y vigilando"
    assert "27/11/2026" in estado.explicacion
