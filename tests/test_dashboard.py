"""Tests del dashboard (S13): rutas FastAPI sobre inventario, campañas y aprobación.

Sin servidor real (eso es arrancar `uvicorn`, decisión del operador): aquí solo se
comprueba que las rutas leen y escriben correctamente lo que ya guardan el inventario,
el perfilador y el generador/desplegador, usando `TestClient` sobre SQLite en memoria.
"""

from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.dashboard import create_app
from securization.desplegador import DeploymentPlanStore, build_deployment_plan
from securization.eventos import EventStore, collect_opencanary_events
from securization.generador import Campaign, CampaignStore, DecoyConfig, build_campaign
from securization.inventario import CredentialVault, Inventory
from securization.modelos import HostProfile, OsFamily, PlausibilityReport, ServiceInfo
from securization.orquestador import (
    VerificationAttempt,
    VerificationResult,
    VerificationResultStore,
)
from securization.perfilador import HostProfileStore

SECRETO = "hunter2-clave-ssh-de-prueba"

PERFIL = HostProfile(
    host_id="victima-01",
    address=IPv4Address("10.0.0.10"),
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 12 (bookworm)",
    services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.2p1")],
    top_level_dirs=["/etc", "/home", "/root"],
)


def campana() -> Campaign:
    return build_campaign(
        PERFIL,
        campaign_id="campana-01",
        decoy_node_id="victima-01-decoy",
        decoy_address=IPv4Address("10.0.0.50"),
        home_dir="/home/lab",
    )


def reporte(
    score: int = 95, threshold: int = 90, differences: Sequence[str] = ()
) -> PlausibilityReport:
    return PlausibilityReport(
        score=score, threshold=threshold, passed=score >= threshold, differences=list(differences)
    )


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path / 'dashboard.db'}")


@pytest.fixture
def vault() -> CredentialVault:
    return CredentialVault(CredentialVault.generate_key())


@pytest.fixture
def client(engine: Engine, vault: CredentialVault) -> TestClient:
    return TestClient(create_app(engine, vault))


def registrar_host(engine: Engine, vault: CredentialVault) -> None:
    Inventory(engine, vault).add_host(
        host_id="victima-01", address="10.0.0.10", ssh_user="lab", ssh_secret=SECRETO
    )


# --- / (resumen) -----------------------------------------------------------------


def test_overview_sin_datos(client: TestClient) -> None:
    respuesta = client.get("/")
    assert respuesta.status_code == 200
    assert "0" in respuesta.text


def test_overview_cuenta_hosts_y_campanas(
    client: TestClient, engine: Engine, vault: CredentialVault
) -> None:
    registrar_host(engine, vault)
    DeploymentPlanStore(engine).save(build_deployment_plan(campana(), reporte()))
    respuesta = client.get("/")
    assert respuesta.status_code == 200
    assert "1</span>" in respuesta.text.replace(" ", "").replace("\n", "")


# --- /hosts ------------------------------------------------------------------------


def test_hosts_list_vacia(client: TestClient) -> None:
    respuesta = client.get("/hosts")
    assert respuesta.status_code == 200
    assert "No hay hosts" in respuesta.text


def test_hosts_list_muestra_el_host_registrado(
    client: TestClient, engine: Engine, vault: CredentialVault
) -> None:
    registrar_host(engine, vault)
    respuesta = client.get("/hosts")
    assert "victima-01" in respuesta.text


def test_host_detail_sin_perfil_avisa(
    client: TestClient, engine: Engine, vault: CredentialVault
) -> None:
    registrar_host(engine, vault)
    respuesta = client.get("/hosts/victima-01")
    assert respuesta.status_code == 200
    assert "todavía no se ha perfilado" in respuesta.text


def test_host_detail_con_perfil_muestra_servicios(
    client: TestClient, engine: Engine, vault: CredentialVault
) -> None:
    registrar_host(engine, vault)
    HostProfileStore(engine).save(PERFIL)
    respuesta = client.get("/hosts/victima-01")
    assert "ssh" in respuesta.text


def test_host_detail_sin_registrar_404(client: TestClient) -> None:
    respuesta = client.get("/hosts/no-existe")
    assert respuesta.status_code == 404


# --- /campaigns --------------------------------------------------------------------


def test_campaigns_list_vacia(client: TestClient) -> None:
    respuesta = client.get("/campaigns")
    assert respuesta.status_code == 200
    assert "No hay campañas" in respuesta.text


def test_campaigns_list_muestra_el_plan(client: TestClient, engine: Engine) -> None:
    DeploymentPlanStore(engine).save(build_deployment_plan(campana(), reporte()))
    respuesta = client.get("/campaigns")
    assert "campana-01" in respuesta.text


def test_campaign_detail_sin_plan_404(client: TestClient) -> None:
    respuesta = client.get("/campaigns/no-existe")
    assert respuesta.status_code == 404


def test_campaign_detail_muestra_diferencias(client: TestClient, engine: Engine) -> None:
    informe = reporte(score=50, threshold=90, differences=["puerto 80 no responde"])
    DeploymentPlanStore(engine).save(build_deployment_plan(campana(), informe))
    respuesta = client.get("/campaigns/campana-01")
    assert "puerto 80 no responde" in respuesta.text


def test_campaign_detail_incluye_el_senuelo_si_la_campana_esta_guardada(
    client: TestClient, engine: Engine
) -> None:
    CampaignStore(engine).save(campana())
    DeploymentPlanStore(engine).save(build_deployment_plan(campana(), reporte()))
    respuesta = client.get("/campaigns/campana-01")
    assert "victima-01-decoy" in respuesta.text


# --- POST /campaigns/{id}/approve ---------------------------------------------------


def test_approve_marca_el_plan_como_aprobado(client: TestClient, engine: Engine) -> None:
    DeploymentPlanStore(engine).save(build_deployment_plan(campana(), reporte(score=95)))
    respuesta = client.post("/campaigns/campana-01/approve")
    assert respuesta.status_code == 200
    assert DeploymentPlanStore(engine).load("campana-01").approved is True


def test_approve_bajo_el_umbral_no_aprueba_y_muestra_el_error(
    client: TestClient, engine: Engine
) -> None:
    DeploymentPlanStore(engine).save(build_deployment_plan(campana(), reporte(score=50)))
    respuesta = client.post("/campaigns/campana-01/approve")
    assert respuesta.status_code == 200
    assert DeploymentPlanStore(engine).load("campana-01").approved is False
    assert "no se puede aprobar" in respuesta.text


def test_approve_sin_plan_404(client: TestClient) -> None:
    respuesta = client.post("/campaigns/no-existe/approve")
    assert respuesta.status_code == 404


# --- /events: alertas reales de los señuelos (H6) ------------------------------------

LOG_REAL = (
    Path(__file__).parent / "fixtures" / "opencanary" / "alertas_breadcrumbs.jsonl"
).read_text(encoding="utf-8")
CAMPANA_FICHEROS = Campaign(
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


def test_events_sin_eventos_lo_dice(client: TestClient) -> None:
    respuesta = client.get("/events")
    assert respuesta.status_code == 200
    assert "todavía no hay alertas" in respuesta.text.lower()


def test_events_muestra_las_alertas_reales_con_su_campana(
    engine: Engine, client: TestClient
) -> None:
    EventStore(engine).add_new(collect_opencanary_events(LOG_REAL, [CAMPANA_FICHEROS]))
    respuesta = client.get("/events")
    assert respuesta.status_code == 200
    assert "campana-victima-02" in respuesta.text
    assert "10.0.0.11" in respuesta.text
    assert "breadcrumb ftp" in respuesta.text
    assert "breadcrumb redis" in respuesta.text


def test_overview_cuenta_alertas_y_breadcrumbs_usados(engine: Engine, client: TestClient) -> None:
    EventStore(engine).add_new(collect_opencanary_events(LOG_REAL, [CAMPANA_FICHEROS]))
    respuesta = client.get("/")
    assert "Alertas de los señuelos" in respuesta.text
    assert "Breadcrumbs usados" in respuesta.text


# --- Detalle de campaña: intentos del bucle de verificación (H4) ------------------------


def campana_guardada(engine: Engine) -> Campaign:
    guardada = campana()
    CampaignStore(engine).save(guardada)
    return guardada


def test_detalle_de_campana_muestra_los_intentos_del_bucle(
    engine: Engine, client: TestClient
) -> None:
    campana = campana_guardada(engine)
    plan = build_deployment_plan(campana, reporte(score=90))
    DeploymentPlanStore(engine).save(plan)
    intentos = [
        VerificationAttempt(
            attempt=1,
            opencanary_config={"device.node_id": "x"},
            report=reporte(score=50, differences=["SO distinguible: el señuelo delata ubuntu"]),
        ),
        VerificationAttempt(
            attempt=2, opencanary_config={"device.node_id": "x"}, report=reporte(score=90)
        ),
    ]
    VerificationResultStore(engine).save(
        VerificationResult(
            campaign=campana, report=intentos[-1].report, attempts=intentos, stop_reason="aprobado"
        )
    )
    respuesta = client.get(f"/campaigns/{campana.campaign_id}")
    assert respuesta.status_code == 200
    assert "Bucle de verificación" in respuesta.text
    assert "50" in respuesta.text
    assert "delata ubuntu" in respuesta.text
    assert "aprobado" in respuesta.text
