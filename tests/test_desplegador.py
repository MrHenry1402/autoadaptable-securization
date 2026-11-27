"""Tests de `DeploymentPlan` (S9): plan de despliegue en modo simulación.

No hay E/S real aquí (eso es L4): solo construcción del plan, comprobación de colisiones
de rutas y aprobación manual del operador condicionada al umbral de plausibilidad (S7).
"""

from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.desplegador import (
    BreadcrumbAlreadyExistsError,
    DeploymentAction,
    DeploymentNotReadyError,
    DeploymentPlan,
    DeploymentPlanNotFoundError,
    DeploymentPlanStore,
    PlausibilityThresholdError,
    SftpTransport,
    approve_plan,
    build_deployment_plan,
    plant_breadcrumbs,
)
from securization.generador import Breadcrumb, Campaign, DecoyConfig
from securization.modelos import PlausibilityReport

CAMPAIGN = Campaign(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    decoy=DecoyConfig(
        node_id="victima-01-decoy",
        address=IPv4Address("10.0.0.50"),
        opencanary_config={"device.node_id": "victima-01-decoy"},
    ),
    breadcrumbs=[
        Breadcrumb(host_id="victima-01", path="/root/.env", content="APP_ENV=production\n"),
        Breadcrumb(
            host_id="victima-01",
            path="/var/backups/backup.sql",
            content="-- backup\n",
        ),
    ],
)


def reporte(score: int = 95, threshold: int = 90) -> PlausibilityReport:
    return PlausibilityReport(
        score=score, threshold=threshold, passed=score >= threshold, differences=[]
    )


# --- build_deployment_plan ----------------------------------------------------


def test_build_deployment_plan_crea_una_accion_por_breadcrumb() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte())
    assert len(plan.actions) == len(CAMPAIGN.breadcrumbs)


def test_build_deployment_plan_copia_ruta_contenido_y_permisos() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte())
    accion = plan.actions[0]
    breadcrumb = CAMPAIGN.breadcrumbs[0]
    assert accion.path == breadcrumb.path
    assert accion.content == breadcrumb.content
    assert accion.mode == breadcrumb.mode


def test_build_deployment_plan_guarda_campaign_id_host_id_y_puntuacion() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte(score=95, threshold=90))
    assert plan.campaign_id == "campana-victima-01"
    assert plan.host_id == "victima-01"
    assert plan.plausibility_score == 95
    assert plan.plausibility_threshold == 90


def test_build_deployment_plan_empieza_sin_aprobar() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte())
    assert plan.approved is False
    assert plan.ready_to_deploy is False


def test_build_deployment_plan_se_puede_construir_aunque_no_supere_el_umbral() -> None:
    # Construir el plan (para poder revisarlo) no es lo mismo que aprobarlo.
    plan = build_deployment_plan(CAMPAIGN, reporte(score=50, threshold=90))
    assert plan.approved is False


def test_build_deployment_plan_falla_si_colisiona_con_una_ruta_conocida() -> None:
    with pytest.raises(Exception, match=r"/root/\.env"):
        build_deployment_plan(CAMPAIGN, reporte(), known_paths=["/root/.env"])


def test_build_deployment_plan_copia_las_diferencias_del_informe() -> None:
    informe = reporte(score=50, threshold=90)
    informe = informe.model_copy(update={"differences": ["puerto 80 no responde en el señuelo"]})
    plan = build_deployment_plan(CAMPAIGN, informe)
    assert plan.differences == ["puerto 80 no responde en el señuelo"]


def test_build_deployment_plan_sin_diferencias_es_una_lista_vacia() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte())
    assert plan.differences == []


# --- approve_plan --------------------------------------------------------------


def test_approve_plan_marca_como_aprobado_si_supera_el_umbral() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte(score=95, threshold=90))
    aprobado = approve_plan(plan)
    assert aprobado.approved is True
    assert aprobado.ready_to_deploy is True


def test_approve_plan_no_modifica_el_plan_original() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte(score=95, threshold=90))
    approve_plan(plan)
    assert plan.approved is False


def test_approve_plan_falla_si_no_supera_el_umbral() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte(score=50, threshold=90))
    with pytest.raises(PlausibilityThresholdError, match="campana-victima-01"):
        approve_plan(plan)


def test_ready_to_deploy_falso_si_aprobado_pero_bajo_el_umbral() -> None:
    # No debería poder darse (approve_plan lo impide), pero ready_to_deploy es la
    # comprobación final: nunca listo si la puntuación no supera el umbral, pase lo que pase.
    plan = build_deployment_plan(CAMPAIGN, reporte(score=50, threshold=90))
    plan_manipulado = plan.model_copy(update={"approved": True})
    assert plan_manipulado.ready_to_deploy is False


# --- Modelos ---------------------------------------------------------------------


def test_deployment_action_rechaza_campos_extra() -> None:
    with pytest.raises(ValidationError):
        DeploymentAction.model_validate(
            {"path": "/root/.env", "content": "x", "mode": 0o600, "extra": "no"}
        )


def test_deployment_plan_rechaza_campos_extra() -> None:
    with pytest.raises(ValidationError):
        DeploymentPlan.model_validate(
            {
                "campaign_id": "c",
                "host_id": "h",
                "actions": [],
                "plausibility_score": 0,
                "plausibility_threshold": 90,
                "extra": "no",
            }
        )


# --- DeploymentPlanStore ---------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path / 'planes.db'}")


def test_deployment_plan_store_guarda_y_recupera_el_plan(engine: Engine) -> None:
    store = DeploymentPlanStore(engine)
    plan = build_deployment_plan(CAMPAIGN, reporte())
    store.save(plan)
    assert store.load("campana-victima-01") == plan


def test_deployment_plan_store_guardar_dos_veces_actualiza_en_vez_de_duplicar(
    engine: Engine,
) -> None:
    store = DeploymentPlanStore(engine)
    plan = build_deployment_plan(CAMPAIGN, reporte())
    store.save(plan)
    aprobado = approve_plan(plan)
    store.save(aprobado)
    assert store.load("campana-victima-01") == aprobado


def test_deployment_plan_store_cargar_sin_plan_falla_con_error_claro(engine: Engine) -> None:
    store = DeploymentPlanStore(engine)
    with pytest.raises(DeploymentPlanNotFoundError, match="campana-victima-01"):
        store.load("campana-victima-01")


def test_deployment_plan_store_persiste_entre_instancias(engine: Engine) -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte())
    DeploymentPlanStore(engine).save(plan)
    otro_store = DeploymentPlanStore(engine)
    assert otro_store.load("campana-victima-01") == plan


def test_deployment_plan_store_list_all_devuelve_todos_los_planes(engine: Engine) -> None:
    store = DeploymentPlanStore(engine)
    plan = build_deployment_plan(CAMPAIGN, reporte())
    otro_plan = plan.model_copy(update={"campaign_id": "campana-victima-02"})
    store.save(plan)
    store.save(otro_plan)
    campaign_ids = {p.campaign_id for p in store.list_all()}
    assert campaign_ids == {"campana-victima-01", "campana-victima-02"}


def test_deployment_plan_store_list_all_vacio_si_no_hay_planes(engine: Engine) -> None:
    assert DeploymentPlanStore(engine).list_all() == []


# --- SftpTransport / plant_breadcrumbs (L4) -------------------------------------


class FakeSftpTransport:
    """Doble de `SftpTransport`: registra los ficheros escritos, puede fallar a propósito."""

    def __init__(self, *, existing: Sequence[str] = ()) -> None:
        self.written: list[tuple[str, str, int]] = []
        self._existing = set(existing)

    async def write_file(self, path: str, content: str, mode: int) -> None:
        if path in self._existing or path in {p for p, _, _ in self.written}:
            raise BreadcrumbAlreadyExistsError(path)
        self.written.append((path, content, mode))


def plan_listo() -> DeploymentPlan:
    return approve_plan(build_deployment_plan(CAMPAIGN, reporte(score=95, threshold=90)))


def test_fake_sftp_transport_satisface_el_protocolo() -> None:
    assert isinstance(FakeSftpTransport(), SftpTransport)


async def test_plant_breadcrumbs_escribe_cada_accion_del_plan() -> None:
    plan = plan_listo()
    transport = FakeSftpTransport()
    await plant_breadcrumbs(plan, transport)
    assert transport.written == [(a.path, a.content, a.mode) for a in plan.actions]


async def test_plant_breadcrumbs_rechaza_un_plan_no_listo() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte(score=50, threshold=90))
    with pytest.raises(DeploymentNotReadyError, match="campana-victima-01"):
        await plant_breadcrumbs(plan, FakeSftpTransport())


async def test_plant_breadcrumbs_rechaza_un_plan_aprobado_pero_sin_superar_el_umbral() -> None:
    plan = build_deployment_plan(CAMPAIGN, reporte(score=50, threshold=90))
    plan_manipulado = plan.model_copy(update={"approved": True})
    with pytest.raises(DeploymentNotReadyError):
        await plant_breadcrumbs(plan_manipulado, FakeSftpTransport())


async def test_plant_breadcrumbs_se_interrumpe_si_una_ruta_ya_existe() -> None:
    plan = plan_listo()
    ruta_existente = plan.actions[-1].path
    transport = FakeSftpTransport(existing=[ruta_existente])
    with pytest.raises(BreadcrumbAlreadyExistsError, match=ruta_existente.replace(".", r"\.")):
        await plant_breadcrumbs(plan, transport)
    # Las acciones anteriores a la que falló ya se plantaron; no hay vuelta atrás con SFTP.
    assert len(transport.written) == len(plan.actions) - 1
