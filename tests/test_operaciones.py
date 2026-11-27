"""Tests de `operaciones.py`: las operaciones de la CLI/dashboard con informe de progreso.

Sin red: el entorno (`conftest.FakeEntorno`) sustituye SSH, SFTP y nmap por dobles con salidas
reales guardadas en `tests/fixtures/`. Se comprueba el progreso (de 0 a 100, sin retroceder, en
lenguaje llano), que el resultado se guarda y que desplegar sigue exigiendo el plan aprobado.
"""

from ipaddress import IPv4Address

import pytest

from conftest import FakeEntorno, leer
from securization.desplegador import DeploymentPlanStore, approve_plan
from securization.eventos import EventStore
from securization.generador import CampaignStore
from securization.operaciones import (
    BarraTerminal,
    PlanNoAprobadoError,
    Trabajos,
    crear_campana,
    desplegar,
    perfilar,
    recoger_alertas,
    sin_informe,
)
from securization.perfilador import HostProfileStore


class Registro:
    def __init__(self) -> None:
        self.pasos: list[tuple[int, str]] = []

    def __call__(self, porcentaje: int, mensaje: str) -> None:
        self.pasos.append((porcentaje, mensaje))

    def porcentajes(self) -> list[int]:
        return [p for p, _ in self.pasos]


# --- perfilar ----------------------------------------------------------------------------


async def test_perfilar_guarda_el_perfil_y_avanza_hasta_100(entorno: FakeEntorno) -> None:
    informe = Registro()
    perfil = await perfilar(entorno, "victima-01", informe)
    assert HostProfileStore(entorno.engine).load("victima-01").os_name == perfil.os_name
    assert informe.porcentajes() == sorted(informe.porcentajes())
    assert informe.porcentajes()[-1] == 100
    assert any("SSH" in m for _, m in informe.pasos)
    assert any("nmap" in m for _, m in informe.pasos)


# --- crear_campana -----------------------------------------------------------------------


async def test_crear_campana_verifica_y_deja_el_plan_sin_aprobar(entorno: FakeEntorno) -> None:
    await perfilar(entorno, "victima-01")
    informe = Registro()
    r = await crear_campana(
        entorno,
        "victima-01",
        decoy_node="web-01",
        decoy_ip=IPv4Address("10.0.0.50"),
        informe=informe,
    )
    plan = DeploymentPlanStore(entorno.engine).load("campana-victima-01")
    assert plan.approved is False
    assert plan == r.plan
    assert CampaignStore(entorno.engine).load("campana-victima-01").decoy.node_id == "web-01"
    assert informe.porcentajes() == sorted(informe.porcentajes())
    assert informe.porcentajes()[-1] == 100
    assert any(m.startswith("Intento 1") for _, m in informe.pasos)
    assert "aprobación" in informe.pasos[-1][1]
    assert any(c[:2] == ("docker", "run") for c in entorno.central.calls)


# --- desplegar ---------------------------------------------------------------------------


async def _campana(entorno: FakeEntorno) -> None:
    await perfilar(entorno, "victima-01")
    await crear_campana(
        entorno, "victima-01", decoy_node="web-01", decoy_ip=IPv4Address("10.0.0.50")
    )


async def test_desplegar_sin_aprobar_no_toca_nada(entorno: FakeEntorno) -> None:
    await _campana(entorno)
    llamadas = len(entorno.central.calls)
    with pytest.raises(PlanNoAprobadoError, match="no está aprobado"):
        await desplegar(entorno, "campana-victima-01")
    assert len(entorno.central.calls) == llamadas
    assert entorno.sftp("victima-01").written == []


async def test_desplegar_aprobado_planta_los_cebos_y_arranca_la_trampa(
    entorno: FakeEntorno,
) -> None:
    await _campana(entorno)
    planes = DeploymentPlanStore(entorno.engine)
    planes.save(approve_plan(planes.load("campana-victima-01")))
    informe = Registro()
    nombre = await desplegar(entorno, "campana-victima-01", informe)
    assert nombre == "decoy-web-01"
    assert planes.load("campana-victima-01").deployed_at is not None
    assert entorno.sftp("victima-01").written
    assert informe.porcentajes()[-1] == 100
    assert any("cebo" in m for _, m in informe.pasos)


# --- recoger_alertas -----------------------------------------------------------------------


async def test_recoger_alertas_sin_campanas(entorno: FakeEntorno) -> None:
    informe = Registro()
    assert await recoger_alertas(entorno, informe) == {}
    assert informe.porcentajes() == [100]


async def test_recoger_alertas_lee_el_log_de_cada_trampa(entorno: FakeEntorno) -> None:
    await _campana(entorno)
    entorno.central.defecto = leer("opencanary/alertas_reales.jsonl")
    nuevas = await recoger_alertas(entorno)
    assert set(nuevas) == {"campana-victima-01"}
    assert (
        sum(EventStore(entorno.engine).count_by_campaign().values()) == nuevas["campana-victima-01"]
    )


# --- Trabajos y barra de la terminal ---------------------------------------------------------


def test_trabajo_acumula_pasos_y_no_retrocede() -> None:
    t = Trabajos().nuevo("Analizando victima-01")
    t.informar(10, "Conectando")
    t.informar(5, "Escaneando")
    assert t.porcentaje == 10
    assert t.pasos == ["Conectando"]
    t.terminar("Hecho", "/hosts/victima-01")
    assert (t.estado, t.porcentaje, t.enlace) == ("hecho", 100, "/hosts/victima-01")


def test_trabajo_con_error() -> None:
    t = Trabajos().nuevo("x")
    t.fallar("No se ha podido completar: sin red")
    assert t.estado == "error"
    assert "sin red" in t.mensaje


def test_registro_de_trabajos() -> None:
    trabajos = Trabajos()
    t = trabajos.nuevo("x")
    assert trabajos.get(t.id) is t
    assert trabajos.en_curso() == [t]
    t.terminar("ok")
    assert trabajos.en_curso() == []
    assert trabajos.get("no-existe") is None


def test_barra_de_la_terminal() -> None:
    lineas: list[str] = []
    BarraTerminal(lineas.append, ancho=10)(50, "Escaneando")
    assert lineas == ["[█████░░░░░]  50 % Escaneando"]


def test_sin_informe_no_hace_nada() -> None:
    sin_informe(10, "x")
