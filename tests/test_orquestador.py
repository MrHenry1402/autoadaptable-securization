"""Tests de `orquestador.run_campaign_simulation`: une generador + verificador + desplegador
en modo simulación, con el bucle de ajuste de H4 (reintenta contra sucesivas huellas
candidatas del señuelo hasta superar el umbral o agotar los intentos).

No ejecuta nada real: perfilar, escanear y plantar de verdad son sesiones con laboratorio.
Las huellas candidatas del señuelo las da quien llama (aquí, una lista fija en los tests);
cómo se genera cada intento (ajuste determinista o con IA) no es cosa de este módulo.
"""

from collections.abc import Iterable, Iterator
from ipaddress import IPv4Address

import pytest

from securization.modelos import (
    Fingerprint,
    HostProfile,
    OsFamily,
    OsMatch,
    ServiceInfo,
)
from securization.orquestador import SimulationResult, run_campaign_simulation

PERFIL = HostProfile(
    host_id="victima-01",
    address=IPv4Address("10.0.0.10"),
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 13 (trixie)",
    services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.6")],
    top_level_dirs=["/root", "/home"],
)

HUELLA_REAL = Fingerprint(
    address=IPv4Address("10.0.0.10"),
    os_matches=[OsMatch(name="Linux 6.1", accuracy=95, os_family="linux")],
    services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.6")],
)

HUELLA_SENUELO_MALA = Fingerprint(
    address=IPv4Address("10.0.0.51"),
    os_matches=[OsMatch(name="Windows 10", accuracy=90, os_family="windows")],
    services=[],
)

HUELLA_SENUELO_BUENA = Fingerprint(
    address=IPv4Address("10.0.0.51"),
    os_matches=[OsMatch(name="Linux 6.1", accuracy=95, os_family="linux")],
    services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.6")],
)


def _simular(huellas: list[Fingerprint], known_paths: Iterable[str] = ()) -> SimulationResult:
    return run_campaign_simulation(
        PERFIL,
        HUELLA_REAL,
        campaign_id="campana-victima-01",
        decoy_node_id="victima-01-decoy",
        decoy_address=IPv4Address("10.0.0.51"),
        decoy_fingerprints=huellas,
        known_paths=known_paths,
    )


def test_para_en_la_primera_huella_que_supera_el_umbral() -> None:
    resultado = _simular([HUELLA_SENUELO_MALA, HUELLA_SENUELO_BUENA])
    assert resultado.report.passed is True
    assert resultado.attempts == 2


def test_usa_todos_los_intentos_si_ninguno_supera_el_umbral() -> None:
    resultado = _simular([HUELLA_SENUELO_MALA, HUELLA_SENUELO_MALA])
    assert resultado.report.passed is False
    assert resultado.attempts == 2


def test_no_sigue_iterando_tras_encontrar_una_huella_valida() -> None:
    # Generador perezoso: si se pidiera un segundo intento, el `raise` de abajo saltaría.
    def huellas_perezosas() -> Iterator[Fingerprint]:
        yield HUELLA_SENUELO_BUENA
        raise AssertionError("no debería pedirse un segundo intento")

    resultado = run_campaign_simulation(
        PERFIL,
        HUELLA_REAL,
        campaign_id="campana-victima-01",
        decoy_node_id="victima-01-decoy",
        decoy_address=IPv4Address("10.0.0.51"),
        decoy_fingerprints=huellas_perezosas(),
    )
    assert resultado.attempts == 1
    assert resultado.report.passed is True


def test_falla_si_no_hay_ninguna_huella_candidata() -> None:
    with pytest.raises(ValueError, match="ninguna huella"):
        _simular([])


def test_la_campana_incluye_los_breadcrumbs_generados() -> None:
    resultado = _simular([HUELLA_SENUELO_BUENA])
    assert len(resultado.campaign.breadcrumbs) > 0
    assert resultado.campaign.host_id == "victima-01"


def test_el_plan_usa_la_puntuacion_del_informe_final() -> None:
    resultado = _simular([HUELLA_SENUELO_BUENA])
    assert resultado.plan.plausibility_score == resultado.report.score
    assert resultado.plan.campaign_id == resultado.campaign.campaign_id


def test_el_plan_empieza_sin_aprobar() -> None:
    resultado = _simular([HUELLA_SENUELO_BUENA])
    assert resultado.plan.approved is False


def test_propaga_colisiones_de_ruta_del_generador() -> None:
    from securization.generador import CollisionError

    with pytest.raises(CollisionError):
        _simular([HUELLA_SENUELO_BUENA], known_paths=["/root/.env"])
