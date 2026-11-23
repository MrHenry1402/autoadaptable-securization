"""Tests del bucle cerrado de verificación (H4): arrancar, escanear, puntuar y ajustar.

La E/S (arrancar el señuelo en deception-central y escanearlo con nmap) se inyecta como
dos funciones; aquí se sustituyen por dobles que devuelven huellas según el config.
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from securization.generador import Campaign, DecoyConfig
from securization.modelos import Fingerprint, HostProfile, OsFamily, OsMatch, ServiceInfo
from securization.orquestador import run_verification_loop

LINUX = OsMatch(name="Linux 5.4 - 5.10", accuracy=94, os_family="Linux")
SSH = ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_10.0p2 Debian-7")
MYSQL_REAL = ServiceInfo(port=3306, protocol="tcp", name="mysql", product="MariaDB")

PERFIL = HostProfile(
    host_id="victima-01",
    address=IPv4Address("10.0.0.10"),
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 13 (trixie)",
    services=[SSH, MYSQL_REAL],
    packages={"mariadb-server": "1:11.8.9+ds-0+deb13u1"},
)
HUELLA_REAL = Fingerprint(address=PERFIL.address, os_matches=[LINUX], services=[SSH, MYSQL_REAL])
CAMPANA = Campaign(
    campaign_id="campana-victima-01",
    host_id="victima-01",
    decoy=DecoyConfig(
        node_id="web-01",
        address=IPv4Address("10.0.0.50"),
        opencanary_config={
            "device.node_id": "web-01",
            "ssh.enabled": True,
            "ssh.port": 22,
            "ssh.version": SSH.banner or "",
            "mysql.enabled": True,
            "mysql.port": 3306,
        },
    ),
    breadcrumbs=[],
)


class FakeLab:
    """Arranca (registra) señuelos y devuelve la huella que daría nmap para cada config."""

    def __init__(self) -> None:
        self.started: list[dict[str, bool | int | str]] = []

    async def start(self, decoy: DecoyConfig) -> None:
        self.started.append(dict(decoy.opencanary_config))

    async def scan(self, decoy: DecoyConfig) -> Fingerprint:
        banner = decoy.opencanary_config.get("mysql.banner", "5.5.43-0ubuntu0.14.04.1")
        producto = "MariaDB" if "MariaDB" in str(banner) else "MySQL"
        mysql = ServiceInfo(
            port=3306, protocol="tcp", name="mysql", product=producto, version=str(banner)
        )
        return Fingerprint(address=decoy.address, os_matches=[LINUX], services=[SSH, mysql])


async def test_ajusta_hasta_superar_el_umbral_y_registra_cada_intento() -> None:
    lab = FakeLab()
    resultado = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=85
    )
    assert [a.report.passed for a in resultado.attempts] == [False, True]
    assert resultado.attempts[0].report.score < resultado.attempts[1].report.score
    assert resultado.stop_reason == "aprobado"
    assert resultado.report == resultado.attempts[-1].report
    assert resultado.campaign.decoy.opencanary_config["mysql.banner"] == (
        "5.5.5-11.8.9-MariaDB-0+deb13u1"
    )
    assert len(lab.started) == 2


async def test_para_si_aprueba_a_la_primera() -> None:
    lab = FakeLab()
    resultado = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=0
    )
    assert len(resultado.attempts) == 1
    assert resultado.stop_reason == "aprobado"
    assert resultado.campaign == CAMPANA


async def test_para_si_no_queda_nada_que_ajustar() -> None:
    lab = FakeLab()
    resultado = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=100
    )
    assert resultado.stop_reason == "sin_ajustes"
    assert len(resultado.attempts) == 2
    assert not resultado.report.passed


async def test_para_al_llegar_al_maximo_de_intentos() -> None:
    lab = FakeLab()
    resultado = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=100, max_attempts=1
    )
    assert resultado.stop_reason == "max_intentos"
    assert len(resultado.attempts) == 1


async def test_para_si_el_ajuste_repite_un_config_ya_probado(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import securization.orquestador as orq

    # Un ajustador que alterna entre dos configs: el bucle no debe dar vueltas.
    def alternar(_perfil: HostProfile, decoy: DecoyConfig, _real: Fingerprint) -> DecoyConfig:
        actual = decoy.opencanary_config.get("ssh.version")
        otro = "SSH-2.0-B" if actual != "SSH-2.0-B" else "SSH-2.0-A"
        return decoy.model_copy(
            update={"opencanary_config": {**decoy.opencanary_config, "ssh.version": otro}}
        )

    monkeypatch.setattr(orq, "adjust_decoy", alternar)
    inicial = CAMPANA.decoy.model_copy(
        update={
            "opencanary_config": {**CAMPANA.decoy.opencanary_config, "ssh.version": "SSH-2.0-A"}
        }
    )
    lab = FakeLab()
    resultado = await run_verification_loop(
        PERFIL,
        HUELLA_REAL,
        CAMPANA.model_copy(update={"decoy": inicial}),
        start=lab.start,
        scan=lab.scan,
        threshold=100,
        max_attempts=10,
    )
    assert resultado.stop_reason == "config_repetido"
    assert len(resultado.attempts) == 2


async def test_el_ajuste_no_cambia_los_breadcrumbs_de_la_campana() -> None:
    lab = FakeLab()
    resultado = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=85
    )
    assert resultado.campaign.breadcrumbs == CAMPANA.breadcrumbs
    assert resultado.campaign.campaign_id == CAMPANA.campaign_id


async def test_max_attempts_debe_ser_positivo() -> None:
    lab = FakeLab()
    with pytest.raises(ValueError, match="max_attempts"):
        await run_verification_loop(
            PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, max_attempts=0
        )


async def test_verification_result_store_guarda_sustituye_y_devuelve_none(tmp_path: Path) -> None:
    from sqlmodel import create_engine

    from securization.orquestador import VerificationResultStore

    store = VerificationResultStore(create_engine(f"sqlite:///{tmp_path / 'v.db'}"))
    assert store.get(CAMPANA.campaign_id) is None
    lab = FakeLab()
    primero = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=0
    )
    segundo = await run_verification_loop(
        PERFIL, HUELLA_REAL, CAMPANA, start=lab.start, scan=lab.scan, threshold=85
    )
    store.save(primero)
    store.save(segundo)
    assert store.get(CAMPANA.campaign_id) == segundo
