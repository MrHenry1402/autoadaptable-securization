"""Tests del ajuste determinista del señuelo (H4).

`adjust_decoy` propone el siguiente config del señuelo a partir de lo observado en el host
real (perfil por SSH y huella nmap). Nunca inventa valores, nunca cambia qué módulos están
activos (los breadcrumbs de L4 dependen de ellos) y devuelve None si no queda nada que
ajustar, que es lo que hace parar el bucle.
"""

from ipaddress import IPv4Address

import pytest

from securization.generador import (
    DecoyConfig,
    adjust_decoy,
    mysql_banner_from_package,
    render_opencanary_conf,
)
from securization.modelos import Fingerprint, HostProfile, OsFamily, ServiceInfo

PERFIL = HostProfile(
    host_id="victima-01",
    address=IPv4Address("10.0.0.10"),
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 13 (trixie)",
    services=[
        ServiceInfo(port=22, protocol="tcp", name="ssh"),
        ServiceInfo(port=80, protocol="tcp", name="http"),
        ServiceInfo(port=3306, protocol="tcp", name="mysql"),
    ],
    packages={"mariadb-server": "1:11.8.9+ds-0+deb13u1", "nginx": "1.26.3-3+deb13u11"},
)
SSH_REAL = "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4"
HUELLA_REAL = Fingerprint(
    address=IPv4Address("10.0.0.10"),
    services=[
        ServiceInfo(port=22, protocol="tcp", name="ssh", banner=SSH_REAL, product="OpenSSH"),
        ServiceInfo(port=80, protocol="tcp", name="http", product="nginx"),
        ServiceInfo(port=3306, protocol="tcp", name="mysql", product="MariaDB"),
    ],
)
SENUELO = DecoyConfig(
    node_id="web-01",
    address=IPv4Address("10.0.0.50"),
    opencanary_config={
        "device.node_id": "web-01",
        "ssh.enabled": True,
        "ssh.port": 22,
        "ssh.version": SSH_REAL,
        "http.enabled": True,
        "http.port": 80,
        "http.banner": "nginx",
        "mysql.enabled": True,
        "mysql.port": 3306,
    },
)


# --- mysql_banner_from_package ----------------------------------------------------


def test_banner_de_mariadb_como_lo_anuncia_el_servidor_real() -> None:
    # `mariadbd --version` en victima-01: 11.8.9-MariaDB-0+deb13u1; MariaDB antepone 5.5.5-.
    assert (
        mysql_banner_from_package("mariadb-server", "1:11.8.9+ds-0+deb13u1")
        == "5.5.5-11.8.9-MariaDB-0+deb13u1"
    )


def test_banner_de_mariadb_sin_revision_debian() -> None:
    assert mysql_banner_from_package("mariadb-server", "10.11.6") == "5.5.5-10.11.6-MariaDB"


def test_banner_de_mysql_5() -> None:
    assert mysql_banner_from_package("mysql-server", "5.7.42-1") == "5.7.42-1"


def test_banner_de_mysql_8_no_es_representable_en_opencanary() -> None:
    # OpenCanary solo admite versiones 3.x-6.x: mejor no tocarlo que tumbar el módulo.
    assert mysql_banner_from_package("mysql-server", "8.0.36-2") is None


@pytest.mark.parametrize("version", ["", "basura", "11.8.9;rm", "7-1"])
def test_banner_de_versiones_no_validas_es_none(version: str) -> None:
    assert mysql_banner_from_package("mariadb-server", version) is None


def test_paquete_desconocido_no_da_banner() -> None:
    assert mysql_banner_from_package("postgresql", "17.5-1") is None


# --- render_opencanary_conf valida mysql.banner -------------------------------------


def test_render_rechaza_un_mysql_banner_que_opencanary_no_admite() -> None:
    # Con un banner fuera de su patrón, OpenCanary descarta el módulo MySQL en silencio.
    with pytest.raises(ValueError, match=r"mysql\.banner"):
        render_opencanary_conf({"mysql.enabled": True, "mysql.banner": "11.8.9-MariaDB"})


def test_render_acepta_el_banner_de_mariadb_con_prefijo() -> None:
    render_opencanary_conf(
        {"mysql.enabled": True, "mysql.banner": "5.5.5-11.8.9-MariaDB-0+deb13u1"}
    )


# --- adjust_decoy -------------------------------------------------------------------


def test_ajusta_mysql_a_la_version_real_de_mariadb() -> None:
    ajustado = adjust_decoy(PERFIL, SENUELO, HUELLA_REAL)
    assert ajustado is not None
    assert ajustado.opencanary_config["mysql.banner"] == "5.5.5-11.8.9-MariaDB-0+deb13u1"


def test_no_cambia_que_modulos_estan_activos_ni_la_identidad() -> None:
    ajustado = adjust_decoy(PERFIL, SENUELO, HUELLA_REAL)
    assert ajustado is not None
    activos = {k for k, v in ajustado.opencanary_config.items() if k.endswith(".enabled") and v}
    originales = {k for k, v in SENUELO.opencanary_config.items() if k.endswith(".enabled") and v}
    assert activos == originales
    assert (ajustado.node_id, ajustado.address) == (SENUELO.node_id, SENUELO.address)


def test_sin_nada_que_ajustar_devuelve_none() -> None:
    ajustado = adjust_decoy(PERFIL, SENUELO, HUELLA_REAL)
    assert ajustado is not None
    assert adjust_decoy(PERFIL, ajustado, HUELLA_REAL) is None


def test_sin_version_del_paquete_no_toca_mysql() -> None:
    perfil = PERFIL.model_copy(update={"packages": {}})
    assert adjust_decoy(perfil, SENUELO, HUELLA_REAL) is None


def test_copia_el_banner_ssh_real_si_el_senuelo_anuncia_otro() -> None:
    senuelo = SENUELO.model_copy(
        update={
            "opencanary_config": {
                **SENUELO.opencanary_config,
                "ssh.version": "SSH-2.0-OpenSSH_5.1p1 Debian-4",
                "mysql.banner": "5.5.5-11.8.9-MariaDB-0+deb13u1",
            }
        }
    )
    ajustado = adjust_decoy(PERFIL, senuelo, HUELLA_REAL)
    assert ajustado is not None
    assert ajustado.opencanary_config["ssh.version"] == SSH_REAL


def test_no_activa_modulos_para_servicios_que_el_senuelo_no_tiene() -> None:
    sin_mysql = {k: v for k, v in SENUELO.opencanary_config.items() if not k.startswith("mysql")}
    senuelo = SENUELO.model_copy(update={"opencanary_config": sin_mysql})
    assert adjust_decoy(PERFIL, senuelo, HUELLA_REAL) is None


def test_el_resultado_siempre_se_puede_renderizar() -> None:
    ajustado = adjust_decoy(PERFIL, SENUELO, HUELLA_REAL)
    assert ajustado is not None
    render_opencanary_conf(ajustado.opencanary_config)


def test_no_copia_banners_de_un_puerto_donde_el_real_tiene_otro_servicio() -> None:
    huella = HUELLA_REAL.model_copy(
        update={
            "services": [
                ServiceInfo(port=22, protocol="tcp", name="tcpwrapped", banner="otro"),
                *HUELLA_REAL.services[1:],
            ]
        }
    )
    perfil = PERFIL.model_copy(update={"packages": {}})
    senuelo = SENUELO.model_copy(
        update={"opencanary_config": {**SENUELO.opencanary_config, "ssh.version": "SSH-2.0-x"}}
    )
    assert adjust_decoy(perfil, senuelo, huella) is None


def test_no_copia_un_banner_ssh_que_no_es_una_version_ssh() -> None:
    huella = HUELLA_REAL.model_copy(
        update={
            "services": [
                ServiceInfo(port=22, protocol="tcp", name="ssh", banner="Protocol mismatch."),
                *HUELLA_REAL.services[1:],
            ]
        }
    )
    perfil = PERFIL.model_copy(update={"packages": {}})
    assert adjust_decoy(perfil, SENUELO, huella) is None
