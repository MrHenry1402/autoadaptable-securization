"""Tests del generador determinista (H2): configuración de OpenCanary y modelo `Campaign`.

Sin IA: los banners se copian tal cual del perfil del host real, nunca se inventan. La
elección de nombre y servicios "creíbles" por IA llega en S8; aquí solo hay plantillas fijas.
"""

from ipaddress import IPv4Address

import pytest
from pydantic import ValidationError

from securization.generador import (
    Campaign,
    DecoyConfig,
    UnsupportedOsFamilyError,
    build_campaign,
    build_opencanary_config,
)
from securization.modelos import HostProfile, OsFamily, ServiceInfo
from securization.perfilador import UnsupportedOsFamilyError as PerfiladorUnsupportedOsFamilyError

SSH = ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.2p1 Debian-2")
HTTP = ServiceInfo(port=80, protocol="tcp", name="http", banner="nginx/1.22.1")
MYSQL_SIN_BANNER = ServiceInfo(port=3306, protocol="tcp", name="mysql")

PERFIL = HostProfile(
    host_id="victima-01",
    address="10.0.0.10",
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 12 (bookworm)",
    services=[SSH, HTTP, MYSQL_SIN_BANNER],
    top_level_dirs=["/etc", "/home", "/root", "/var"],
)


# --- build_opencanary_config -------------------------------------------------


def test_config_siempre_lleva_node_id_y_autodetect_desactivado() -> None:
    config = build_opencanary_config(PERFIL, node_id="victima-01-decoy")
    assert config["device.node_id"] == "victima-01-decoy"
    assert config["ip.autodetect"] is False


def test_config_copia_el_banner_de_ssh_como_version() -> None:
    config = build_opencanary_config(PERFIL, node_id="x")
    assert config["ssh.enabled"] is True
    assert config["ssh.port"] == 22
    assert config["ssh.version"] == "SSH-2.0-OpenSSH_9.2p1 Debian-2"


def test_config_copia_el_banner_de_http() -> None:
    config = build_opencanary_config(PERFIL, node_id="x")
    assert config["http.enabled"] is True
    assert config["http.port"] == 80
    assert config["http.banner"] == "nginx/1.22.1"


def test_config_sin_banner_capturado_no_inventa_uno() -> None:
    config = build_opencanary_config(PERFIL, node_id="x")
    assert config["mysql.enabled"] is True
    assert config["mysql.port"] == 3306
    assert "mysql.banner" not in config


def test_config_ignora_servicios_sin_modulo_opencanary() -> None:
    perfil = PERFIL.model_copy(
        update={"services": [SSH, ServiceInfo(port=8080, protocol="tcp", name="unknown")]}
    )
    config = build_opencanary_config(perfil, node_id="x")
    assert not any(clave.startswith("unknown") for clave in config)
    assert "ssh.enabled" in config


def test_config_sin_servicios_solo_lleva_las_claves_base() -> None:
    perfil = PERFIL.model_copy(update={"services": []})
    config = build_opencanary_config(perfil, node_id="x")
    assert set(config) == {"device.node_id", "ip.autodetect"}


def test_config_con_modulo_duplicado_se_queda_con_el_puerto_mas_bajo() -> None:
    otro_ssh = ServiceInfo(port=2222, protocol="tcp", name="ssh", banner="otro banner")
    perfil = PERFIL.model_copy(update={"services": [otro_ssh, SSH]})
    config = build_opencanary_config(perfil, node_id="x")
    assert config["ssh.port"] == 22
    assert config["ssh.version"] == "SSH-2.0-OpenSSH_9.2p1 Debian-2"


def test_config_es_determinista() -> None:
    assert build_opencanary_config(PERFIL, node_id="x") == build_opencanary_config(
        PERFIL, node_id="x"
    )


# --- build_campaign -----------------------------------------------------------


def campana(**cambios: object) -> Campaign:
    datos: dict[str, object] = {
        "profile": PERFIL,
        "campaign_id": "campana-01",
        "decoy_node_id": "victima-01-decoy",
        "decoy_address": IPv4Address("10.0.0.50"),
    }
    datos.update(cambios)
    return build_campaign(**datos)  # type: ignore[arg-type]


def test_build_campaign_rellena_los_identificadores() -> None:
    assert campana().campaign_id == "campana-01"
    assert campana().host_id == "victima-01"


def test_build_campaign_incluye_la_configuracion_de_opencanary_del_perfil() -> None:
    assert campana().decoy.opencanary_config == build_opencanary_config(
        PERFIL, node_id="victima-01-decoy"
    )


def test_build_campaign_fija_la_direccion_del_senuelo() -> None:
    assert campana().decoy.address == IPv4Address("10.0.0.50")


def test_build_campaign_incluye_los_breadcrumbs_del_catalogo() -> None:
    breadcrumbs = campana().breadcrumbs
    assert breadcrumbs
    assert all(b.host_id == "victima-01" for b in breadcrumbs)


def test_build_campaign_rechaza_direccion_del_senuelo_igual_a_la_real() -> None:
    with pytest.raises(ValueError, match=r"10\.0\.0\.10"):
        campana(decoy_address=IPv4Address("10.0.0.10"))


def test_build_campaign_propaga_colision_de_breadcrumbs() -> None:
    from securization.generador import CollisionError

    ruta_ocupada = campana().breadcrumbs[0].path
    with pytest.raises(CollisionError):
        campana(known_paths=[ruta_ocupada])


def test_build_campaign_con_so_no_soportado_falla() -> None:
    perfil_windows = PERFIL.model_copy(update={"os_family": OsFamily.WINDOWS})
    with pytest.raises(UnsupportedOsFamilyError):
        campana(profile=perfil_windows)


def test_unsupported_os_family_error_es_la_misma_clase_que_en_perfilador() -> None:
    # Un solo tipo de error para "SO no soportado" en todo el proyecto (perfilador y generador).
    assert UnsupportedOsFamilyError is PerfiladorUnsupportedOsFamilyError


def test_build_campaign_es_determinista() -> None:
    assert campana() == campana()


# --- Modelos: inmutables y sin campos extra ----------------------------------


def test_decoy_config_es_inmutable() -> None:
    decoy = DecoyConfig(node_id="x", address=IPv4Address("10.0.0.50"), opencanary_config={})
    with pytest.raises(ValidationError):
        decoy.node_id = "y"  # type: ignore[misc]


def test_decoy_config_rechaza_campos_extra() -> None:
    datos = {"node_id": "x", "address": "10.0.0.50", "opencanary_config": {}, "extra": "no"}
    with pytest.raises(ValidationError):
        DecoyConfig.model_validate(datos)


def test_campaign_es_inmutable() -> None:
    with pytest.raises(ValidationError):
        campana().campaign_id = "otra"  # type: ignore[misc]


def test_campaign_rechaza_campos_extra() -> None:
    datos = campana().model_dump()
    datos["extra"] = "no"
    with pytest.raises(ValidationError):
        Campaign.model_validate(datos)


def test_campaign_ida_y_vuelta_json() -> None:
    original = campana()
    assert Campaign.model_validate_json(original.model_dump_json()) == original
