"""Tests del generador determinista (H2): configuración de OpenCanary y modelo `Campaign`.

Sin IA: los banners se copian tal cual del perfil del host real, nunca se inventan. La
elección de nombre y servicios "creíbles" por IA llega en S8; aquí solo hay plantillas fijas.
"""

import json
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.generador import (
    Campaign,
    CampaignNotFoundError,
    CampaignStore,
    DecoyConfig,
    UnsupportedOsFamilyError,
    build_campaign,
    build_opencanary_config,
    get_catalog,
    render_opencanary_conf,
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


def test_config_siempre_lleva_node_id() -> None:
    config = build_opencanary_config(PERFIL, node_id="victima-01-decoy")
    assert config["device.node_id"] == "victima-01-decoy"


def test_config_solo_usa_claves_que_existen_en_opencanary() -> None:
    # `ip.autodetect` se escribió de memoria y no existe en OpenCanary 0.9.10.
    assert "ip.autodetect" not in build_opencanary_config(PERFIL, node_id="x")
    render_opencanary_conf(build_opencanary_config(PERFIL, node_id="x"))


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
    assert set(config) == {"device.node_id"}


# Banners tal como los captura nmap con `--script banner` en el laboratorio real.
FTP_REAL = ServiceInfo(
    port=21, protocol="tcp", name="ftp", banner="220 (vsFTPd 3.0.5)", product="vsftpd"
)
REDIS_REAL = ServiceInfo(
    port=6379, protocol="tcp", name="redis", banner="-DENIED Redis is running in protected mode"
)
MYSQL_REAL = ServiceInfo(
    port=3306,
    protocol="tcp",
    name="mysql",
    banner="C\\x00\\x00\\x00\\xFFj\\x04Host '10.0.0.1' is not allowed to connect",
    product="MariaDB",
    version="10.3.23 or earlier",
)


def _con(*servicios: ServiceInfo) -> HostProfile:
    return PERFIL.model_copy(update={"services": list(servicios)})


def test_config_ftp_quita_el_codigo_220_que_opencanary_ya_antepone() -> None:
    config = build_opencanary_config(_con(FTP_REAL), node_id="x")
    assert config["ftp.enabled"] is True
    assert config["ftp.port"] == 21
    assert config["ftp.banner"] == "(vsFTPd 3.0.5)"


def test_config_ftp_con_banner_multilinea_220_guion_tambien_lo_quita() -> None:
    ftp = FTP_REAL.model_copy(update={"banner": "220-Bienvenido"})
    assert build_opencanary_config(_con(ftp), node_id="x")["ftp.banner"] == "Bienvenido"


def test_config_ftp_sin_codigo_220_copia_el_banner_tal_cual() -> None:
    ftp = FTP_REAL.model_copy(update={"banner": "FTP listo"})
    assert build_opencanary_config(_con(ftp), node_id="x")["ftp.banner"] == "FTP listo"


def test_config_redis_activa_el_modulo_sin_banner() -> None:
    config = build_opencanary_config(_con(REDIS_REAL), node_id="x")
    assert config["redis.enabled"] is True
    assert config["redis.port"] == 6379
    assert not any(clave.startswith("redis.") and clave.endswith("banner") for clave in config)


def test_config_mysql_no_copia_el_saludo_crudo_como_version() -> None:
    # `mysql.banner` en OpenCanary es la versión del servidor; lo que captura nmap es el
    # paquete de saludo (o un rechazo), y su versión ("10.3.23 or earlier") no es fiable.
    config = build_opencanary_config(_con(MYSQL_REAL), node_id="x")
    assert config["mysql.enabled"] is True
    assert "mysql.banner" not in config


def test_config_ssh_ignora_un_banner_que_no_es_una_version_ssh() -> None:
    ssh = SSH.model_copy(update={"banner": "Protocol mismatch."})
    assert "ssh.version" not in build_opencanary_config(_con(ssh), node_id="x")


def test_config_http_sin_banner_usa_producto_y_version_de_nmap() -> None:
    http = ServiceInfo(port=80, protocol="tcp", name="http", product="nginx", version="1.26.3")
    assert build_opencanary_config(_con(http), node_id="x")["http.banner"] == "nginx/1.26.3"


def test_config_http_sin_banner_ni_version_usa_solo_el_producto() -> None:
    http = ServiceInfo(port=80, protocol="tcp", name="http", product="nginx")
    assert build_opencanary_config(_con(http), node_id="x")["http.banner"] == "nginx"


def test_config_http_sin_banner_ni_producto_no_inventa_uno() -> None:
    http = ServiceInfo(port=80, protocol="tcp", name="http")
    assert "http.banner" not in build_opencanary_config(_con(http), node_id="x")


def test_config_telnet_copia_el_banner() -> None:
    telnet = ServiceInfo(port=23, protocol="tcp", name="telnet", banner="Debian GNU/Linux 13")
    assert build_opencanary_config(_con(telnet), node_id="x")["telnet.banner"] == (
        "Debian GNU/Linux 13"
    )


# --- render_opencanary_conf ---------------------------------------------------


def test_render_parte_del_config_por_defecto_con_todo_desactivado() -> None:
    conf = json.loads(render_opencanary_conf({"device.node_id": "x"}))
    activados = [clave for clave, valor in conf.items() if clave.endswith(".enabled") and valor]
    assert activados == []
    assert "logger" in conf
    assert conf["device.node_id"] == "x"


def test_render_desactiva_ftp_que_opencanary_trae_activado_por_defecto() -> None:
    conf = json.loads(render_opencanary_conf({"device.node_id": "x"}))
    assert conf["ftp.enabled"] is False


def test_render_activa_solo_los_modulos_del_perfil() -> None:
    config = build_opencanary_config(_con(SSH, FTP_REAL, REDIS_REAL), node_id="files-02")
    conf = json.loads(render_opencanary_conf(config))
    activados = sorted(c for c, v in conf.items() if c.endswith(".enabled") and v is True)
    assert activados == ["ftp.enabled", "redis.enabled", "ssh.enabled"]
    assert conf["ssh.version"] == "SSH-2.0-OpenSSH_9.2p1 Debian-2"
    assert conf["ftp.banner"] == "(vsFTPd 3.0.5)"
    assert conf["device.node_id"] == "files-02"


def test_render_rechaza_claves_que_opencanary_no_conoce() -> None:
    with pytest.raises(ValueError, match=r"ip\.autodetect"):
        render_opencanary_conf({"device.node_id": "x", "ip.autodetect": False})


def test_render_es_determinista() -> None:
    config = build_opencanary_config(PERFIL, node_id="x")
    assert render_opencanary_conf(config) == render_opencanary_conf(config)


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
        "home_dir": "/home/lab",
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


def test_build_campaign_los_breadcrumbs_apuntan_a_su_senuelo() -> None:
    c = campana()
    assert c.breadcrumbs == get_catalog(OsFamily.LINUX).generate(
        PERFIL, c.decoy, home_dir="/home/lab"
    )
    assert any("10.0.0.50" in b.content for b in c.breadcrumbs)
    assert all(b.path.startswith("/home/lab/") for b in c.breadcrumbs)


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


# --- CampaignStore -------------------------------------------------------------


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path / 'campanas.db'}")


def test_campaign_store_guarda_y_recupera_la_campana(engine: Engine) -> None:
    store = CampaignStore(engine)
    store.save(campana())
    assert store.load("campana-01") == campana()


def test_campaign_store_guardar_dos_veces_actualiza_en_vez_de_duplicar(engine: Engine) -> None:
    store = CampaignStore(engine)
    store.save(campana())
    actualizada = campana(decoy_node_id="victima-01-decoy-2")
    store.save(actualizada)
    assert store.load("campana-01") == actualizada


def test_campaign_store_cargar_sin_campana_falla_con_error_claro(engine: Engine) -> None:
    store = CampaignStore(engine)
    with pytest.raises(CampaignNotFoundError, match="campana-01"):
        store.load("campana-01")


def test_campaign_store_persiste_entre_instancias(engine: Engine) -> None:
    CampaignStore(engine).save(campana())
    otro_store = CampaignStore(engine)
    assert otro_store.load("campana-01") == campana()


def test_campaign_store_list_all_devuelve_todas_las_campanas(engine: Engine) -> None:
    store = CampaignStore(engine)
    store.save(campana())
    store.save(campana(campaign_id="campana-02"))
    campaign_ids = {c.campaign_id for c in store.list_all()}
    assert campaign_ids == {"campana-01", "campana-02"}


def test_campaign_store_list_all_vacio_si_no_hay_campanas(engine: Engine) -> None:
    assert CampaignStore(engine).list_all() == []
