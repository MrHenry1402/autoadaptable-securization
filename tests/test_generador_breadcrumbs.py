"""Tests del catálogo de breadcrumbs: plantillas deterministas, lista blanca, tamaño,
permisos y colisiones. Sin IA y sin E/S: el desplegador decide cuándo plantarlos.
"""

import re
from ipaddress import IPv4Address

import pytest

from securization.generador import (
    MAX_BREADCRUMB_SIZE,
    Breadcrumb,
    BreadcrumbCatalog,
    BreadcrumbError,
    CollisionError,
    DecoyConfig,
    LinuxBreadcrumbCatalog,
    breadcrumb_credentials,
    check_collisions,
    get_catalog,
    validate_breadcrumb,
)
from securization.modelos import HostProfile, OsFamily
from securization.perfilador import UnsupportedOsFamilyError

PERFIL_CON_ROOT = HostProfile(
    host_id="victima-01",
    address="10.0.0.10",
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 12 (bookworm)",
    top_level_dirs=["/etc", "/home", "/root", "/var"],
)

PERFIL_SIN_ROOT = PERFIL_CON_ROOT.model_copy(update={"top_level_dirs": ["/etc", "/home", "/var"]})


# --- Interfaz y selección por SO --------------------------------------------


def test_catalogo_linux_declara_su_familia() -> None:
    assert LinuxBreadcrumbCatalog.os_family is OsFamily.LINUX


def test_catalogo_es_abstracto() -> None:
    with pytest.raises(TypeError):
        BreadcrumbCatalog()  # type: ignore[abstract]


def test_get_catalog_linux() -> None:
    catalogo = get_catalog(OsFamily.LINUX)
    assert isinstance(catalogo, LinuxBreadcrumbCatalog)
    assert isinstance(catalogo, BreadcrumbCatalog)


def test_get_catalog_windows_falla_con_error_claro() -> None:
    with pytest.raises(UnsupportedOsFamilyError, match="windows"):
        get_catalog(OsFamily.WINDOWS)


# --- Generación de breadcrumbs -----------------------------------------------
#
# Cada breadcrumb lleva a un servicio que el señuelo tiene activo, con unas credenciales
# propias de la campaña: así un intento con ellas dispara una alerta de OpenCanary que se
# atribuye a la campaña. Se plantan en el home del usuario de gestión (escribible sin
# root), sin crear directorios y sin pisar ficheros que ya existan.

HOME = "/home/lab"

SENUELO_WEB = DecoyConfig(
    node_id="web-01",
    address=IPv4Address("10.0.0.50"),
    opencanary_config={
        "device.node_id": "web-01",
        "ssh.enabled": True,
        "ssh.port": 22,
        "http.enabled": True,
        "http.port": 80,
        "mysql.enabled": True,
        "mysql.port": 3306,
    },
)
SENUELO_FICHEROS = DecoyConfig(
    node_id="files-02",
    address=IPv4Address("10.0.0.51"),
    opencanary_config={
        "device.node_id": "files-02",
        "ftp.enabled": True,
        "ftp.port": 21,
        "ssh.enabled": True,
        "ssh.port": 22,
        "redis.enabled": True,
        "redis.port": 6379,
    },
)


def _generar(senuelo: DecoyConfig = SENUELO_WEB, **kwargs: object) -> list[Breadcrumb]:
    return LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT, senuelo, home_dir=HOME, **kwargs)  # type: ignore[arg-type]


def _por_nombre(breadcrumbs: list[Breadcrumb]) -> dict[str, Breadcrumb]:
    return {b.path.rsplit("/", 1)[-1]: b for b in breadcrumbs}


def test_generate_planta_en_el_home_indicado_sin_subdirectorios() -> None:
    for breadcrumb in _generar() + _generar(SENUELO_FICHEROS):
        assert breadcrumb.path.rsplit("/", 1)[0] == HOME


def test_generate_no_usa_rutas_que_exigen_root() -> None:
    rutas = [b.path for b in _generar() + _generar(SENUELO_FICHEROS)]
    assert not any(r.startswith(("/root/", "/var/")) for r in rutas)


def test_generate_no_pisa_ficheros_que_siempre_existen() -> None:
    nombres = set(_por_nombre(_generar())) | set(_por_nombre(_generar(SENUELO_FICHEROS)))
    assert not nombres & {".bash_history", ".bashrc", ".profile", ".ssh"}


def test_generate_senuelo_con_mysql_y_http() -> None:
    nombres = _por_nombre(_generar(SENUELO_WEB))
    assert {".env", ".my.cnf", "db_backup.sql", "notas_acceso.txt"} <= set(nombres)
    assert ".netrc" not in nombres
    my_cnf = nombres[".my.cnf"].content
    assert "host=10.0.0.50" in my_cnf
    assert "port=3306" in my_cnf
    env = nombres[".env"].content
    assert "DB_HOST=10.0.0.50" in env
    assert "INTRANET_URL=http://10.0.0.50:80/" in env
    assert "REDIS_URL" not in env


def test_generate_senuelo_con_ftp_y_redis() -> None:
    nombres = _por_nombre(_generar(SENUELO_FICHEROS))
    assert {".env", ".netrc", "notas_acceso.txt"} <= set(nombres)
    assert ".my.cnf" not in nombres
    assert "db_backup.sql" not in nombres
    assert "machine 10.0.0.51" in nombres[".netrc"].content
    env = nombres[".env"].content
    assert "REDIS_URL=redis://" in env
    assert "@10.0.0.51:6379/0" in env
    assert "DB_HOST" not in env


def test_generate_respeta_puertos_no_estandar_del_senuelo() -> None:
    config = {**SENUELO_WEB.opencanary_config, "mysql.port": 3307}
    senuelo = SENUELO_WEB.model_copy(update={"opencanary_config": config})
    assert "port=3307" in _por_nombre(_generar(senuelo))[".my.cnf"].content


def test_generate_solo_apunta_a_servicios_activos_del_senuelo() -> None:
    # Ningún breadcrumb puede llevar a un host o puerto donde nadie escucha.
    for senuelo in (SENUELO_WEB, SENUELO_FICHEROS):
        activos = {
            int(v)
            for k, v in senuelo.opencanary_config.items()
            if k.endswith(".port") and senuelo.opencanary_config.get(k[:-5] + ".enabled")
        }
        for breadcrumb in _generar(senuelo):
            for ip in re.findall(r"\b\d+\.\d+\.\d+\.\d+\b", breadcrumb.content):
                assert ip == str(senuelo.address), (breadcrumb.path, ip)
            for puerto in re.findall(r"(?:port=|:)(\d{2,5})\b", breadcrumb.content):
                assert int(puerto) in activos, (breadcrumb.path, puerto)


def test_generate_no_deja_rastro_de_que_es_un_cebo() -> None:
    for breadcrumb in _generar() + _generar(SENUELO_FICHEROS):
        texto = breadcrumb.content.lower()
        assert "cebo" not in texto
        assert "fake" not in texto
        assert "127.0.0.1" not in texto


def test_generate_credenciales_distintas_por_senuelo() -> None:
    # Permite atribuir una alerta a su campaña por el usuario o la contraseña usados.
    web = _por_nombre(_generar(SENUELO_WEB))["notas_acceso.txt"].content
    otro = SENUELO_WEB.model_copy(update={"node_id": "web-99"})
    assert web != _por_nombre(_generar(otro))["notas_acceso.txt"].content


def test_breadcrumb_credentials_coinciden_con_el_contenido() -> None:
    credenciales = breadcrumb_credentials(SENUELO_FICHEROS)
    nombres = _por_nombre(_generar(SENUELO_FICHEROS))
    ftp = credenciales["ftp"]
    assert f"login {ftp.username} password {ftp.password}" in nombres[".netrc"].content
    assert f":{credenciales['redis'].password}@" in nombres[".env"].content
    assert set(credenciales) == {"ftp", "ssh", "redis"}


def test_generate_todas_las_rutas_son_para_el_host_del_perfil() -> None:
    assert all(b.host_id == "victima-01" for b in _generar())


def test_generate_sin_permisos_de_ejecucion_y_solo_para_el_propietario() -> None:
    assert all(b.mode == 0o600 for b in _generar() + _generar(SENUELO_FICHEROS))


def test_generate_dentro_del_limite_de_tamano() -> None:
    assert all(len(b.content.encode("utf-8")) <= MAX_BREADCRUMB_SIZE for b in _generar())


def test_generate_es_determinista() -> None:
    assert _generar() == _generar()


def test_generate_detecta_colision_con_rutas_conocidas() -> None:
    ruta_ocupada = f"{HOME}/.env"
    with pytest.raises(CollisionError, match=ruta_ocupada):
        _generar(known_paths=[ruta_ocupada])


@pytest.mark.parametrize("home", ["/etc", "/home/lab/../../etc", "home/lab", "/var/www"])
def test_generate_rechaza_un_home_fuera_de_la_lista_blanca(home: str) -> None:
    with pytest.raises(BreadcrumbError):
        LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT, SENUELO_WEB, home_dir=home)


def test_generate_senuelo_sin_servicios_con_credenciales_no_genera_nada() -> None:
    vacio = SENUELO_WEB.model_copy(update={"opencanary_config": {"device.node_id": "web-01"}})
    assert _generar(vacio) == []


# --- validate_breadcrumb (lista blanca, permisos, tamaño) -------------------


def test_validate_acepta_ruta_en_la_lista_blanca() -> None:
    breadcrumb = Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="x", mode=0o600)
    validate_breadcrumb(breadcrumb, ("/home", "/root"))


def test_validate_rechaza_ruta_fuera_de_la_lista_blanca() -> None:
    breadcrumb = Breadcrumb(host_id="victima-01", path="/etc/shadow", content="x", mode=0o600)
    with pytest.raises(BreadcrumbError, match="/etc/shadow"):
        validate_breadcrumb(breadcrumb, ("/home", "/root"))


def test_validate_rechaza_rutas_con_punto_punto() -> None:
    breadcrumb = Breadcrumb(host_id="victima-01", path="/home/../etc/cron.d/x", content="x")
    with pytest.raises(BreadcrumbError, match=r"\.\."):
        validate_breadcrumb(breadcrumb, ("/home",))


def test_validate_rechaza_directorio_parecido_sin_ser_subdirectorio() -> None:
    # "/homeless/.env" no es un subdirectorio de "/home", aunque empiece igual.
    breadcrumb = Breadcrumb(host_id="victima-01", path="/homeless/.env", content="x", mode=0o600)
    with pytest.raises(BreadcrumbError):
        validate_breadcrumb(breadcrumb, ("/home",))


def test_validate_rechaza_permisos_de_ejecucion() -> None:
    breadcrumb = Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="x", mode=0o700)
    with pytest.raises(BreadcrumbError, match="ejecución"):
        validate_breadcrumb(breadcrumb, ("/home",))


def test_validate_rechaza_contenido_demasiado_grande() -> None:
    breadcrumb = Breadcrumb(
        host_id="victima-01",
        path="/home/admin/.env",
        content="A" * (MAX_BREADCRUMB_SIZE + 1),
        mode=0o600,
    )
    with pytest.raises(BreadcrumbError, match="grande"):
        validate_breadcrumb(breadcrumb, ("/home",))


# --- check_collisions --------------------------------------------------------


def test_check_collisions_sin_conflicto_no_falla() -> None:
    breadcrumbs = [Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="x")]
    check_collisions(breadcrumbs, known_paths=["/home/admin/.bash_history"])


def test_check_collisions_detecta_duplicado_interno() -> None:
    breadcrumbs = [
        Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="x"),
        Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="y"),
    ]
    with pytest.raises(CollisionError):
        check_collisions(breadcrumbs, known_paths=())


def test_check_collisions_detecta_coincidencia_con_ruta_conocida() -> None:
    breadcrumbs = [Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="x")]
    with pytest.raises(CollisionError):
        check_collisions(breadcrumbs, known_paths=["/home/admin/.env"])
