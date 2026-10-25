"""Tests del catálogo de breadcrumbs: plantillas deterministas, lista blanca, tamaño,
permisos y colisiones. Sin IA y sin E/S: el desplegador decide cuándo plantarlos.
"""

import pytest

from securization.generador import (
    MAX_BREADCRUMB_SIZE,
    Breadcrumb,
    BreadcrumbCatalog,
    BreadcrumbError,
    CollisionError,
    LinuxBreadcrumbCatalog,
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


def test_generate_produce_al_menos_los_cuatro_tipos_del_plan() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    nombres = {b.path.rsplit("/", 1)[-1] for b in breadcrumbs}
    assert ".env" in nombres
    assert "backup.sql" in nombres
    assert ".bash_history" in nombres
    assert any(nombre.startswith("id_") for nombre in nombres)


def test_generate_usa_root_si_esta_disponible() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    assert any(b.path.startswith("/root/") for b in breadcrumbs)


def test_generate_sin_root_usa_home() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_SIN_ROOT)
    assert all(not b.path.startswith("/root/") for b in breadcrumbs)
    assert any(b.path.startswith("/home/") for b in breadcrumbs)


def test_generate_todas_las_rutas_son_para_el_host_del_perfil() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    assert all(b.host_id == "victima-01" for b in breadcrumbs)


def test_generate_sin_permisos_de_ejecucion() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    assert all(b.mode & 0o111 == 0 for b in breadcrumbs)


def test_generate_dentro_del_limite_de_tamano() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    assert all(len(b.content.encode("utf-8")) <= MAX_BREADCRUMB_SIZE for b in breadcrumbs)


def test_generate_sin_rutas_duplicadas() -> None:
    breadcrumbs = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    rutas = [b.path for b in breadcrumbs]
    assert len(rutas) == len(set(rutas))


def test_generate_es_determinista() -> None:
    primero = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    segundo = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    assert primero == segundo


def test_generate_detecta_colision_con_rutas_conocidas() -> None:
    adelanto = LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT)
    ruta_ocupada = adelanto[0].path
    with pytest.raises(CollisionError, match=ruta_ocupada):
        LinuxBreadcrumbCatalog().generate(PERFIL_CON_ROOT, known_paths=[ruta_ocupada])


# --- validate_breadcrumb (lista blanca, permisos, tamaño) -------------------


def test_validate_acepta_ruta_en_la_lista_blanca() -> None:
    breadcrumb = Breadcrumb(host_id="victima-01", path="/home/admin/.env", content="x", mode=0o600)
    validate_breadcrumb(breadcrumb, ("/home", "/root"))


def test_validate_rechaza_ruta_fuera_de_la_lista_blanca() -> None:
    breadcrumb = Breadcrumb(host_id="victima-01", path="/etc/shadow", content="x", mode=0o600)
    with pytest.raises(BreadcrumbError, match="/etc/shadow"):
        validate_breadcrumb(breadcrumb, ("/home", "/root"))


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
