"""Tests de los parsers de LinuxProfiler: reciben texto y devuelven modelos, sin red."""

import shlex
from pathlib import Path

import pytest

from securization.modelos import ServiceInfo
from securization.parsers_linux import (
    LS_ROOT_CMD,
    OS_RELEASE_CMD,
    SS_CMD,
    ParseError,
    parse_os_release,
    parse_ss_listening,
    parse_top_level_dirs,
    to_command_line,
)

FIXTURES = Path(__file__).parent / "fixtures" / "linux"


def fixture(nombre: str) -> str:
    return (FIXTURES / nombre).read_text(encoding="utf-8")


# --- /etc/os-release -------------------------------------------------------


def test_os_release_debian12() -> None:
    assert parse_os_release(fixture("os_release_debian12.txt")) == "Debian GNU/Linux 12 (bookworm)"


def test_os_release_sin_pretty_name_usa_name_y_version_id() -> None:
    texto = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n'
    assert parse_os_release(texto) == "Ubuntu 22.04"


def test_os_release_solo_name() -> None:
    assert parse_os_release("NAME=Alpine\n") == "Alpine"


def test_os_release_admite_comillas_simples_y_sin_comillas() -> None:
    assert parse_os_release("PRETTY_NAME='Arch Linux'\n") == "Arch Linux"
    assert parse_os_release("PRETTY_NAME=Gentoo\n") == "Gentoo"


def test_os_release_ignora_comentarios_y_lineas_vacias() -> None:
    texto = '# comentario\n\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
    assert parse_os_release(texto) == "Debian GNU/Linux 12 (bookworm)"


@pytest.mark.parametrize("texto", ["", "\n\n", "# solo comentarios\n", "ID=debian\n"])
def test_os_release_sin_nombre_falla(texto: str) -> None:
    with pytest.raises(ParseError):
        parse_os_release(texto)


def test_os_release_descarta_caracteres_de_control() -> None:
    texto = 'PRETTY_NAME="Debian\x1b[31m 12"\n'
    resultado = parse_os_release(texto)
    assert "\x1b" not in resultado


def test_os_release_trunca_valores_enormes() -> None:
    texto = f'PRETTY_NAME="{"A" * 5000}"\n'
    assert len(parse_os_release(texto)) <= 256


# --- ss -tlnp -------------------------------------------------------------


def test_ss_como_root_devuelve_servicios_expuestos() -> None:
    servicios = parse_ss_listening(fixture("ss_tlnp_root.txt"))
    assert servicios == [
        ServiceInfo(port=22, protocol="tcp", name="sshd"),
        ServiceInfo(port=80, protocol="tcp", name="nginx"),
        ServiceInfo(port=443, protocol="tcp", name="nginx"),
    ]


def test_ss_excluye_los_que_solo_escuchan_en_loopback() -> None:
    puertos = {s.port for s in parse_ss_listening(fixture("ss_tlnp_root.txt"))}
    assert 3306 not in puertos
    assert 53 not in puertos


def test_ss_deduplica_ipv4_e_ipv6_del_mismo_puerto() -> None:
    servicios = parse_ss_listening(fixture("ss_tlnp_root.txt"))
    assert [s.port for s in servicios].count(22) == 1


def test_ss_sin_privilegios_nombra_unknown() -> None:
    servicios = parse_ss_listening(fixture("ss_tlnp_user.txt"))
    assert servicios == [
        ServiceInfo(port=22, protocol="tcp", name="unknown"),
        ServiceInfo(port=8080, protocol="tcp", name="unknown"),
    ]


def test_ss_banner_siempre_vacio() -> None:
    # Los banners los obtiene nmap (S3); el parser de ss no los inventa.
    assert all(s.banner is None for s in parse_ss_listening(fixture("ss_tlnp_root.txt")))


@pytest.mark.parametrize(
    "texto",
    [
        "",
        "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n",
        "basura que no es salida de ss\n",
        "LISTEN 0 128\n",
    ],
)
def test_ss_entradas_vacias_o_mal_formadas_dan_lista_vacia(texto: str) -> None:
    assert parse_ss_listening(texto) == []


def test_ss_ignora_puertos_fuera_de_rango() -> None:
    texto = "LISTEN 0 128 0.0.0.0:99999 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:0 0.0.0.0:*\n"
    assert parse_ss_listening(texto) == []


def test_ss_el_nombre_del_proceso_se_sanea() -> None:
    texto = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("ss\x1bh",pid=1,fd=3))\n'
    (servicio,) = parse_ss_listening(texto)
    assert "\x1b" not in servicio.name


# --- ls -1Ap / ------------------------------------------------------------


def test_directorios_de_primer_nivel() -> None:
    assert parse_top_level_dirs(fixture("ls_root.txt")) == [
        "/boot",
        "/etc",
        "/home",
        "/media",
        "/mnt",
        "/opt",
        "/root",
        "/srv",
        "/tmp",  # noqa: S108 - ruta del host perfilado, no un fichero temporal local
        "/usr",
        "/var",
    ]


def test_directorios_excluye_sistemas_de_ficheros_virtuales_y_ficheros() -> None:
    dirs = parse_top_level_dirs(fixture("ls_root.txt"))
    for ausente in ("/proc", "/sys", "/dev", "/run", "/lost+found", "/vmlinuz", "/bin"):
        assert ausente not in dirs


def test_directorios_descarta_nombres_con_caracteres_de_control() -> None:
    dirs = parse_top_level_dirs("etc/\nev\x1bil/\nvar/\n")
    assert dirs == ["/etc", "/var"]


def test_directorios_descarta_nombres_demasiado_largos() -> None:
    dirs = parse_top_level_dirs(f"etc/\n{'a' * 300}/\n")
    assert dirs == ["/etc"]


def test_directorios_no_acepta_rutas_anidadas_ni_traversal() -> None:
    assert parse_top_level_dirs("etc/\n../\n./\na/b/\n") == ["/etc"]


def test_directorios_salida_vacia() -> None:
    assert parse_top_level_dirs("") == []


# --- Comandos remotos (deterministas, como listas de argumentos) ----------


def test_los_comandos_son_tuplas_de_argumentos_fijas() -> None:
    assert OS_RELEASE_CMD == ("cat", "/etc/os-release")
    assert SS_CMD == ("ss", "-tlnp")
    assert LS_ROOT_CMD == ("ls", "-1Ap", "/")


def test_to_command_line_ida_y_vuelta_con_shlex() -> None:
    for argv in (OS_RELEASE_CMD, SS_CMD, LS_ROOT_CMD):
        assert tuple(shlex.split(to_command_line(argv))) == argv


def test_to_command_line_escapa_metacaracteres() -> None:
    argv = ("echo", "a; rm -rf /", "$(id)", "x y")
    linea = to_command_line(argv)
    assert tuple(shlex.split(linea)) == argv
    assert "'a; rm -rf /'" in linea  # entrecomillado como un único argumento
