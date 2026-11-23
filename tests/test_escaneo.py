"""Tests del módulo de escaneo: parseo de nmap XML, IPs libres y comandos de nmap."""

import asyncio
from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from securization.escaneo import (
    AsyncNmapRunner,
    NmapScanError,
    ProcessRunner,
    build_ping_sweep_command,
    build_scan_command,
    find_free_ips,
    parse_alive_hosts,
    parse_nmap_xml,
    profile_tcp_ports,
    scan_host,
)
from securization.modelos import Fingerprint, HostProfile, OsFamily, OsMatch, ServiceInfo
from securization.parsing import ParseError

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def fixture(nombre: str) -> str:
    return (FIXTURES / nombre).read_text(encoding="utf-8")


def nmap_con_puerto(servicio: str) -> str:
    return (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        f"{servicio}</port></ports></host></nmaprun>"
    )


# --- parse_nmap_xml -------------------------------------------------------


def test_parsea_la_huella_completa_de_un_host() -> None:
    (huella,) = parse_nmap_xml(fixture("sv_o_victima01.xml"))
    assert isinstance(huella, Fingerprint)
    assert huella.address == IPv4Address("10.0.0.10")
    assert huella.services == [
        ServiceInfo(
            port=22,
            protocol="tcp",
            name="ssh",
            product="OpenSSH",
            version="9.2p1 Debian 2+deb12u3",
            extrainfo="protocol 2.0",
            banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        ),
        ServiceInfo(
            port=80,
            protocol="tcp",
            name="http",
            product="nginx",
            version="1.22.1",
            banner="nginx/1.22.1",
        ),
    ]


def test_solo_se_incluyen_puertos_abiertos() -> None:
    (huella,) = parse_nmap_xml(fixture("sv_o_victima01.xml"))
    assert {s.port for s in huella.services} == {22, 80}  # 3306 filtered, 5353 open|filtered


def test_los_os_matches_vienen_ordenados_por_precision() -> None:
    (huella,) = parse_nmap_xml(fixture("sv_o_victima01.xml"))
    assert huella.os_matches == [
        OsMatch(name="Linux 5.10 - 5.15", accuracy=97, os_family="Linux"),
        OsMatch(name="Linux 4.15 - 5.8", accuracy=91, os_family="Linux"),
    ]


def test_host_sin_seccion_os() -> None:
    (huella,) = parse_nmap_xml(nmap_con_puerto('<service name="ssh"/>'))
    assert huella.os_matches == []
    assert huella.services == [ServiceInfo(port=22, protocol="tcp", name="ssh")]


def test_puerto_sin_servicio_se_llama_unknown() -> None:
    (huella,) = parse_nmap_xml(nmap_con_puerto(""))
    assert huella.services[0].name == "unknown"


def test_hosts_caidos_o_sin_ipv4_se_omiten() -> None:
    xml = (
        '<nmaprun><host><status state="down"/><address addr="10.0.0.7" addrtype="ipv4"/></host>'
        '<host><status state="up"/><address addr="fe80::1" addrtype="ipv6"/></host>'
        '<host><status state="up"/><address addr="08:00:27:00:00:11" addrtype="mac"/></host>'
        "</nmaprun>"
    )
    assert parse_nmap_xml(xml) == []


def test_varios_hosts_en_una_salida() -> None:
    xml = (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.11" addrtype="ipv4"/></host>'
        '<host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/></host></nmaprun>'
    )
    assert [str(h.address) for h in parse_nmap_xml(xml)] == ["10.0.0.10", "10.0.0.11"]


def test_accuracy_no_numerica_descarta_ese_os_match() -> None:
    xml = (
        '<nmaprun><host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/>'
        '<os><osmatch name="Malo" accuracy="abc"/><osmatch name="Bueno" accuracy="80"/></os>'
        "</host></nmaprun>"
    )
    (huella,) = parse_nmap_xml(xml)
    assert [m.name for m in huella.os_matches] == ["Bueno"]


def test_los_valores_del_host_se_sanean() -> None:
    # U+007F (DEL) es un carácter de control que XML 1.0 sí permite escribir.
    servicio = (
        '<service name="ssh" product="Open&#x7F;SSH"/><script id="banner" output="a&#x7F;b"/>'
    )
    (huella,) = parse_nmap_xml(nmap_con_puerto(servicio))
    assert huella.services[0].product == "OpenSSH"
    assert huella.services[0].banner == "ab"


def test_banner_enorme_se_trunca() -> None:
    servicio = f'<service name="ssh"/><script id="banner" output="{"A" * 5000}"/>'
    (huella,) = parse_nmap_xml(nmap_con_puerto(servicio))
    banner = huella.services[0].banner
    assert banner is not None
    assert len(banner) <= 256


@pytest.mark.parametrize("texto", ["", "no es xml", "<otraraiz/>", "<nmaprun><host>"])
def test_xml_invalido_lanza_parse_error(texto: str) -> None:
    with pytest.raises(ParseError):
        parse_nmap_xml(texto)


def test_xml_con_entidades_externas_se_rechaza() -> None:
    xxe = (
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        "<nmaprun>&x;</nmaprun>"
    )
    with pytest.raises(ParseError):
        parse_nmap_xml(xxe)


def test_xml_con_expansion_de_entidades_se_rechaza() -> None:
    bomba = (
        '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    )
    with pytest.raises(ParseError):
        parse_nmap_xml(bomba)


# --- parse_alive_hosts ----------------------------------------------------


def test_hosts_vivos_del_barrido() -> None:
    vivos = parse_alive_hosts(fixture("ping_sweep.xml"))
    assert vivos == [IPv4Address("10.0.0.5"), IPv4Address("10.0.0.10"), IPv4Address("10.0.0.11")]


def test_barrido_invalido_lanza_parse_error() -> None:
    with pytest.raises(ParseError):
        parse_alive_hosts("no es xml")


# --- find_free_ips --------------------------------------------------------


def test_ips_libres_excluyen_red_broadcast_y_usadas() -> None:
    libres = find_free_ips("10.0.0.0/28", used=["10.0.0.1", IPv4Address("10.0.0.5")])
    esperadas = [f"10.0.0.{n}" for n in (2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14)]
    assert [str(ip) for ip in libres] == esperadas


def test_ips_libres_respeta_el_limite() -> None:
    libres = find_free_ips("10.0.0.0/24", used=["10.0.0.1"], limit=3)
    assert [str(ip) for ip in libres] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]


def test_ips_libres_limite_cero() -> None:
    assert find_free_ips("10.0.0.0/24", used=[], limit=0) == []


def test_ips_libres_todas_usadas() -> None:
    usadas = [f"10.0.0.{n}" for n in range(1, 15)]
    assert find_free_ips("10.0.0.0/28", used=usadas) == []


def test_ips_libres_ignora_usadas_de_otra_red() -> None:
    libres = find_free_ips("10.0.0.0/30", used=["192.168.1.1"])
    assert [str(ip) for ip in libres] == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.parametrize("red", ["10.0.0.0/8", "no-es-una-red", "fd00::/64", ""])
def test_ips_libres_rechaza_redes_no_validas_o_enormes(red: str) -> None:
    with pytest.raises(ValueError, match="network"):
        find_free_ips(red, used=[])


# --- Comandos de nmap (listas de argumentos) ------------------------------


def test_comando_de_escaneo() -> None:
    assert build_scan_command("10.0.0.10") == ("nmap", "-sV", "-O", "-oX", "-", "10.0.0.10")
    assert build_scan_command(IPv4Address("10.0.0.10")) == build_scan_command("10.0.0.10")


@pytest.mark.parametrize(
    "direccion",
    ["10.0.0.10; rm -rf /", "-oN /etc/x", "--script=evil", "10.0.0.0/24", "host.local", ""],
)
def test_comando_de_escaneo_rechaza_destinos_que_no_son_una_ip(direccion: str) -> None:
    with pytest.raises(ValueError, match="address"):
        build_scan_command(direccion)


def test_comando_de_escaneo_con_puertos_los_limita_con_p() -> None:
    assert build_scan_command("10.0.0.11", ports=[22, 21, 6379]) == (
        "nmap",
        "-sV",
        "-O",
        "-p",
        "21,22,6379",
        "-oX",
        "-",
        "10.0.0.11",
    )


def test_comando_de_escaneo_con_puertos_quita_duplicados() -> None:
    assert build_scan_command("10.0.0.11", ports=(80, 80, 22))[3:5] == ("-p", "22,80")


def test_comando_de_escaneo_sin_puertos_no_anade_p() -> None:
    assert "-p" not in build_scan_command("10.0.0.11", ports=None)


@pytest.mark.parametrize("puertos", [[], [0], [65536], [-1], [22, 70000]])
def test_comando_de_escaneo_rechaza_puertos_no_validos(puertos: list[int]) -> None:
    with pytest.raises(ValueError, match="ports"):
        build_scan_command("10.0.0.11", ports=puertos)


@pytest.mark.parametrize("puerto", [True, "22", "22,80", 22.0])
def test_comando_de_escaneo_rechaza_puertos_que_no_son_enteros(puerto: object) -> None:
    with pytest.raises(ValueError, match="ports"):
        build_scan_command("10.0.0.11", ports=[puerto])  # type: ignore[list-item]


def test_profile_tcp_ports_devuelve_solo_tcp_ordenados_y_sin_duplicados() -> None:
    perfil = HostProfile(
        host_id="victima-02",
        address=IPv4Address("10.0.0.11"),
        os_family=OsFamily.LINUX,
        os_name="Debian GNU/Linux 13 (trixie)",
        services=[
            ServiceInfo(port=6379, protocol="tcp", name="redis"),
            ServiceInfo(port=22, protocol="tcp", name="ssh"),
            ServiceInfo(port=22, protocol="tcp", name="ssh"),
            ServiceInfo(port=123, protocol="udp", name="ntp"),
            ServiceInfo(port=21, protocol="tcp", name="ftp"),
        ],
    )
    assert profile_tcp_ports(perfil) == (21, 22, 6379)


def test_profile_tcp_ports_de_un_perfil_sin_servicios_tcp_es_vacio() -> None:
    perfil = HostProfile(
        host_id="victima-02",
        address=IPv4Address("10.0.0.11"),
        os_family=OsFamily.LINUX,
        os_name="Debian",
    )
    assert profile_tcp_ports(perfil) == ()


def test_comando_de_barrido() -> None:
    assert build_ping_sweep_command("10.0.0.0/24") == ("nmap", "-sn", "-oX", "-", "10.0.0.0/24")


@pytest.mark.parametrize("red", ["-sS", "10.0.0.0/24; id", "fd00::/64", "10.0.0.0/8", ""])
def test_comando_de_barrido_rechaza_redes_no_validas(red: str) -> None:
    with pytest.raises(ValueError, match="network"):
        build_ping_sweep_command(red)


# --- ProcessRunner / AsyncNmapRunner / scan_host (L2) -----------------------


class FakeProcessRunner:
    """Doble de `ProcessRunner`: registra el comando recibido y devuelve salida fija."""

    def __init__(self, stdout: str = "", *, error: Exception | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._stdout = stdout
        self._error = error

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        if self._error is not None:
            raise self._error
        return self._stdout


def test_fake_process_runner_satisface_el_protocolo() -> None:
    assert isinstance(FakeProcessRunner(), ProcessRunner)


async def test_scan_host_construye_el_comando_y_lo_ejecuta() -> None:
    runner = FakeProcessRunner(stdout=fixture("sv_o_victima01.xml"))
    await scan_host(IPv4Address("10.0.0.10"), runner)
    assert runner.calls == [build_scan_command("10.0.0.10")]


async def test_scan_host_con_puertos_los_pasa_al_comando() -> None:
    runner = FakeProcessRunner(stdout=fixture("sv_o_victima01.xml"))
    await scan_host(IPv4Address("10.0.0.10"), runner, ports=[3306, 22, 80])
    assert runner.calls == [build_scan_command("10.0.0.10", ports=[22, 80, 3306])]


async def test_scan_host_con_puertos_no_validos_falla_antes_de_lanzar_nmap() -> None:
    runner = FakeProcessRunner(stdout=fixture("sv_o_victima01.xml"))
    with pytest.raises(ValueError, match="ports"):
        await scan_host(IPv4Address("10.0.0.10"), runner, ports=[])
    assert runner.calls == []


async def test_scan_host_devuelve_la_huella_de_la_direccion_pedida() -> None:
    runner = FakeProcessRunner(stdout=fixture("sv_o_victima01.xml"))
    huella = await scan_host(IPv4Address("10.0.0.10"), runner)
    assert huella == parse_nmap_xml(fixture("sv_o_victima01.xml"))[0]


async def test_scan_host_falla_si_la_direccion_no_aparece_en_la_salida() -> None:
    runner = FakeProcessRunner(stdout=fixture("sv_o_victima01.xml"))
    with pytest.raises(NmapScanError, match=r"10\.0\.0\.99"):
        await scan_host(IPv4Address("10.0.0.99"), runner)


async def test_scan_host_propaga_el_fallo_del_runner_como_nmapscanerror() -> None:
    runner = FakeProcessRunner(error=RuntimeError("nmap: comando no encontrado"))
    with pytest.raises(NmapScanError, match="comando no encontrado"):
        await scan_host(IPv4Address("10.0.0.10"), runner)


async def test_scan_host_propaga_un_nmapscanerror_del_runner_sin_envolverlo_dos_veces() -> None:
    runner = FakeProcessRunner(error=NmapScanError("nmap terminó con código 1: host abajo"))
    with pytest.raises(NmapScanError, match="host abajo"):
        await scan_host(IPv4Address("10.0.0.10"), runner)


async def test_scan_host_falla_con_xml_no_interpretable() -> None:
    runner = FakeProcessRunner(stdout="esto no es XML de nmap")
    with pytest.raises(NmapScanError):
        await scan_host(IPv4Address("10.0.0.10"), runner)


class _FakeProcess:
    """Doble de `asyncio.subprocess.Process`: salida y código de salida fijos."""

    def __init__(self, stdout: bytes, stderr: bytes, returncode: int) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


def test_async_nmap_runner_satisface_el_protocolo() -> None:
    assert isinstance(AsyncNmapRunner(), ProcessRunner)


async def test_async_nmap_runner_ejecuta_sin_shell_y_devuelve_el_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    llamadas: list[tuple[str, ...]] = []

    async def fake_exec(*argv: str, **kwargs: object) -> _FakeProcess:
        llamadas.append(argv)
        return _FakeProcess(stdout=b"salida XML\n", stderr=b"", returncode=0)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    resultado = await AsyncNmapRunner().run(("nmap", "-sV", "-O", "-oX", "-", "10.0.0.10"))
    assert resultado == "salida XML\n"
    assert llamadas == [("nmap", "-sV", "-O", "-oX", "-", "10.0.0.10")]


async def test_async_nmap_runner_falla_con_codigo_de_salida_distinto_de_cero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_exec(*argv: str, **kwargs: object) -> _FakeProcess:
        return _FakeProcess(stdout=b"", stderr=b"nmap: host inalcanzable\n", returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(NmapScanError, match="host inalcanzable"):
        await AsyncNmapRunner().run(("nmap", "-sV", "-O", "-oX", "-", "10.0.0.99"))


async def test_async_nmap_runner_sanea_el_stderr_del_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_exec(*argv: str, **kwargs: object) -> _FakeProcess:
        return _FakeProcess(stdout=b"", stderr=b"error\x07con\x07control", returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    with pytest.raises(NmapScanError) as excinfo:
        await AsyncNmapRunner().run(("nmap",))
    assert "\x07" not in str(excinfo.value)
