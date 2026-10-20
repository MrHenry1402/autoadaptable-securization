"""Tests del módulo de escaneo: parseo de nmap XML, IPs libres y comandos de nmap."""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from securization.escaneo import (
    build_ping_sweep_command,
    build_scan_command,
    find_free_ips,
    parse_alive_hosts,
    parse_nmap_xml,
)
from securization.modelos import Fingerprint, OsMatch, ServiceInfo
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


def test_comando_de_barrido() -> None:
    assert build_ping_sweep_command("10.0.0.0/24") == ("nmap", "-sn", "-oX", "-", "10.0.0.0/24")


@pytest.mark.parametrize("red", ["-sS", "10.0.0.0/24; id", "fd00::/64", "10.0.0.0/8", ""])
def test_comando_de_barrido_rechaza_redes_no_validas(red: str) -> None:
    with pytest.raises(ValueError, match="network"):
        build_ping_sweep_command(red)
