"""Tests de los modelos Pydantic compartidos (perfil de host, independiente del SO)."""

from typing import Any

import pytest
from pydantic import ValidationError

from securization.modelos import HostProfile, OsFamily, ServiceInfo


def perfil_valido(**cambios: Any) -> dict[str, Any]:
    datos: dict[str, Any] = {
        "host_id": "victima-01",
        "address": "10.0.0.10",
        "os_family": "linux",
        "os_name": "Debian GNU/Linux 12 (bookworm)",
        "services": [
            {"port": 22, "protocol": "tcp", "name": "ssh", "banner": "OpenSSH_9.2p1 Debian-2"},
        ],
        "top_level_dirs": ["/etc", "/home", "/var"],
        "free_ips": ["10.0.0.30", "10.0.0.31"],
    }
    datos.update(cambios)
    return datos


def test_os_family_solo_linux_y_windows() -> None:
    assert {f.value for f in OsFamily} == {"linux", "windows"}


def test_perfil_valido_se_construye() -> None:
    perfil = HostProfile.model_validate(perfil_valido())
    assert perfil.os_family is OsFamily.LINUX
    assert str(perfil.address) == "10.0.0.10"
    assert perfil.services[0] == ServiceInfo(
        port=22, protocol="tcp", name="ssh", banner="OpenSSH_9.2p1 Debian-2"
    )


def test_perfil_ida_y_vuelta_json() -> None:
    perfil = HostProfile.model_validate(perfil_valido())
    assert HostProfile.model_validate_json(perfil.model_dump_json()) == perfil


def test_os_family_desconocido_se_rechaza() -> None:
    with pytest.raises(ValidationError):
        HostProfile.model_validate(perfil_valido(os_family="macos"))


def test_os_family_es_obligatorio() -> None:
    datos = perfil_valido()
    del datos["os_family"]
    with pytest.raises(ValidationError):
        HostProfile.model_validate(datos)


def test_campos_extra_se_rechazan() -> None:
    with pytest.raises(ValidationError):
        HostProfile.model_validate(perfil_valido(password="secreto"))


@pytest.mark.parametrize("puerto", [0, 65536, -1])
def test_puerto_fuera_de_rango_se_rechaza(puerto: int) -> None:
    servicio = {"port": puerto, "protocol": "tcp", "name": "ssh", "banner": None}
    with pytest.raises(ValidationError):
        HostProfile.model_validate(perfil_valido(services=[servicio]))


def test_protocolo_invalido_se_rechaza() -> None:
    servicio = {"port": 22, "protocol": "icmp", "name": "ssh", "banner": None}
    with pytest.raises(ValidationError):
        HostProfile.model_validate(perfil_valido(services=[servicio]))


def test_direccion_ip_invalida_se_rechaza() -> None:
    with pytest.raises(ValidationError):
        HostProfile.model_validate(perfil_valido(address="no-es-una-ip"))


def test_perfil_es_inmutable() -> None:
    perfil = HostProfile.model_validate(perfil_valido())
    with pytest.raises(ValidationError):
        perfil.host_id = "otro"  # type: ignore[misc]
