"""Tests de los modelos Pydantic compartidos (perfil de host, independiente del SO)."""

from typing import Any

import pytest
from pydantic import ValidationError

from securization.modelos import (
    Fingerprint,
    HostProfile,
    OsFamily,
    PlausibilityReport,
    ServiceInfo,
)


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


# --- Huella de red (Fingerprint) -------------------------------------------


def huella_valida(**cambios: Any) -> dict[str, Any]:
    datos: dict[str, Any] = {
        "address": "10.0.0.10",
        "os_matches": [{"name": "Linux 5.10 - 5.15", "accuracy": 97, "os_family": "Linux"}],
        "services": [
            {
                "port": 22,
                "protocol": "tcp",
                "name": "ssh",
                "product": "OpenSSH",
                "version": "9.2p1 Debian 2+deb12u3",
                "extrainfo": "protocol 2.0",
                "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
            }
        ],
    }
    datos.update(cambios)
    return datos


def test_huella_valida_ida_y_vuelta_json() -> None:
    huella = Fingerprint.model_validate(huella_valida())
    assert Fingerprint.model_validate_json(huella.model_dump_json()) == huella
    assert huella.services[0].product == "OpenSSH"


def test_service_info_conserva_compatibilidad_sin_campos_nmap() -> None:
    servicio = ServiceInfo(port=22, protocol="tcp", name="ssh")
    assert (servicio.product, servicio.version, servicio.extrainfo) == (None, None, None)


@pytest.mark.parametrize("precision", [-1, 101])
def test_precision_del_os_fuera_de_rango(precision: int) -> None:
    match = {"name": "Linux", "accuracy": precision, "os_family": "Linux"}
    with pytest.raises(ValidationError):
        Fingerprint.model_validate(huella_valida(os_matches=[match]))


def test_huella_rechaza_campos_extra() -> None:
    with pytest.raises(ValidationError):
        Fingerprint.model_validate(huella_valida(extra="no"))


# --- PlausibilityReport -----------------------------------------------------


def informe_valido(**cambios: Any) -> dict[str, Any]:
    datos: dict[str, Any] = {
        "score": 85,
        "threshold": 90,
        "passed": False,
        "differences": ["falta el servicio 80/tcp (http) que sí tiene el host real"],
    }
    datos.update(cambios)
    return datos


def test_plausibility_report_valido_ida_y_vuelta_json() -> None:
    informe = PlausibilityReport.model_validate(informe_valido())
    assert PlausibilityReport.model_validate_json(informe.model_dump_json()) == informe


def test_plausibility_report_es_inmutable() -> None:
    informe = PlausibilityReport.model_validate(informe_valido())
    with pytest.raises(ValidationError):
        informe.score = 100  # type: ignore[misc]


def test_plausibility_report_rechaza_campos_extra() -> None:
    with pytest.raises(ValidationError):
        PlausibilityReport.model_validate(informe_valido(extra="no"))


@pytest.mark.parametrize("campo", ["score", "threshold"])
@pytest.mark.parametrize("valor", [-1, 101])
def test_plausibility_report_score_y_umbral_en_rango_0_100(campo: str, valor: int) -> None:
    with pytest.raises(ValidationError):
        PlausibilityReport.model_validate(informe_valido(**{campo: valor}))


def test_plausibility_report_differences_por_defecto_vacio() -> None:
    datos = informe_valido()
    del datos["differences"]
    assert PlausibilityReport.model_validate(datos).differences == []
