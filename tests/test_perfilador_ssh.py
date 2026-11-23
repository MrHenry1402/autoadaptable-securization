"""Tests de `LinuxProfiler.profile`: orquesta los comandos SSH sobre un `SshTransport` falso."""

from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from securization.modelos import HostProfile, OsFamily, ServiceInfo
from securization.parsers_linux import DPKG_CMD, LS_ROOT_CMD, OS_RELEASE_CMD, SS_CMD
from securization.perfilador import LinuxProfiler, ProfilingError

FIXTURES = Path(__file__).parent / "fixtures" / "linux"


def fixture(nombre: str) -> str:
    return (FIXTURES / nombre).read_text(encoding="utf-8")


class FakeSshTransport:
    """Transporte SSH falso: responde con una salida fija por comando, sin red."""

    def __init__(self, respuestas: dict[tuple[str, ...], str]) -> None:
        self._respuestas = respuestas
        self.calls: list[tuple[str, ...]] = []

    async def run(self, argv: Sequence[str]) -> str:
        argv = tuple(argv)
        self.calls.append(argv)
        try:
            return self._respuestas[argv]
        except KeyError:
            raise RuntimeError(f"comando no esperado en el transporte falso: {argv}") from None


class FailingSshTransport:
    """Transporte SSH falso que siempre falla, para probar la propagación de errores."""

    def __init__(self, error: Exception) -> None:
        self._error = error
        self.calls: list[tuple[str, ...]] = []

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        raise self._error


def transporte_debian() -> FakeSshTransport:
    return FakeSshTransport(
        {
            OS_RELEASE_CMD: fixture("os_release_debian12.txt"),
            SS_CMD: fixture("ss_tlnp_root.txt"),
            LS_ROOT_CMD: fixture("ls_root.txt"),
        }
    )


# --- Perfilado correcto -----------------------------------------------------


async def test_perfila_host_linux_con_transporte_falso() -> None:
    perfil = await LinuxProfiler().profile(
        "victima-01", IPv4Address("10.0.0.10"), transporte_debian()
    )
    assert perfil == HostProfile(
        host_id="victima-01",
        address=IPv4Address("10.0.0.10"),
        os_family=OsFamily.LINUX,
        os_name="Debian GNU/Linux 12 (bookworm)",
        services=[
            ServiceInfo(port=22, protocol="tcp", name="sshd"),
            ServiceInfo(port=80, protocol="tcp", name="nginx"),
            ServiceInfo(port=443, protocol="tcp", name="nginx"),
        ],
        top_level_dirs=[
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
        ],
    )


async def test_perfilado_no_calcula_ips_libres() -> None:
    # Las IPs libres se calculan a partir de un barrido de red (S3), no del perfilado SSH.
    perfil = await LinuxProfiler().profile(
        "victima-01", IPv4Address("10.0.0.10"), transporte_debian()
    )
    assert perfil.free_ips == []


async def test_perfilado_ejecuta_los_tres_comandos_esperados() -> None:
    transporte = transporte_debian()
    await LinuxProfiler().profile("victima-01", IPv4Address("10.0.0.10"), transporte)
    assert set(transporte.calls) == {OS_RELEASE_CMD, SS_CMD, LS_ROOT_CMD, DPKG_CMD}


# --- Propagación de errores -------------------------------------------------


async def test_perfilado_propaga_fallo_de_transporte_con_error_claro() -> None:
    transporte = FailingSshTransport(ConnectionError("conexión rechazada"))
    with pytest.raises(ProfilingError, match="victima-01"):
        await LinuxProfiler().profile("victima-01", IPv4Address("10.0.0.10"), transporte)


async def test_perfilado_propaga_fallo_de_parseo_con_error_claro() -> None:
    transporte = FakeSshTransport(
        {
            OS_RELEASE_CMD: "basura sin PRETTY_NAME ni NAME\n",
            SS_CMD: fixture("ss_tlnp_root.txt"),
            LS_ROOT_CMD: fixture("ls_root.txt"),
        }
    )
    with pytest.raises(ProfilingError, match="victima-01"):
        await LinuxProfiler().profile("victima-01", IPv4Address("10.0.0.10"), transporte)


# --- Versiones de paquetes (H4): de mejor esfuerzo ------------------------------


async def test_perfilado_guarda_las_versiones_de_los_paquetes_de_servicio() -> None:
    respuestas = {
        OS_RELEASE_CMD: fixture("os_release_debian12.txt"),
        SS_CMD: fixture("ss_tlnp_root.txt"),
        LS_ROOT_CMD: fixture("ls_root.txt"),
        DPKG_CMD: fixture("dpkg_query_victima01.txt"),
    }
    perfil = await LinuxProfiler().profile(
        "victima-01", IPv4Address("10.0.0.10"), FakeSshTransport(respuestas)
    )
    assert perfil.packages["mariadb-server"] == "1:11.8.9+ds-0+deb13u1"


async def test_perfilado_sin_dpkg_deja_los_paquetes_vacios_sin_fallar() -> None:
    # transporte_debian() no responde a DPKG_CMD: equivale a un Linux sin dpkg.
    perfil = await LinuxProfiler().profile(
        "victima-01", IPv4Address("10.0.0.10"), transporte_debian()
    )
    assert perfil.packages == {}
