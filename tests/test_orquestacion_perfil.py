"""Tests de `HostProfileStore` y `orchestrate_profiling`: perfil completo guardado en BD."""

from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.modelos import HostProfile, OsFamily, ServiceInfo
from securization.parsers_linux import LS_ROOT_CMD, OS_RELEASE_CMD, SS_CMD
from securization.perfilador import (
    HostProfileStore,
    ProfileNotFoundError,
    orchestrate_profiling,
)

FIXTURES = Path(__file__).parent / "fixtures" / "linux"


def fixture(nombre: str) -> str:
    return (FIXTURES / nombre).read_text(encoding="utf-8")


class FakeSshTransport:
    def __init__(self, respuestas: dict[tuple[str, ...], str]) -> None:
        self._respuestas = respuestas

    async def run(self, argv: Sequence[str]) -> str:
        return self._respuestas[tuple(argv)]


def transporte_debian() -> FakeSshTransport:
    return FakeSshTransport(
        {
            OS_RELEASE_CMD: fixture("os_release_debian12.txt"),
            SS_CMD: fixture("ss_tlnp_root.txt"),
            LS_ROOT_CMD: fixture("ls_root.txt"),
        }
    )


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path / 'perfiles.db'}")


PERFIL = HostProfile(
    host_id="victima-01",
    address=IPv4Address("10.0.0.10"),
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 12 (bookworm)",
    services=[ServiceInfo(port=22, protocol="tcp", name="sshd")],
    top_level_dirs=["/etc", "/home"],
)


# --- HostProfileStore --------------------------------------------------------


def test_guarda_y_recupera_el_perfil(engine: Engine) -> None:
    store = HostProfileStore(engine)
    store.save(PERFIL)
    assert store.load("victima-01") == PERFIL


def test_guardar_dos_veces_actualiza_en_vez_de_duplicar(engine: Engine) -> None:
    store = HostProfileStore(engine)
    store.save(PERFIL)
    actualizado = PERFIL.model_copy(update={"os_name": "Debian GNU/Linux 12 (actualizado)"})
    store.save(actualizado)
    assert store.load("victima-01") == actualizado


def test_cargar_host_sin_perfil_falla_con_error_claro(engine: Engine) -> None:
    store = HostProfileStore(engine)
    with pytest.raises(ProfileNotFoundError, match="victima-01"):
        store.load("victima-01")


def test_el_store_persiste_entre_instancias(engine: Engine) -> None:
    HostProfileStore(engine).save(PERFIL)
    otro_store = HostProfileStore(engine)
    assert otro_store.load("victima-01") == PERFIL


# --- orchestrate_profiling ---------------------------------------------------


async def test_orchestrate_profiling_perfila_y_guarda(engine: Engine) -> None:
    store = HostProfileStore(engine)
    perfil = await orchestrate_profiling(
        host_id="victima-01",
        address=IPv4Address("10.0.0.10"),
        os_family=OsFamily.LINUX,
        transport=transporte_debian(),
        store=store,
    )
    assert perfil.os_name == "Debian GNU/Linux 12 (bookworm)"
    assert store.load("victima-01") == perfil


async def test_orchestrate_profiling_con_so_no_soportado_falla(engine: Engine) -> None:
    from securization.perfilador import UnsupportedOsFamilyError

    store = HostProfileStore(engine)
    with pytest.raises(UnsupportedOsFamilyError):
        await orchestrate_profiling(
            host_id="victima-01",
            address=IPv4Address("10.0.0.10"),
            os_family=OsFamily.WINDOWS,
            transport=transporte_debian(),
            store=store,
        )
