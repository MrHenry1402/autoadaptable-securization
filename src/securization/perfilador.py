"""Perfilado de hosts por SSH y nmap: SO, servicios, banners, directorios e IPs libres.

Todo lo que dependa del sistema operativo va detrás de la interfaz `HostProfiler`. La E/S
SSH real va detrás de `SshTransport`: aquí solo se orquesta sobre esa interfaz, con una
implementación falsa en los tests y la real (asyncssh) prevista para cuando haya laboratorio.
"""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Sequence
from ipaddress import IPv4Address
from typing import ClassVar, Protocol, runtime_checkable

import asyncssh
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel

from securization.modelos import HostProfile, OsFamily
from securization.parsers_linux import (
    LS_ROOT_CMD,
    OS_RELEASE_CMD,
    SS_CMD,
    parse_os_release,
    parse_ss_listening,
    parse_top_level_dirs,
    to_command_line,
)
from securization.parsing import ParseError


class UnsupportedOsFamilyError(Exception):
    """El `os_family` del host no tiene una implementación disponible."""


class ProfilingError(Exception):
    """Fallo al perfilar un host: transporte SSH o salida remota no interpretable."""


class ProfileNotFoundError(Exception):
    """No hay un perfil guardado para ese host."""


@runtime_checkable
class SshTransport(Protocol):
    """Transporte SSH abstracto; la implementación real llega con el laboratorio (asyncssh)."""

    async def run(self, argv: Sequence[str]) -> str:
        """Ejecuta el comando remoto (lista de argumentos) y devuelve su salida estándar."""
        ...


class AsyncSshTransport:
    """Implementación real de `SshTransport` sobre asyncssh, para el laboratorio (L1).

    No se fía de ningún `known_hosts`: las VMs del laboratorio se recrean con claves de
    host distintas en cada reinstalación, así que una huella guardada de una vez anterior
    solo causaría fallos de verificación falsos. La autenticidad del host no es lo que
    protege esta capa; las credenciales de gestión (cifradas en el inventario) sí lo son.
    """

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password

    async def run(self, argv: Sequence[str]) -> str:
        command = to_command_line(argv)
        async with asyncssh.connect(
            self._host,
            port=self._port,
            username=self._username,
            password=self._password,
            known_hosts=None,
        ) as conn:
            result = await conn.run(command, check=True)
            return str(result.stdout)


class HostProfiler(ABC):
    """Interfaz de perfilado; una implementación por familia de SO."""

    os_family: ClassVar[OsFamily]

    @abstractmethod
    async def profile(
        self, host_id: str, address: IPv4Address, transport: SshTransport
    ) -> HostProfile:
        """Perfila el host indicado usando el transporte dado y devuelve su `HostProfile`."""


class LinuxProfiler(HostProfiler):
    """Perfilador para hosts Linux (/etc/os-release, ss -tlnp, ls por SSH)."""

    os_family: ClassVar[OsFamily] = OsFamily.LINUX

    async def profile(
        self, host_id: str, address: IPv4Address, transport: SshTransport
    ) -> HostProfile:
        try:
            os_release_out, ss_out, ls_out = await asyncio.gather(
                transport.run(OS_RELEASE_CMD),
                transport.run(SS_CMD),
                transport.run(LS_ROOT_CMD),
            )
        except Exception as error:
            raise ProfilingError(
                f"{host_id}: fallo de transporte SSH al perfilar: {error}"
            ) from error

        try:
            os_name = parse_os_release(os_release_out)
            services = parse_ss_listening(ss_out)
            top_level_dirs = parse_top_level_dirs(ls_out)
        except ParseError as error:
            raise ProfilingError(
                f"{host_id}: no se pudo interpretar la salida remota: {error}"
            ) from error

        return HostProfile(
            host_id=host_id,
            address=address,
            os_family=self.os_family,
            os_name=os_name,
            services=services,
            top_level_dirs=top_level_dirs,
        )


_PROFILERS: dict[OsFamily, type[HostProfiler]] = {
    OsFamily.LINUX: LinuxProfiler,
}


def get_profiler(os_family: OsFamily) -> HostProfiler:
    """Devuelve el perfilador del SO indicado o falla; nunca usa un valor por defecto."""
    try:
        return _PROFILERS[os_family]()
    except KeyError:
        raise UnsupportedOsFamilyError(f"os_family no soportado: {os_family}") from None


class _HostProfileRecord(SQLModel, table=True):
    """Fila con el `HostProfile` completo de un host, serializado en JSON."""

    __tablename__ = "host_profile"

    host_id: str = Field(primary_key=True)
    profile_json: str


class HostProfileStore:
    """Guarda y recupera el `HostProfile` completo de cada host en la base de datos."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        SQLModel.metadata.create_all(engine)

    def save(self, profile: HostProfile) -> None:
        """Guarda el perfil; si ya había uno para ese host, lo sustituye."""
        payload = profile.model_dump_json()
        with Session(self._engine) as session:
            registro = session.get(_HostProfileRecord, profile.host_id)
            if registro is None:
                registro = _HostProfileRecord(host_id=profile.host_id, profile_json=payload)
            else:
                registro.profile_json = payload
            session.add(registro)
            session.commit()

    def load(self, host_id: str) -> HostProfile:
        """Recupera el perfil guardado de un host o falla con un error claro."""
        with Session(self._engine) as session:
            registro = session.get(_HostProfileRecord, host_id)
        if registro is None:
            raise ProfileNotFoundError(host_id)
        return HostProfile.model_validate_json(registro.profile_json)


async def orchestrate_profiling(
    *,
    host_id: str,
    address: IPv4Address,
    os_family: OsFamily,
    transport: SshTransport,
    store: HostProfileStore,
) -> HostProfile:
    """Perfila un host con el transporte dado y guarda el resultado completo en la BD."""
    profiler = get_profiler(os_family)
    profile = await profiler.profile(host_id, address, transport)
    store.save(profile)
    return profile
