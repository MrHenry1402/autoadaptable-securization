"""Perfilado de hosts por SSH y nmap: SO, servicios, banners, directorios e IPs libres.

Todo lo que dependa del sistema operativo va detrás de la interfaz `HostProfiler`.
"""

from abc import ABC, abstractmethod
from ipaddress import IPv4Address
from typing import ClassVar

from securization.modelos import HostProfile, OsFamily


class UnsupportedOsFamilyError(Exception):
    """El `os_family` del host no tiene una implementación disponible."""


class HostProfiler(ABC):
    """Interfaz de perfilado; una implementación por familia de SO."""

    os_family: ClassVar[OsFamily]

    @abstractmethod
    async def profile(self, host_id: str, address: IPv4Address) -> HostProfile:
        """Perfila el host indicado y devuelve su `HostProfile`."""


class LinuxProfiler(HostProfiler):
    """Perfilador para hosts Linux (uname, /etc/os-release, ss -tlnp, ls por SSH)."""

    os_family: ClassVar[OsFamily] = OsFamily.LINUX

    async def profile(self, host_id: str, address: IPv4Address) -> HostProfile:
        raise NotImplementedError("El perfilado por SSH se implementa en una tarea posterior.")


_PROFILERS: dict[OsFamily, type[HostProfiler]] = {
    OsFamily.LINUX: LinuxProfiler,
}


def get_profiler(os_family: OsFamily) -> HostProfiler:
    """Devuelve el perfilador del SO indicado o falla; nunca usa un valor por defecto."""
    try:
        return _PROFILERS[os_family]()
    except KeyError:
        raise UnsupportedOsFamilyError(f"os_family no soportado: {os_family}") from None
