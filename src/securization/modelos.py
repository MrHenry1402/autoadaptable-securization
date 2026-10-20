"""Modelos Pydantic compartidos entre módulos. Son independientes del sistema operativo."""

from enum import StrEnum
from ipaddress import IPv4Address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class OsFamily(StrEnum):
    """Familia de sistema operativo del host; decide qué implementación se usa."""

    LINUX = "linux"
    WINDOWS = "windows"


class _Modelo(BaseModel):
    """Base estricta: inmutable y sin campos desconocidos."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class ServiceInfo(_Modelo):
    """Servicio de red observado en un host."""

    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    name: str
    banner: str | None = None


class HostProfile(_Modelo):
    """Perfil de un host registrado: SO, servicios, directorios e IPs libres."""

    host_id: str
    address: IPv4Address
    os_family: OsFamily
    os_name: str
    services: list[ServiceInfo] = Field(default_factory=list)
    top_level_dirs: list[str] = Field(default_factory=list)
    free_ips: list[IPv4Address] = Field(default_factory=list)
