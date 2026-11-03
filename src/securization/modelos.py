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
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None


class OsMatch(_Modelo):
    """Hipótesis de sistema operativo devuelta por `nmap -O`."""

    name: str
    accuracy: int = Field(ge=0, le=100)
    os_family: str | None = None


class Fingerprint(_Modelo):
    """Huella de red de un host: SO estimado y servicios abiertos observados con nmap."""

    address: IPv4Address
    os_matches: list[OsMatch] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)


class PlausibilityReport(_Modelo):
    """Resultado de comparar la huella de un señuelo con la de un host real."""

    score: int = Field(ge=0, le=100)
    threshold: int = Field(ge=0, le=100)
    passed: bool
    differences: list[str] = Field(default_factory=list)


class GenerationQuality(StrEnum):
    """Procedencia de un contenido generado: del LLM o de la plantilla de respaldo.

    CLAUDE.md: si la salida del LLM no valida contra su esquema, se usa la plantilla de
    respaldo y se marca como de menor calidad. Compartido por los tres usos de IA (S8).
    """

    AI = "ia"
    FALLBACK = "respaldo"


class HostProfile(_Modelo):
    """Perfil de un host registrado: SO, servicios, directorios e IPs libres."""

    host_id: str
    address: IPv4Address
    os_family: OsFamily
    os_name: str
    services: list[ServiceInfo] = Field(default_factory=list)
    top_level_dirs: list[str] = Field(default_factory=list)
    free_ips: list[IPv4Address] = Field(default_factory=list)
