"""Capa de abstracción del LLM (H3/S8): cliente, saneado del perfil y respaldo determinista.

El LLM solo genera contenido (CLAUDE.md, principio de diseño innegociable): esta capa nunca
decide ni ejecuta nada sobre un host real. Los datos del perfil que se envían al modelo se
tratan como no confiables en el sentido inverso de lo habitual —no es que el host ataque al
LLM con ellos, es que no deben salir del proceso datos reales—: viajan truncados, sin
caracteres de control y con las IPs seudonimizadas, nunca con credenciales, contenido de
ficheros reales ni nombres de usuario reales. Si la salida del LLM no es JSON válido o no
cumple el esquema esperado, se usa una plantilla de respaldo determinista y el resultado se
marca con `GenerationQuality.FALLBACK` en vez de fallar o inventar un valor por defecto.
"""

import json
from collections.abc import Callable, Sequence
from ipaddress import IPv4Address
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from securization.modelos import GenerationQuality, HostProfile, ServiceInfo
from securization.parsing import sanitize_text

DEFAULT_MAX_PROFILE_LEN = 4096


class LlmError(Exception):
    """El cliente del LLM no pudo completar la petición (red, cuota, modelo no disponible)."""


@runtime_checkable
class LlmClient(Protocol):
    """Cliente mínimo de un LLM: manda un prompt, devuelve texto. Sin herramientas."""

    async def complete(self, prompt: str) -> str:
        """Pide una respuesta al modelo para el prompt dado."""
        ...


class PseudonymMap(BaseModel):
    """Traduce los placeholders (`IP_1`, `IP_2`, ...) de vuelta a las direcciones reales."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entries: dict[str, str] = Field(default_factory=dict)

    def restore(self, text: str) -> str:
        """Sustituye cada placeholder por la dirección real que representa."""
        resultado = text
        for placeholder, real in self.entries.items():
            resultado = resultado.replace(placeholder, real)
        return resultado


def pseudonymize_addresses(
    addresses: Sequence[IPv4Address],
) -> tuple[dict[str, str], PseudonymMap]:
    """Asigna un placeholder `IP_n` a cada dirección distinta, en orden de aparición."""
    forward: dict[str, str] = {}
    reverse: dict[str, str] = {}
    for direccion in addresses:
        clave = str(direccion)
        if clave in forward:
            continue
        placeholder = f"IP_{len(forward) + 1}"
        forward[clave] = placeholder
        reverse[placeholder] = clave
    return forward, PseudonymMap(entries=reverse)


class ProfilePayload(BaseModel):
    """Subconjunto del perfil que se puede enviar al LLM: sin IPs reales en claro."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str
    address: str
    os_name: str
    services: list[ServiceInfo] = Field(default_factory=list)
    top_level_dirs: list[str] = Field(default_factory=list)
    free_ips: list[str] = Field(default_factory=list)


def build_profile_payload(profile: HostProfile) -> tuple[ProfilePayload, PseudonymMap]:
    """Construye el payload que se puede enviar al LLM, con las IPs ya seudonimizadas."""
    forward, mapa = pseudonymize_addresses([profile.address, *profile.free_ips])
    payload = ProfilePayload(
        host_id=profile.host_id,
        address=forward[str(profile.address)],
        os_name=profile.os_name,
        services=list(profile.services),
        top_level_dirs=list(profile.top_level_dirs),
        free_ips=[forward[str(ip)] for ip in profile.free_ips],
    )
    return payload, mapa


def render_untrusted_block(payload: ProfilePayload, max_len: int = DEFAULT_MAX_PROFILE_LEN) -> str:
    """Envuelve el payload en un bloque delimitado, saneado y truncado para el prompt."""
    contenido = sanitize_text(payload.model_dump_json(), max_len=max_len)
    return f"<perfil_host_no_confiable>\n{contenido}\n</perfil_host_no_confiable>"


async def generate_with_fallback[T: BaseModel](
    client: LlmClient,
    prompt: str,
    schema: type[T],
    fallback: Callable[[], T],
) -> tuple[T, GenerationQuality]:
    """Pide al LLM una salida que cumpla `schema`; si falla, usa `fallback` determinista.

    Solo se cae al respaldo por fallos esperados: `LlmError`, JSON inválido o un esquema que
    no valida. Un error de programación en el cliente (cualquier otra excepción) se propaga
    tal cual, nunca se confunde con una salida de menor calidad.
    """
    try:
        respuesta = await client.complete(prompt)
    except LlmError:
        return fallback(), GenerationQuality.FALLBACK

    try:
        datos = json.loads(respuesta)
        resultado = schema.model_validate(datos)
    except (json.JSONDecodeError, ValidationError):
        return fallback(), GenerationQuality.FALLBACK

    return resultado, GenerationQuality.AI
