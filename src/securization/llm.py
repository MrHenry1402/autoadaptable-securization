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

import asyncio
import json
import re
import urllib.error
import urllib.parse
import urllib.request
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


_LOCAL_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class OllamaClient:
    """`LlmClient` contra un Ollama local (L5): POST /api/generate, sin streaming.

    Solo acepta una URL local, porque el perfil (aunque seudonimizado) no debe salir de la
    máquina. Pide JSON (`format: json`) y desactiva el razonamiento de los modelos que lo
    tienen (`think: false`), que si no antepone texto a la respuesta. Cualquier fallo
    esperado (red, HTTP, respuesta mal formada) se convierte en `LlmError`.
    """

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        temperature: float = 0.7,
        seed: int | None = None,
        timeout: float = 120.0,
    ) -> None:
        if not model:
            raise ValueError("model no puede estar vacío")
        partes = urllib.parse.urlsplit(base_url)
        if partes.scheme != "http" or partes.hostname not in _LOCAL_HOSTS:
            raise ValueError(f"OllamaClient solo admite un Ollama local por http: {base_url!r}")
        self._url = f"http://{partes.netloc}/api/generate"
        self._model = model
        self._options: dict[str, float | int] = {"temperature": temperature}
        if seed is not None:
            self._options["seed"] = seed
        self._timeout = timeout

    def _post(self, cuerpo: bytes) -> bytes:
        peticion = urllib.request.Request(  # noqa: S310 - URL local validada en __init__
            self._url, data=cuerpo, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(peticion, timeout=self._timeout) as respuesta:  # noqa: S310  # nosec B310
            datos: bytes = respuesta.read()
            return datos

    async def complete(self, prompt: str) -> str:
        cuerpo = json.dumps(
            {
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "think": False,
                "options": self._options,
            }
        ).encode()
        try:
            crudo = await asyncio.to_thread(self._post, cuerpo)
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise LlmError(f"Ollama no respondió: {error}") from error
        try:
            datos = json.loads(crudo)
        except json.JSONDecodeError as error:
            raise LlmError("respuesta de Ollama no es JSON") from error
        texto = datos.get("response") if isinstance(datos, dict) else None
        if not isinstance(texto, str):
            raise LlmError("respuesta de Ollama sin campo 'response' de texto")
        return texto


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


_IPV4_IN_TEXT = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])")
_SERVICE_TEXT_FIELDS = ("banner", "product", "version", "extrainfo")


def _ips_in_text(texto: str | None) -> list[IPv4Address]:
    if not texto:
        return []
    encontradas: list[IPv4Address] = []
    for candidata in _IPV4_IN_TEXT.findall(texto):
        try:
            encontradas.append(IPv4Address(candidata))
        except ValueError:
            continue
    return encontradas


def _replace_ips(texto: str | None, forward: dict[str, str]) -> str | None:
    if not texto:
        return texto
    return _IPV4_IN_TEXT.sub(lambda m: forward.get(m.group(), m.group()), texto)


def build_profile_payload(profile: HostProfile) -> tuple[ProfilePayload, PseudonymMap]:
    """Construye el payload que se puede enviar al LLM, con las IPs ya seudonimizadas.

    También las IPs que aparecen dentro del texto de los servicios (banner, producto,
    versión, extrainfo): el banner real de MariaDB, por ejemplo, incluye la IP del escáner.
    """
    en_servicios = [
        ip
        for servicio in profile.services
        for campo in _SERVICE_TEXT_FIELDS
        for ip in _ips_in_text(getattr(servicio, campo))
    ]
    forward, mapa = pseudonymize_addresses([profile.address, *profile.free_ips, *en_servicios])
    servicios = [
        servicio.model_copy(
            update={
                campo: _replace_ips(getattr(servicio, campo), forward)
                for campo in _SERVICE_TEXT_FIELDS
            }
        )
        for servicio in profile.services
    ]
    payload = ProfilePayload(
        host_id=profile.host_id,
        address=forward[str(profile.address)],
        os_name=profile.os_name,
        services=servicios,
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
