"""Tests de `OllamaClient`: implementación de `LlmClient` contra un Ollama local (L5).

Sin red: `urllib.request.urlopen` se sustituye por un doble. El cliente solo acepta una
URL local (los datos del perfil no salen de la máquina) y convierte cualquier fallo
esperado en `LlmError`, para que `generate_with_fallback` use la plantilla de respaldo.
"""

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from securization.llm import LlmClient, LlmError, OllamaClient


class _FakeResponse:
    def __init__(self, cuerpo: bytes) -> None:
        self._cuerpo = cuerpo

    def read(self) -> bytes:
        return self._cuerpo

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class _FakeUrlopen:
    def __init__(self, *, cuerpo: bytes = b"", error: Exception | None = None) -> None:
        self.peticiones: list[tuple[str, dict[str, Any], float]] = []
        self._cuerpo = cuerpo
        self._error = error

    def __call__(self, peticion: urllib.request.Request, timeout: float) -> _FakeResponse:
        datos = peticion.data
        assert isinstance(datos, bytes)
        self.peticiones.append((peticion.full_url, json.loads(datos), timeout))
        if self._error is not None:
            raise self._error
        return _FakeResponse(self._cuerpo)


def _respuesta(texto: str) -> bytes:
    return json.dumps({"model": "qwen3:8b", "response": texto, "done": True}).encode()


@pytest.fixture
def urlopen_ok(monkeypatch: pytest.MonkeyPatch) -> _FakeUrlopen:
    fake = _FakeUrlopen(cuerpo=_respuesta('{"hostname": "db-02"}'))
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    return fake


def test_cumple_el_protocolo_llmclient() -> None:
    assert isinstance(OllamaClient("qwen3:8b"), LlmClient)


async def test_devuelve_el_texto_generado(urlopen_ok: _FakeUrlopen) -> None:
    assert await OllamaClient("qwen3:8b").complete("hola") == '{"hostname": "db-02"}'


async def test_pide_json_sin_razonamiento_y_sin_streaming(urlopen_ok: _FakeUrlopen) -> None:
    await OllamaClient("qwen3:8b", temperature=0.2, seed=7, timeout=30).complete("hola")
    ((url, cuerpo, timeout),) = urlopen_ok.peticiones
    assert url == "http://127.0.0.1:11434/api/generate"
    assert cuerpo["model"] == "qwen3:8b"
    assert cuerpo["prompt"] == "hola"
    assert cuerpo["stream"] is False
    assert cuerpo["format"] == "json"
    assert cuerpo["think"] is False
    assert cuerpo["options"] == {"temperature": 0.2, "seed": 7}
    assert timeout == 30


async def test_sin_semilla_no_la_envia(urlopen_ok: _FakeUrlopen) -> None:
    await OllamaClient("qwen3:8b").complete("hola")
    assert "seed" not in urlopen_ok.peticiones[0][1]["options"]


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("conexión rechazada"),
        TimeoutError("timed out"),
        urllib.error.HTTPError("http://127.0.0.1:11434", 404, "model not found", {}, None),  # type: ignore[arg-type]
    ],
)
async def test_fallos_de_red_o_http_son_llmerror(
    monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _FakeUrlopen(error=error))
    with pytest.raises(LlmError):
        await OllamaClient("qwen3:8b").complete("hola")


@pytest.mark.parametrize(
    "cuerpo", [b"no es json", b"[]", json.dumps({"done": True}).encode(), _respuesta("")[:0]]
)
async def test_respuesta_de_ollama_mal_formada_es_llmerror(
    monkeypatch: pytest.MonkeyPatch, cuerpo: bytes
) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", _FakeUrlopen(cuerpo=cuerpo))
    with pytest.raises(LlmError):
        await OllamaClient("qwen3:8b").complete("hola")


async def test_respuesta_con_campo_response_no_textual_es_llmerror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cuerpo = json.dumps({"response": 42}).encode()
    monkeypatch.setattr(urllib.request, "urlopen", _FakeUrlopen(cuerpo=cuerpo))
    with pytest.raises(LlmError):
        await OllamaClient("qwen3:8b").complete("hola")


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:11434",
        "https://api.ejemplo.com",
        "file:///etc/passwd",
        "http://localhost.evil.com:11434",
        "ftp://127.0.0.1",
    ],
)
def test_solo_acepta_un_ollama_local(url: str) -> None:
    with pytest.raises(ValueError, match="local"):
        OllamaClient("qwen3:8b", base_url=url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434", "http://localhost:11434/"])
def test_acepta_urls_locales(url: str) -> None:
    OllamaClient("qwen3:8b", base_url=url)


def test_modelo_vacio_no_es_valido() -> None:
    with pytest.raises(ValueError, match="model"):
        OllamaClient("")
