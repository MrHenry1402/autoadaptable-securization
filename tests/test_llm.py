"""Tests de la capa de abstracción del LLM: cliente, seudonimización, saneado y respaldo.

Sin red ni modelo real: el cliente es siempre un `FakeLlmClient` de este fichero. Cubre lo que
pide el PLAN para S8: interfaz `LlmClient`, saneado del perfil (JSON delimitado, truncado,
sin caracteres de control), seudonimización de IPs y validación con respaldo determinista.
"""

import json
from ipaddress import IPv4Address

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from securization.llm import (
    LlmClient,
    LlmError,
    PseudonymMap,
    build_profile_payload,
    generate_with_fallback,
    pseudonymize_addresses,
    render_untrusted_block,
)
from securization.modelos import GenerationQuality, HostProfile, OsFamily, ServiceInfo

PERFIL = HostProfile(
    host_id="victima-01",
    address="10.0.0.10",
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 12 (bookworm)",
    services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.2p1")],
    top_level_dirs=["/etc", "/home"],
    free_ips=[IPv4Address("10.0.0.50"), IPv4Address("10.0.0.51")],
)


class FakeLlmClient:
    """Cliente falso: responde con un texto fijo, o lanza el error dado."""

    def __init__(self, respuesta: str = "", *, error: Exception | None = None) -> None:
        self._respuesta = respuesta
        self._error = error
        self.prompts: list[str] = []

    async def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self._error is not None:
            raise self._error
        return self._respuesta


def test_fake_llm_client_cumple_el_protocolo() -> None:
    assert isinstance(FakeLlmClient(), LlmClient)


# --- pseudonymize_addresses / PseudonymMap -----------------------------------


def test_pseudonymize_asigna_placeholders_en_orden() -> None:
    forward, mapa = pseudonymize_addresses([IPv4Address("10.0.0.10"), IPv4Address("10.0.0.50")])
    assert forward == {"10.0.0.10": "IP_1", "10.0.0.50": "IP_2"}
    assert mapa.entries == {"IP_1": "10.0.0.10", "IP_2": "10.0.0.50"}


def test_pseudonymize_reutiliza_el_mismo_placeholder_para_una_ip_repetida() -> None:
    forward, mapa = pseudonymize_addresses([IPv4Address("10.0.0.10"), IPv4Address("10.0.0.10")])
    assert forward == {"10.0.0.10": "IP_1"}
    assert mapa.entries == {"IP_1": "10.0.0.10"}


def test_pseudonymize_lista_vacia() -> None:
    forward, mapa = pseudonymize_addresses([])
    assert forward == {}
    assert mapa.entries == {}


def test_pseudonym_map_restore_deshace_los_placeholders() -> None:
    _, mapa = pseudonymize_addresses([IPv4Address("10.0.0.10"), IPv4Address("10.0.0.50")])
    texto = '{"hostname": "x", "ref": "IP_1 y IP_2"}'
    assert mapa.restore(texto) == '{"hostname": "x", "ref": "10.0.0.10 y 10.0.0.50"}'


def test_pseudonym_map_es_inmutable_y_rechaza_extra() -> None:
    mapa = PseudonymMap(entries={"IP_1": "10.0.0.10"})
    with pytest.raises(ValidationError):
        mapa.entries = {}  # type: ignore[misc]
    with pytest.raises(ValidationError):
        PseudonymMap.model_validate({"entries": {}, "extra": "no"})


# --- build_profile_payload / render_untrusted_block --------------------------


def test_build_profile_payload_seudonimiza_direccion_y_free_ips() -> None:
    payload, mapa = build_profile_payload(PERFIL)
    assert payload.address == "IP_1"
    assert payload.free_ips == ["IP_2", "IP_3"]
    assert mapa.entries == {"IP_1": "10.0.0.10", "IP_2": "10.0.0.50", "IP_3": "10.0.0.51"}


def test_build_profile_payload_conserva_lo_que_la_memoria_permite_enviar() -> None:
    payload, _ = build_profile_payload(PERFIL)
    assert payload.host_id == "victima-01"
    assert payload.os_name == "Debian GNU/Linux 12 (bookworm)"
    assert payload.top_level_dirs == ["/etc", "/home"]
    assert payload.services[0].banner == "SSH-2.0-OpenSSH_9.2p1"


def test_build_profile_payload_no_contiene_la_ip_real_en_claro() -> None:
    payload, _ = build_profile_payload(PERFIL)
    assert "10.0.0.10" not in payload.model_dump_json()


def test_render_untrusted_block_envuelve_en_delimitadores() -> None:
    payload, _ = build_profile_payload(PERFIL)
    bloque = render_untrusted_block(payload)
    assert bloque.startswith("<perfil_host_no_confiable>")
    assert bloque.endswith("</perfil_host_no_confiable>")
    assert "victima-01" in bloque


def test_render_untrusted_block_quita_caracteres_de_control() -> None:
    perfil = PERFIL.model_copy(update={"os_name": "Debian\x1b[31m 12"})
    payload, _ = build_profile_payload(perfil)
    assert "\x1b" not in render_untrusted_block(payload)


def test_render_untrusted_block_trunca_a_un_limite() -> None:
    perfil = PERFIL.model_copy(update={"os_name": "A" * 10_000})
    payload, _ = build_profile_payload(perfil)
    assert len(render_untrusted_block(payload, max_len=500)) <= 500 + len(
        "<perfil_host_no_confiable>\n\n</perfil_host_no_confiable>"
    )


# --- generate_with_fallback ---------------------------------------------------


class _Esquema(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    nombre: str


def _respaldo() -> _Esquema:
    return _Esquema(nombre="respaldo")


async def test_generate_with_fallback_usa_la_respuesta_del_llm_si_valida() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"nombre": "ok"}))
    resultado, calidad = await generate_with_fallback(cliente, "prompt", _Esquema, _respaldo)
    assert resultado == _Esquema(nombre="ok")
    assert calidad is GenerationQuality.AI


async def test_generate_with_fallback_cae_en_respaldo_si_el_json_es_invalido() -> None:
    cliente = FakeLlmClient(respuesta="esto no es json")
    resultado, calidad = await generate_with_fallback(cliente, "prompt", _Esquema, _respaldo)
    assert resultado == _respaldo()
    assert calidad is GenerationQuality.FALLBACK


async def test_generate_with_fallback_cae_en_respaldo_si_no_cumple_el_esquema() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"nombre": "ok", "extra": "no"}))
    resultado, calidad = await generate_with_fallback(cliente, "prompt", _Esquema, _respaldo)
    assert resultado == _respaldo()
    assert calidad is GenerationQuality.FALLBACK


async def test_generate_with_fallback_cae_en_respaldo_si_falta_un_campo() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({}))
    resultado, calidad = await generate_with_fallback(cliente, "prompt", _Esquema, _respaldo)
    assert resultado == _respaldo()
    assert calidad is GenerationQuality.FALLBACK


async def test_generate_with_fallback_cae_en_respaldo_si_el_cliente_falla() -> None:
    cliente = FakeLlmClient(error=LlmError("conexión rechazada"))
    resultado, calidad = await generate_with_fallback(cliente, "prompt", _Esquema, _respaldo)
    assert resultado == _respaldo()
    assert calidad is GenerationQuality.FALLBACK


async def test_generate_with_fallback_no_oculta_un_error_de_programacion() -> None:
    # Solo se cae a la plantilla de respaldo por fallos esperados (LlmError, JSON/esquema
    # inválidos). Un error de programación en el cliente no se silencia como si fuera eso.
    cliente = FakeLlmClient(error=RuntimeError("bug en el cliente"))
    with pytest.raises(RuntimeError, match="bug en el cliente"):
        await generate_with_fallback(cliente, "prompt", _Esquema, _respaldo)


async def test_generate_with_fallback_el_prompt_llega_tal_cual_al_cliente() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"nombre": "ok"}))
    await generate_with_fallback(cliente, "mi prompt exacto", _Esquema, _respaldo)
    assert cliente.prompts == ["mi prompt exacto"]


# --- IPs dentro del texto de los servicios (L5) -------------------------------------
# Comprobado en el laboratorio: el MariaDB real responde "Host '10.0.0.1' is not allowed",
# con la IP del escáner dentro del banner. Ninguna IP puede llegar al LLM en claro.


def test_build_profile_payload_seudonimiza_ips_dentro_de_los_banners() -> None:
    perfil = PERFIL.model_copy(
        update={
            "services": [
                ServiceInfo(
                    port=3306,
                    protocol="tcp",
                    name="mysql",
                    banner="Host '10.0.0.1' is not allowed to connect to this MariaDB server",
                    extrainfo="desde 192.168.56.7",
                )
            ]
        }
    )
    payload, mapa = build_profile_payload(perfil)
    texto = payload.model_dump_json()
    assert "10.0.0.1'" not in texto
    assert "192.168.56.7" not in texto
    servicio = payload.services[0]
    assert servicio.banner is not None
    assert mapa.restore(servicio.banner) == perfil.services[0].banner


def test_build_profile_payload_reutiliza_el_placeholder_de_la_direccion_del_host() -> None:
    perfil = PERFIL.model_copy(
        update={
            "services": [
                ServiceInfo(port=80, protocol="tcp", name="http", banner=f"srv {PERFIL.address}")
            ]
        }
    )
    payload, _ = build_profile_payload(perfil)
    assert payload.services[0].banner == f"srv {payload.address}"


def test_build_profile_payload_no_toca_versiones_que_parecen_ips_a_medias() -> None:
    perfil = PERFIL.model_copy(
        update={"services": [ServiceInfo(port=22, protocol="tcp", name="ssh", version="10.0p2")]}
    )
    payload, _ = build_profile_payload(perfil)
    assert payload.services[0].version == "10.0p2"


def test_build_profile_payload_deja_numeros_con_puntos_que_no_son_ips() -> None:
    perfil = PERFIL.model_copy(
        update={
            "services": [ServiceInfo(port=80, protocol="tcp", name="http", banner="v999.0.0.1")]
        }
    )
    payload, _ = build_profile_payload(perfil)
    assert payload.services[0].banner == "v999.0.0.1"
