"""Tests de la propuesta de hostname del señuelo (componente de IA: identidad del señuelo).

El LLM solo propone texto; nunca decide a qué host conectarse ni ejecuta nada. Si falla o su
salida no valida, se usa la plantilla de respaldo determinista, marcada como menor calidad.
"""

import json

from securization.generador import DecoyIdentity, propose_decoy_hostname
from securization.modelos import GenerationQuality, HostProfile, OsFamily, ServiceInfo

PERFIL = HostProfile(
    host_id="victima-01",
    address="10.0.0.10",
    os_family=OsFamily.LINUX,
    os_name="Debian GNU/Linux 12 (bookworm)",
    services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.2p1")],
)


class FakeLlmClient:
    def __init__(self, respuesta: str = "", *, error: Exception | None = None) -> None:
        self._respuesta = respuesta
        self._error = error
        self.prompts: list[str] = []

    async def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self._error is not None:
            raise self._error
        return self._respuesta


async def test_usa_el_hostname_propuesto_por_el_llm_si_valida() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"hostname": "SRV-MAD-03"}))
    identidad, calidad = await propose_decoy_hostname(PERFIL, cliente)
    assert identidad == DecoyIdentity(hostname="SRV-MAD-03")
    assert calidad is GenerationQuality.AI


async def test_cae_en_la_plantilla_de_respaldo_si_el_llm_falla() -> None:
    from securization.llm import LlmError

    cliente = FakeLlmClient(error=LlmError("sin respuesta"))
    identidad, calidad = await propose_decoy_hostname(PERFIL, cliente)
    assert identidad == DecoyIdentity(hostname="victima-01-decoy")
    assert calidad is GenerationQuality.FALLBACK


async def test_cae_en_la_plantilla_de_respaldo_si_la_salida_no_valida() -> None:
    cliente = FakeLlmClient(respuesta="no es json")
    identidad, calidad = await propose_decoy_hostname(PERFIL, cliente)
    assert identidad == DecoyIdentity(hostname="victima-01-decoy")
    assert calidad is GenerationQuality.FALLBACK


async def test_el_prompt_no_lleva_la_ip_real_en_claro() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"hostname": "x"}))
    await propose_decoy_hostname(PERFIL, cliente)
    (prompt,) = cliente.prompts
    assert "10.0.0.10" not in prompt
    assert "IP_1" in prompt


async def test_el_prompt_incluye_el_host_id_y_el_so_para_inferir_la_convencion() -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"hostname": "x"}))
    await propose_decoy_hostname(PERFIL, cliente)
    (prompt,) = cliente.prompts
    assert "victima-01" in prompt
    assert "Debian GNU/Linux 12 (bookworm)" in prompt


async def test_el_prompt_no_contiene_caracteres_de_control() -> None:
    perfil = PERFIL.model_copy(update={"os_name": "Debian\x1b[31m 12"})
    cliente = FakeLlmClient(respuesta=json.dumps({"hostname": "x"}))
    await propose_decoy_hostname(perfil, cliente)
    (prompt,) = cliente.prompts
    assert "\x1b" not in prompt


def test_decoy_identity_rechaza_campos_extra() -> None:
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        DecoyIdentity.model_validate({"hostname": "x", "extra": "no"})


# --- Validez del hostname propuesto (L5) ---------------------------------------------
# Una salida "válida" tiene que ser un hostname utilizable: si no, la tasa de salidas
# válidas del modelo no mediría nada.

import pytest  # noqa: E402


@pytest.mark.parametrize(
    "propuesto",
    ["srv mad 03", "srv;rm -rf", "-srv", "srv-", "a" * 64, "", "srv.example.com", "srv_01"],
)
async def test_hostname_no_valido_cae_en_el_respaldo(propuesto: str) -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"hostname": propuesto}))
    identidad, calidad = await propose_decoy_hostname(PERFIL, cliente)
    assert identidad == DecoyIdentity(hostname="victima-01-decoy")
    assert calidad is GenerationQuality.FALLBACK


@pytest.mark.parametrize("propuesto", ["victima-01", "VICTIMA-01"])
async def test_hostname_que_copia_el_del_host_real_cae_en_el_respaldo(propuesto: str) -> None:
    cliente = FakeLlmClient(respuesta=json.dumps({"hostname": propuesto}))
    identidad, calidad = await propose_decoy_hostname(PERFIL, cliente)
    assert calidad is GenerationQuality.FALLBACK
    assert identidad.hostname == "victima-01-decoy"


async def test_hostname_valido_de_un_solo_caracter_y_maximo_largo() -> None:
    for propuesto in ("x", "a" * 63, "db-02"):
        cliente = FakeLlmClient(respuesta=json.dumps({"hostname": propuesto}))
        identidad, calidad = await propose_decoy_hostname(PERFIL, cliente)
        assert (identidad.hostname, calidad) == (propuesto, GenerationQuality.AI)
