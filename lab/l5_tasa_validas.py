"""L5: tasa de salidas válidas de modelos locales (Ollama) en la propuesta de hostname.

Uso: python lab/l5_tasa_validas.py [modelos separados por comas] [N]
     (desde la raíz; por defecto qwen3:8b,qwen3:14b y 25 semillas por víctima)

Requiere el código de L5, Ollama en local con los modelos descargados y los perfiles de
las víctimas en inventario.db. Comprueba además que ninguna IP del laboratorio llega en
claro al prompt. Guarda el resultado en lab/l5_resultado.json.
"""

import asyncio
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

from pydantic import ValidationError
from sqlmodel import create_engine

from securization.generador import DecoyIdentity, propose_decoy_hostname
from securization.llm import LlmError, OllamaClient
from securization.modelos import GenerationQuality
from securization.perfilador import HostProfileStore

MODELOS = sys.argv[1].split(",") if len(sys.argv) > 1 else ["qwen3:8b", "qwen3:14b"]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 25
IP_RE = re.compile(r"\b10\.0\.0\.\d+\b")


class Registro:
    """Envuelve el cliente para guardar prompt, respuesta cruda y latencia."""

    def __init__(self, cliente: OllamaClient) -> None:
        self.cliente = cliente
        self.prompt = ""
        self.crudo: str | None = None
        self.error: str | None = None
        self.segundos = 0.0

    async def complete(self, prompt: str) -> str:
        self.prompt, inicio = prompt, time.perf_counter()
        try:
            self.crudo = await self.cliente.complete(prompt)
            return self.crudo
        except LlmError as error:
            self.error = str(error)
            raise
        finally:
            self.segundos = time.perf_counter() - inicio


def motivo(reg: Registro, host_id: str) -> str:
    if reg.error is not None:
        return "error_ollama"
    try:
        datos = json.loads(reg.crudo or "")
    except json.JSONDecodeError:
        return "json_invalido"
    try:
        identidad = DecoyIdentity.model_validate(datos)
    except ValidationError:
        return "esquema"
    if identidad.hostname.lower() == host_id.lower():
        return "copia_host_id"
    return "delata_engano"


async def main() -> None:
    store = HostProfileStore(create_engine(f"sqlite:///{Path.cwd() / 'inventario.db'}"))
    perfiles = [store.load("victima-01"), store.load("victima-02")]
    resultados = {}
    for modelo in MODELOS:
        for perfil in perfiles:
            validas, fallos, nombres, tiempos = 0, Counter(), Counter(), []
            for semilla in range(1, N + 1):
                reg = Registro(OllamaClient(modelo, seed=semilla, temperature=0.7))
                identidad, calidad = await propose_decoy_hostname(perfil, reg)
                if IP_RE.search(reg.prompt):
                    raise SystemExit("IP real del laboratorio en el prompt")
                tiempos.append(reg.segundos)
                if calidad is GenerationQuality.AI:
                    validas += 1
                    nombres[identidad.hostname] += 1
                else:
                    fallos[motivo(reg, perfil.host_id)] += 1
            clave = f"{modelo} / {perfil.host_id}"
            resultados[clave] = {
                "validas": f"{validas}/{N}",
                "tasa": round(validas / N, 3),
                "fallos": dict(fallos),
                "nombres_distintos": len(nombres),
                "mas_frecuentes": nombres.most_common(5),
                "latencia_media_s": round(sum(tiempos[1:]) / max(1, len(tiempos) - 1), 2),
            }
            print(clave, json.dumps(resultados[clave], ensure_ascii=False), flush=True)
    salida = Path(__file__).parent / "l5_resultado.json"  # junto al script
    salida.write_text(json.dumps(resultados, indent=2, ensure_ascii=False), encoding="utf-8")


asyncio.run(main())
