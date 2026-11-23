"""Orquestador: une generador, verificador y desplegador en modo simulación (S12).

`run_campaign_simulation` genera la campaña (S6), la verifica contra una secuencia de
huellas candidatas del señuelo —el bucle de ajuste de H4— parando en la primera que supera
el umbral de plausibilidad o, si ninguna lo hace, cuando se agotan los intentos, y
construye el plan de despliegue (S9) en modo simulación, sin aprobar.

Cómo se genera cada huella candidata sucesiva (ajustar el señuelo determinista o pedirle al
LLM una variación) es responsabilidad de quien llama, no de esta función: aquí solo se
decide cuándo parar de intentarlo. Perfilar un host de verdad (L1, ya implementado y
validado contra el laboratorio) y escanear el señuelo de verdad (L2) son las piezas que
producirán esas huellas cuando haya laboratorio; esta sesión no las ejecuta.

Todavía no hay un `main()` de línea de comandos que ate esto a entradas reales: montarlo
tiene sentido cuando también exista la ejecución real de nmap (fuera del alcance descrito
para S12), para no dejar subcomandos que no hacen nada de verdad.
"""

import json
from collections.abc import Awaitable, Callable, Iterable
from ipaddress import IPv4Address
from typing import Literal

from pydantic import BaseModel, ConfigDict

from securization.desplegador import DeploymentPlan, build_deployment_plan
from securization.generador import Campaign, DecoyConfig, adjust_decoy, build_campaign
from securization.modelos import Fingerprint, HostProfile, PlausibilityReport
from securization.verificador import DEFAULT_THRESHOLD, verify_decoy


class SimulationResult(BaseModel):
    """Resultado de simular una campaña: la campaña, el informe final y el plan."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign: Campaign
    report: PlausibilityReport
    attempts: int
    plan: DeploymentPlan


def run_campaign_simulation(
    profile: HostProfile,
    real_fingerprint: Fingerprint,
    *,
    campaign_id: str,
    decoy_node_id: str,
    decoy_address: IPv4Address,
    decoy_fingerprints: Iterable[Fingerprint],
    home_dir: str,
    threshold: int = DEFAULT_THRESHOLD,
    known_paths: Iterable[str] = (),
) -> SimulationResult:
    """Genera la campaña y la verifica contra sucesivas huellas candidatas del señuelo.

    Para en la primera huella cuyo informe supere el umbral; si ninguna lo supera, el
    resultado usa el informe de la última huella intentada. El plan de despliegue siempre
    se construye (para poder revisarlo), nunca se aprueba aquí.
    """
    campaign = build_campaign(
        profile,
        campaign_id=campaign_id,
        decoy_node_id=decoy_node_id,
        decoy_address=decoy_address,
        home_dir=home_dir,
        known_paths=known_paths,
    )

    report: PlausibilityReport | None = None
    intentos = 0
    for huella_senuelo in decoy_fingerprints:
        intentos += 1
        report = verify_decoy(real_fingerprint, huella_senuelo, threshold=threshold)
        if report.passed:
            break
    if report is None:
        raise ValueError(f"{campaign_id}: no se ha dado ninguna huella candidata del señuelo")

    plan = build_deployment_plan(campaign, report, known_paths=known_paths)
    return SimulationResult(campaign=campaign, report=report, attempts=intentos, plan=plan)


# --- Bucle cerrado de verificación con el laboratorio (H4) ------------------------

DecoyStarter = Callable[[DecoyConfig], Awaitable[object]]
DecoyScanner = Callable[[DecoyConfig], Awaitable[Fingerprint]]
StopReason = Literal["aprobado", "sin_ajustes", "config_repetido", "max_intentos"]


class VerificationAttempt(BaseModel):
    """Un intento del bucle: el config probado y su informe de plausibilidad."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    attempt: int
    opencanary_config: dict[str, bool | int | str]
    report: PlausibilityReport


class VerificationResult(BaseModel):
    """Resultado del bucle: la campaña con el último señuelo probado y cada intento."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign: Campaign
    report: PlausibilityReport
    attempts: list[VerificationAttempt]
    stop_reason: StopReason


def _config_key(decoy: DecoyConfig) -> str:
    return json.dumps(decoy.opencanary_config, sort_keys=True)


async def run_verification_loop(
    profile: HostProfile,
    real_fingerprint: Fingerprint,
    campaign: Campaign,
    *,
    start: DecoyStarter,
    scan: DecoyScanner,
    threshold: int = DEFAULT_THRESHOLD,
    max_attempts: int = 3,
) -> VerificationResult:
    """Arranca el señuelo, lo escanea, lo puntúa y lo ajusta hasta que es plausible.

    Para cuando supera el umbral, cuando `adjust_decoy` no propone nada, cuando el ajuste
    repetiría un config ya probado o al llegar a `max_attempts`. El señuelo solo se
    arranca para escanearlo en el laboratorio (`start_decoy`, excepción de CLAUDE.md); el
    despliegue definitivo sigue exigiendo el plan aprobado. Los breadcrumbs no cambian:
    el ajuste nunca altera qué servicios ofrece el señuelo.
    """
    if max_attempts < 1:
        raise ValueError(f"max_attempts debe ser al menos 1: {max_attempts}")
    decoy = campaign.decoy
    probados: set[str] = set()
    intentos: list[VerificationAttempt] = []
    motivo: StopReason = "max_intentos"
    for numero in range(1, max_attempts + 1):
        probados.add(_config_key(decoy))
        await start(decoy)
        informe = verify_decoy(real_fingerprint, await scan(decoy), threshold=threshold)
        intentos.append(
            VerificationAttempt(
                attempt=numero, opencanary_config=dict(decoy.opencanary_config), report=informe
            )
        )
        if informe.passed:
            motivo = "aprobado"
            break
        siguiente = adjust_decoy(profile, decoy, real_fingerprint)
        if siguiente is None:
            motivo = "sin_ajustes"
            break
        if _config_key(siguiente) in probados:
            motivo = "config_repetido"
            break
        if numero < max_attempts:
            decoy = siguiente
    return VerificationResult(
        campaign=campaign.model_copy(update={"decoy": decoy}),
        report=intentos[-1].report,
        attempts=intentos,
        stop_reason=motivo,
    )
