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

from collections.abc import Iterable
from ipaddress import IPv4Address

from pydantic import BaseModel, ConfigDict

from securization.desplegador import DeploymentPlan, build_deployment_plan
from securization.generador import Campaign, build_campaign
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
