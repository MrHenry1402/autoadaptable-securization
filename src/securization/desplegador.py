"""Plantado de breadcrumbs por SFTP y arranque de deception hosts en contenedores.

La sesión S9 cubre solo la parte sin E/S: construir un `DeploymentPlan` a partir de una
`Campaign` ya generada (S6) y de su `PlausibilityReport` (S7), en modo simulación. El
plantado real por SFTP y el arranque de contenedores (L4) quedan para cuando haya
laboratorio; este módulo todavía no toca ningún host real.

Nunca se sobrescribe un fichero existente: `build_deployment_plan` comprueba colisiones
de ruta (contra el perfil real del host o contra lo ya plantado por una campaña anterior)
antes de devolver el plan. Ningún señuelo se despliega sin superar el umbral de
plausibilidad (S7) ni sin aprobación manual explícita del operador: `approve_plan` es la
única forma de marcar un plan como aprobado, y solo lo permite si la puntuación superó el
umbral.
"""

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine
from sqlmodel import Field as SqlField
from sqlmodel import Session, SQLModel, select

from securization.generador import Campaign, check_collisions
from securization.modelos import PlausibilityReport


class PlausibilityThresholdError(Exception):
    """El informe de plausibilidad no supera el umbral: el plan no se puede aprobar."""


class DeploymentPlanNotFoundError(Exception):
    """No hay un plan de despliegue guardado con ese `campaign_id`."""


class DeploymentAction(BaseModel):
    """Una acción concreta del plan: plantar un breadcrumb en una ruta."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str
    content: str
    mode: int


class DeploymentPlan(BaseModel):
    """Plan de despliegue de una campaña, en modo simulación hasta que se aprueba a mano."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    host_id: str
    actions: list[DeploymentAction]
    plausibility_score: int
    plausibility_threshold: int
    differences: list[str] = Field(default_factory=list)
    approved: bool = False

    @property
    def ready_to_deploy(self) -> bool:
        """Listo para desplegar solo si está aprobado y superó el umbral de plausibilidad."""
        return self.approved and self.plausibility_score >= self.plausibility_threshold


def build_deployment_plan(
    campaign: Campaign,
    plausibility: PlausibilityReport,
    known_paths: Iterable[str] = (),
) -> DeploymentPlan:
    """Construye el plan de despliegue de una campaña, sin tocar nada real todavía.

    Comprueba colisiones de ruta antes de devolver el plan, para que nunca se llegue a
    aprobar uno que sobrescribiría un fichero existente. El plan se crea siempre sin
    aprobar, aunque el señuelo ya supere el umbral: eso permite revisarlo antes de decidir.
    """
    check_collisions(campaign.breadcrumbs, known_paths)
    actions = [
        DeploymentAction(path=breadcrumb.path, content=breadcrumb.content, mode=breadcrumb.mode)
        for breadcrumb in campaign.breadcrumbs
    ]
    return DeploymentPlan(
        campaign_id=campaign.campaign_id,
        host_id=campaign.host_id,
        actions=actions,
        plausibility_score=plausibility.score,
        plausibility_threshold=plausibility.threshold,
        differences=plausibility.differences,
    )


def approve_plan(plan: DeploymentPlan) -> DeploymentPlan:
    """Aprueba el plan a mano; falla si el señuelo no superó el umbral de plausibilidad."""
    if plan.plausibility_score < plan.plausibility_threshold:
        raise PlausibilityThresholdError(
            f"{plan.campaign_id}: puntuación {plan.plausibility_score} por debajo del "
            f"umbral {plan.plausibility_threshold}, no se puede aprobar"
        )
    return plan.model_copy(update={"approved": True})


class _DeploymentPlanRecord(SQLModel, table=True):
    """Fila con el `DeploymentPlan` completo, serializado en JSON."""

    __tablename__ = "deployment_plan"

    campaign_id: str = SqlField(primary_key=True)
    plan_json: str


class DeploymentPlanStore:
    """Guarda y recupera planes de despliegue en la base de datos, para el dashboard (S13)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        SQLModel.metadata.create_all(engine)

    def save(self, plan: DeploymentPlan) -> None:
        """Guarda el plan; si ya había uno con ese `campaign_id`, lo sustituye."""
        payload = plan.model_dump_json()
        with Session(self._engine) as session:
            registro = session.get(_DeploymentPlanRecord, plan.campaign_id)
            if registro is None:
                registro = _DeploymentPlanRecord(campaign_id=plan.campaign_id, plan_json=payload)
            else:
                registro.plan_json = payload
            session.add(registro)
            session.commit()

    def load(self, campaign_id: str) -> DeploymentPlan:
        """Recupera el plan guardado o falla con un error claro."""
        with Session(self._engine) as session:
            registro = session.get(_DeploymentPlanRecord, campaign_id)
        if registro is None:
            raise DeploymentPlanNotFoundError(campaign_id)
        return DeploymentPlan.model_validate_json(registro.plan_json)

    def list_all(self) -> list[DeploymentPlan]:
        """Todos los planes de despliegue guardados."""
        with Session(self._engine) as session:
            registros = session.exec(select(_DeploymentPlanRecord)).all()
        return [DeploymentPlan.model_validate_json(registro.plan_json) for registro in registros]
