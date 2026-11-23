"""Dashboard mínimo (S13): FastAPI + Jinja2 + HTMX.

Cubre inventario, campañas, puntuaciones de plausibilidad, eventos y aprobación manual de
despliegues. No ejecuta nada sobre hosts reales: solo lee lo que ya guardaron el inventario
(`inventario.py`), el perfilador (`perfilador.py`) y el generador/desplegador
(`generador.py`/`desplegador.py`), y aprueba planes a través de `desplegador.approve_plan`,
que ya impone el umbral de plausibilidad.

La pestaña de eventos muestra las alertas reales de los señuelos que securization events
recoge de OpenCanary (H6), ya correlacionadas con su campaña y con el breadcrumb usado. El
detalle de campaña muestra los intentos del bucle de verificación (H2 frente a H4).
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import Engine

from securization.desplegador import (
    DeploymentPlan,
    DeploymentPlanNotFoundError,
    DeploymentPlanStore,
    PlausibilityThresholdError,
    approve_plan,
)
from securization.eventos import EventStore
from securization.generador import Campaign, CampaignNotFoundError, CampaignStore
from securization.inventario import CredentialVault, HostNotFoundError, Inventory
from securization.orquestador import VerificationResultStore
from securization.perfilador import HostProfileStore, ProfileNotFoundError

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app(engine: Engine, vault: CredentialVault) -> FastAPI:
    """Construye la app del dashboard sobre el `Engine` y el `CredentialVault` dados."""
    inventory = Inventory(engine, vault)
    profiles = HostProfileStore(engine)
    campaigns = CampaignStore(engine)
    plans = DeploymentPlanStore(engine)
    events_store = EventStore(engine)
    verifications = VerificationResultStore(engine)
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    app = FastAPI(title="securization - dashboard")

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request) -> HTMLResponse:
        plan_list = plans.list_all()
        pendientes = [plan for plan in plan_list if not plan.approved]
        return templates.TemplateResponse(
            request,
            "overview.html",
            {
                "total_hosts": len(inventory.list_hosts()),
                "total_campaigns": len(plan_list),
                "total_pending": len(pendientes),
                "total_events": sum(events_store.count_by_campaign().values()),
                "total_breadcrumb_uses": sum(events_store.count_breadcrumb_uses().values()),
            },
        )

    @app.get("/hosts", response_class=HTMLResponse)
    def hosts_list(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "hosts.html", {"hosts": inventory.list_hosts()})

    @app.get("/hosts/{host_id}", response_class=HTMLResponse)
    def host_detail(request: Request, host_id: str) -> HTMLResponse:
        try:
            host = inventory.get_host(host_id)
        except HostNotFoundError:
            raise HTTPException(404, f"host no registrado: {host_id}") from None
        try:
            profile = profiles.load(host_id)
        except ProfileNotFoundError:
            profile = None
        return templates.TemplateResponse(
            request, "host_detail.html", {"host": host, "profile": profile}
        )

    @app.get("/campaigns", response_class=HTMLResponse)
    def campaigns_list(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "campaigns.html", {"plans": plans.list_all()})

    def _load_plan_or_404(campaign_id: str) -> DeploymentPlan:
        try:
            return plans.load(campaign_id)
        except DeploymentPlanNotFoundError:
            raise HTTPException(404, f"campaña no encontrada: {campaign_id}") from None

    def _campaign_or_none(campaign_id: str) -> Campaign | None:
        try:
            return campaigns.load(campaign_id)
        except CampaignNotFoundError:
            return None

    @app.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
    def campaign_detail(request: Request, campaign_id: str) -> HTMLResponse:
        plan = _load_plan_or_404(campaign_id)
        return templates.TemplateResponse(
            request,
            "campaign_detail.html",
            {
                "plan": plan,
                "campaign": _campaign_or_none(plan.campaign_id),
                "verification": verifications.get(plan.campaign_id),
                "error": None,
            },
        )

    @app.post("/campaigns/{campaign_id}/approve", response_class=HTMLResponse)
    def approve(request: Request, campaign_id: str) -> HTMLResponse:
        plan = _load_plan_or_404(campaign_id)
        error: str | None = None
        try:
            plan = approve_plan(plan)
        except PlausibilityThresholdError as exc:
            error = str(exc)
        else:
            plans.save(plan)
        return templates.TemplateResponse(
            request,
            "campaign_detail.html",
            {
                "plan": plan,
                "campaign": _campaign_or_none(plan.campaign_id),
                "verification": verifications.get(plan.campaign_id),
                "error": error,
            },
        )

    @app.get("/events", response_class=HTMLResponse)
    def events(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "events.html",
            {
                "events": events_store.list_recent(),
                "by_campaign": events_store.count_by_campaign(),
                "breadcrumb_uses": events_store.count_breadcrumb_uses(),
            },
        )

    return app
