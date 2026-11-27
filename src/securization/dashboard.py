"""Dashboard (S13, rediseñado para un público no técnico): FastAPI + Jinja2 + HTMX.

- Inicio: qué hace la herramienta, en qué paso está, el mapa de la red en directo y las
  últimas alertas contadas en lenguaje llano (`presentacion.py`).
- Equipos, trampas (campañas) y alertas, con el bucle de verificación y la aprobación manual,
  que sigue pasando por `desplegador.approve_plan` y su umbral.
- Acciones con barra de progreso: analizar un equipo, crear su trampa, desplegarla y recoger
  alertas. Son las mismas operaciones deterministas de la CLI (`operaciones.py`) ejecutadas en
  segundo plano; el navegador consulta su progreso cada segundo. Solo están disponibles si se
  arranca con un `entorno` (la CLI lo pasa únicamente cuando escucha en local) y desplegar
  sigue exigiendo el plan aprobado.
"""

from collections.abc import Awaitable, Callable
from html import escape
from ipaddress import AddressValueError, IPv4Address
from pathlib import Path
from urllib.parse import parse_qs

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
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
from securization.operaciones import (
    Entorno,
    Trabajo,
    Trabajos,
    crear_campana,
    desplegar,
    perfilar,
    recoger_alertas,
)
from securization.orquestador import VerificationResultStore
from securization.perfilador import HostProfileStore, ProfileNotFoundError
from securization.presentacion import (
    MapaRed,
    construir_mapa,
    describir_alerta,
    estado_trampa,
    nombre_servicio,
    pasos_flujo,
)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app(
    engine: Engine,
    vault: CredentialVault,
    *,
    entorno: Entorno | None = None,
    ips_propias: frozenset[str] = frozenset(),
) -> FastAPI:
    """Construye la app del dashboard; con `entorno` además permite lanzar operaciones.

    `ips_propias` son las direcciones desde las que la propia herramienta escanea sus trampas:
    sus alertas se presentan como comprobaciones, no como intrusos.
    """
    inventory = Inventory(engine, vault)
    profiles = HostProfileStore(engine)
    campaigns = CampaignStore(engine)
    plans = DeploymentPlanStore(engine)
    events_store = EventStore(engine)
    verifications = VerificationResultStore(engine)
    trabajos = Trabajos()
    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    templates.env.globals.update(
        describir_alerta=lambda evento: describir_alerta(evento, ips_propias),
        estado_trampa=estado_trampa,
        nombre_servicio=nombre_servicio,
        acciones=entorno is not None,
    )
    host_senuelos = entorno.deception_host if entorno is not None else "deception-central"

    app = FastAPI(title="securization - dashboard")

    def _requiere_entorno() -> Entorno:
        if entorno is None:
            raise RuntimeError("acciones desactivadas: dashboard en modo solo lectura")
        return entorno

    def _mapa() -> MapaRed:
        return construir_mapa(
            inventory.list_hosts(),
            campaigns.list_all(),
            events_store.list_recent(limit=500),
            host_senuelos=host_senuelos,
            ips_propias=ips_propias,
        )

    def _perfilados() -> int:
        total = 0
        for host in inventory.list_hosts():
            try:
                profiles.load(host.host_id)
            except ProfileNotFoundError:
                continue
            total += 1
        return total

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request) -> HTMLResponse:
        plan_list = plans.list_all()
        pendientes = [plan for plan in plan_list if not plan.approved]
        total_events = sum(events_store.count_by_campaign().values())
        return templates.TemplateResponse(
            request,
            "overview.html",
            {
                "total_hosts": len(inventory.list_hosts()),
                "total_campaigns": len(plan_list),
                "total_pending": len(pendientes),
                "total_events": total_events,
                "total_breadcrumb_uses": sum(events_store.count_breadcrumb_uses().values()),
                "pasos": pasos_flujo(
                    equipos=len(inventory.list_hosts()),
                    perfilados=_perfilados(),
                    campanas=len(plan_list),
                    aprobadas=sum(1 for p in plan_list if p.approved),
                    alertas=total_events,
                ),
                "mapa": _mapa(),
                "ultimas": events_store.list_recent(limit=5),
                "trabajos": trabajos.en_curso(),
            },
        )

    @app.get("/mapa", response_class=HTMLResponse)
    def mapa(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "_mapa.html", {"mapa": _mapa()})

    @app.get("/ayuda", response_class=HTMLResponse)
    def ayuda(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(request, "ayuda.html", {})

    @app.get("/hosts", response_class=HTMLResponse)
    def hosts_list(request: Request) -> HTMLResponse:
        hosts = inventory.list_hosts()
        perfilados = set()
        for host in hosts:
            try:
                profiles.load(host.host_id)
                perfilados.add(host.host_id)
            except ProfileNotFoundError:
                pass
        return templates.TemplateResponse(
            request,
            "hosts.html",
            {"hosts": hosts, "perfilados": perfilados, "host_senuelos": host_senuelos},
        )

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
        sugerida = str(profile.free_ips[0]) if profile and profile.free_ips else ""
        return templates.TemplateResponse(
            request,
            "host_detail.html",
            {
                "host": host,
                "profile": profile,
                "es_host_senuelos": host_id == host_senuelos,
                "nodo_sugerido": f"{host_id}-bak",
                "ip_sugerida": sugerida,
            },
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

    def _detalle(request: Request, plan: DeploymentPlan, error: str | None) -> HTMLResponse:
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

    @app.get("/campaigns/{campaign_id}", response_class=HTMLResponse)
    def campaign_detail(request: Request, campaign_id: str) -> HTMLResponse:
        return _detalle(request, _load_plan_or_404(campaign_id), None)

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
        return _detalle(request, plan, error)

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

    # --- Acciones con barra de progreso ----------------------------------------------

    def _error(mensaje: str, estado: int) -> HTMLResponse:
        return HTMLResponse(f'<p class="error">{escape(mensaje)}</p>', status_code=estado)

    def _fragmento(request: Request, trabajo: Trabajo) -> HTMLResponse:
        return templates.TemplateResponse(request, "_trabajo.html", {"t": trabajo})

    def _lanzar(
        request: Request,
        tareas: BackgroundTasks,
        titulo: str,
        operacion: Callable[[Trabajo], Awaitable[None]],
    ) -> HTMLResponse:
        if entorno is None:
            return _error(
                "Este dashboard está en modo solo lectura: las acciones solo se permiten "
                "cuando escucha en local (o con securization dashboard --acciones).",
                403,
            )
        trabajo = trabajos.nuevo(titulo)

        async def ejecutar() -> None:
            try:
                await operacion(trabajo)
            except Exception as error:  # se enseña al operador, no se oculta
                trabajo.fallar(f"No se ha podido completar: {error}")

        tareas.add_task(ejecutar)
        return _fragmento(request, trabajo)

    @app.get("/trabajos/{trabajo_id}", response_class=HTMLResponse)
    def trabajo(request: Request, trabajo_id: str) -> HTMLResponse:
        encontrado = trabajos.get(trabajo_id)
        if encontrado is None:
            raise HTTPException(404, "trabajo no encontrado")
        return _fragmento(request, encontrado)

    @app.post("/acciones/perfilar/{host_id}", response_class=HTMLResponse)
    def accion_perfilar(request: Request, tareas: BackgroundTasks, host_id: str) -> HTMLResponse:
        async def op(t: Trabajo) -> None:
            perfil = await perfilar(_requiere_entorno(), host_id, t.informar)
            t.terminar(f"Análisis terminado: {perfil.os_name}", f"/hosts/{host_id}")

        return _lanzar(request, tareas, f"Analizando {host_id}", op)

    @app.post("/acciones/campana/{host_id}", response_class=HTMLResponse)
    async def accion_campana(
        request: Request, tareas: BackgroundTasks, host_id: str
    ) -> HTMLResponse:
        # Formulario urlencoded leído con la biblioteca estándar (sin python-multipart).
        datos = parse_qs((await request.body()).decode("utf-8"))
        decoy_node = datos.get("decoy_node", [""])[0]
        decoy_ip = datos.get("decoy_ip", [""])[0]
        try:
            ip = IPv4Address(decoy_ip.strip())
        except AddressValueError:
            return _error(f"«{decoy_ip}» no es una dirección IP válida.", 400)

        async def op(t: Trabajo) -> None:
            r = await crear_campana(
                _requiere_entorno(),
                host_id,
                decoy_node=decoy_node.strip(),
                decoy_ip=ip,
                informe=t.informar,
            )
            t.terminar(
                f"Trampa creada: se parece {r.plan.plausibility_score}/"
                f"{r.plan.plausibility_threshold} al equipo real. Revísala y apruébala.",
                f"/campaigns/{r.plan.campaign_id}",
            )

        return _lanzar(request, tareas, f"Creando la trampa de {host_id}", op)

    @app.post("/acciones/desplegar/{campaign_id}", response_class=HTMLResponse)
    def accion_desplegar(
        request: Request, tareas: BackgroundTasks, campaign_id: str
    ) -> HTMLResponse:
        _load_plan_or_404(campaign_id)

        async def op(t: Trabajo) -> None:
            nombre = await desplegar(_requiere_entorno(), campaign_id, t.informar)
            t.terminar(f"La trampa {nombre} ya está en la red y vigilando.", "/events")

        return _lanzar(request, tareas, f"Desplegando {campaign_id}", op)

    @app.post("/acciones/alertas", response_class=HTMLResponse)
    def accion_alertas(request: Request, tareas: BackgroundTasks) -> HTMLResponse:
        async def op(t: Trabajo) -> None:
            nuevas = await recoger_alertas(_requiere_entorno(), t.informar)
            t.terminar(f"{sum(nuevas.values())} alertas nuevas recogidas.", "/events")

        return _lanzar(request, tareas, "Recogiendo alertas de las trampas", op)

    return app
