"""Presentación para personas sin conocimientos técnicos (dashboard).

Funciones puras: traducen los datos de la herramienta (alertas de OpenCanary, planes de
despliegue, inventario) a lenguaje llano y construyen el diagrama de la red que dibuja el
dashboard. No hacen E/S ni deciden nada: solo describen lo que ya está guardado.
"""

from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from securization.desplegador import DeploymentPlan
from securization.eventos import CollectedEvent
from securization.generador import Campaign
from securization.inventario import Host

Gravedad = Literal["alta", "media", "baja", "propia"]

# logtype de OpenCanary → (qué ha pasado, gravedad si no hay breadcrumb de por medio)
_TIPOS: dict[int, tuple[str, Gravedad]] = {
    2000: ("Intento de entrar por FTP (transferencia de ficheros)", "media"),
    3000: ("Visita a la página web de la trampa", "baja"),
    3001: ("Intento de iniciar sesión en la web de la trampa", "media"),
    4000: ("Conexión al servicio SSH (acceso remoto) de la trampa", "baja"),
    4001: ("Un programa se ha identificado ante el SSH de la trampa", "baja"),
    4002: ("Intento de iniciar sesión por SSH (acceso remoto)", "media"),
    8001: ("Intento de entrar en la base de datos MySQL", "media"),
    17001: ("Orden enviada a la base de datos Redis", "baja"),
}

_SERVICIOS = {"ftp": "FTP", "http": "la web", "ssh": "SSH", "mysql": "MySQL", "redis": "Redis"}


_NOMBRES_SERVICIO = {
    "ssh": "Acceso remoto (SSH)",
    "http": "Página web",
    "https": "Página web segura",
    "mysql": "Base de datos MySQL / MariaDB",
    "ftp": "Transferencia de ficheros (FTP)",
    "redis": "Base de datos Redis",
}


def nombre_servicio(nombre: str) -> str:
    """Nombre de un servicio de red en lenguaje llano (el técnico si no se conoce)."""
    return _NOMBRES_SERVICIO.get(nombre.lower(), nombre)


@dataclass(frozen=True)
class AlertaLegible:
    """Una alerta contada en lenguaje llano."""

    titulo: str
    detalle: str
    gravedad: Gravedad


def describir_alerta(evento: CollectedEvent, ips_propias: Collection[str] = ()) -> AlertaLegible:
    """Traduce una alerta de OpenCanary a una frase que entienda cualquiera.

    Las que vienen de la propia herramienta (`ips_propias`: los escaneos con los que comprueba
    sus trampas) se cuentan como lo que son, no como un posible intruso.
    """
    if evento.src_host in ips_propias:
        return AlertaLegible(
            titulo="Comprobación de la propia herramienta",
            detalle=(
                f"La herramienta ({evento.src_host}) ha escaneado la trampa {evento.node_id} para "
                "verificar que se parece al equipo real. No es un intruso."
            ),
            gravedad="propia",
        )
    if evento.breadcrumb_service:
        servicio = _SERVICIOS.get(evento.breadcrumb_service, evento.breadcrumb_service)
        return AlertaLegible(
            titulo=f"¡Ha usado una contraseña-cebo contra {servicio}!",
            detalle=(
                f"Alguien desde {evento.src_host} ha usado una credencial falsa que solo existía "
                f"en un fichero cebo de {evento.host_id}: es casi seguro un atacante que ya ha "
                "entrado en ese equipo."
            ),
            gravedad="alta",
        )
    titulo, gravedad = _TIPOS.get(
        evento.logtype, (f"Actividad en la trampa (tipo {evento.logtype})", "baja")
    )
    return AlertaLegible(
        titulo=titulo,
        detalle=(
            f"Desde {evento.src_host} contra la trampa {evento.node_id} "
            f"(puerto {evento.dst_port}). Nadie legítimo debería tocar una trampa."
        ),
        gravedad=gravedad,
    )


@dataclass(frozen=True)
class EstadoTrampa:
    """Estado de una campaña explicado en palabras."""

    texto: str
    clase: Literal["ok", "pendiente", "mal"]
    explicacion: str


def estado_trampa(plan: DeploymentPlan) -> EstadoTrampa:
    """Explica en qué punto está una campaña y qué falta para desplegarla."""
    if plan.deployed_at is not None:
        return EstadoTrampa(
            "Desplegada y vigilando",
            "ok",
            f"En la red desde el {plan.deployed_at:%d/%m/%Y a las %H:%M} (UTC); los cebos ya están "
            f"en {plan.host_id}.",
        )
    if plan.ready_to_deploy:
        return EstadoTrampa("Aprobada", "ok", "Lista para desplegar (o ya desplegada) en la red.")
    if plan.approved:
        return EstadoTrampa(
            "Aprobada sin nota suficiente", "mal", "No se desplegará: no supera el umbral."
        )
    if plan.plausibility_score >= plan.plausibility_threshold:
        return EstadoTrampa(
            "Esperando tu aprobación",
            "pendiente",
            "La trampa ya se parece lo bastante al equipo real; revísala y apruébala.",
        )
    return EstadoTrampa(
        "Se distingue del equipo real",
        "mal",
        "Un atacante podría notar que es una trampa; no se puede desplegar.",
    )


# --- Diagrama de la red ----------------------------------------------------------------

TipoNodo = Literal["herramienta", "real", "trampas", "senuelo", "atacante"]
TipoEnlace = Literal["gestion", "cebo", "ataque", "comprobacion"]


@dataclass(frozen=True)
class Nodo:
    id: str
    etiqueta: str
    detalle: str
    tipo: TipoNodo
    x: int
    y: int


@dataclass(frozen=True)
class Enlace:
    origen: str
    destino: str
    tipo: TipoEnlace
    etiqueta: str


@dataclass(frozen=True)
class MapaRed:
    ancho: int
    alto: int
    nodos: list[Nodo] = field(default_factory=list)
    enlaces: list[Enlace] = field(default_factory=list)

    def nodo(self, nodo_id: str) -> Nodo:
        return next(n for n in self.nodos if n.id == nodo_id)


_COLUMNAS = {"herramienta": 110, "real": 340, "senuelo": 590, "atacante": 820}
_ALTO_FILA = 120
_MARGEN = 80


def _ys(cuantos: int, alto: int) -> list[int]:
    if cuantos == 0:
        return []
    paso = (alto - 2 * _MARGEN) / max(cuantos, 1)
    return [int(_MARGEN + paso * (i + 0.5)) for i in range(cuantos)]


def construir_mapa(
    hosts: Sequence[Host],
    campanas: Sequence[Campaign],
    eventos: Iterable[CollectedEvent],
    *,
    host_senuelos: str = "deception-central",
    ips_propias: Collection[str] = (),
) -> MapaRed:
    """Construye el diagrama: herramienta → equipos reales → trampas ← atacantes.

    - La herramienta gestiona por SSH los equipos dados de alta (enlace de gestión).
    - Cada equipo real lleva cebos que apuntan a su trampa (enlace de cebo).
    - Cada origen que ha tocado una trampa aparece como posible atacante (enlace de ataque),
      salvo la propia herramienta (`ips_propias`): sus escaneos de verificación se dibujan
      como un enlace de comprobación hacia la trampa.
    """
    reales = [h for h in hosts if h.host_id != host_senuelos]
    por_campana = {c.campaign_id: c for c in campanas}
    atacantes: dict[str, set[str]] = {}
    comprobadas: set[str] = set()
    for e in eventos:
        if e.src_host in ips_propias:
            comprobadas.add(e.node_id)
        else:
            atacantes.setdefault(e.src_host, set()).add(e.node_id)

    filas = max(len(reales), len(campanas), len(atacantes), 1)
    alto = 2 * _MARGEN + filas * _ALTO_FILA
    nodos = [
        Nodo(
            "herramienta",
            "Esta herramienta",
            "orquestador",
            "herramienta",
            _COLUMNAS["herramienta"],
            alto // 2,
        )
    ]
    enlaces: list[Enlace] = []
    for h, y in zip(reales, _ys(len(reales), alto), strict=True):
        nodos.append(Nodo(f"real:{h.host_id}", h.host_id, h.address, "real", _COLUMNAS["real"], y))
        enlaces.append(Enlace("herramienta", f"real:{h.host_id}", "gestion", "analiza por SSH"))
    for c, y in zip(por_campana.values(), _ys(len(campanas), alto), strict=True):
        nodo_id = f"senuelo:{c.decoy.node_id}"
        nodos.append(
            Nodo(nodo_id, c.decoy.node_id, str(c.decoy.address), "senuelo", _COLUMNAS["senuelo"], y)
        )
        if any(n.id == f"real:{c.host_id}" for n in nodos):
            enlaces.append(Enlace(f"real:{c.host_id}", nodo_id, "cebo", "sus cebos apuntan aquí"))
        if c.decoy.node_id in comprobadas:
            enlaces.append(
                Enlace("herramienta", nodo_id, "comprobacion", "la herramienta la comprueba")
            )
    for (ip, trampas), y in zip(sorted(atacantes.items()), _ys(len(atacantes), alto), strict=True):
        nodos.append(
            Nodo(f"atacante:{ip}", ip, "ha tocado una trampa", "atacante", _COLUMNAS["atacante"], y)
        )
        for trampa in sorted(trampas):
            if any(n.id == f"senuelo:{trampa}" for n in nodos):
                enlaces.append(Enlace(f"atacante:{ip}", f"senuelo:{trampa}", "ataque", "ataca"))
    return MapaRed(ancho=930, alto=alto, nodos=nodos, enlaces=enlaces)


# --- Pasos del flujo ---------------------------------------------------------------------


@dataclass(frozen=True)
class Paso:
    numero: int
    titulo: str
    explicacion: str
    hecho: bool


def pasos_flujo(
    *, equipos: int, perfilados: int, campanas: int, aprobadas: int, alertas: int
) -> list[Paso]:
    """Los seis pasos de la herramienta, marcando los que ya se han dado."""
    return [
        Paso(1, "Registrar equipos", "Das de alta los equipos que quieres proteger.", equipos > 0),
        Paso(
            2, "Analizarlos", "La herramienta mira qué sistema y servicios tienen.", perfilados > 0
        ),
        Paso(
            3,
            "Crear la trampa",
            "Fabrica un equipo falso idéntico y comprueba que no se nota.",
            campanas > 0,
        ),
        Paso(4, "Aprobar", "Tú revisas la trampa y das el visto bueno.", aprobadas > 0),
        Paso(
            5,
            "Desplegar",
            "La trampa aparece en la red y se dejan cebos en los equipos reales.",
            aprobadas > 0,
        ),
        Paso(6, "Vigilar", "Cualquier contacto con la trampa genera una alerta.", alertas > 0),
    ]
