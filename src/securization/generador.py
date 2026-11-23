"""Generación de campañas (breadcrumbs y deception hosts).

Catálogo de breadcrumbs deterministas por sistema operativo (interfaz `BreadcrumbCatalog`,
hoy solo `LinuxBreadcrumbCatalog`): genera rutas y contenido de ficheros cebo coherentes con
el perfil de un host, sin IA todavía (eso llega con H3/S8) y sin tocar hosts reales (eso es
responsabilidad del desplegador). Rutas limitadas a una lista blanca, sin permisos de
ejecución, con límite de tamaño y sin colisionar con rutas ya conocidas o ya plantadas.

También la línea base sin IA del generador (H2): `build_opencanary_config` copia los
servicios y banners del perfil a una configuración de OpenCanary, y `build_campaign` la
empaqueta junto con los breadcrumbs en un `Campaign`. El nombre y la dirección del señuelo
los decide quien llame a `build_campaign`; adivinar la convención de nombres con IA es la S8.

Aviso: los nombres de clave de OpenCanary (`<módulo>.enabled`, `<módulo>.port`, el banner)
están tomados de memoria del formato de `canary.conf` y no se han comprobado contra una
instalación real. Antes de desplegar de verdad (L3), hay que verificarlos contra la versión
de OpenCanary del laboratorio.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from ipaddress import IPv4Address
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from securization.modelos import HostProfile, OsFamily
from securization.perfilador import UnsupportedOsFamilyError as UnsupportedOsFamilyError

MAX_BREADCRUMB_SIZE = 4096

# service.name (tal como lo da nmap/ss) -> (módulo de OpenCanary, clave del banner).
# Solo los módulos con una correspondencia clara y bien documentada; smb y rdp se quedan
# fuera porque nmap los nombra de forma menos uniforme (microsoft-ds, ms-wbt-server, ...).
_OPENCANARY_MODULES: dict[str, tuple[str, str]] = {
    "ssh": ("ssh", "version"),
    "ftp": ("ftp", "banner"),
    "http": ("http", "banner"),
    "mysql": ("mysql", "banner"),
    "telnet": ("telnet", "banner"),
}

_LINUX_WHITELIST_DIRS: tuple[str, ...] = ("/home", "/root", "/var/backups")
_LINUX_HOME_FALLBACK = "/home/admin"


class BreadcrumbError(Exception):
    """Un breadcrumb no cumple la lista blanca, el límite de tamaño o los permisos."""


class CollisionError(Exception):
    """Un breadcrumb colisiona con una ruta ya conocida o ya usada por otro breadcrumb."""


class Breadcrumb(BaseModel):
    """Fichero cebo: ruta y contenido deterministas para un host. Aún no está plantado."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str
    path: str
    content: str
    mode: int = Field(default=0o600, ge=0, le=0o777)


def validate_breadcrumb(breadcrumb: Breadcrumb, whitelist_dirs: Sequence[str]) -> None:
    """Comprueba la lista blanca de rutas, los permisos y el límite de tamaño."""
    if not any(
        breadcrumb.path == directorio or breadcrumb.path.startswith(f"{directorio.rstrip('/')}/")
        for directorio in whitelist_dirs
    ):
        raise BreadcrumbError(f"ruta fuera de la lista blanca: {breadcrumb.path}")
    if breadcrumb.mode & 0o111:
        raise BreadcrumbError(f"breadcrumb con permisos de ejecución: {breadcrumb.path}")
    tamano = len(breadcrumb.content.encode("utf-8"))
    if tamano > MAX_BREADCRUMB_SIZE:
        raise BreadcrumbError(
            f"breadcrumb demasiado grande ({tamano} > {MAX_BREADCRUMB_SIZE}): {breadcrumb.path}"
        )


def check_collisions(breadcrumbs: Iterable[Breadcrumb], known_paths: Iterable[str]) -> None:
    """Falla si algún breadcrumb repite una ruta ya conocida o la de otro breadcrumb.

    `known_paths` son rutas reales del host o ya plantadas por una campaña anterior; esta
    función nunca sobrescribe nada por sí misma, solo impide generar una colisión.
    """
    conocidas = set(known_paths)
    vistas: set[str] = set()
    for breadcrumb in breadcrumbs:
        if breadcrumb.path in conocidas or breadcrumb.path in vistas:
            raise CollisionError(f"colisión de ruta: {breadcrumb.path}")
        vistas.add(breadcrumb.path)


class BreadcrumbCatalog(ABC):
    """Interfaz del catálogo de breadcrumbs; una implementación por familia de SO."""

    os_family: ClassVar[OsFamily]

    @abstractmethod
    def generate(self, profile: HostProfile, known_paths: Iterable[str] = ()) -> list[Breadcrumb]:
        """Genera los breadcrumbs deterministas coherentes con el perfil del host."""


def _linux_home_dir(profile: HostProfile) -> str:
    """Directorio base de los breadcrumbs de usuario: `/root` si existe, si no un `/home/*`."""
    if "/root" in profile.top_level_dirs:
        return "/root"
    return _LINUX_HOME_FALLBACK


def _env_template() -> str:
    return (
        "APP_ENV=production\n"
        "DB_HOST=127.0.0.1\n"
        "DB_NAME=app\n"
        "DB_USER=app_svc\n"
        "DB_PASSWORD=Tr0ub4dor&3-cebo\n"
        "API_KEY=sk-cebo-4f3c2a1e9d7b6c5a\n"
    )


def _bash_history_template() -> str:
    return (
        "ls -la /var/backups\n"
        "mysql -u app_svc -p app\n"
        "scp backup.sql admin@10.0.0.5:/tmp/\n"
        "ssh admin@10.0.0.5\n"
        "sudo cat /var/backups/backup.sql | head\n"
    )


def _backup_sql_template() -> str:
    return (
        "-- backup generado automaticamente\n"
        "CREATE TABLE users (id INT, username VARCHAR(32), password_hash VARCHAR(64));\n"
        "INSERT INTO users VALUES (1, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99');\n"
        "INSERT INTO users VALUES (2, 'app_svc', 'e99a18c428cb38d5f260853678922e03');\n"
    )


def _fake_ssh_key_template() -> str:
    return (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "Y2VibzFmYWtlc3Noa2V5bm90cmVhbGRvbm90dXNlY2VibzJmYWtlc3Noa2V5\n"
        "bm90cmVhbGRvbm90dXNlY2VibzNmYWtlc3Noa2V5bm90cmVhbGRvbm90dXNl\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )


class LinuxBreadcrumbCatalog(BreadcrumbCatalog):
    """Catálogo de breadcrumbs para hosts Linux."""

    os_family: ClassVar[OsFamily] = OsFamily.LINUX

    def generate(self, profile: HostProfile, known_paths: Iterable[str] = ()) -> list[Breadcrumb]:
        home_dir = _linux_home_dir(profile)
        breadcrumbs = [
            Breadcrumb(host_id=profile.host_id, path=f"{home_dir}/.env", content=_env_template()),
            Breadcrumb(
                host_id=profile.host_id,
                path=f"{home_dir}/.bash_history",
                content=_bash_history_template(),
            ),
            Breadcrumb(
                host_id=profile.host_id,
                path="/var/backups/backup.sql",
                content=_backup_sql_template(),
            ),
            Breadcrumb(
                host_id=profile.host_id,
                path=f"{home_dir}/.ssh/id_rsa",
                content=_fake_ssh_key_template(),
            ),
        ]
        for breadcrumb in breadcrumbs:
            validate_breadcrumb(breadcrumb, _LINUX_WHITELIST_DIRS)
        check_collisions(breadcrumbs, known_paths)
        return breadcrumbs


_CATALOGS: dict[OsFamily, type[BreadcrumbCatalog]] = {
    OsFamily.LINUX: LinuxBreadcrumbCatalog,
}


def get_catalog(os_family: OsFamily) -> BreadcrumbCatalog:
    """Devuelve el catálogo de breadcrumbs del SO indicado o falla; nunca usa un por defecto."""
    try:
        return _CATALOGS[os_family]()
    except KeyError:
        raise UnsupportedOsFamilyError(f"os_family no soportado: {os_family}") from None


def build_opencanary_config(profile: HostProfile, node_id: str) -> dict[str, bool | int | str]:
    """Configuración de OpenCanary que replica los servicios y banners del perfil.

    Un banner no capturado no se inventa: el módulo se activa sin esa clave y OpenCanary
    usa el suyo por defecto. Si dos servicios del perfil caen en el mismo módulo, se queda
    con el de menor puerto.
    """
    config: dict[str, bool | int | str] = {
        "device.node_id": node_id,
        "ip.autodetect": False,
    }
    vistos: set[str] = set()
    for servicio in sorted(profile.services, key=lambda s: s.port):
        correspondencia = _OPENCANARY_MODULES.get(servicio.name)
        if correspondencia is None or correspondencia[0] in vistos:
            continue
        modulo, clave_banner = correspondencia
        vistos.add(modulo)
        config[f"{modulo}.enabled"] = True
        config[f"{modulo}.port"] = servicio.port
        if servicio.banner:
            config[f"{modulo}.{clave_banner}"] = servicio.banner
    return config


class DecoyConfig(BaseModel):
    """Identidad y configuración de OpenCanary de un deception host."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    address: IPv4Address
    opencanary_config: dict[str, bool | int | str]


class Campaign(BaseModel):
    """Campaña: señuelo (deception host) y breadcrumbs generados para un host real."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    campaign_id: str
    host_id: str
    decoy: DecoyConfig
    breadcrumbs: list[Breadcrumb]


def build_campaign(
    profile: HostProfile,
    *,
    campaign_id: str,
    decoy_node_id: str,
    decoy_address: IPv4Address,
    known_paths: Iterable[str] = (),
) -> Campaign:
    """Genera la campaña determinista (H2) de un host: señuelo + breadcrumbs.

    `decoy_node_id` y `decoy_address` los decide quien llama (por ejemplo una IP libre de
    `securization.escaneo.find_free_ips`); aquí solo se valida que no sea la del host real.
    """
    if decoy_address == profile.address:
        raise ValueError(f"la dirección del señuelo no puede ser la del host real: {decoy_address}")
    breadcrumbs = get_catalog(profile.os_family).generate(profile, known_paths=known_paths)
    decoy = DecoyConfig(
        node_id=decoy_node_id,
        address=decoy_address,
        opencanary_config=build_opencanary_config(profile, node_id=decoy_node_id),
    )
    return Campaign(
        campaign_id=campaign_id,
        host_id=profile.host_id,
        decoy=decoy,
        breadcrumbs=breadcrumbs,
    )
