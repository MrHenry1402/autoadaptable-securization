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

Los nombres de clave de OpenCanary están comprobados (L3) contra el config por defecto de
la imagen oficial `thinkst/opencanary` (OpenCanary 0.9.10), guardado en
`securization/data/opencanary_base.json`, y contra un señuelo real en el laboratorio.
"""

import hashlib
import json
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping, Sequence
from importlib import resources
from ipaddress import IPv4Address
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine
from sqlmodel import Field as SqlField
from sqlmodel import Session, SQLModel, select

from securization.llm import (
    LlmClient,
    build_profile_payload,
    generate_with_fallback,
    render_untrusted_block,
)
from securization.modelos import (
    Fingerprint,
    GenerationQuality,
    HostProfile,
    OsFamily,
    ServiceInfo,
)
from securization.parsing import sanitize_text
from securization.perfilador import UnsupportedOsFamilyError as UnsupportedOsFamilyError

MAX_BREADCRUMB_SIZE = 4096

# service.name (tal como lo da nmap) -> (módulo de OpenCanary, clave del banner o None).
# Claves comprobadas contra el config por defecto de OpenCanary 0.9.10
# (`securization/data/opencanary_base.json`, sacado de la imagen oficial). Solo módulos con
# una correspondencia clara; smb y rdp se quedan fuera porque nmap los nombra de forma
# menos uniforme (microsoft-ds, ms-wbt-server, ...).
_OPENCANARY_MODULES: dict[str, tuple[str, str | None]] = {
    "ssh": ("ssh", "version"),
    "ftp": ("ftp", "banner"),
    "http": ("http", "banner"),
    # `mysql.banner` es la versión del servidor, no el saludo que captura nmap.
    "mysql": ("mysql", None),
    "redis": ("redis", None),
    "telnet": ("telnet", "banner"),
}
_OPENCANARY_BASE = "data/opencanary_base.json"
_FTP_CODE = re.compile(r"^220[ -]")
# Patrón que OpenCanary 0.9.10 exige a mysql.banner (modules/mysql.py); si no lo cumple,
# el módulo MySQL no arranca y el puerto desaparece sin ningún error visible.
_MYSQL_BANNER_RE = re.compile(r"[3456]\.[-_~.+\w]+")
_UPSTREAM_VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
_DEBIAN_VERSION_RE = re.compile(r"[0-9][A-Za-z0-9.+~:-]{0,63}")

_LINUX_WHITELIST_DIRS: tuple[str, ...] = ("/home", "/root", "/var/backups")


class BreadcrumbError(Exception):
    """Un breadcrumb no cumple la lista blanca, el límite de tamaño o los permisos."""


class CollisionError(Exception):
    """Un breadcrumb colisiona con una ruta ya conocida o ya usada por otro breadcrumb."""


class CampaignNotFoundError(Exception):
    """No hay una campaña guardada con ese `campaign_id`."""


class DecoyConfig(BaseModel):
    """Identidad y configuración de OpenCanary de un deception host."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str
    address: IPv4Address
    opencanary_config: dict[str, bool | int | str]


class Breadcrumb(BaseModel):
    """Fichero cebo: ruta y contenido deterministas para un host. Aún no está plantado."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    host_id: str
    path: str
    content: str
    mode: int = Field(default=0o600, ge=0, le=0o777)


def validate_breadcrumb(breadcrumb: Breadcrumb, whitelist_dirs: Sequence[str]) -> None:
    """Comprueba la lista blanca de rutas, los permisos y el límite de tamaño."""
    if ".." in breadcrumb.path.split("/"):
        raise BreadcrumbError(f"ruta con '..': {breadcrumb.path}")
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
    def generate(
        self,
        profile: HostProfile,
        decoy: DecoyConfig,
        *,
        home_dir: str,
        known_paths: Iterable[str] = (),
    ) -> list[Breadcrumb]:
        """Genera los breadcrumbs del host, que llevan a los servicios del señuelo.

        `home_dir` es el home del usuario de gestión en el host real: los breadcrumbs se
        plantan ahí porque es escribible sin privilegios y no hace falta crear directorios.
        """


class BreadcrumbCredential(BaseModel):
    """Credencial falsa que un breadcrumb ofrece para un servicio del señuelo."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    username: str
    password: str


# Servicios del señuelo que registran credenciales en OpenCanary (comprobado en L4 con
# alertas reales: FTP 2000, HTTP 3001, SSH 4002, MySQL 8001, Redis 17001) y el usuario
# que se ofrece para cada uno.
_CREDENTIAL_USERS: dict[str, str] = {
    "mysql": "app_svc",
    "http": "intranet_admin",
    "ftp": "backup",
    "redis": "default",
    "ssh": "deploy",
}
_CREDENTIAL_CHARSET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CREDENTIAL_LEN = 16


def _active_credential_services(decoy: DecoyConfig) -> dict[str, int]:
    """Servicios con credenciales que el señuelo tiene activos, con su puerto."""
    config = decoy.opencanary_config
    activos: dict[str, int] = {}
    for servicio in _CREDENTIAL_USERS:
        puerto = config.get(f"{servicio}.port")
        if config.get(f"{servicio}.enabled") is True and type(puerto) is int:
            activos[servicio] = puerto
    return activos


def _password(node_id: str, servicio: str) -> str:
    """Contraseña determinista y distinta por señuelo y servicio (atribuye la alerta)."""
    resumen = hashlib.sha256(f"{node_id}:{servicio}".encode()).digest()
    return "".join(
        _CREDENTIAL_CHARSET[b % len(_CREDENTIAL_CHARSET)] for b in resumen[:_CREDENTIAL_LEN]
    )


def breadcrumb_credentials(decoy: DecoyConfig) -> dict[str, BreadcrumbCredential]:
    """Credenciales que ofrecen los breadcrumbs de un señuelo, por servicio activo.

    Sirven para reconocer en las alertas de OpenCanary un intento con un breadcrumb.
    """
    return {
        servicio: BreadcrumbCredential(
            username=_CREDENTIAL_USERS[servicio], password=_password(decoy.node_id, servicio)
        )
        for servicio in _active_credential_services(decoy)
    }


def _env_template(ip: str, puertos: dict[str, int], cred: dict[str, BreadcrumbCredential]) -> str:
    lineas = ["APP_ENV=production"]
    if "mysql" in puertos:
        lineas += [
            f"DB_HOST={ip}",
            f"DB_PORT={puertos['mysql']}",
            "DB_NAME=app",
            f"DB_USER={cred['mysql'].username}",
            f"DB_PASSWORD={cred['mysql'].password}",
        ]
    if "redis" in puertos:
        lineas.append(f"REDIS_URL=redis://:{cred['redis'].password}@{ip}:{puertos['redis']}/0")
    if "http" in puertos:
        lineas += [
            f"INTRANET_URL=http://{ip}:{puertos['http']}/",
            f"INTRANET_USER={cred['http'].username}",
            f"INTRANET_PASSWORD={cred['http'].password}",
        ]
    return "\n".join(lineas) + "\n"


def _my_cnf_template(ip: str, puerto: int, cred: BreadcrumbCredential) -> str:
    return f"[client]\nhost={ip}\nport={puerto}\nuser={cred.username}\npassword={cred.password}\n"


def _netrc_template(ip: str, cred: BreadcrumbCredential) -> str:
    return f"machine {ip} login {cred.username} password {cred.password}\n"


def _db_backup_template(ip: str) -> str:
    # Es el texto de un fichero cebo, no una consulta: nunca se ejecuta contra una base de
    # datos. El cuerpo va aparte para que no parezca SQL construido por concatenación.
    return f"-- Host: {ip}    Database: app\n" + _DB_BACKUP_BODY


_DB_BACKUP_BODY = (
    "-- ------------------------------------------------------\n"
    "CREATE TABLE users (id INT, username VARCHAR(32), password_hash VARCHAR(64));\n"
    "INSERT INTO users VALUES (1, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99');\n"
    "INSERT INTO users VALUES (2, 'app_svc', 'e99a18c428cb38d5f260853678922e03');\n"
)


def _access_notes_template(
    ip: str, puertos: dict[str, int], cred: dict[str, BreadcrumbCredential]
) -> str:
    lineas = [f"Accesos al servidor {ip}"]
    if "ssh" in puertos:
        c = cred["ssh"]
        lineas.append(f"- ssh -p {puertos['ssh']} {c.username}@{ip}  (clave: {c.password})")
    if "ftp" in puertos:
        c = cred["ftp"]
        lineas.append(f"- ftp {ip}  usuario {c.username} / {c.password}")
    if "http" in puertos:
        c = cred["http"]
        lineas.append(f"- intranet http://{ip}:{puertos['http']}/  {c.username} / {c.password}")
    if "mysql" in puertos:
        c = cred["mysql"]
        lineas.append(f"- base de datos: mysql -h {ip} -P {puertos['mysql']} -u {c.username} -p")
    return "\n".join(lineas) + "\n"


class LinuxBreadcrumbCatalog(BreadcrumbCatalog):
    """Catálogo de breadcrumbs para hosts Linux.

    Cada fichero lleva solo a servicios activos del señuelo (un breadcrumb hacia un puerto
    cerrado no dispara ninguna alerta), con credenciales propias de la campaña. Se plantan
    directamente en el home del usuario de gestión, sin subdirectorios, y nunca con
    nombres que casi siempre existen (`.bash_history`, `.ssh/`...), porque nunca se
    sobrescribe un fichero real.
    """

    os_family: ClassVar[OsFamily] = OsFamily.LINUX

    def generate(
        self,
        profile: HostProfile,
        decoy: DecoyConfig,
        *,
        home_dir: str,
        known_paths: Iterable[str] = (),
    ) -> list[Breadcrumb]:
        ip = str(decoy.address)
        puertos = _active_credential_services(decoy)
        cred = breadcrumb_credentials(decoy)
        base = home_dir.rstrip("/")
        contenidos: list[tuple[str, str]] = []
        if puertos.keys() & {"mysql", "redis", "http"}:
            contenidos.append((".env", _env_template(ip, puertos, cred)))
        if "mysql" in puertos:
            contenidos.append((".my.cnf", _my_cnf_template(ip, puertos["mysql"], cred["mysql"])))
            contenidos.append(("db_backup.sql", _db_backup_template(ip)))
        if "ftp" in puertos:
            contenidos.append((".netrc", _netrc_template(ip, cred["ftp"])))
        if puertos:
            contenidos.append(("notas_acceso.txt", _access_notes_template(ip, puertos, cred)))

        breadcrumbs = [
            Breadcrumb(host_id=profile.host_id, path=f"{base}/{nombre}", content=texto)
            for nombre, texto in contenidos
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


def _opencanary_banner(modulo: str, servicio: ServiceInfo) -> str | None:
    """Valor de la clave de banner de OpenCanary para un servicio real, o None.

    Cada módulo espera algo distinto: SSH la línea de versión completa, FTP el texto tras
    el código 220 (OpenCanary ya lo antepone) y HTTP la cabecera `Server`, que nmap no
    repite en un script cuando ya identificó el producto. Nunca se inventa un valor.
    """
    banner = servicio.banner
    if modulo == "ssh":
        return banner if banner and banner.startswith("SSH-") else None
    if modulo == "ftp":
        return _FTP_CODE.sub("", banner, count=1) if banner else None
    if modulo == "http" and not banner and servicio.product:
        sufijo = f"/{servicio.version}" if servicio.version else ""
        return f"{servicio.product}{sufijo}"
    return banner


def build_opencanary_config(profile: HostProfile, node_id: str) -> dict[str, bool | int | str]:
    """Claves de OpenCanary que replican los servicios y banners del perfil.

    Un banner no capturado no se inventa: el módulo se activa sin esa clave y OpenCanary
    usa el suyo por defecto. Si dos servicios del perfil caen en el mismo módulo, se queda
    con el de menor puerto. El fichero completo lo genera `render_opencanary_conf`.
    """
    config: dict[str, bool | int | str] = {"device.node_id": node_id}
    vistos: set[str] = set()
    for servicio in sorted(profile.services, key=lambda s: s.port):
        correspondencia = _OPENCANARY_MODULES.get(servicio.name)
        if correspondencia is None or correspondencia[0] in vistos:
            continue
        modulo, clave_banner = correspondencia
        vistos.add(modulo)
        config[f"{modulo}.enabled"] = True
        config[f"{modulo}.port"] = servicio.port
        if clave_banner is not None and (valor := _opencanary_banner(modulo, servicio)):
            config[f"{modulo}.{clave_banner}"] = valor
    return config


def render_opencanary_conf(config: Mapping[str, bool | int | str]) -> str:
    """Fichero `opencanary.conf` completo (JSON) a partir de las claves del señuelo.

    Parte del config por defecto de OpenCanary 0.9.10, desactiva todos sus módulos (por
    defecto trae FTP activado) y aplica `config` encima, así que solo quedan activos los
    módulos que vienen del perfil. Rechaza claves que OpenCanary no conoce, para que una
    errata no deje un servicio activado o mal configurado sin aviso.
    """
    base = json.loads(resources.files("securization").joinpath(_OPENCANARY_BASE).read_text("utf-8"))
    desconocidas = sorted(set(config) - set(base))
    if desconocidas:
        raise ValueError(f"claves que OpenCanary no conoce: {', '.join(desconocidas)}")
    banner_mysql = config.get("mysql.banner")
    if banner_mysql is not None and not _MYSQL_BANNER_RE.fullmatch(str(banner_mysql)):
        raise ValueError(
            f"mysql.banner no admitido por OpenCanary (descartaría el módulo): {banner_mysql!r}"
        )
    for clave in base:
        if clave.endswith(".enabled"):
            base[clave] = False
    base.update(config)
    return json.dumps(base, indent=2, ensure_ascii=False) + "\n"


def mysql_banner_from_package(package: str, version: str) -> str | None:
    """`mysql.banner` que anunciaría el servidor real instalado desde ese paquete.

    MariaDB 10+ antepone `5.5.5-` por compatibilidad con clientes MySQL antiguos: el
    paquete Debian `1:11.8.9+ds-0+deb13u1` da `5.5.5-11.8.9-MariaDB-0+deb13u1`, que es lo
    que muestra `mariadbd --version` en el laboratorio. Devuelve None si la versión no es
    válida o si OpenCanary no podría anunciarla (solo admite 3.x-6.x).
    """
    if package not in ("mariadb-server", "mysql-server") or not _DEBIAN_VERSION_RE.fullmatch(
        version
    ):
        return None
    sin_epoch = version.split(":", 1)[-1]
    original, _, revision = sin_epoch.partition("-")
    numerica = _UPSTREAM_VERSION_RE.match(original)
    if numerica is None:
        return None
    sufijo = f"-{revision}" if revision else ""
    if package == "mariadb-server":
        banner = f"5.5.5-{numerica.group()}-MariaDB{sufijo}"
    else:
        banner = f"{numerica.group()}{sufijo}"
    return banner if _MYSQL_BANNER_RE.fullmatch(banner) else None


def adjust_decoy(profile: HostProfile, decoy: DecoyConfig, real: Fingerprint) -> DecoyConfig | None:
    """Siguiente config del señuelo según lo observado en el host real, o None si no cambia.

    Solo toca claves de banner de módulos ya activos: nunca activa ni desactiva un módulo,
    porque los breadcrumbs de la campaña llevan a esos servicios. Los valores salen del
    perfil por SSH (versión del paquete de MySQL/MariaDB, que no se ve por red cuando el
    servidor rechaza al escáner) y de la huella nmap del host real; nunca se inventan.
    """
    config = dict(decoy.opencanary_config)
    propuesta = dict(config)

    if config.get("mysql.enabled") is True:
        for paquete in ("mariadb-server", "mysql-server"):
            version = profile.packages.get(paquete)
            banner = mysql_banner_from_package(paquete, version) if version else None
            if banner is not None:
                propuesta["mysql.banner"] = banner
                break

    reales = {s.port: s for s in real.services if s.protocol == "tcp"}
    for servicio, (modulo, clave) in _OPENCANARY_MODULES.items():
        if clave is None or config.get(f"{modulo}.enabled") is not True:
            continue
        observado = reales.get(int(config.get(f"{modulo}.port", 0)))
        if observado is None or observado.name != servicio:
            continue
        valor = _opencanary_banner(modulo, observado)
        if valor:
            propuesta[f"{modulo}.{clave}"] = valor

    if propuesta == config:
        return None
    return decoy.model_copy(update={"opencanary_config": propuesta})


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
    home_dir: str,
    known_paths: Iterable[str] = (),
) -> Campaign:
    """Genera la campaña determinista (H2) de un host: señuelo + breadcrumbs.

    `decoy_node_id` y `decoy_address` los decide quien llama (por ejemplo una IP libre de
    `securization.escaneo.find_free_ips`); aquí solo se valida que no sea la del host real.
    Primero se construye el señuelo y después los breadcrumbs, que llevan a sus servicios.
    `home_dir` es el home del usuario de gestión en el host real, donde se plantan.
    """
    if decoy_address == profile.address:
        raise ValueError(f"la dirección del señuelo no puede ser la del host real: {decoy_address}")
    decoy = DecoyConfig(
        node_id=decoy_node_id,
        address=decoy_address,
        opencanary_config=build_opencanary_config(profile, node_id=decoy_node_id),
    )
    breadcrumbs = get_catalog(profile.os_family).generate(
        profile, decoy, home_dir=home_dir, known_paths=known_paths
    )
    return Campaign(
        campaign_id=campaign_id,
        host_id=profile.host_id,
        decoy=decoy,
        breadcrumbs=breadcrumbs,
    )


class _CampaignRecord(SQLModel, table=True):
    """Fila con la `Campaign` completa, serializada en JSON."""

    __tablename__ = "campaign"

    campaign_id: str = SqlField(primary_key=True)
    campaign_json: str


class CampaignStore:
    """Guarda y recupera campañas completas en la base de datos, para el dashboard (S13)."""

    def __init__(self, engine: Engine) -> None:
        self._engine = engine
        SQLModel.metadata.create_all(engine)

    def save(self, campaign: Campaign) -> None:
        """Guarda la campaña; si ya había una con ese `campaign_id`, la sustituye."""
        payload = campaign.model_dump_json()
        with Session(self._engine) as session:
            registro = session.get(_CampaignRecord, campaign.campaign_id)
            if registro is None:
                registro = _CampaignRecord(campaign_id=campaign.campaign_id, campaign_json=payload)
            else:
                registro.campaign_json = payload
            session.add(registro)
            session.commit()

    def load(self, campaign_id: str) -> Campaign:
        """Recupera la campaña guardada o falla con un error claro."""
        with Session(self._engine) as session:
            registro = session.get(_CampaignRecord, campaign_id)
        if registro is None:
            raise CampaignNotFoundError(campaign_id)
        return Campaign.model_validate_json(registro.campaign_json)

    def list_all(self) -> list[Campaign]:
        """Todas las campañas guardadas."""
        with Session(self._engine) as session:
            registros = session.exec(select(_CampaignRecord)).all()
        return [Campaign.model_validate_json(registro.campaign_json) for registro in registros]


class DecoyIdentity(BaseModel):
    """Hostname propuesto para el deception host (componente de IA: S8).

    Una etiqueta DNS válida (RFC 1123): letras, dígitos y guiones, 1-63 caracteres, sin
    empezar ni acabar en guion. Una salida que no lo cumple cuenta como no válida.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    hostname: str = Field(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _decoy_hostname_fallback(profile: HostProfile) -> DecoyIdentity:
    """Plantilla de respaldo determinista: `<host_id>-decoy`, sin IA."""
    return DecoyIdentity(hostname=f"{profile.host_id}-decoy")


async def propose_decoy_hostname(
    profile: HostProfile, client: LlmClient
) -> tuple[DecoyIdentity, GenerationQuality]:
    """Propone un hostname plausible para el señuelo a partir del perfil del host real.

    El LLM solo propone texto; nunca decide a qué host conectarse ni ejecuta nada. El
    `host_id` y el sistema operativo viajan en claro (no son datos personales ni
    credenciales) para que el modelo pueda inferir la convención de nombres del entorno; el
    resto del perfil va seudonimizado y delimitado, igual que para cualquier otro uso del
    LLM. Si el LLM falla o su salida no valida, se usa la plantilla de respaldo.
    """
    payload, _ = build_profile_payload(profile)
    bloque_perfil = render_untrusted_block(payload)
    host_id = sanitize_text(profile.host_id)
    os_name = sanitize_text(profile.os_name)
    prompt = (
        "Propón un hostname de servidor plausible para un señuelo (deception host) que "
        "debe encajar con el resto de la red de este host real. Responde solo JSON con la "
        'forma {"hostname": "..."}.\n'
        f"host_id del host real (solo para inferir la convención de nombres, no lo copies "
        f"tal cual): {host_id}\n"
        f"Sistema operativo: {os_name}\n"
        f"{bloque_perfil}"
    )
    identidad, calidad = await generate_with_fallback(
        client, prompt, DecoyIdentity, lambda: _decoy_hostname_fallback(profile)
    )
    if identidad.hostname.lower() == profile.host_id.lower():
        # Copiar el nombre del host real no sirve como señuelo: se trata como no válida.
        return _decoy_hostname_fallback(profile), GenerationQuality.FALLBACK
    return identidad, calidad
