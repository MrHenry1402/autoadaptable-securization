"""Escaneo del señuelo y del host real, comparación de huellas y puntuación de plausibilidad.

Recibe dos `Fingerprint` ya calculados (S3: `securization.escaneo`), uno del host real y otro
del señuelo, y mide cuánto se parecen. No decide el despliegue: el umbral y la aprobación
manual del operador son responsabilidad de la sesión S9. No hace ningún escaneo por sí mismo.

La puntuación combina tres componentes con pesos fijos:
- Sistema operativo (40 puntos): la familia del `OsMatch` de mayor precisión de cada lado.
  Si el host real no tiene ningún `OsMatch`, no hay nada que replicar y no se penaliza.
- Servicios (30 puntos): similitud de Jaccard sobre el conjunto de puertos/protocolo
  abiertos. Un servicio que falta en el señuelo y uno que sobra penalizan igual, porque
  ambos lo hacen distinguible de un host real.
- Banners (30 puntos): de los puertos que ambos exponen, qué fracción tiene el mismo
  servicio: nombre, producto, versión, extrainfo y banner. Si no comparten ningún puerto
  no hay nada que comparar, y no se penaliza.

Ajustes de H4, comprobados con escaneos reales del laboratorio (`tests/fixtures/nmap/`):
- El saludo de MySQL lleva un "salt" aleatorio por conexión; se compara por la versión que
  anuncia. Sin esto, un señuelo comparado consigo mismo no daba 100.
- Si un banner del señuelo delata una distribución que el host real no muestra en ninguno
  de los suyos (el MySQL por defecto de OpenCanary anuncia Ubuntu 14.04 en un Debian), el
  SO es distinguible aunque `nmap -O` diga Linux en ambos.
"""

import re

from securization.modelos import Fingerprint, PlausibilityReport, ServiceInfo

DEFAULT_THRESHOLD = 90

_OS_WEIGHT = 40
_SERVICES_WEIGHT = 30
_BANNER_WEIGHT = 30

# Saludo de MySQL/MariaDB tal como lo escapa nmap: protocolo 10 (\x0A), versión, \x00, salt.
_MYSQL_HANDSHAKE = re.compile(r"\\x0A(\d[^\\]*)\\x00")
_DISTROS = (
    "debian",
    "ubuntu",
    "centos",
    "red hat",
    "fedora",
    "alpine",
    "suse",
    "rocky",
    "almalinux",
    "raspbian",
    "freebsd",
    "windows",
)


def _normalize_banner(banner: str | None) -> str | None:
    """Banner comparable: el saludo de MySQL se reduce a la versión que anuncia."""
    if banner is None:
        return None
    saludo = _MYSQL_HANDSHAKE.search(banner)
    return f"mysql-handshake {saludo.group(1)}" if saludo else banner


def _service_signature(servicio: ServiceInfo) -> dict[str, str | None]:
    return {
        "nombre": servicio.name,
        "producto": servicio.product,
        "versión": servicio.version,
        "extrainfo": servicio.extrainfo,
        "banner": _normalize_banner(servicio.banner),
    }


def _distros(fingerprint: Fingerprint) -> set[str]:
    """Distribuciones que mencionan los servicios de una huella."""
    texto = " ".join(
        campo.lower()
        for s in fingerprint.services
        for campo in (s.product, s.version, s.extrainfo, s.banner)
        if campo
    )
    return {distro for distro in _DISTROS if distro in texto}


def _top_os_family(fingerprint: Fingerprint) -> str | None:
    """Familia del `OsMatch` de mayor precisión, tal cual, o `None` si no hay ninguno."""
    if not fingerprint.os_matches:
        return None
    mejor = max(fingerprint.os_matches, key=lambda m: m.accuracy)
    return mejor.os_family


def _service_keys(fingerprint: Fingerprint) -> dict[tuple[int, str], ServiceInfo]:
    return {(s.port, s.protocol): s for s in fingerprint.services}


def _compare(real: Fingerprint, decoy: Fingerprint) -> tuple[int, list[str]]:
    differences: list[str] = []

    # --- Sistema operativo ---
    real_family = _top_os_family(real)
    decoy_family = _top_os_family(decoy)
    coincide = real_family is None or (
        decoy_family is not None and real_family.lower() == decoy_family.lower()
    )
    if coincide:
        os_score = 100
    else:
        os_score = 0
        differences.append(f"SO distinguible: host real={real_family!r} señuelo={decoy_family!r}")

    distros_real = _distros(real)
    delatadas = _distros(decoy) - distros_real
    if distros_real and delatadas:
        os_score = 0
        differences.append(
            f"SO distinguible: el señuelo delata {', '.join(sorted(delatadas))} y el host real "
            f"muestra {', '.join(sorted(distros_real))}"
        )

    # --- Servicios ---
    real_keys = _service_keys(real)
    decoy_keys = _service_keys(decoy)
    union = real_keys.keys() | decoy_keys.keys()
    intersection = real_keys.keys() & decoy_keys.keys()
    services_score = 100 if not union else round(100 * len(intersection) / len(union))

    for port, protocol in sorted(real_keys.keys() - decoy_keys.keys()):
        servicio = real_keys[(port, protocol)]
        differences.append(
            f"falta el servicio {port}/{protocol} ({servicio.name}) que sí tiene el host real"
        )
    for port, protocol in sorted(decoy_keys.keys() - real_keys.keys()):
        servicio = decoy_keys[(port, protocol)]
        differences.append(
            f"el señuelo expone {port}/{protocol} ({servicio.name}) que el host real no tiene"
        )

    # --- Banners de los puertos compartidos ---
    if not intersection:
        banner_score = 100
    else:
        coincidencias = 0
        for port, protocol in sorted(intersection):
            firma_real = _service_signature(real_keys[(port, protocol)])
            firma_decoy = _service_signature(decoy_keys[(port, protocol)])
            distintos = [campo for campo in firma_real if firma_real[campo] != firma_decoy[campo]]
            if not distintos:
                coincidencias += 1
            else:
                detalle = "; ".join(
                    f"{campo}: real={firma_real[campo]!r} señuelo={firma_decoy[campo]!r}"
                    for campo in distintos
                )
                differences.append(
                    f"{' y '.join(distintos)} distinto en {port}/{protocol}: {detalle}"
                )
        banner_score = round(100 * coincidencias / len(intersection))

    score = round(
        (os_score * _OS_WEIGHT + services_score * _SERVICES_WEIGHT + banner_score * _BANNER_WEIGHT)
        / 100
    )
    return score, differences


def score_fingerprints(real: Fingerprint, decoy: Fingerprint) -> int:
    """Puntuación de plausibilidad (0-100) del señuelo frente al host real."""
    return _compare(real, decoy)[0]


def verify_decoy(
    real: Fingerprint, decoy: Fingerprint, threshold: int = DEFAULT_THRESHOLD
) -> PlausibilityReport:
    """Compara las huellas y devuelve el informe completo, con las diferencias detectadas."""
    score, differences = _compare(real, decoy)
    return PlausibilityReport(
        score=score,
        threshold=threshold,
        passed=score >= threshold,
        differences=differences,
    )
