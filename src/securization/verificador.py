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
- Banners (30 puntos): de los puertos que ambos exponen, qué fracción tiene el banner
  idéntico. Si no comparten ningún puerto no hay banners que comparar, y no se penaliza.
"""

from securization.modelos import Fingerprint, PlausibilityReport, ServiceInfo

DEFAULT_THRESHOLD = 90

_OS_WEIGHT = 40
_SERVICES_WEIGHT = 30
_BANNER_WEIGHT = 30


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
            banner_real = real_keys[(port, protocol)].banner
            banner_decoy = decoy_keys[(port, protocol)].banner
            if banner_real == banner_decoy:
                coincidencias += 1
            else:
                differences.append(
                    f"banner distinto en {port}/{protocol}: "
                    f"real={banner_real!r} señuelo={banner_decoy!r}"
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
