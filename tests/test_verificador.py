"""Tests del verificador: comparación de huellas (nmap) y puntuación de plausibilidad.

No hace escaneos: recibe dos `Fingerprint` ya calculados (host real y señuelo) y decide si
son lo bastante parecidos. El umbral y la aprobación manual son quien decide el despliegue
(S9); aquí solo se mide.
"""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from securization.escaneo import parse_nmap_xml
from securization.modelos import Fingerprint, OsMatch, PlausibilityReport, ServiceInfo
from securization.verificador import DEFAULT_THRESHOLD, score_fingerprints, verify_decoy

LINUX_MATCH = OsMatch(name="Linux 5.10 - 5.15", accuracy=97, os_family="Linux")
WINDOWS_MATCH = OsMatch(name="Windows Server 2022", accuracy=95, os_family="Windows")
SSH_REAL = ServiceInfo(port=22, protocol="tcp", name="ssh", banner="SSH-2.0-OpenSSH_9.2p1")
HTTP_REAL = ServiceInfo(port=80, protocol="tcp", name="http", banner="nginx/1.22.1")


def huella(**cambios: Any) -> Fingerprint:
    datos: dict[str, Any] = {
        "address": "10.0.0.10",
        "os_matches": [LINUX_MATCH],
        "services": [SSH_REAL],
    }
    datos.update(cambios)
    return Fingerprint.model_validate(datos)


# --- score_fingerprints: casos exactos ------------------------------------


def test_huellas_identicas_puntuan_100() -> None:
    real = huella(services=[SSH_REAL, HTTP_REAL])
    assert score_fingerprints(real, real) == 100


def test_ambos_sin_servicios_ni_os_matches_puntua_100() -> None:
    vacia = huella(os_matches=[], services=[])
    assert score_fingerprints(vacia, vacia) == 100


def test_familia_de_so_distinta_penaliza_40_puntos() -> None:
    real = huella(os_matches=[LINUX_MATCH])
    senuelo = huella(os_matches=[WINDOWS_MATCH])
    assert score_fingerprints(real, senuelo) == 60


def test_senuelo_sin_os_matches_frente_a_real_con_os_matches_penaliza_igual() -> None:
    real = huella(os_matches=[LINUX_MATCH])
    senuelo = huella(os_matches=[])
    assert score_fingerprints(real, senuelo) == 60


def test_real_sin_os_matches_no_penaliza_aunque_el_senuelo_tenga() -> None:
    # Sin huella de SO del host real no hay nada que exigir que el señuelo replique.
    real = huella(os_matches=[])
    senuelo = huella(os_matches=[WINDOWS_MATCH])
    assert score_fingerprints(real, senuelo) == 100


def test_os_match_usa_el_de_mayor_precision() -> None:
    real = huella(os_matches=[OsMatch(name="Peor", accuracy=10, os_family="Windows"), LINUX_MATCH])
    senuelo = huella(os_matches=[LINUX_MATCH])
    assert score_fingerprints(real, senuelo) == 100


def test_comparacion_de_familia_ignora_mayusculas() -> None:
    real = huella(os_matches=[OsMatch(name="Linux", accuracy=90, os_family="LINUX")])
    senuelo = huella(os_matches=[OsMatch(name="Linux", accuracy=90, os_family="linux")])
    assert score_fingerprints(real, senuelo) == 100


def test_servicio_que_falta_en_el_senuelo_penaliza_15_puntos() -> None:
    real = huella(services=[SSH_REAL, HTTP_REAL])
    senuelo = huella(services=[SSH_REAL])
    assert score_fingerprints(real, senuelo) == 85


def test_servicio_extra_en_el_senuelo_penaliza_igual_que_uno_que_falta() -> None:
    extra = ServiceInfo(port=8080, protocol="tcp", name="http-alt")
    real = huella(services=[SSH_REAL])
    senuelo = huella(services=[SSH_REAL, extra])
    assert score_fingerprints(real, senuelo) == 85


def test_banner_distinto_en_un_puerto_compartido_penaliza_30_puntos() -> None:
    real = huella(services=[SSH_REAL])
    senuelo = huella(services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="otro")])
    assert score_fingerprints(real, senuelo) == 70


def test_banner_ausente_frente_a_banner_presente_se_cuenta_como_distinto() -> None:
    real = huella(services=[SSH_REAL])
    sin_banner = ServiceInfo(port=22, protocol="tcp", name="ssh")
    senuelo = huella(services=[sin_banner])
    assert score_fingerprints(real, senuelo) == 70


def test_ambos_sin_banner_en_un_puerto_compartido_no_penaliza() -> None:
    sin_banner = ServiceInfo(port=22, protocol="tcp", name="ssh")
    real = huella(services=[sin_banner])
    assert score_fingerprints(real, real) == 100


def test_puertos_de_distinto_protocolo_no_se_consideran_compartidos() -> None:
    real = huella(services=[ServiceInfo(port=53, protocol="tcp", name="dns")])
    senuelo = huella(services=[ServiceInfo(port=53, protocol="udp", name="dns")])
    # No comparten ninguna clave (puerto, protocolo): 0 de servicios, banner no aplicable.
    assert (
        score_fingerprints(real, senuelo) == 70
    )  # 40 (SO igual) + 0 (servicios) + 30 (banner n/a)


def test_huellas_completamente_distintas_puntuan_30() -> None:
    real = huella(os_matches=[LINUX_MATCH], services=[SSH_REAL])
    senuelo = huella(
        os_matches=[WINDOWS_MATCH],
        services=[ServiceInfo(port=3389, protocol="tcp", name="rdp")],
    )
    assert score_fingerprints(real, senuelo) == 30


@pytest.mark.parametrize(
    ("real_servicios", "senuelo_servicios"),
    [
        ([], []),
        ([SSH_REAL], []),
        ([], [SSH_REAL]),
        ([SSH_REAL, HTTP_REAL], [HTTP_REAL]),
    ],
)
def test_la_puntuacion_siempre_esta_entre_0_y_100(
    real_servicios: list[ServiceInfo], senuelo_servicios: list[ServiceInfo]
) -> None:
    real = huella(services=real_servicios)
    senuelo = huella(services=senuelo_servicios)
    assert 0 <= score_fingerprints(real, senuelo) <= 100


# --- verify_decoy: informe con umbral y diferencias -----------------------


def test_verify_decoy_supera_el_umbral_por_defecto() -> None:
    real = huella(services=[SSH_REAL])
    informe = verify_decoy(real, real)
    assert informe.passed is True
    assert informe.score == 100
    assert informe.threshold == DEFAULT_THRESHOLD
    assert informe.differences == []


def test_verify_decoy_no_supera_el_umbral_por_defecto_si_hay_diferencias() -> None:
    real = huella(os_matches=[LINUX_MATCH], services=[SSH_REAL])
    senuelo = huella(os_matches=[WINDOWS_MATCH], services=[SSH_REAL])
    informe = verify_decoy(real, senuelo)
    assert informe.score == 60
    assert informe.passed is False


def test_verify_decoy_admite_un_umbral_personalizado() -> None:
    real = huella(os_matches=[LINUX_MATCH], services=[SSH_REAL])
    senuelo = huella(os_matches=[WINDOWS_MATCH], services=[SSH_REAL])
    informe = verify_decoy(real, senuelo, threshold=50)
    assert informe.score == 60
    assert informe.passed is True
    assert informe.threshold == 50


def test_verify_decoy_describe_la_diferencia_de_so() -> None:
    real = huella(os_matches=[LINUX_MATCH])
    senuelo = huella(os_matches=[WINDOWS_MATCH])
    (diferencia,) = verify_decoy(real, senuelo).differences
    assert "Linux" in diferencia
    assert "Windows" in diferencia


def test_verify_decoy_describe_el_servicio_que_falta() -> None:
    real = huella(services=[SSH_REAL, HTTP_REAL])
    senuelo = huella(services=[SSH_REAL])
    diferencias = verify_decoy(real, senuelo).differences
    assert any("80" in d and "falta" in d for d in diferencias)


def test_verify_decoy_describe_el_servicio_sobrante() -> None:
    extra = ServiceInfo(port=8080, protocol="tcp", name="http-alt")
    real = huella(services=[SSH_REAL])
    senuelo = huella(services=[SSH_REAL, extra])
    diferencias = verify_decoy(real, senuelo).differences
    assert any("8080" in d for d in diferencias)


def test_verify_decoy_describe_el_banner_distinto() -> None:
    real = huella(services=[SSH_REAL])
    senuelo = huella(services=[ServiceInfo(port=22, protocol="tcp", name="ssh", banner="otro")])
    diferencias = verify_decoy(real, senuelo).differences
    assert any("banner" in d.lower() and "22" in d for d in diferencias)


def test_verify_decoy_sin_diferencias_cuando_todo_coincide() -> None:
    real = huella(services=[SSH_REAL, HTTP_REAL])
    assert verify_decoy(real, real).differences == []


# --- PlausibilityReport: tests que no están ya en test_modelos.py ---------


def test_verify_decoy_devuelve_un_plausibility_report() -> None:
    real = huella()
    assert isinstance(verify_decoy(real, real), PlausibilityReport)


def test_plausibility_report_rechaza_umbral_fuera_de_rango() -> None:
    with pytest.raises(ValidationError):
        PlausibilityReport(score=50, threshold=150, passed=False, differences=[])


# --- H4: huellas reales del laboratorio ------------------------------------------
#
# Escaneos reales (nmap 7.993 con los scripts de banner, limitados a los puertos del
# perfil). Cada host se escaneó dos veces: comparado consigo mismo debe dar 100, o el
# verificador estaría midiendo ruido. El saludo de MySQL lleva un "salt" aleatorio en cada
# conexión, así que se compara por la versión que anuncia, no byte a byte.

FIXTURES = Path(__file__).parent / "fixtures" / "nmap"


def _huella_real(nombre: str) -> Fingerprint:
    (huella_xml,) = parse_nmap_xml((FIXTURES / f"{nombre}.xml").read_text(encoding="utf-8"))
    return huella_xml


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("real_victima01_a", "real_victima01_b"),
        ("real_victima02_a", "real_victima02_b"),
        ("senuelo_web01_ubuntu_a", "senuelo_web01_ubuntu_b"),
    ],
)
def test_dos_escaneos_del_mismo_host_puntuan_100(a: str, b: str) -> None:
    informe = verify_decoy(_huella_real(a), _huella_real(b))
    assert informe.score == 100, informe.differences


def test_senuelo_que_delata_ubuntu_frente_a_un_debian_no_supera_el_umbral() -> None:
    # Línea base H2: OpenCanary anuncia MySQL 5.5.43-0ubuntu0.14.04.1 en un "Debian 13".
    informe = verify_decoy(_huella_real("real_victima01_a"), _huella_real("senuelo_web01_ubuntu_a"))
    assert not informe.passed
    assert any("ubuntu" in d.lower() for d in informe.differences)


def test_senuelo_de_ficheros_solo_difiere_en_redis_y_supera_el_umbral() -> None:
    informe = verify_decoy(_huella_real("real_victima02_a"), _huella_real("senuelo_files02"))
    assert informe.passed
    assert len(informe.differences) == 1
    assert "6379" in informe.differences[0]


SALUDO_A = "[\\x00\\x00\\x00\\x0A5.5.43-0ubuntu0.14.04.1\\x00V\\x07\\x00\\x00NKYB\\x00\\xFF"
SALUDO_B = "[\\x00\\x00\\x00\\x0A5.5.43-0ubuntu0.14.04.1\\x00`\\x07\\x00\\x00Q\\sd^\\x00\\xFF"


def test_saludos_mysql_que_solo_difieren_en_el_salt_coinciden() -> None:
    real = huella(services=[ServiceInfo(port=3306, protocol="tcp", name="mysql", banner=SALUDO_A)])
    senuelo = huella(
        services=[ServiceInfo(port=3306, protocol="tcp", name="mysql", banner=SALUDO_B)]
    )
    assert verify_decoy(real, senuelo).differences == []


def test_saludos_mysql_con_distinta_version_no_coinciden() -> None:
    otro = SALUDO_B.replace("5.5.43-0ubuntu0.14.04.1", "5.5.5-11.8.9-MariaDB-0+deb13u1")
    real = huella(services=[ServiceInfo(port=3306, protocol="tcp", name="mysql", banner=SALUDO_A)])
    senuelo = huella(services=[ServiceInfo(port=3306, protocol="tcp", name="mysql", banner=otro)])
    assert verify_decoy(real, senuelo).score < 100


def test_distinto_producto_en_un_puerto_compartido_penaliza() -> None:
    real = huella(services=[ServiceInfo(port=80, protocol="tcp", name="http", product="nginx")])
    senuelo = huella(
        services=[ServiceInfo(port=80, protocol="tcp", name="http", product="Apache httpd")]
    )
    informe = verify_decoy(real, senuelo)
    assert informe.score == 70
    assert any("Apache httpd" in d for d in informe.differences)


def test_distinta_version_en_un_puerto_compartido_penaliza() -> None:
    real = huella(
        services=[
            ServiceInfo(port=21, protocol="tcp", name="ftp", product="vsftpd", version="3.0.5")
        ]
    )
    senuelo = huella(
        services=[
            ServiceInfo(port=21, protocol="tcp", name="ftp", product="vsftpd", version="2.3.4")
        ]
    )
    assert verify_decoy(real, senuelo).score == 70


def test_banner_que_delata_otra_distribucion_hace_distinguible_el_so() -> None:
    real = huella(
        services=[ServiceInfo(port=22, protocol="tcp", name="ssh", version="9.2p1 Debian 2")]
    )
    senuelo = huella(
        services=[
            ServiceInfo(port=22, protocol="tcp", name="ssh", version="9.2p1 Debian 2"),
            ServiceInfo(port=80, protocol="tcp", name="http", version="2.4.7 (Ubuntu)"),
        ]
    )
    informe = verify_decoy(real, senuelo)
    assert any("ubuntu" in d.lower() and "SO" in d for d in informe.differences)


def test_misma_distribucion_en_ambos_no_es_una_delacion() -> None:
    servicios = [ServiceInfo(port=22, protocol="tcp", name="ssh", version="8.2p1 Ubuntu 4")]
    informe = verify_decoy(huella(services=servicios), huella(services=servicios))
    assert informe.score == 100


def test_senuelo_sin_marcas_de_distribucion_no_se_penaliza_por_ello() -> None:
    real = huella(
        services=[ServiceInfo(port=22, protocol="tcp", name="ssh", version="9.2p1 Debian 2")]
    )
    senuelo = huella(
        services=[ServiceInfo(port=22, protocol="tcp", name="ssh", version="9.2p1 Debian 2")]
    )
    assert verify_decoy(real, senuelo).score == 100
