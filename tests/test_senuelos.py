"""Tests del arranque de deception hosts en contenedores OpenCanary (L3).

Toda la E/S va detrás de `SshTransport` (docker) y `SftpTransport` (config), con dobles
que registran lo que se habría ejecutado. Los comandos son listas de argumentos fijas; el
único texto variable que llega a ellas (node_id, IP, ruta) se valida antes.
"""

import json
from collections.abc import Sequence
from ipaddress import IPv4Address

import pytest

from securization.desplegador import (
    DEFAULT_DECOY_IMAGE,
    DEFAULT_DECOY_NETWORK,
    BreadcrumbAlreadyExistsError,
    DeploymentNotReadyError,
    approve_plan,
    build_decoy_remove_command,
    build_decoy_run_command,
    build_deployment_plan,
    decoy_config_path,
    decoy_container_name,
    decoy_mac,
    deploy_decoy,
    start_decoy,
    stop_decoy,
)
from securization.generador import Campaign, DecoyConfig, render_opencanary_conf
from securization.modelos import PlausibilityReport
from securization.perfilador import SshTransport

DECOY = DecoyConfig(
    node_id="files-02",
    address=IPv4Address("10.0.0.50"),
    opencanary_config={
        "device.node_id": "files-02",
        "ssh.enabled": True,
        "ssh.port": 22,
        "ssh.version": "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4",
    },
)
CONFIG_DIR = "/home/lab/decoys"


class FakeSshTransport:
    """Doble de `SshTransport`: registra cada comando y devuelve una salida fija."""

    def __init__(self, *, fail_on: str | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._fail_on = fail_on

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        if self._fail_on is not None and self._fail_on in argv:
            raise RuntimeError(f"fallo simulado en {self._fail_on}")
        return ""


class FakeSftpTransport:
    """Doble de `SftpTransport` con creación exclusiva, como el real."""

    def __init__(self, *, existing: Sequence[str] = ()) -> None:
        self.written: list[tuple[str, str, int]] = []
        self._existing = set(existing)

    async def write_file(self, path: str, content: str, mode: int) -> None:
        if path in self._existing or path in {p for p, _, _ in self.written}:
            raise BreadcrumbAlreadyExistsError(path)
        self.written.append((path, content, mode))


def test_fake_ssh_transport_satisface_el_protocolo() -> None:
    assert isinstance(FakeSshTransport(), SshTransport)


# --- Identidad del contenedor -------------------------------------------------


def test_nombre_del_contenedor_lleva_prefijo_decoy() -> None:
    assert decoy_container_name("files-02") == "decoy-files-02"


@pytest.mark.parametrize("node_id", ["", "Files", "files 02", "-x", "x;rm", "a" * 64, "--rm"])
def test_nombre_del_contenedor_rechaza_node_id_no_valido(node_id: str) -> None:
    with pytest.raises(ValueError, match="node_id"):
        decoy_container_name(node_id)


def test_mac_usa_el_oui_de_virtualbox_y_no_el_de_docker() -> None:
    mac = decoy_mac("files-02")
    assert mac.startswith("08:00:27:")
    assert len(mac.split(":")) == 6
    assert all(len(octeto) == 2 for octeto in mac.split(":"))


def test_mac_es_determinista_y_distinta_por_node_id() -> None:
    assert decoy_mac("files-02") == decoy_mac("files-02")
    assert decoy_mac("files-02") != decoy_mac("web-01")


def test_ruta_de_config_depende_del_contenido() -> None:
    a = decoy_config_path(CONFIG_DIR, "files-02", "conf A")
    b = decoy_config_path(CONFIG_DIR, "files-02", "conf B")
    assert a.startswith(f"{CONFIG_DIR}/files-02-")
    assert a.endswith(".conf")
    assert a != b
    assert a == decoy_config_path(CONFIG_DIR, "files-02", "conf A")


@pytest.mark.parametrize("directorio", ["relativo/dir", "/home/lab/../etc", "/home/lab dir", ""])
def test_ruta_de_config_rechaza_directorios_no_validos(directorio: str) -> None:
    with pytest.raises(ValueError, match="config_dir"):
        decoy_config_path(directorio, "files-02", "conf")


# --- Comandos docker ----------------------------------------------------------


def test_comando_de_arranque_completo() -> None:
    ruta = "/home/lab/decoys/files-02-abc.conf"
    assert build_decoy_run_command(DECOY, config_path=ruta) == (
        "docker",
        "run",
        "-d",
        "--name",
        "decoy-files-02",
        "--network",
        DEFAULT_DECOY_NETWORK,
        "--ip",
        "10.0.0.50",
        "--mac-address",
        decoy_mac("files-02"),
        "--hostname",
        "files-02",
        "-v",
        f"{ruta}:/etc/opencanaryd/opencanary.conf:ro",
        DEFAULT_DECOY_IMAGE,
    )


def test_imagen_por_defecto_fijada_por_digest() -> None:
    assert "@sha256:" in DEFAULT_DECOY_IMAGE


def test_comando_de_arranque_admite_red_e_imagen_propias() -> None:
    comando = build_decoy_run_command(
        DECOY, config_path="/srv/x.conf", network="otra-red", image="mi/imagen@sha256:abc"
    )
    assert comando[comando.index("--network") + 1] == "otra-red"
    assert comando[-1] == "mi/imagen@sha256:abc"


def test_comando_de_arranque_rechaza_una_ruta_de_config_relativa() -> None:
    with pytest.raises(ValueError, match="config_path"):
        build_decoy_run_command(DECOY, config_path="x.conf")


def test_comando_de_borrado() -> None:
    assert build_decoy_remove_command("files-02") == ("docker", "rm", "-f", "decoy-files-02")


# --- start_decoy / stop_decoy ---------------------------------------------------


async def test_start_decoy_sube_el_config_renderizado_y_arranca_el_contenedor() -> None:
    ssh, sftp = FakeSshTransport(), FakeSftpTransport()
    nombre = await start_decoy(DECOY, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)

    assert nombre == "decoy-files-02"
    conf = render_opencanary_conf(DECOY.opencanary_config)
    ruta = decoy_config_path(CONFIG_DIR, "files-02", conf)
    assert sftp.written == [(ruta, conf, 0o644)]
    assert ssh.calls == [
        ("mkdir", "-p", CONFIG_DIR),
        build_decoy_remove_command("files-02"),
        build_decoy_run_command(DECOY, config_path=ruta),
    ]


async def test_start_decoy_activa_solo_los_modulos_del_senuelo() -> None:
    sftp = FakeSftpTransport()
    await start_decoy(DECOY, sftp=sftp, ssh=FakeSshTransport(), config_dir=CONFIG_DIR)
    conf = json.loads(sftp.written[0][1])
    assert sorted(c for c, v in conf.items() if c.endswith(".enabled") and v) == ["ssh.enabled"]


async def test_start_decoy_reutiliza_un_config_identico_ya_subido() -> None:
    # Bucle de ajuste: relanzar el mismo señuelo no debe fallar por la creación exclusiva.
    conf = render_opencanary_conf(DECOY.opencanary_config)
    ruta = decoy_config_path(CONFIG_DIR, "files-02", conf)
    ssh, sftp = FakeSshTransport(), FakeSftpTransport(existing=[ruta])
    await start_decoy(DECOY, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)
    assert sftp.written == []
    assert ssh.calls[-1] == build_decoy_run_command(DECOY, config_path=ruta)


async def test_start_decoy_con_config_distinto_sube_otro_fichero() -> None:
    sftp, ssh = FakeSftpTransport(), FakeSshTransport()
    await start_decoy(DECOY, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)
    ajustado = DECOY.model_copy(
        update={"opencanary_config": {**DECOY.opencanary_config, "ssh.port": 2222}}
    )
    await start_decoy(ajustado, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)
    assert len({ruta for ruta, _, _ in sftp.written}) == 2


async def test_start_decoy_no_arranca_si_falla_el_borrado_previo() -> None:
    ssh = FakeSshTransport(fail_on="rm")
    with pytest.raises(RuntimeError):
        await start_decoy(DECOY, sftp=FakeSftpTransport(), ssh=ssh, config_dir=CONFIG_DIR)
    assert all(c[:2] != ("docker", "run") for c in ssh.calls)


async def test_start_decoy_con_claves_desconocidas_falla_antes_de_tocar_nada() -> None:
    malo = DECOY.model_copy(update={"opencanary_config": {"inventada.enabled": True}})
    ssh, sftp = FakeSshTransport(), FakeSftpTransport()
    with pytest.raises(ValueError, match="inventada"):
        await start_decoy(malo, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)
    assert ssh.calls == []
    assert sftp.written == []


async def test_stop_decoy_borra_el_contenedor() -> None:
    ssh = FakeSshTransport()
    await stop_decoy("files-02", ssh=ssh)
    assert ssh.calls == [build_decoy_remove_command("files-02")]


# --- deploy_decoy: despliegue definitivo con aprobación ---------------------------

CAMPANA = Campaign(
    campaign_id="campana-victima-02", host_id="victima-02", decoy=DECOY, breadcrumbs=[]
)


def _reporte(score: int) -> PlausibilityReport:
    return PlausibilityReport(score=score, threshold=90, passed=score >= 90, differences=[])


async def test_deploy_decoy_sin_aprobar_no_toca_nada() -> None:
    plan = build_deployment_plan(CAMPANA, _reporte(95))
    ssh, sftp = FakeSshTransport(), FakeSftpTransport()
    with pytest.raises(DeploymentNotReadyError):
        await deploy_decoy(plan, CAMPANA, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)
    assert ssh.calls == []
    assert sftp.written == []


async def test_deploy_decoy_aprobado_arranca_el_senuelo() -> None:
    plan = approve_plan(build_deployment_plan(CAMPANA, _reporte(95)))
    ssh = FakeSshTransport()
    nombre = await deploy_decoy(
        plan, CAMPANA, sftp=FakeSftpTransport(), ssh=ssh, config_dir=CONFIG_DIR
    )
    assert nombre == "decoy-files-02"
    assert ssh.calls[-1][:2] == ("docker", "run")


async def test_deploy_decoy_rechaza_un_plan_de_otra_campana() -> None:
    otra = CAMPANA.model_copy(update={"campaign_id": "otra"})
    plan = approve_plan(build_deployment_plan(otra, _reporte(95)))
    with pytest.raises(ValueError, match="campaign_id"):
        await deploy_decoy(
            plan, CAMPANA, sftp=FakeSftpTransport(), ssh=FakeSshTransport(), config_dir=CONFIG_DIR
        )
