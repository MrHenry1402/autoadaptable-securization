"""Tests de la CLI `securization` (H6): el flujo completo desde una terminal.

La E/S real (SSH, SFTP, nmap, Ollama) se crea en `Runtime`; aquí se sustituye por dobles,
igual que en el resto de módulos. Las contraseñas nunca llegan por argumentos.
"""

import json
from collections.abc import Sequence
from ipaddress import IPv4Address
from pathlib import Path

import pytest

from securization import cli
from securization.desplegador import DeploymentPlanStore, build_deployment_plan
from securization.eventos import EventStore
from securization.generador import Campaign, CampaignStore, DecoyConfig
from securization.inventario import CredentialVault, Inventory
from securization.modelos import HostProfile, OsFamily, PlausibilityReport, ServiceInfo
from securization.perfilador import HostProfileStore

LOG_REAL = (
    Path(__file__).parent / "fixtures" / "opencanary" / "alertas_breadcrumbs.jsonl"
).read_text(encoding="utf-8")


class FakeSsh:
    def __init__(self, salida: str = "") -> None:
        self.calls: list[tuple[str, ...]] = []
        self.salida = salida

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        return self.salida


class FakeSftp:
    def __init__(self) -> None:
        self.written: list[str] = []

    async def write_file(self, path: str, content: str, mode: int) -> None:
        self.written.append(path)


class FakeRuntime(cli.Runtime):
    """Runtime con transportes falsos; registra a qué host se conecta cada uno."""

    def __init__(self, base: Path, ssh_salida: str = "") -> None:
        key = base / "test.key"
        if not key.exists():
            key.write_bytes(CredentialVault.generate_key())
        super().__init__(db_path=base / "t.db", key_path=key)
        self.ssh_por_host: dict[str, FakeSsh] = {}
        self.sftp_por_host: dict[str, FakeSftp] = {}
        self._ssh_salida = ssh_salida

    def ssh(self, host_id: str) -> FakeSsh:  # type: ignore[override]
        return self.ssh_por_host.setdefault(host_id, FakeSsh(self._ssh_salida))

    def sftp(self, host_id: str) -> FakeSftp:  # type: ignore[override]
        return self.sftp_por_host.setdefault(host_id, FakeSftp())


def _reporte(score: int) -> PlausibilityReport:
    return PlausibilityReport(score=score, threshold=90, passed=score >= 90, differences=[])


CAMPANA = Campaign(
    campaign_id="campana-victima-02",
    host_id="victima-02",
    decoy=DecoyConfig(
        node_id="files-02",
        address=IPv4Address("10.0.0.51"),
        opencanary_config={
            "device.node_id": "files-02",
            "ftp.enabled": True,
            "ftp.port": 21,
            "redis.enabled": True,
            "redis.port": 6379,
        },
    ),
    breadcrumbs=[],
)


@pytest.fixture
def rt(tmp_path: Path) -> FakeRuntime:
    return FakeRuntime(tmp_path)


# --- Parser -----------------------------------------------------------------------


def test_parser_reconoce_el_flujo_completo() -> None:
    parser = cli.build_parser()
    for argv in (
        ["hosts", "list"],
        ["hosts", "add", "victima-01", "10.0.0.10", "--user", "lab"],
        ["profile", "victima-01"],
        ["name", "victima-01", "--model", "qwen3:8b"],
        ["campaign", "victima-01", "--decoy-node", "web-01", "--decoy-ip", "10.0.0.50"],
        ["approve", "campana-victima-01"],
        ["deploy", "campana-victima-01"],
        ["events", "collect"],
        ["events", "list"],
        ["dashboard", "--port", "8000"],
    ):
        assert parser.parse_args(argv).command == argv[0]


def test_hosts_add_no_acepta_la_contrasena_por_argumentos() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["hosts", "add", "x", "10.0.0.1", "--password", "p"])


def test_campaign_rechaza_una_ip_de_senuelo_no_valida() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["campaign", "victima-01", "--decoy-node", "web-01", "--decoy-ip", "10.0.0.500"]
        )


# --- hosts --------------------------------------------------------------------------


async def test_hosts_add_pide_la_contrasena_y_la_guarda_cifrada(
    rt: FakeRuntime, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "getpass", lambda _prompt: "secreto-de-prueba")
    args = cli.build_parser().parse_args(
        ["hosts", "add", "victima-01", "10.0.0.10", "--user", "lab"]
    )
    await cli.run_command(args, rt)
    inventario = Inventory(rt.engine, rt.vault)
    assert inventario.get_ssh_secret("victima-01") == "secreto-de-prueba"
    assert "secreto-de-prueba" not in capsys.readouterr().out


async def test_hosts_list_muestra_los_hosts(
    rt: FakeRuntime, capsys: pytest.CaptureFixture[str]
) -> None:
    Inventory(rt.engine, rt.vault).add_host(
        host_id="victima-01", address="10.0.0.10", ssh_user="lab", ssh_secret="x"
    )
    await cli.run_command(cli.build_parser().parse_args(["hosts", "list"]), rt)
    salida = capsys.readouterr().out
    assert "victima-01" in salida
    assert "10.0.0.10" in salida
    assert "lab@10.0.0.10:22" in salida
    assert "@:" not in salida


# --- campaign -----------------------------------------------------------------------


class _SshConHome(FakeSsh):
    """Doble que responde al comando del home y al `ls` como lo haría el host real."""

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        if argv[0] == "ls":
            return ".bashrc\n.env\n"
        return "/home/lab\n"


async def test_campaign_con_colision_falla_con_mensaje_claro_sin_arrancar_nada(
    rt: FakeRuntime,
) -> None:
    # Visto en el ensayo de la demo: un .env ya existente en el home del host real.
    perfil = HostProfile(
        host_id="victima-01",
        address=IPv4Address("10.0.0.10"),
        os_family=OsFamily.LINUX,
        os_name="Debian GNU/Linux 13 (trixie)",
        services=[ServiceInfo(port=3306, protocol="tcp", name="mysql")],
    )
    HostProfileStore(rt.engine).save(perfil)
    rt.ssh_por_host["victima-01"] = _SshConHome()
    args = cli.build_parser().parse_args(
        ["campaign", "victima-01", "--decoy-node", "web-01", "--decoy-ip", "10.0.0.50"]
    )
    with pytest.raises(SystemExit, match=r"/home/lab/\.env.*nunca sobrescribe"):
        await cli.run_command(args, rt)
    assert "deception-central" not in rt.ssh_por_host


# --- approve ------------------------------------------------------------------------


async def test_approve_aprueba_un_plan_que_supera_el_umbral(rt: FakeRuntime) -> None:
    DeploymentPlanStore(rt.engine).save(build_deployment_plan(CAMPANA, _reporte(95)))
    await cli.run_command(cli.build_parser().parse_args(["approve", CAMPANA.campaign_id]), rt)
    assert DeploymentPlanStore(rt.engine).load(CAMPANA.campaign_id).approved


async def test_approve_por_debajo_del_umbral_falla_con_mensaje(rt: FakeRuntime) -> None:
    DeploymentPlanStore(rt.engine).save(build_deployment_plan(CAMPANA, _reporte(50)))
    with pytest.raises(SystemExit, match="umbral"):
        await cli.run_command(cli.build_parser().parse_args(["approve", CAMPANA.campaign_id]), rt)


# --- deploy -------------------------------------------------------------------------


async def test_deploy_sin_aprobar_no_toca_nada(rt: FakeRuntime) -> None:
    CampaignStore(rt.engine).save(CAMPANA)
    DeploymentPlanStore(rt.engine).save(build_deployment_plan(CAMPANA, _reporte(95)))
    with pytest.raises(SystemExit, match="aprob"):
        await cli.run_command(cli.build_parser().parse_args(["deploy", CAMPANA.campaign_id]), rt)
    assert rt.ssh_por_host == {}
    assert rt.sftp_por_host == {}


# --- events -------------------------------------------------------------------------


async def test_events_collect_lee_cada_senuelo_y_guarda_sin_duplicar(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rt = FakeRuntime(tmp_path, ssh_salida=LOG_REAL)
    CampaignStore(rt.engine).save(CAMPANA)
    args = cli.build_parser().parse_args(["events", "collect"])
    await cli.run_command(args, rt)
    await cli.run_command(args, rt)
    assert len(EventStore(rt.engine).list_recent()) == 5
    (llamada,) = {c for s in rt.ssh_por_host.values() for c in s.calls}
    assert llamada[:3] == ("docker", "exec", "decoy-files-02")
    assert list(rt.ssh_por_host) == [rt.deception_host]
    salida = capsys.readouterr().out
    assert "5 nuevas" in salida
    assert "0 nuevas" in salida


async def test_events_list_muestra_las_alertas_y_el_breadcrumb(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rt = FakeRuntime(tmp_path, ssh_salida=LOG_REAL)
    CampaignStore(rt.engine).save(CAMPANA)
    await cli.run_command(cli.build_parser().parse_args(["events", "collect"]), rt)
    await cli.run_command(cli.build_parser().parse_args(["events", "list"]), rt)
    salida = capsys.readouterr().out
    assert "campana-victima-02" in salida
    assert "breadcrumb ftp" in salida


# --- Runtime --------------------------------------------------------------------------


def test_runtime_lee_la_clave_de_fichero_y_no_la_imprime(tmp_path: Path) -> None:
    key = tmp_path / "k.key"
    key.write_bytes(CredentialVault.generate_key())
    rt = cli.Runtime(db_path=tmp_path / "x.db", key_path=key)
    assert isinstance(rt.vault, CredentialVault)
    assert "k.key" not in repr(rt.vault)


def test_runtime_sin_clave_falla_con_error_claro(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="clave"):
        cli.Runtime(db_path=tmp_path / "x.db", key_path=tmp_path / "no-existe.key")


def test_events_collect_json_valido_en_el_fixture() -> None:
    assert all(json.loads(linea) for linea in LOG_REAL.splitlines())


def test_runtime_usa_la_clave_de_la_variable_de_entorno(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SECURIZATION_KEY", CredentialVault.generate_key().decode())
    rt = cli.Runtime(db_path=tmp_path / "x.db", key_path=tmp_path / "no-existe.key")
    assert isinstance(rt.vault, CredentialVault)


def test_runtime_from_env_lee_la_configuracion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "k.key"
    key.write_bytes(CredentialVault.generate_key())
    monkeypatch.setenv("SECURIZATION_DB", str(tmp_path / "x.db"))
    monkeypatch.setenv("SECURIZATION_KEY_FILE", str(key))
    monkeypatch.setenv("SECURIZATION_DECEPTION_HOST", "dc-2")
    monkeypatch.setenv("SECURIZATION_DECOY_DIR", "/srv/decoys")
    rt = cli.Runtime.from_env()
    assert (rt.deception_host, rt.decoy_config_dir) == ("dc-2", "/srv/decoys")


# --- campaign y deploy por las operaciones (con barra de progreso) -------------------------


async def test_campaign_imprime_los_intentos_y_el_plan(
    rt: FakeRuntime, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from securization.operaciones import ResultadoCampana
    from securization.orquestador import VerificationAttempt, VerificationResult

    plan = build_deployment_plan(CAMPANA, _reporte(90))
    verificacion = VerificationResult(
        campaign=CAMPANA,
        report=_reporte(90),
        attempts=[VerificationAttempt(attempt=1, opencanary_config={}, report=_reporte(90))],
        stop_reason="aprobado",
    )

    async def falso(*_a: object, **_k: object) -> ResultadoCampana:
        return ResultadoCampana(verificacion, plan)

    monkeypatch.setattr(cli, "crear_campana", falso)
    args = cli.build_parser().parse_args(
        ["campaign", "victima-02", "--decoy-node", "files-02", "--decoy-ip", "10.0.0.51"]
    )
    await cli.run_command(args, rt)
    salida = capsys.readouterr().out
    assert "Intento 1: 90/90" in salida
    assert "guardado SIN aprobar" in salida


async def test_deploy_aprobado_imprime_lo_desplegado(
    rt: FakeRuntime, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    DeploymentPlanStore(rt.engine).save(build_deployment_plan(CAMPANA, _reporte(95)))

    async def falso(*_a: object, **_k: object) -> str:
        return "decoy-files-02"

    monkeypatch.setattr(cli, "desplegar", falso)
    await cli.run_command(cli.build_parser().parse_args(["deploy", CAMPANA.campaign_id]), rt)
    assert "señuelo decoy-files-02" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("host", "forzar", "esperado"),
    [
        ("127.0.0.1", False, True),
        ("::1", False, True),
        ("localhost", False, True),
        ("0.0.0.0", False, False),  # noqa: S104 - es justo el caso que se prueba
        ("0.0.0.0", True, True),  # noqa: S104
        ("mi-servidor", False, False),
    ],
)
def test_acciones_solo_en_local_salvo_que_se_fuercen(
    host: str, forzar: bool, esperado: bool
) -> None:
    assert cli.acciones_permitidas(host, forzar) is esperado


def test_ip_local_hacia_localhost() -> None:
    assert cli.ip_local_hacia("127.0.0.1") == "127.0.0.1"


def test_ip_local_hacia_destino_no_valido() -> None:
    assert cli.ip_local_hacia("no-es-una-ip.invalid") is None
