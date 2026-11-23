"""Tests de `AsyncSshTransport`: implementación real de `SshTransport` sobre asyncssh.

Sin red: `asyncssh.connect` se sustituye por un doble de prueba que registra los comandos
recibidos y devuelve una salida fija, igual que haría un `SSHClientConnection` real.
"""

from types import SimpleNamespace

import asyncssh
import pytest

from securization.perfilador import AsyncSshTransport, SshTransport


class _FakeCompletedProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


class _FakeSshConnection:
    """Doble de `asyncssh.SSHClientConnection`: registra comandos, devuelve stdout fijo."""

    def __init__(self, stdout: str = "", *, error: Exception | None = None) -> None:
        self.commands: list[str] = []
        self.closed = False
        self._stdout = stdout
        self._error = error

    async def run(self, command: str, check: bool = True) -> _FakeCompletedProcess:
        self.commands.append(command)
        if self._error is not None:
            raise self._error
        return _FakeCompletedProcess(self._stdout)

    async def __aenter__(self) -> "_FakeSshConnection":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        self.closed = True
        return False


class _FakeAsyncsshConnect:
    """Doble de `asyncssh.connect`: registra con qué parámetros se llamó."""

    def __init__(self, connection: _FakeSshConnection) -> None:
        self.connection = connection
        self.calls: list[dict[str, object]] = []

    def __call__(self, host: str, **kwargs: object) -> _FakeSshConnection:
        self.calls.append({"host": host, **kwargs})
        return self.connection


@pytest.fixture
def fake_connect(monkeypatch: pytest.MonkeyPatch) -> _FakeAsyncsshConnect:
    fake = _FakeAsyncsshConnect(_FakeSshConnection(stdout="salida de ejemplo\n"))
    monkeypatch.setattr(asyncssh, "connect", fake)
    return fake


def test_satisface_el_protocolo_sshtransport() -> None:
    assert isinstance(AsyncSshTransport("10.0.0.10", 22, "lab", "clave"), SshTransport)


async def test_run_devuelve_el_stdout(fake_connect: _FakeAsyncsshConnect) -> None:
    transport = AsyncSshTransport("10.0.0.10", 22, "lab", "clave")
    resultado = await transport.run(("cat", "/etc/os-release"))
    assert resultado == "salida de ejemplo\n"


async def test_run_conecta_con_el_host_puerto_usuario_y_password(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    transport = AsyncSshTransport("10.0.0.10", 2222, "lab", "hunter2")
    await transport.run(("ls",))
    (llamada,) = fake_connect.calls
    assert llamada["host"] == "10.0.0.10"
    assert llamada["port"] == 2222
    assert llamada["username"] == "lab"
    assert llamada["password"] == "hunter2"


async def test_run_no_confia_en_claves_de_host_ya_guardadas(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    # El laboratorio recrea las VMs con claves de host distintas cada vez; nunca se debe
    # fallar por un known_hosts desactualizado, ni guardar una clave nueva en disco.
    transport = AsyncSshTransport("10.0.0.10", 22, "lab", "clave")
    await transport.run(("ls",))
    (llamada,) = fake_connect.calls
    assert llamada["known_hosts"] is None


async def test_run_construye_la_linea_de_comando_escapada(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    transport = AsyncSshTransport("10.0.0.10", 22, "lab", "clave")
    await transport.run(("echo", "a; rm -rf /"))
    (comando,) = fake_connect.connection.commands
    assert comando == "echo 'a; rm -rf /'"


async def test_run_cierra_la_conexion_tras_ejecutar(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    transport = AsyncSshTransport("10.0.0.10", 22, "lab", "clave")
    await transport.run(("ls",))
    assert fake_connect.connection.closed


async def test_run_propaga_errores_de_conexion_sin_envolverlos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Boom(Exception):
        pass

    def _raise(host: str, **kwargs: object) -> SimpleNamespace:
        raise _Boom("host inalcanzable")

    monkeypatch.setattr(asyncssh, "connect", _raise)
    transport = AsyncSshTransport("10.0.0.99", 22, "lab", "clave")
    with pytest.raises(Exception, match="host inalcanzable"):
        await transport.run(("ls",))


async def test_run_propaga_errores_de_ejecucion_del_comando(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ComandoFallido(Exception):
        pass

    fake = _FakeAsyncsshConnect(_FakeSshConnection(error=_ComandoFallido("exit 127")))
    monkeypatch.setattr(asyncssh, "connect", fake)
    transport = AsyncSshTransport("10.0.0.10", 22, "lab", "clave")
    with pytest.raises(Exception, match="exit 127"):
        await transport.run(("comando-que-no-existe",))


async def test_lo_que_orchestrate_profiling_construye_funciona_con_el_transporte_real(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    # No perfila de verdad (nada que no sea asyncssh.connect está sustituido), solo
    # confirma que AsyncSshTransport encaja como `transport` de LinuxProfiler.profile.
    from ipaddress import IPv4Address

    from securization.modelos import OsFamily
    from securization.perfilador import LinuxProfiler, ProfilingError

    transport = AsyncSshTransport("10.0.0.10", 22, "lab", "clave")
    with pytest.raises(ProfilingError):
        # La salida falsa ("salida de ejemplo") no es un os-release válido: debe fallar
        # con ProfilingError, no con un error sin interpretar ni un perfil incompleto.
        await LinuxProfiler().profile("victima-01", IPv4Address("10.0.0.10"), transport)
    assert OsFamily.LINUX  # sanity: el import no falla
