"""Tests de `AsyncSftpTransport`: implementación real de `SftpTransport` sobre asyncssh.

Sin red: `asyncssh.connect` se sustituye por un doble de prueba que simula un cliente SFTP,
igual que `test_ssh_transport.py` hace con la ejecución de comandos (L1).
"""

import asyncssh
import pytest

from securization.desplegador import AsyncSftpTransport, BreadcrumbAlreadyExistsError, SftpTransport


class _FakeSftpFile:
    def __init__(self, sftp: "_FakeSftpClient", path: str) -> None:
        self._sftp = sftp
        self._path = path

    async def write(self, content: str) -> None:
        self._sftp.writes.append((self._path, content))

    async def __aenter__(self) -> "_FakeSftpFile":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False


class _FakeSftpClient:
    """Doble de `asyncssh.SFTPClient`: registra escrituras y chmod, simula ficheros ya creados."""

    def __init__(
        self,
        *,
        existing: set[str] | None = None,
        exists_code: int = asyncssh.FX_FILE_ALREADY_EXISTS,
        fail_code: int | None = None,
    ) -> None:
        self.writes: list[tuple[str, str]] = []
        self.chmods: list[tuple[str, int]] = []
        self.closed = False
        self._existing = existing or set()
        # OpenSSH (sftp-server) responde FX_FAILURE genérico, no FX_FILE_ALREADY_EXISTS.
        self._exists_code = exists_code
        self._fail_code = fail_code

    def open(self, path: str, mode: str) -> _FakeSftpFile:
        assert mode == "x"
        if path in self._existing:
            raise asyncssh.SFTPError(self._exists_code, "file already exists")
        if self._fail_code is not None:
            raise asyncssh.SFTPError(self._fail_code, "Failure")
        self._existing.add(path)
        return _FakeSftpFile(self, path)

    async def exists(self, path: str) -> bool:
        return path in self._existing

    async def chmod(self, path: str, mode: int) -> None:
        self.chmods.append((path, mode))

    async def __aenter__(self) -> "_FakeSftpClient":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        self.closed = True
        return False


class _FakeSshConnection:
    def __init__(self, sftp: _FakeSftpClient) -> None:
        self._sftp = sftp
        self.closed = False

    def start_sftp_client(self) -> _FakeSftpClient:
        return self._sftp

    async def __aenter__(self) -> "_FakeSshConnection":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        self.closed = True
        return False


class _FakeAsyncsshConnect:
    def __init__(self, connection: _FakeSshConnection) -> None:
        self.connection = connection
        self.calls: list[dict[str, object]] = []

    def __call__(self, host: str, **kwargs: object) -> _FakeSshConnection:
        self.calls.append({"host": host, **kwargs})
        return self.connection


@pytest.fixture
def fake_sftp() -> _FakeSftpClient:
    return _FakeSftpClient()


@pytest.fixture
def fake_connect(
    monkeypatch: pytest.MonkeyPatch, fake_sftp: _FakeSftpClient
) -> _FakeAsyncsshConnect:
    fake = _FakeAsyncsshConnect(_FakeSshConnection(fake_sftp))
    monkeypatch.setattr(asyncssh, "connect", fake)
    return fake


def test_satisface_el_protocolo_sftptransport() -> None:
    assert isinstance(AsyncSftpTransport("10.0.0.10", 22, "lab", "clave"), SftpTransport)


async def test_write_file_conecta_con_host_puerto_usuario_y_password(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    transport = AsyncSftpTransport("10.0.0.10", 2222, "lab", "hunter2")
    await transport.write_file("/root/.env", "APP_ENV=production\n", 0o600)
    (llamada,) = fake_connect.calls
    assert llamada["host"] == "10.0.0.10"
    assert llamada["port"] == 2222
    assert llamada["username"] == "lab"
    assert llamada["password"] == "hunter2"
    assert llamada["known_hosts"] is None


async def test_write_file_escribe_el_contenido_y_aplica_los_permisos(
    fake_connect: _FakeAsyncsshConnect, fake_sftp: _FakeSftpClient
) -> None:
    transport = AsyncSftpTransport("10.0.0.10", 22, "lab", "clave")
    await transport.write_file("/root/.env", "APP_ENV=production\n", 0o600)
    assert fake_sftp.writes == [("/root/.env", "APP_ENV=production\n")]
    assert fake_sftp.chmods == [("/root/.env", 0o600)]


async def test_write_file_abre_en_modo_creacion_exclusiva(
    fake_connect: _FakeAsyncsshConnect, fake_sftp: _FakeSftpClient
) -> None:
    # 'x' en asyncssh es SFTP_CREAT|EXCL|WRITE: crea el fichero y falla si ya existe, en vez
    # de fiarse solo de la comprobación de colisiones hecha al construir el plan (S9).
    transport = AsyncSftpTransport("10.0.0.10", 22, "lab", "clave")
    await transport.write_file("/root/.env", "x", 0o600)
    assert fake_sftp.writes


async def test_write_file_falla_si_la_ruta_ya_existe_en_el_servidor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sftp = _FakeSftpClient(existing={"/root/.env"})
    fake = _FakeAsyncsshConnect(_FakeSshConnection(sftp))
    monkeypatch.setattr(asyncssh, "connect", fake)
    transport = AsyncSftpTransport("10.0.0.10", 22, "lab", "clave")
    with pytest.raises(BreadcrumbAlreadyExistsError, match=r"/root/\.env"):
        await transport.write_file("/root/.env", "x", 0o600)
    assert not sftp.chmods


async def test_write_file_propaga_otros_errores_sftp_sin_envolverlos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _SftpQuePeta(_FakeSftpClient):
        def open(self, path: str, mode: str) -> _FakeSftpFile:
            raise asyncssh.SFTPError(asyncssh.FX_PERMISSION_DENIED, "permission denied")

    fake = _FakeAsyncsshConnect(_FakeSshConnection(_SftpQuePeta()))
    monkeypatch.setattr(asyncssh, "connect", fake)
    transport = AsyncSftpTransport("10.0.0.10", 22, "lab", "clave")
    with pytest.raises(asyncssh.SFTPError, match="permission denied"):
        await transport.write_file("/root/.env", "x", 0o600)


async def test_write_file_cierra_la_conexion_tras_escribir(
    fake_connect: _FakeAsyncsshConnect,
) -> None:
    transport = AsyncSftpTransport("10.0.0.10", 22, "lab", "clave")
    await transport.write_file("/root/.env", "x", 0o600)
    assert fake_connect.connection.closed


async def test_openssh_fx_failure_sobre_fichero_existente_es_ya_existe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Comprobado en el laboratorio: OpenSSH responde FX_FAILURE (no FX_FILE_ALREADY_EXISTS)
    # cuando la creación exclusiva choca con un fichero existente.
    sftp = _FakeSftpClient(existing={"/home/lab/.env"}, exists_code=asyncssh.FX_FAILURE)
    monkeypatch.setattr(asyncssh, "connect", _FakeAsyncsshConnect(_FakeSshConnection(sftp)))
    transporte = AsyncSftpTransport("10.0.0.11", 22, "lab", "x")
    with pytest.raises(BreadcrumbAlreadyExistsError, match=r"/home/lab/\.env"):
        await transporte.write_file("/home/lab/.env", "nuevo", 0o600)
    assert sftp.writes == []


async def test_fx_failure_sin_fichero_existente_se_propaga(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sftp = _FakeSftpClient(fail_code=asyncssh.FX_FAILURE)
    monkeypatch.setattr(asyncssh, "connect", _FakeAsyncsshConnect(_FakeSshConnection(sftp)))
    transporte = AsyncSftpTransport("10.0.0.11", 22, "lab", "x")
    with pytest.raises(asyncssh.SFTPError):
        await transporte.write_file("/no/existe/dir/.env", "x", 0o600)
