"""Dobles compartidos: un `Entorno` de operaciones sin red (SSH, SFTP y nmap falsos).

Lo usan los tests de `operaciones.py` y los de las acciones del dashboard. Las salidas son
reales, guardadas en `tests/fixtures/`.
"""

from collections.abc import Sequence
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.inventario import CredentialVault, Inventory
from securization.parsers_linux import DPKG_CMD, LS_ROOT_CMD, OS_RELEASE_CMD, SS_CMD

FIX = Path(__file__).parent / "fixtures"


def leer(ruta: str) -> str:
    return (FIX / ruta).read_text(encoding="utf-8")


class FakeSsh:
    def __init__(
        self, respuestas: dict[tuple[str, ...], str] | None = None, defecto: str = ""
    ) -> None:
        self.respuestas = respuestas or {}
        self.defecto = defecto
        self.calls: list[tuple[str, ...]] = []

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        return self.respuestas.get(tuple(argv), self.defecto)


class FakeSftp:
    def __init__(self) -> None:
        self.written: list[str] = []

    async def write_file(self, path: str, content: str, mode: int) -> None:
        self.written.append(path)


class FakeRunner:
    """nmap falso: el equipo real y la trampa devuelven escaneos reales del mismo host."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def run(self, argv: Sequence[str]) -> str:
        self.calls.append(tuple(argv))
        if "10.0.0.50" in argv:
            return leer("nmap/real_victima01_b.xml").replace("10.0.0.10", "10.0.0.50")
        return leer("nmap/real_victima01_a.xml")


class FakeEntorno:
    deception_host = "deception-central"
    decoy_config_dir = "/home/lab/decoys"
    decoy_startup_s = 0.0

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.vault = CredentialVault(CredentialVault.generate_key())
        self.runner = FakeRunner()
        self.victima = FakeSsh(
            {
                OS_RELEASE_CMD: leer("linux/os_release_debian12.txt"),
                SS_CMD: leer("linux/ss_tlnp_root.txt"),
                LS_ROOT_CMD: leer("linux/ls_root.txt"),
                DPKG_CMD: leer("linux/dpkg_query_victima01.txt"),
                ("sh", "-c", 'getent passwd "$(id -un)" | cut -d: -f6'): "/home/lab\n",
                ("ls", "-A", "/home/lab"): ".bashrc\n.profile\n",
            }
        )
        self.central = FakeSsh()
        self.sftps: dict[str, FakeSftp] = {}
        inv = self.inventory
        inv.add_host(host_id="victima-01", address="10.0.0.10", ssh_user="lab", ssh_secret="x")
        inv.add_host(
            host_id="deception-central", address="10.0.0.5", ssh_user="lab", ssh_secret="x"
        )

    @property
    def inventory(self) -> Inventory:
        return Inventory(self.engine, self.vault)

    def ssh(self, host_id: str) -> FakeSsh:
        return self.central if host_id == self.deception_host else self.victima

    def sftp(self, host_id: str) -> FakeSftp:
        return self.sftps.setdefault(host_id, FakeSftp())


@pytest.fixture
def entorno(tmp_path: Path) -> FakeEntorno:
    return FakeEntorno(create_engine(f"sqlite:///{tmp_path / 'op.db'}"))
