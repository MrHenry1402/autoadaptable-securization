"""Tests del inventario: alta/baja de hosts y credenciales SSH cifradas con Fernet."""

import logging
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import Engine
from sqlmodel import create_engine

from securization.inventario import (
    CredentialError,
    CredentialVault,
    HostAlreadyRegisteredError,
    HostNotFoundError,
    Inventory,
)
from securization.modelos import OsFamily

SECRETO = "hunter2-clave-ssh-de-prueba"


@pytest.fixture
def vault() -> CredentialVault:
    return CredentialVault(CredentialVault.generate_key())


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "inventario.db"


@pytest.fixture
def engine(db_path: Path) -> Engine:
    return create_engine(f"sqlite:///{db_path}")


@pytest.fixture
def inventory(engine: Engine, vault: CredentialVault) -> Inventory:
    return Inventory(engine, vault)


def alta(inv: Inventory, host_id: str = "victima-01", address: str = "10.0.0.10") -> None:
    inv.add_host(host_id=host_id, address=address, ssh_user="admin", ssh_secret=SECRETO)


# --- CredentialVault -------------------------------------------------------


def test_vault_ida_y_vuelta(vault: CredentialVault) -> None:
    assert vault.decrypt(vault.encrypt(SECRETO)) == SECRETO


def test_token_no_contiene_el_secreto_en_claro(vault: CredentialVault) -> None:
    assert SECRETO not in vault.encrypt(SECRETO)


def test_cifrar_dos_veces_da_tokens_distintos(vault: CredentialVault) -> None:
    assert vault.encrypt(SECRETO) != vault.encrypt(SECRETO)


def test_clave_incorrecta_falla_con_error_claro(vault: CredentialVault) -> None:
    token = vault.encrypt(SECRETO)
    otra = CredentialVault(CredentialVault.generate_key())
    with pytest.raises(CredentialError):
        otra.decrypt(token)


def test_token_manipulado_falla(vault: CredentialVault) -> None:
    token = vault.encrypt(SECRETO)
    manipulado = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(CredentialError):
        vault.decrypt(manipulado)


@pytest.mark.parametrize("clave", [b"", b"corta", b"no-es-una-clave-fernet-valida"])
def test_clave_invalida_se_rechaza(clave: bytes) -> None:
    with pytest.raises(CredentialError):
        CredentialVault(clave)


def test_from_env_lee_la_clave() -> None:
    clave = CredentialVault.generate_key()
    vault = CredentialVault.from_env({"SECURIZATION_KEY": clave.decode()})
    assert vault.decrypt(vault.encrypt(SECRETO)) == SECRETO


def test_from_env_sin_clave_falla() -> None:
    with pytest.raises(CredentialError, match="SECURIZATION_KEY"):
        CredentialVault.from_env({})


def test_generate_key_produce_clave_fernet_valida() -> None:
    Fernet(CredentialVault.generate_key())


# --- Inventory: alta y consulta -------------------------------------------


def test_alta_y_consulta(inventory: Inventory) -> None:
    host = inventory.add_host(
        host_id="victima-01",
        address="10.0.0.10",
        ssh_user="admin",
        ssh_secret=SECRETO,
        ssh_port=2222,
    )
    assert host.host_id == "victima-01"
    assert host.address == "10.0.0.10"
    assert host.ssh_user == "admin"
    assert host.ssh_port == 2222
    assert host.os_family is OsFamily.LINUX
    assert inventory.get_host("victima-01").address == "10.0.0.10"


def test_puerto_ssh_por_defecto_es_22(inventory: Inventory) -> None:
    alta(inventory)
    assert inventory.get_host("victima-01").ssh_port == 22


def test_listado_ordenado_por_host_id(inventory: Inventory) -> None:
    alta(inventory, "victima-02", "10.0.0.11")
    alta(inventory, "victima-01", "10.0.0.10")
    assert [h.host_id for h in inventory.list_hosts()] == ["victima-01", "victima-02"]


def test_listado_vacio(inventory: Inventory) -> None:
    assert inventory.list_hosts() == []


def test_is_registered_por_direccion(inventory: Inventory) -> None:
    alta(inventory)
    assert inventory.is_registered("10.0.0.10")
    assert not inventory.is_registered("10.0.0.99")


def test_consultar_host_inexistente(inventory: Inventory) -> None:
    with pytest.raises(HostNotFoundError):
        inventory.get_host("no-existe")


# --- Inventory: validación y duplicados -----------------------------------


def test_host_id_duplicado(inventory: Inventory) -> None:
    alta(inventory)
    with pytest.raises(HostAlreadyRegisteredError):
        alta(inventory, "victima-01", "10.0.0.50")


def test_direccion_duplicada(inventory: Inventory) -> None:
    alta(inventory)
    with pytest.raises(HostAlreadyRegisteredError):
        alta(inventory, "otro-host", "10.0.0.10")


def test_duplicado_no_modifica_el_inventario(inventory: Inventory) -> None:
    alta(inventory)
    with pytest.raises(HostAlreadyRegisteredError):
        alta(inventory, "victima-01", "10.0.0.50")
    assert [h.address for h in inventory.list_hosts()] == ["10.0.0.10"]


@pytest.mark.parametrize("direccion", ["no-es-una-ip", "999.0.0.1", "10.0.0", ""])
def test_direccion_invalida(inventory: Inventory, direccion: str) -> None:
    with pytest.raises(ValueError, match="address"):
        alta(inventory, "host-x", direccion)


@pytest.mark.parametrize("host_id", ["", "Mayusculas", "con espacio", "-empieza", "a/b", "x" * 64])
def test_host_id_invalido(inventory: Inventory, host_id: str) -> None:
    with pytest.raises(ValueError, match="host_id"):
        alta(inventory, host_id, "10.0.0.20")


@pytest.mark.parametrize("puerto", [0, 65536, -1])
def test_puerto_ssh_invalido(inventory: Inventory, puerto: int) -> None:
    with pytest.raises(ValueError, match="ssh_port"):
        inventory.add_host(
            host_id="host-x",
            address="10.0.0.20",
            ssh_user="admin",
            ssh_secret=SECRETO,
            ssh_port=puerto,
        )


def test_secreto_vacio_se_rechaza(inventory: Inventory) -> None:
    with pytest.raises(ValueError, match="ssh_secret"):
        inventory.add_host(host_id="host-x", address="10.0.0.20", ssh_user="admin", ssh_secret="")


# --- Inventory: baja ------------------------------------------------------


def test_baja(inventory: Inventory) -> None:
    alta(inventory)
    inventory.remove_host("victima-01")
    assert inventory.list_hosts() == []
    assert not inventory.is_registered("10.0.0.10")


def test_baja_de_host_inexistente(inventory: Inventory) -> None:
    with pytest.raises(HostNotFoundError):
        inventory.remove_host("no-existe")


def test_se_puede_volver_a_dar_de_alta_tras_la_baja(inventory: Inventory) -> None:
    alta(inventory)
    inventory.remove_host("victima-01")
    alta(inventory)
    assert inventory.is_registered("10.0.0.10")


# --- Inventory: persistencia y credenciales -------------------------------


def test_persistencia_entre_instancias(engine: Engine, vault: CredentialVault) -> None:
    alta(Inventory(engine, vault))
    otra = Inventory(engine, vault)
    assert otra.get_host("victima-01").address == "10.0.0.10"


def test_recuperar_el_secreto_ssh(inventory: Inventory) -> None:
    alta(inventory)
    assert inventory.get_ssh_secret("victima-01") == SECRETO


def test_recuperar_secreto_de_host_inexistente(inventory: Inventory) -> None:
    with pytest.raises(HostNotFoundError):
        inventory.get_ssh_secret("no-existe")


def test_el_secreto_no_se_guarda_en_claro(inventory: Inventory, db_path: Path) -> None:
    alta(inventory)
    with sqlite3.connect(db_path) as con:
        filas = con.execute("SELECT * FROM host").fetchall()
    assert filas
    assert SECRETO not in repr(filas)
    assert SECRETO.encode() not in db_path.read_bytes()


def test_el_secreto_no_aparece_en_la_representacion_del_host(inventory: Inventory) -> None:
    alta(inventory)
    host = inventory.get_host("victima-01")
    for texto in (repr(host), str(host), host.model_dump_json()):
        assert SECRETO not in texto


def test_el_secreto_no_se_escribe_en_los_logs(
    inventory: Inventory, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.DEBUG):
        alta(inventory)
        inventory.get_ssh_secret("victima-01")
        inventory.remove_host("victima-01")
    assert SECRETO not in caplog.text


def test_con_otra_clave_no_se_puede_leer_el_secreto(engine: Engine, vault: CredentialVault) -> None:
    alta(Inventory(engine, vault))
    otra = Inventory(engine, CredentialVault(CredentialVault.generate_key()))
    with pytest.raises(CredentialError):
        otra.get_ssh_secret("victima-01")
