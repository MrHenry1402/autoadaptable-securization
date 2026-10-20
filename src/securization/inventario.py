"""Alta/baja de hosts y almacenamiento cifrado (Fernet) de credenciales SSH de gestión.

Los secretos solo existen en claro en memoria, durante la llamada que los usa: en la base de
datos se guarda únicamente el token Fernet, y la clave se obtiene de fuera del repositorio.
"""

import logging
import os
import re
from collections.abc import Mapping
from ipaddress import IPv4Address

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import Engine
from sqlalchemy.exc import IntegrityError
from sqlmodel import Field, Session, SQLModel, col, select

from securization.modelos import OsFamily

logger = logging.getLogger(__name__)

KEY_ENV_VAR = "SECURIZATION_KEY"
_HOST_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


class CredentialError(Exception):
    """Clave o token de credenciales inválido, o no se puede descifrar."""


class HostNotFoundError(Exception):
    """El host no está dado de alta en el inventario."""


class HostAlreadyRegisteredError(Exception):
    """Ya existe un host con ese identificador o esa dirección."""


class CredentialVault:
    """Cifra y descifra secretos con Fernet."""

    def __init__(self, key: bytes) -> None:
        try:
            self._fernet = Fernet(key)
        except (ValueError, TypeError):
            raise CredentialError("Clave Fernet inválida") from None

    @staticmethod
    def generate_key() -> bytes:
        """Genera una clave Fernet nueva."""
        return Fernet.generate_key()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "CredentialVault":
        """Crea el vault con la clave de la variable de entorno `SECURIZATION_KEY`."""
        entorno = os.environ if environ is None else environ
        clave = entorno.get(KEY_ENV_VAR)
        if not clave:
            raise CredentialError(f"Falta la variable de entorno {KEY_ENV_VAR}")
        return cls(clave.encode())

    def encrypt(self, secret: str) -> str:
        return self._fernet.encrypt(secret.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            raise CredentialError(
                "No se pudo descifrar: clave incorrecta o token alterado"
            ) from None


class Host(SQLModel, table=True):
    """Host registrado. El secreto SSH se guarda cifrado y no aparece en repr ni en JSON."""

    id: int | None = Field(default=None, primary_key=True)
    host_id: str = Field(unique=True, index=True)
    address: str = Field(unique=True, index=True)
    ssh_user: str
    ssh_port: int = 22
    os_family: OsFamily = OsFamily.LINUX
    ssh_secret_token: str = Field(repr=False, exclude=True)


def _validate(host_id: str, address: str, ssh_port: int, ssh_secret: str) -> str:
    """Valida los datos de alta y devuelve la dirección normalizada."""
    if not _HOST_ID_RE.fullmatch(host_id):
        raise ValueError("host_id inválido: use minúsculas, dígitos y guiones (máx. 63)")
    try:
        direccion = str(IPv4Address(address))
    except ValueError:
        raise ValueError(f"address inválida: {address!r}") from None
    if not 1 <= ssh_port <= 65535:
        raise ValueError("ssh_port fuera de rango (1-65535)")
    if not ssh_secret:
        raise ValueError("ssh_secret no puede estar vacío")
    return direccion


class Inventory:
    """Inventario de hosts registrados sobre SQLite."""

    def __init__(self, engine: Engine, vault: CredentialVault) -> None:
        self._engine = engine
        self._vault = vault
        SQLModel.metadata.create_all(engine)

    def _session(self) -> Session:
        return Session(self._engine, expire_on_commit=False)

    def add_host(
        self,
        *,
        host_id: str,
        address: str,
        ssh_user: str,
        ssh_secret: str,
        ssh_port: int = 22,
        os_family: OsFamily = OsFamily.LINUX,
    ) -> Host:
        direccion = _validate(host_id, address, ssh_port, ssh_secret)
        host = Host(
            host_id=host_id,
            address=direccion,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            os_family=os_family,
            ssh_secret_token=self._vault.encrypt(ssh_secret),
        )
        with self._session() as session:
            duplicado = session.exec(
                select(Host).where(
                    (col(Host.host_id) == host_id) | (col(Host.address) == direccion)
                )
            ).first()
            if duplicado is not None:
                raise HostAlreadyRegisteredError(f"Ya registrado: {host_id} / {direccion}")
            session.add(host)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                raise HostAlreadyRegisteredError(
                    f"Ya registrado: {host_id} / {direccion}"
                ) from None
            session.refresh(host)
        logger.info("Host dado de alta: %s", host_id)
        return host

    def get_host(self, host_id: str) -> Host:
        with self._session() as session:
            host = session.exec(select(Host).where(col(Host.host_id) == host_id)).first()
        if host is None:
            raise HostNotFoundError(host_id)
        return host

    def list_hosts(self) -> list[Host]:
        with self._session() as session:
            return list(session.exec(select(Host).order_by(col(Host.host_id))).all())

    def is_registered(self, address: str) -> bool:
        """Indica si la dirección pertenece a un host registrado."""
        with self._session() as session:
            return (
                session.exec(select(Host).where(col(Host.address) == address)).first() is not None
            )

    def remove_host(self, host_id: str) -> None:
        with self._session() as session:
            host = session.exec(select(Host).where(col(Host.host_id) == host_id)).first()
            if host is None:
                raise HostNotFoundError(host_id)
            session.delete(host)
            session.commit()
        logger.info("Host dado de baja: %s", host_id)

    def get_ssh_secret(self, host_id: str) -> str:
        """Descifra y devuelve el secreto SSH; es la única vía de acceso a él."""
        return self._vault.decrypt(self.get_host(host_id).ssh_secret_token)
