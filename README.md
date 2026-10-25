# autoadaptable-securization

Herramienta de deception autodesplegable (proyecto de la asignatura *Proyectos de
Ciberseguridad*, U-Tad). Un orquestador sin agentes que se conecta por SSH a hosts dados
de alta explícitamente en una LAN, los perfila y genera campañas de engaño (breadcrumbs y
deception hosts) coherentes con el entorno real, con un bucle de verificación de
plausibilidad frente a un host real. Alcance, principios de diseño y reglas de código
completos en [CLAUDE.md](CLAUDE.md); plan de desarrollo por sesiones en
[docs/PLAN.md](docs/PLAN.md).

> **Alcance actual (ver [AI_USAGE.md](AI_USAGE.md) para el detalle de cada sesión):**
> inventario de hosts con credenciales SSH cifradas, perfilador Linux (SSH + nmap),
> orquestación del perfilado sobre un transporte SSH abstracto con perfil guardado en BD,
> y el catálogo de breadcrumbs deterministas. Generador con IA, verificador, desplegador,
> eventos, respuesta y dashboard son módulos planificados (ver `docs/PLAN.md`) y hoy están
> vacíos o incompletos.

## Requisitos

- Python 3.12 (el proyecto fija `>=3.12,<3.13`; no se garantiza con otras versiones).
- En Windows, si solo tienes otra versión de Python, instala 3.12 desde
  [python.org](https://www.python.org/downloads/) o con `winget install Python.Python.3.12`.
- Para las sesiones con laboratorio (fuera del alcance de esta instalación): VirtualBox,
  nmap y acceso SSH a los hosts de la red de laboratorio (`labnet`, ver `CLAUDE.md`).

## Instalación

```bash
python -m venv .venv
```

Activa el entorno virtual:

```bash
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate
```

Instala el paquete en modo editable con las dependencias de desarrollo:

```bash
pip install -e ".[dev]"
```

## Configuración

El inventario cifra las credenciales SSH con [Fernet](https://cryptography.io/en/latest/fernet/).
La clave nunca se guarda en el repositorio: se lee de la variable de entorno
`SECURIZATION_KEY`. Para generar una clave nueva:

```bash
python -c "from securization.inventario import CredentialVault; print(CredentialVault.generate_key().decode())"
```

```bash
# Windows (PowerShell)
$env:SECURIZATION_KEY = "<clave generada>"

# Linux / macOS
export SECURIZATION_KEY="<clave generada>"
```

No existe todavía una CLI de orquestador (planificada en `docs/PLAN.md`, sesión S12): por
ahora cada módulo se usa como librería Python (ver ejemplo de uso más abajo) o a través de
sus tests, que son la referencia más fiable del comportamiento actual.

## Ejecución

Comprobaciones de calidad, las mismas que corre la CI (`.github/workflows/ci.yml`):

```bash
ruff check .
ruff format --check .
mypy
bandit -r src -c pyproject.toml
pip-audit
pytest --cov --cov-report=term-missing
```

### Ejemplo de uso de lo ya implementado

Dar de alta un host y perfilarlo (con un transporte SSH falso; la implementación real por
`asyncssh` llega con el laboratorio, hito L1):

```python
import asyncio
from ipaddress import IPv4Address

from sqlmodel import create_engine

from securization.generador import LinuxBreadcrumbCatalog
from securization.inventario import CredentialVault, Inventory
from securization.perfilador import HostProfileStore, orchestrate_profiling

engine = create_engine("sqlite:///inventario.db")
vault = CredentialVault.from_env()  # lee SECURIZATION_KEY
inventory = Inventory(engine, vault)

inventory.add_host(
    host_id="victima-01",
    address="10.0.0.10",
    ssh_user="admin",
    ssh_secret="clave-ssh-de-ejemplo",
)
host = inventory.get_host("victima-01")


class TransporteDeEjemplo:
    async def run(self, argv: list[str]) -> str:
        raise NotImplementedError("sustituir por un SshTransport real o uno falso de test")


async def main() -> None:
    store = HostProfileStore(engine)
    perfil = await orchestrate_profiling(
        host_id=host.host_id,
        address=IPv4Address(host.address),
        os_family=host.os_family,
        transport=TransporteDeEjemplo(),
        store=store,
    )
    breadcrumbs = LinuxBreadcrumbCatalog().generate(perfil)
    print(perfil, breadcrumbs)


asyncio.run(main())
```

## Estructura del proyecto

```
src/securization/   Paquete Python, un módulo por responsabilidad (ver CLAUDE.md)
tests/               Tests pytest; tests/fixtures/ contiene salidas de ejemplo (nmap, ss, etc.)
docs/PLAN.md         Plan de desarrollo por sesiones (MVP sin laboratorio + sesiones con laboratorio)
AI_USAGE.md          Registro de trazabilidad del uso de IA, una entrada por tarea
.github/workflows/   CI: ruff, mypy, bandit, pip-audit, pytest con cobertura
```

## Flujo de trabajo y seguridad

- Nunca se trabaja directamente sobre `main`: una rama e issue por sesión, PR con squash
  merge (ver `CLAUDE.md`).
- Las credenciales reales de los hosts de laboratorio nunca van en el repositorio, en
  claro ni en los logs; solo existen cifradas en la base de datos local (ignorada por
  `.gitignore`) y en memoria durante la llamada que las usa.
- La IA solo genera contenido (código, plantillas, breadcrumbs deterministas); ningún
  comando que toque hosts reales se construye con texto de un LLM.
