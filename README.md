# autoadaptable-securization

Herramienta de deception autodesplegable (proyecto de la asignatura *Proyectos de
Ciberseguridad*, U-Tad). Es un orquestador sin agentes: se conecta por SSH a hosts dados de
alta explícitamente en una LAN, los perfila y genera campañas de engaño coherentes con el
entorno real:

- **Deception hosts**: contenedores OpenCanary en IPs libres de la LAN (red Docker macvlan,
  IP y MAC propias) que copian los banners reales de un host de la red.
- **Breadcrumbs**: ficheros cebo (`.env`, `backup.sql`, `.bash_history`…) plantados por SFTP
  en los hosts reales, con credenciales falsas que apuntan al señuelo.
- **Bucle de verificación de plausibilidad** (aportación diferencial): el señuelo se escanea
  con nmap junto al host real, se comparan las huellas, se puntúa (0-100) y se ajusta hasta
  superar el umbral. Nada se despliega sin superar el umbral y sin aprobación manual.
- **Eventos**: las alertas de OpenCanary se recogen, se atribuyen a su campaña y se marca
  cuándo el atacante ha usado una credencial de un breadcrumb.

La IA (un LLM local con Ollama) solo genera contenido validado contra un esquema estricto;
todo lo que toca hosts reales lo decide código determinista. Alcance y reglas completas en
[CLAUDE.md](CLAUDE.md); plan, resultados y hallazgos en [docs/PLAN.md](docs/PLAN.md); diseño
del laboratorio en [docs/lab-design.md](docs/lab-design.md); trazabilidad del uso de IA en
[AI_USAGE.md](AI_USAGE.md).

## Requisitos

| Para… | Necesitas |
| --- | --- |
| Usar la CLI y el dashboard | Python 3.12 (`>=3.12,<3.13`) y `nmap` en el PATH |
| Desplegar señuelos | Un host Linux con Docker y una red macvlan (`labnet-decoys`) en la LAN |
| Generar con IA (opcional) | [Ollama](https://ollama.com) local con un modelo, p. ej. `qwen3:8b` |
| Autodespliegue | Docker y Docker Compose |
| Reproducir el laboratorio | VirtualBox, Debian 12/13 y Kali (ver `docs/lab-design.md`) |

Los hosts gestionados solo necesitan un servidor SSH y un usuario con contraseña: no se
instala ningún agente.

## Instalación

### Opción A: entorno virtual (desarrollo y laboratorio)

```bash
python -m venv .venv
# Windows (PowerShell):  .\.venv\Scripts\Activate.ps1
# Linux / macOS:         source .venv/bin/activate
pip install -e ".[dev]"
```

Genera la clave Fernet que cifra las credenciales SSH del inventario. Se guarda en
`securization.key`, que está en `.gitignore` y nunca debe versionarse:

```bash
python -c "from securization.inventario import CredentialVault as V; open('securization.key','wb').write(V.generate_key())"
```

### Opción B: Docker Compose (autodespliegue)

```bash
mkdir -p data && sudo chown 10001:10001 data && chmod 700 data
docker compose run --rm --entrypoint python securization -c \
  "from securization.inventario import CredentialVault as V; open('/data/securization.key','wb').write(V.generate_key())"
docker compose up -d                    # dashboard en http://<host>:8000
docker compose --profile llm up -d      # además, Ollama local (solo en 127.0.0.1)
docker compose run --rm securization hosts list
```

La imagen corre sin root (uid 10001) e incluye nmap. `./data` guarda `inventario.db` y
`securization.key`; nunca se copia a la imagen.

> Un host Docker no alcanza a sus propios contenedores macvlan: lanza `campaign` (que
> escanea el señuelo) desde una máquina distinta de la que aloja los señuelos.

## Configuración

Por variables de entorno (todas opcionales):

| Variable | Por defecto | Uso |
| --- | --- | --- |
| `SECURIZATION_DB` | `inventario.db` | Base de datos SQLite (inventario, perfiles, campañas, eventos) |
| `SECURIZATION_KEY_FILE` | `securization.key` | Fichero con la clave Fernet |
| `SECURIZATION_KEY` | — | Alternativa: la clave en la propia variable |
| `SECURIZATION_DECEPTION_HOST` | `deception-central` | `host_id` del inventario que aloja los señuelos |
| `SECURIZATION_DECOY_DIR` | `/home/lab/decoys` | Directorio de configs de OpenCanary en ese host |

## Uso: flujo completo con la CLI

```bash
# 1. Alta de hosts (la contraseña se pide por teclado y se guarda cifrada)
securization hosts add victima-01 10.0.0.10 --user lab
securization hosts add deception-central 10.0.0.5 --user lab
securization hosts list

# 2. Perfil real: SO, servicios, paquetes (SSH) + huella y banners (nmap)
securization profile victima-01

# 3. (Opcional) hostname del señuelo propuesto por el LLM local
securization name victima-01 --model qwen3:8b

# 4. Campaña: señuelo + breadcrumbs, bucle de verificación y plan SIN aprobar
securization campaign victima-01 --decoy-node web-01 --decoy-ip 10.0.0.50 --max-attempts 3

# 5. Aprobación manual (falla si la puntuación no supera el umbral)
securization approve campana-victima-01

# 6. Despliegue: planta los breadcrumbs y arranca el señuelo definitivo
securization deploy campana-victima-01

# 7. Eventos: recoge las alertas de los señuelos y las lista por campaña
securization events collect
securization events list

# 8. Dashboard web: inventario, campañas, intentos del bucle, aprobación y eventos
securization dashboard --host 127.0.0.1 --port 8000
```

`campaign` arranca el señuelo en modo de verificación solo para escanearlo (excepción
limitada al laboratorio aislado); el despliegue definitivo es siempre `deploy`, que exige el
plan aprobado. Los breadcrumbs nunca sobrescriben ficheros existentes: se crean en modo
exclusivo, sin permisos de ejecución y dentro de una lista blanca de directorios.

## Laboratorio

Los scripts de `lab/` reproducen y validan el laboratorio (red `labnet` 10.0.0.0/24:
deception-central .5, victima-01 .10, victima-02 .11, atacante Kali .20). Leen las
credenciales de `lab-credentials.local.txt`, ignorado por git, con una línea por VM:

```
<host_id> <usuario> <contraseña> puerto_nat=<n> ip_labnet=<ip>
```

| Script | Qué hace |
| --- | --- |
| `provision_vm.ps1`, `debian_preseed_minimal.cfg`, `set_static_ip.py`, `retry_boot_until_ssh.ps1` | Crean las VMs Debian y fijan sus IPs |
| `provision_services.py`, `provision_deception.py` | Instalan nginx/MariaDB, vsftpd/Redis y Docker + macvlan |
| `check_lab.py`, `register_lab.py`, `profile_lab.py` | Comprueban el laboratorio, dan de alta y perfilan los hosts |
| `e2e_l3.py`, `l4_breadcrumbs.py` | Señuelo en macvlan y breadcrumb que lleva al señuelo, de extremo a extremo |
| `h4_bucle.py` | Bucle de verificación (H2 frente a H4) |
| `l5_tasa_validas.py` | Tasa de salidas válidas de los modelos de Ollama |
| `l6_ofensiva.py`, `atacante/` | Pruebas ofensivas desde Kali (nmap, whatweb, hydra) |

## Calidad y pruebas

Las mismas comprobaciones que ejecuta la CI (`.github/workflows/ci.yml`):

```bash
ruff check .
ruff format --check .
mypy
bandit -r src -c pyproject.toml
pip-audit
pytest --cov --cov-report=term-missing
```

Los tests no necesitan red: SSH, SFTP, nmap y Ollama se sustituyen por dobles de prueba.

## Estructura

```
src/securization/   inventario, perfilador, escaneo, generador, llm, verificador,
                    orquestador, desplegador, eventos, respuesta, dashboard, cli
tests/              tests pytest; tests/fixtures/ con salidas reales (nmap, ss, os-release…)
lab/                scripts de aprovisionamiento y pruebas del laboratorio
docs/               PLAN.md (plan y resultados), lab-design.md (laboratorio)
AI_USAGE.md         registro del uso de IA, una entrada por tarea
Dockerfile, docker-compose.yml   autodespliegue (dashboard + Ollama opcional)
```

## Seguridad

- Credenciales SSH cifradas con Fernet; nunca en claro, en logs ni en el repositorio.
- Prohibido `shell=True`: todos los comandos son listas de argumentos fijas y ninguno se
  construye con texto del LLM.
- El cliente de Ollama solo acepta una URL local; el perfil viaja al modelo seudonimizado,
  truncado y sin caracteres de control, y la salida se valida con Pydantic (si falla, se
  usa una plantilla determinista).
- El módulo `respuesta` decide la acción (observación, contención con una regla nftables
  como lista de argumentos, o escalado) pero no la aplica de forma automática.
