# AI_USAGE.md

Registro de trazabilidad del uso de IA (ver CLAUDE.md). Una entrada por tarea. Este
fichero es el único registro del uso de IA: los commits y los PR no llevan marcas de IA.

## Plantilla

```markdown
### YYYY-MM-DD - <título de la tarea> (issue #N)
- **Herramienta:** <herramienta y modelo>
- **Resumen del prompt:** <qué se pidió>
- **Qué se generó:** <ficheros / funciones>
- **Qué se modificó a mano:** <cambios humanos tras la generación, o "nada">
- **Commit(s):** <hash o enlace>
```

## Entradas

### 2026-10-13 - Esqueleto del repositorio
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** crear esqueleto con pyproject.toml (Python 3.12), paquete con módulos vacíos de CLAUDE.md, configuración de ruff/mypy/bandit, workflow de CI, AI_USAGE.md y .gitignore, sin lógica.
- **Qué se generó:** pyproject.toml, src/securization (8 módulos vacíos), tests/test_paquete.py, .github/workflows/ci.yml, AI_USAGE.md, .gitignore.
- **Qué se modificó a mano:** pendiente de revisión.
- **Commit(s):** pendiente.

### 2026-10-13 - H1: modelos HostProfile/OsFamily e interfaz HostProfiler
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** crear primero los tests y, tras aprobarlos, implementar el modelo `HostProfile` con `os_family` y la interfaz `HostProfiler` con selección por SO.
- **Qué se generó:** tests/test_modelos.py, tests/test_perfilador_interfaz.py, src/securization/modelos.py y src/securization/perfilador.py (interfaz, `LinuxProfiler` sin lógica y `get_profiler`).
- **Qué se modificó a mano:** tests revisados y aprobados por el usuario antes de implementar; resto pendiente de revisión.
- **Commit(s):** ver historial de la rama feature/h1-modelos-perfil.

### 2026-10-19 - Plan del MVP por sesiones
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** a partir de la memoria (PDF) y CLAUDE.md, definir el MVP y dividirlo en sesiones que se puedan hacer sin acceso al laboratorio.
- **Qué se generó:** docs/PLAN.md.
- **Qué se modificó a mano:** pendiente de revisión.
- **Commit(s):** ver el PR de la rama feature/plan-mvp.

### 2026-10-19 - S1: inventario y credenciales cifradas
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** implementar el inventario del PLAN (alta/baja de hosts en SQLite con SQLModel y credenciales SSH cifradas con Fernet), tests primero.
- **Qué se generó:** tests/test_inventario.py y src/securization/inventario.py (`CredentialVault`, `Host`, `Inventory`).
- **Qué se modificó a mano:** tests aprobados y implementación revisada línea a línea por el usuario (sin cambios).
- **Commit(s):** ver el PR de la rama feature/s1-inventario.

### 2026-10-19 - S2: parsers de LinuxProfiler
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** implementar los parsers de `/etc/os-release`, `ss -tlnp` y `ls -1Ap /` del PLAN, tests primero con salidas de ejemplo.
- **Qué se generó:** tests/test_parsers_linux.py, tests/fixtures/linux/*.txt y src/securization/parsers_linux.py (parsers y comandos remotos como tuplas de argumentos).
- **Qué se modificó a mano:** tests aprobados por el usuario antes de implementar; implementación pendiente de revisión.
- **Commit(s):** ver el PR de la rama feature/s2-parsers-linux.

### 2026-10-20 - S3: nmap XML, huella de red e IPs libres
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** implementar el parser de nmap XML (-sV -O), el modelo de huella y el cálculo de IPs libres del PLAN, tests primero con salidas de ejemplo.
- **Qué se generó:** tests/test_escaneo.py, tests/test_parsing.py, tests/fixtures/nmap/*.xml, src/securization/escaneo.py, src/securization/parsing.py y los modelos `OsMatch` y `Fingerprint` (y campos nuevos de `ServiceInfo`) en modelos.py.
- **Qué se modificó a mano:** tests aprobados por el usuario antes de implementar; implementación pendiente de revisión. Se movió el saneado común de parsers_linux.py a parsing.py.
- **Commit(s):** ver el PR de la rama feature/s3-nmap-huella.

### 2026-10-26 - S4: orquestación del perfilado SSH y perfil en base de datos
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** implementar la interfaz `SshTransport` (sin E/S real; implementación falsa en tests), hacer que `LinuxProfiler.profile` la use para ejecutar los tres comandos de S2 y construir el `HostProfile`, y añadir `HostProfileStore` + `orchestrate_profiling` para guardar el perfil completo en JSON en SQLite. Tests primero, con las fixtures ya existentes de tests/fixtures/linux/.
- **Qué se generó:** tests/test_perfilador_ssh.py, tests/test_orquestacion_perfil.py y los cambios en src/securization/perfilador.py (`SshTransport`, `ProfilingError`, `ProfileNotFoundError`, `LinuxProfiler.profile` real, `HostProfileStore`, `orchestrate_profiling`).
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en perfilador.py) ejecutados y en verde antes de abrir el PR.
- **Commit(s):** ver el PR de la rama feature/s4-orquestacion-perfilado.

### 2026-10-26 - S5: catálogo de breadcrumbs Linux
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** implementar la interfaz `BreadcrumbCatalog` y `LinuxBreadcrumbCatalog` del PLAN: plantillas deterministas de .env, backup.sql, .bash_history y una clave SSH falsa a partir del `HostProfile`, con lista blanca de directorios, sin permisos de ejecución, límite de tamaño y comprobación de colisiones contra rutas ya conocidas o ya plantadas. Tests primero.
- **Qué se generó:** tests/test_generador_breadcrumbs.py y src/securization/generador.py (`Breadcrumb`, `BreadcrumbCatalog`, `LinuxBreadcrumbCatalog`, `validate_breadcrumb`, `check_collisions`, `get_catalog`).
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en generador.py) ejecutados y en verde antes de abrir el PR.
- **Commit(s):** ver el PR de la rama feature/s5-breadcrumb-catalog-linux.

### 2026-11-03 - S7: comparador de huellas y puntuación de plausibilidad
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** implementar el verificador del PLAN (comparación de dos Fingerprint, host real y señuelo, con puntuación 0-100 y umbral), tests primero; revisión completa del código ya fusionado de S1-S5 antes de continuar.
- **Qué se generó:** tests/test_verificador.py, ampliación de tests/test_modelos.py (PlausibilityReport), src/securization/verificador.py y el modelo PlausibilityReport en modelos.py.
- **Qué se modificó a mano:** tests aprobados por el usuario antes de implementar; implementación pendiente de revisión. No se encontraron errores en el código de S1-S5 durante la revisión.
- **Commit(s):** ver el PR de la rama feature/s7-verificador.

### 2026-11-03 - S6: generador determinista (OpenCanary y Campaign)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** implementar la linea base sin IA (H2) del generador: configuracion de OpenCanary copiada del perfil y modelo Campaign que empaqueta senuelo + breadcrumbs, tests primero.
- **Que se genero:** tests/test_generador_campanas.py, build_opencanary_config, DecoyConfig, Campaign y build_campaign en src/securization/generador.py.
- **Que se modifico a mano:** tests aprobados por el usuario antes de implementar; dos ajustes tras el mypy strict (reexport explicito de UnsupportedOsFamilyError y un test de campos extra pasado a model_validate en vez de kwargs).
- **Commit(s):** ver el PR de la rama feature/s6-generador-campanas.

### 2026-11-03 - S8 (tests): capa de LLM y propuesta de hostname del señuelo
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** "adelante, nos ponemos con ello" (tras aprobar seguir con S8 según el PLAN): implementar la interfaz `LlmClient` del PLAN (saneado del perfil en JSON delimitado y truncado sin caracteres de control, seudonimización de IPs, validación con Pydantic estricto y plantilla de respaldo marcada como menor calidad, cliente falso en tests), y como primer caso de uso concreto la propuesta de hostname del señuelo. Tests primero.
- **Qué se generó:** tests/test_llm.py, tests/test_generador_identidad.py y `GenerationQuality` en modelos.py. Todavía no hay implementación (`src/securization/llm.py` no existe).
- **Qué se modificó a mano:** ninguno todavía; **pendiente de aprobación del usuario antes de implementar** (ver PR). La CI del PR falla a propósito por eso (módulo sin implementar), no es un error.
- **Commit(s):** ver el PR en borrador #13, rama feature/s8-llm-client (apilada sobre feature/s6-generador-campanas, PR #12, aún sin fusionar).

### 2026-11-19 - S8 (implementación): `llm.py` y `propose_decoy_hostname`
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** retomar S8 donde se dejó (tests ya escritos y aprobados en la entrada anterior) e implementar `src/securization/llm.py` y `propose_decoy_hostname`/`DecoyIdentity` en `generador.py` para que los tests pasen.
- **Qué se generó:** `src/securization/llm.py` (`LlmClient`, `LlmError`, `PseudonymMap`, `pseudonymize_addresses`, `ProfilePayload`, `build_profile_payload`, `render_untrusted_block`, `generate_with_fallback`) y, en `generador.py`, `DecoyIdentity` + `propose_decoy_hostname` (usa `host_id` y el nombre del SO en claro para que el modelo infiera la convención de nombres, el resto del perfil seudonimizado y delimitado).
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en llm.py y generador.py) en verde antes de abrir el PR. Un aviso de ruff (`UP047`) llevó a usar la sintaxis de genéricos de PEP 695 (`def generate_with_fallback[T: BaseModel](...)`) en vez de `TypeVar`.
- **Commit(s):** ver el PR de la rama feature/s8-llm-client.

### 2026-11-19 - S9: plan de despliegue en modo simulación (`DeploymentPlan`)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** continuar avanzando tras S8: implementar S9 del PLAN (`DeploymentPlan`, aprobación manual del operador condicionada al umbral de plausibilidad de S7, comprobación de colisiones de ruta reutilizando `check_collisions` de S5), tests primero. Sin E/S real: eso es L4.
- **Qué se generó:** tests/test_desplegador.py y, en src/securization/desplegador.py, `DeploymentAction`, `DeploymentPlan` (con la propiedad `ready_to_deploy`), `PlausibilityThresholdError`, `build_deployment_plan` y `approve_plan`.
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en desplegador.py) en verde antes de abrir el PR.
- **Commit(s):** ver el PR de la rama feature/s9-plan-despliegue.

### 2026-11-19 - S10: eventos de OpenCanary y correlación por campaña
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** continuar avanzando (en paralelo a preparar victima-02 en el laboratorio): implementar S10 del PLAN (parser de logs de OpenCanary, modelo de acceso a breadcrumb y correlación por campaña mediante `CampaignIndex`), tests primero. El esquema de log de OpenCanary se tomó de su documentación pública, no de una instalación real (sin laboratorio para verificarlo en esta sesión).
- **Qué se generó:** tests/test_eventos.py y, en src/securization/eventos.py, `OpenCanaryEvent`, `BreadcrumbAccessEvent`, `CorrelatedEvent`, `UnknownCampaignError`, `parse_opencanary_log` y `CampaignIndex`.
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en eventos.py) en verde antes de abrir el PR.
- **Commit(s):** ver el PR de la rama feature/s10-eventos.

### 2026-11-19 - S11: respuesta (observación, contención, escalado)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** continuar con S11 del PLAN: decidir la acción de respuesta ante un `CorrelatedEvent` (S10) según el modo configurado, y construir la regla de nftables de contención como lista de argumentos fija (nunca `shell=True` ni texto concatenado). Tests primero. Se añadió `source_host` a `CorrelatedEvent` (S10) porque la contención necesita la IP de origen, que antes solo vivía en el `OpenCanaryEvent` sin propagar.
- **Qué se generó:** tests/test_respuesta.py y, en src/securization/respuesta.py, `ResponseMode`, `ResponseAction`, `build_nftables_block_rule` y `decide_response`. Además, el campo `source_host` en `CorrelatedEvent` (src/securization/eventos.py) y dos tests nuevos en test_eventos.py para cubrirlo.
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en respuesta.py y eventos.py) en verde antes de abrir el PR. Este módulo decide y construye el comando, pero no ejecuta nada: aplicarlo de verdad contra un host registrado necesita el transporte SSH real (L1) y queda para otra sesión, a propósito, para que la revisión línea a línea de lo que sí toca el firewall se quede en un único sitio pequeño.
- **Commit(s):** ver el PR de la rama feature/s11-respuesta.

### 2026-11-19 - S12: orquestador en modo simulación con bucle de ajuste (H4)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** continuar con S12 del PLAN: unir generador (S6), verificador (S7) y desplegador (S9) en una función de orquestación que repite la verificación contra sucesivas huellas candidatas del señuelo —el bucle de ajuste de H4— hasta superar el umbral o agotar los intentos. Tests primero.
- **Qué se generó:** tests/test_orquestador.py y, en src/securization/orquestador.py, `SimulationResult` y `run_campaign_simulation`.
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en orquestador.py) en verde antes de abrir el PR. **Decisión de alcance explícita**: no se ha construido el `main()` de línea de comandos (argparse) que menciona el enunciado de S12, porque sin la ejecución real de nmap (fuera de lo descrito para esta sesión) los subcomandos de verificación/despliegue no harían nada de verdad; se deja anotado en docs/PLAN.md para retomarlo cuando exista esa pieza.
- **Commit(s):** ver el PR de la rama feature/s12-orquestador-cli.

### 2026-11-19 - S13: dashboard mínimo (FastAPI, Jinja2, HTMX)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** continuar con S13 del PLAN: dashboard mínimo sobre lo ya construido (inventario, perfiles, campañas, planes de despliegue), con inventario, campañas, puntuaciones, eventos y aprobación manual del operador (reutilizando `approve_plan` de S9, que ya impone el umbral). Tests primero.
- **Qué se generó:** `CampaignStore` en `src/securization/generador.py` y `DeploymentPlanStore` + el campo `differences` en `DeploymentPlan` en `src/securization/desplegador.py` (persistencia en SQLite, mismo patrón que `HostProfileStore`); `src/securization/dashboard.py` (`create_app`, rutas `/`, `/hosts`, `/hosts/{id}`, `/campaigns`, `/campaigns/{id}`, `POST /campaigns/{id}/approve`, `/events`) y las plantillas Jinja2 en `src/securization/templates/`; tests/test_generador_campanas.py (CampaignStore), tests/test_desplegador.py (DeploymentPlanStore y `differences`) y tests/test_dashboard.py (rutas con `TestClient`).
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en dashboard.py, generador.py y desplegador.py) en verde; además probado de verdad arrancando `uvicorn` y navegando las rutas en el navegador. Se actualizó `opentelemetry-api` (dependencia transitiva de fastapi) tras un aviso de pip-audit (CVE-2026-126360), sin tocar código propio. La pestaña `/events` muestra un aviso en vez de datos de ejemplo porque todavía no hay una fuente real de eventos conectada (depende de L3).
- **Commit(s):** ver el PR de la rama feature/s13-dashboard.

### 2026-11-19 - L1: transporte SSH real (AsyncSshTransport, asyncssh)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** implementar la interfaz `SshTransport` sobre asyncssh (sesión L1 del PLAN) y usarla para perfilar un host real del laboratorio; tests primero con `asyncssh.connect` sustituido por un doble, sin red.
- **Qué se generó:** tests/test_ssh_transport.py y `AsyncSshTransport` en src/securization/perfilador.py (no verifica `known_hosts`, justificado en el docstring: las VMs del laboratorio se recrean con clave de host distinta cada vez).
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en perfilador.py) en verde. Validado además contra un host real del laboratorio (victima-01, 10.0.0.10): `AsyncSshTransport` trajo el `/etc/os-release` real por SSH, con autorización explícita del usuario para que el propio agente hiciera el login SSH en esta sesión. `victima-02` seguía sin estar operativa en el laboratorio a fecha de esta entrada, así que L1 queda validado solo contra `victima-01`.
- **Commit(s):** ver el PR de la rama feature/l1-asyncssh-transport.

### 2026-11-22 - L2: ejecución real de nmap (`ProcessRunner`, `AsyncNmapRunner`, `scan_host`)
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** continuar con la parte de L2 que no depende de tener el laboratorio encendido delante (igual que L1 con `AsyncSshTransport`): una interfaz `ProcessRunner` (mismo contrato que `SshTransport`) con una implementación real `AsyncNmapRunner` sobre `asyncio.create_subprocess_exec` (nunca shell), y `scan_host` para construir el comando con `build_scan_command`, ejecutarlo y devolver la `Fingerprint` de la dirección pedida. Tests primero, con un runner falso y las fixtures XML ya existentes.
- **Qué se generó:** en `src/securization/escaneo.py`, `NmapScanError`, `ProcessRunner`, `AsyncNmapRunner` y `scan_host`; tests nuevos en `tests/test_escaneo.py` (runner falso, proceso fallido, host no encontrado en la salida, saneado del stderr del error).
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (98% total, el módulo nuevo cubierto al 100%, los huecos restantes de escaneo.py son de código anterior sin tocar) en verde antes de abrir el PR. Sin validar todavía contra un host o un señuelo reales en VirtualBox: eso queda para cuando el laboratorio esté operativo.
- **Commit(s):** ver el PR de la rama feature/l2-nmap-real.

### 2026-11-22 - L4 (plantado): `SftpTransport`, `AsyncSftpTransport`, `plant_breadcrumbs`
- **Herramienta:** Claude Code (Claude Sonnet 5)
- **Resumen del prompt:** seguir con la parte de L4 que no depende del laboratorio encendido: plantado real de breadcrumbs por SFTP sobre el `DeploymentPlan` de S9, siguiendo el mismo patrón de interfaz + implementación falsa/real que L1 y L2. Tests primero.
- **Qué se generó:** en `src/securization/desplegador.py`, `SftpTransport`, `AsyncSftpTransport` (asyncssh, modo de apertura `x` = creación exclusiva SFTP, para no fiarse solo de la comprobación de colisiones hecha al construir el plan), `DeploymentNotReadyError`, `BreadcrumbAlreadyExistsError` y `plant_breadcrumbs` (exige `ready_to_deploy`); tests/test_sftp_transport.py (dobles de asyncssh, igual que test_ssh_transport.py de L1) y los tests de `plant_breadcrumbs` añadidos a tests/test_desplegador.py.
- **Qué se modificó a mano:** ninguno; ruff, mypy --strict, bandit y pytest --cov (100% en desplegador.py, 98% total) en verde antes de abrir el PR. Las semánticas exactas de `asyncssh.SFTPClient.open`/`SFTPError` se comprobaron por introspección contra la versión instalada (2.24.1) en vez de asumirlas de memoria. Quedan pendientes las alertas de extremo a extremo (necesitan OpenCanary real, L3) y la validación contra un host real en VirtualBox.
- **Commit(s):** ver el PR de la rama feature/l4-sftp-planting.

### 2026-11-23 - Integración L1 + L2 + L4 y validación real de L1
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** juntar en una sola rama sobre S13 el código de laboratorio (L1, L2, L4), que estaba repartido en ramas que no se contenían entre sí, y dejar constancia de la validación real de L1 contra victima-01 y victima-02.
- **Qué se generó:** rama feature/integracion-lab (merges de L1, L2 y L4 con los conflictos de AI_USAGE.md resueltos conservando todas las entradas), L1 marcado como hecho en docs/PLAN.md y `ruff format` aplicado a cinco ficheros que venían sin formatear de S13, L2 y L4 (solo cambios de formato).
- **Qué se modificó a mano:** nada; ruff, ruff format, mypy, bandit, pip-audit y pytest (380 tests, 98% de cobertura) en verde.
- **Commit(s):** ver el PR de la rama feature/integracion-lab.

### 2026-11-23 - L2: validación contra el laboratorio real
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** instalar Nmap y Npcap en la torre y validar `scan_host`/`AsyncNmapRunner` contra las víctimas reales.
- **Qué se generó:** instalación de Nmap 7.993 (instalador oficial, firma Authenticode y SHA256 verificados contra nmap.org; Npcap instalado por el usuario desde el asistente) y la anotación de L2 en docs/PLAN.md. Hallazgo: sin `-p`, nmap no ve Redis (6379) en victima-02 aunque el perfilador por SSH sí lo detecta.
- **Qué se modificó a mano:** nada en el código; el usuario aceptó el UAC y completó el asistente de Npcap.
- **Commit(s):** ver el PR de la rama feature/integracion-lab.

### 2026-11-23 - L2: escaneo limitado a los puertos del perfil
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** corregir que nmap no viera Redis (6379) en victima-02 haciendo que el escaneo cubra los puertos del perfil del host. Tests primero.
- **Qué se generó:** `ports` opcional en `build_scan_command` y `scan_host` (`-p` con puertos validados, ordenados y sin duplicados; lista vacía, fuera de rango o no entera → `ValueError` antes de lanzar nmap), `profile_tcp_ports` y sus tests en tests/test_escaneo.py.
- **Qué se modificó a mano:** nada; ruff, mypy, bandit y pytest (396 tests, 98%) en verde, y verificado contra el laboratorio real: con los puertos del perfil, nmap detecta 22/80/3306 en victima-01 y 21/22/6379 en victima-02.
- **Commit(s):** ver el PR de la rama feature/l2-puertos-perfil.

### 2026-11-23 - L3: señuelos OpenCanary en contenedores (macvlan)
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** implementar L3: señuelos OpenCanary en contenedores con IP propia en deception-central, comprobando primero a mano en el laboratorio las claves reales de OpenCanary y el comportamiento de nmap. Tests primero.
- **Qué se generó:** en `escaneo.py`, los scripts `banner,http-server-header` en `build_scan_command` y `enrich_profile` (completa el perfil de `ss` con lo que ve nmap); en `generador.py`, el mapa de módulos corregido (Redis añadido, `mysql.banner` no se rellena con el saludo crudo, banner propio por módulo: SSH, FTP sin el 220, HTTP desde producto/versión), `render_opencanary_conf` sobre `src/securization/data/opencanary_base.json` (config por defecto real de OpenCanary 0.9.10, todos los módulos desactivados) y la eliminación de la clave inventada `ip.autodetect`; en `desplegador.py`, `start_decoy`, `stop_decoy`, `deploy_decoy` (exige `ready_to_deploy`), comandos docker como listas validadas, MAC con OUI de VirtualBox y config subido por SFTP en una ruta por contenido; tests en tests/test_senuelos.py, tests/test_escaneo.py y tests/test_generador_campanas.py.
- **Qué se modificó a mano:** nada; ruff, mypy, bandit y pytest (450 tests, 99%) en verde. Validado de punta a punta contra el laboratorio real: señuelos de las dos víctimas alcanzables desde la torre, 90/90 en el verificador, sin puertos de más, y alertas reales de OpenCanary interpretadas por `parse_opencanary_log` sin cambios.
- **Commit(s):** ver el PR de la rama feature/l3-senuelos-contenedores.

### 2026-11-23 - L4: breadcrumbs que llevan al señuelo y alerta de punta a punta
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** cerrar L4: que los breadcrumbs apunten a los servicios del señuelo y se puedan plantar de verdad, y validar la cadena completa en el laboratorio (breadcrumb → uso de su credencial contra el señuelo → alerta → campaña). Tests primero.
- **Qué se generó:** el catálogo de breadcrumbs genera los ficheros desde el `DecoyConfig` (`.env`, `.my.cnf`, `.netrc`, `db_backup.sql`, `notas_acceso.txt`, solo para servicios activos del señuelo y con credenciales por campaña, `breadcrumb_credentials`), en el home del usuario de gestión y sin rutas que exigen root ni ficheros habituales; `validate_breadcrumb` rechaza `..`; `build_campaign` y `run_campaign_simulation` reciben `home_dir`; `eventos.breadcrumb_service_used` reconoce en una alerta la credencial de un breadcrumb; fixtures con alertas reales de OpenCanary lanzadas desde las víctimas; regla de `.gitignore` para el fichero de credenciales del laboratorio.
- **Qué se modificó a mano:** nada en el código. El usuario aprobó en el chat los planes de despliegue tras revisar rutas y contenido antes de plantar nada. ruff, mypy, bandit y pytest (481 tests, 99%) en verde.
- **Commit(s):** ver el PR de la rama feature/l4-breadcrumbs-senuelo.

### 2026-11-23 - H4: bucle cerrado de verificación y ajuste con el laboratorio
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** implementar H4: que el bucle escanee el señuelo real, lo compare con el host real y lo ajuste hasta que sea indistinguible. Antes, medir el ruido del verificador con escaneos reales y comprobar en el laboratorio qué claves de OpenCanary cambian lo que ve nmap. Tests primero.
- **Qué se generó:** verificador con el saludo de MySQL normalizado, comparación de producto/versión/extrainfo y detección de una distribución delatora, con escaneos reales como fixtures; `HostProfile.packages` y `parse_dpkg_query`/`DPKG_CMD` en el perfilador; `mysql_banner_from_package`, `adjust_decoy` y la validación de `mysql.banner` en `render_opencanary_conf`; `run_verification_loop` en el orquestador; arreglo de `AsyncSftpTransport` (OpenSSH responde FX_FAILURE y no FX_FILE_ALREADY_EXISTS ante un fichero existente).
- **Qué se modificó a mano:** nada; ruff, mypy, bandit y pytest (528 tests, 99%) en verde. Validado en el laboratorio: web-01 pasa de 50 a 90 en el segundo intento y files-02 aprueba a la primera.
- **Commit(s):** ver el PR de la rama feature/h4-bucle-ajuste.

### 2026-11-23 - L5: Ollama local y tasa de salidas válidas
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** conectar el generador a un modelo local con Ollama y medir la tasa de salidas válidas con los perfiles reales del laboratorio, comparando modelos. Tests primero.
- **Qué se generó:** `OllamaClient` en `llm.py` (solo URL local, JSON sin razonamiento, fallos como `LlmError`); seudonimización de las IPs dentro del texto de los servicios en `build_profile_payload`; validación del hostname propuesto (etiqueta DNS, sin copiar el del host real, sin palabras que delaten el engaño), prompt que lo pide y respaldo `<host>-bak`; tests en tests/test_ollama.py, tests/test_llm.py y tests/test_generador_identidad.py.
- **Qué se modificó a mano:** nada; ruff, mypy, bandit y pytest (573 tests, 99%) en verde. Medido contra Ollama local con qwen3:8b y qwen3:14b (25 semillas por víctima): 100% válidas en ambos tras las correcciones. La primera medición mostró que el 8b nombraba "deco" al señuelo en 24 de 25 casos.
- **Commit(s):** ver el PR de la rama feature/l5-ollama.

### 2026-11-23 - H6 y L6: CLI, alertas reales, Docker Compose y pruebas ofensivas desde Kali
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** dejar la herramienta usable de punta a punta para la demo y los vídeos (CLI, dashboard con alertas reales, autodespliegue con Docker Compose) y evaluar desde Kali la diferencia entre H2 y H4 y la detección de ataques. Tests primero.
- **Qué se generó:** `cli.py` (subcomandos hosts, profile, name, campaign, approve, deploy, events, dashboard; contraseñas con getpass), `collect_opencanary_events`, `fetch_decoy_log` y `EventStore` en `eventos.py`, `VerificationResultStore` en `orquestador.py`, páginas de eventos, resumen y detalle de campaña del dashboard, `Dockerfile`, `docker-compose.yml`, `.dockerignore`; corrección del `readme` de `pyproject.toml`; tests en tests/test_cli.py, tests/test_eventos_store.py, tests/test_dashboard.py y tests/test_bucle_verificacion.py; `lab/l6_ofensiva.py` en la rama del laboratorio.
- **Qué se modificó a mano:** nada; ruff, mypy, bandit, pip-audit y pytest (601 tests, 99%) en verde. Validado en el laboratorio: imagen construida y dashboard servido con docker compose en deception-central; desde Kali, web-01 50 → 90 (H2 → H4) y todos los ataques contra los señuelos detectados y atribuidos a su campaña.
- **Commit(s):** ver el PR de la rama feature/h6-cli-eventos.

### 2026-11-23 - H0: laboratorio operativo, scripts de aprovisionamiento y alta en inventario
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** dejar el laboratorio estable sin reiniciar la torre, dar de alta victima-01, victima-02 y deception-central en el inventario, perfilarlas con el perfilador real (L1) y guardar en el repositorio los scripts del laboratorio.
- **Qué se generó:** diagnóstico del cuelgue de las VMs (VirtualBox cae al backend NEM por Hyper-V; 1 vCPU, sin IO-APIC ni paravirtualización), actualización de docs/lab-design.md y la carpeta lab/ (provision_vm.ps1, debian_preseed_minimal.cfg con `tasksel/first` corregido, set_static_ip.py, retry_boot_until_ssh.ps1, check_lab.py, register_lab.py, profile_lab.py).
- **Qué se modificó a mano:** nada; los scripts se ejecutaron contra el laboratorio real (SSH, ping cruzado, alta en inventario y perfilado de las dos víctimas con AsyncSshTransport) antes de commitear.
- **Commit(s):** ver el PR de la rama chore/h0-laboratorio-virtualbox.

### 2026-11-23 - H0: servicios reales en las víctimas
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** dar contenido a las víctimas (solo tenían SSH) con servicios distintos en cada una que OpenCanary sepa emular.
- **Qué se generó:** lab/provision_services.py (victima-01: nginx + MariaDB; victima-02: vsftpd + Redis; idempotente, comandos como listas de argumentos) y la sección de servicios en docs/lab-design.md. victima-01 pasó a arrancar sin entorno gráfico (tenía GNOME de una instalación anterior al arreglo del preseed).
- **Qué se modificó a mano:** nada; verificado contra el laboratorio real: puertos accesibles desde la torre, servicios activos tras reiniciar las VMs y perfiles reales actualizados con los nuevos puertos.
- **Commit(s):** ver el PR de la rama chore/h0-laboratorio-virtualbox.

### 2026-11-23 - L3 (laboratorio): deception-central lista para señuelos
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** preparar deception-central para alojar señuelos OpenCanary con macvlan y comprobarlo con un señuelo levantado a mano antes de escribir el código del desplegador.
- **Qué se generó:** lab/provision_deception.py (Docker, promiscuo persistente, red macvlan, imagen OpenCanary fijada por digest) y la sección de deception-central en docs/lab-design.md. Diagnóstico de por qué el señuelo no respondía: además de `allow-all` en VirtualBox hace falta el modo promiscuo dentro del invitado.
- **Qué se modificó a mano:** nada; verificado con un señuelo manual de victima-02 alcanzable desde la torre, reinicio de la VM incluido, y con alertas reales de OpenCanary.
- **Commit(s):** ver el PR de la rama chore/h0-laboratorio-virtualbox.

### 2026-11-23 - Entrega final: README como manual de instalación y uso
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** preparar el código para la entrega final: manual de instalación y uso en el README y comprobación de que el repositorio no contiene credenciales ni claves de API.
- **Qué se generó:** README.md reescrito (requisitos, instalación con venv y con Docker Compose, configuración por variables de entorno, flujo completo con la CLI `securization`, scripts del laboratorio, calidad y seguridad). Auditoría del historial completo de git: ninguna contraseña del laboratorio, ninguna clave Fernet ni claves de API; las únicas claves privadas son las falsas de las plantillas de breadcrumbs.
- **Qué se modificó a mano:** pendiente de revisión del alumno.
- **Commit(s):** ver el PR de la rama docs/readme-manual.

### 2026-11-23 - Entrega final: memoria en Word
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** redactar desde cero la memoria final en Word con los apartados del enunciado (herramienta final y diferencias con el plan, pruebas y validación, uso de IA, componente de IA, limitaciones y continuidad, manual), partiendo de la entrega intermedia y la memoria informativa.
- **Qué se generó:** docs/memoria/memoria.js (genera docs/Memoria-final.docx con la librería docx), docs/memoria/diagramas.py (diagramas de arquitectura y flujo con matplotlib) y el propio documento. Las cifras salen de docs/PLAN.md, AI_USAGE.md y de una ejecución real de pytest --cov sobre main; el papel del LLM y del módulo de respuesta se comprobó en el código antes de redactar.
- **Qué se modificó a mano:** pendiente de revisión del alumno (maquetación sin comprobar visualmente: no hay Word ni LibreOffice en la torre).
- **Commit(s):** ver el PR de la rama docs/readme-manual.

### 2026-11-23 - Ensayo de la demo: errores de la CLI
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** ensayar en el laboratorio la demo completa con la CLI antes de grabar el vídeo.
- **Qué se generó:** `campaign` convierte una colisión de ruta (un breadcrumb que ya existe en el host real) en un mensaje claro en vez de una traza de Python, sin arrancar ningún señuelo; `hosts list` muestra `usuario@ip:puerto` (antes `lab@:22`). Tests de ambos casos. El dashboard fija un fondo claro explícito: sin él, en un navegador con tema oscuro el texto quedaba sobre fondo negro y era ilegible.
- **Qué se modificó a mano:** nada; ruff, mypy, bandit y pytest (602 tests, 99 %) en verde. Detectado en el ensayo real contra victima-01, que conservaba los breadcrumbs de L4.
- **Commit(s):** ver el PR de la rama fix/cli-demo-errors.

### 2026-11-27 - Evidencias reales para la memoria e interfaz para público no técnico
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** reunir pruebas reales del funcionamiento (laboratorio, salidas de la CLI, ataques desde Kali, capturas del dashboard) para la memoria; y rediseñar la interfaz para alguien con conocimientos mínimos: barras de carga de las operaciones, diagrama de cómo trabaja la herramienta en la red y un aspecto más presentable.
- **Qué se generó:**
  - `docs/evidencias/`: 25 salidas reales (prueba del laboratorio, perfiles, campañas 50→90 y 90, despliegues, batería de ataques desde Kali con las cuatro credenciales-cebo atribuidas, eventos y log bruto de OpenCanary) y capturas del dashboard; scripts que las generan en `lab/evidencias/`.
  - `operaciones.py`: perfilar, crear campaña, desplegar y recoger alertas con informe de progreso, compartido por la CLI (barra de texto) y el dashboard (barra de carga). `presentacion.py`: alertas en lenguaje llano, estado de cada trampa, mapa de la red y pasos del flujo.
  - Dashboard rediseñado (inicio con explicación, pasos y mapa en directo, equipos, trampas, alertas, ayuda con glosario) con acciones y barra de progreso; solo permite acciones si escucha en local (o con `--acciones`). La propia IP del orquestador se reconoce: sus escaneos de verificación se muestran como comprobaciones, no como intrusos. `DeploymentPlan.deployed_at` registra el despliegue real.
  - Memoria ampliada (`docs/memoria/memoria.js` → `docs/Memoria-final.docx`): casos de uso (2.5), la interfaz con capturas (2.6), prueba de que el laboratorio funciona (3.3), ejecución completa con salidas reales (3.4), batería de ataques como casos de prueba con técnicas de MITRE ATT&CK (3.6), cómo se muestra la información (3.7) y ciclo de vida de las pruebas (3.8). README con la sección del dashboard.
- **Qué se modificó a mano:** nada; ruff, mypy, bandit y pytest (650 tests, 99 %) en verde. Probado contra el laboratorio real (análisis de victima-01 con la barra de progreso de 10 % a 100 %). El usuario aprobó los dos planes desde el dashboard. Las dos campañas de `casos.db`, desplegadas con la CLI antes de existir `deployed_at`, se marcaron con su hora real de despliegue (evidencias 13 y 14).
- **Commit(s):** ver el PR de la rama docs/evidencias-memoria.