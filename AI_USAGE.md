# AI_USAGE.md

Registro de trazabilidad del uso de IA (ver CLAUDE.md). Una entrada por tarea;
los commits con código generado llevan el trailer `AI-Assisted: Claude Code`.

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
