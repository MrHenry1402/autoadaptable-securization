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

### 2026-11-23 - H0: laboratorio operativo, scripts de aprovisionamiento y alta en inventario
- **Herramienta:** Claude Code (Claude Opus 5.5)
- **Resumen del prompt:** dejar el laboratorio estable sin reiniciar la torre, dar de alta victima-01, victima-02 y deception-central en el inventario, perfilarlas con el perfilador real (L1) y guardar en el repositorio los scripts del laboratorio.
- **Qué se generó:** diagnóstico del cuelgue de las VMs (VirtualBox cae al backend NEM por Hyper-V; 1 vCPU, sin IO-APIC ni paravirtualización), actualización de docs/lab-design.md y la carpeta lab/ (provision_vm.ps1, debian_preseed_minimal.cfg con `tasksel/first` corregido, set_static_ip.py, retry_boot_until_ssh.ps1, check_lab.py, register_lab.py, profile_lab.py).
- **Qué se modificó a mano:** nada; los scripts se ejecutaron contra el laboratorio real (SSH, ping cruzado, alta en inventario y perfilado de las dos víctimas con AsyncSshTransport) antes de commitear.
- **Commit(s):** ver el PR de la rama chore/h0-laboratorio-virtualbox.
