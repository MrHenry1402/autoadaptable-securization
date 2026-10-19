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

### 2026-10-19 - S1: inventario y credenciales cifradas
- **Herramienta:** Claude Code (Claude Sonnet 5.5)
- **Resumen del prompt:** implementar el inventario del PLAN (alta/baja de hosts en SQLite con SQLModel y credenciales SSH cifradas con Fernet), tests primero.
- **Qué se generó:** tests/test_inventario.py y src/securization/inventario.py (`CredentialVault`, `Host`, `Inventory`).
- **Qué se modificó a mano:** tests aprobados por el usuario antes de implementar; implementación pendiente de revisión línea a línea (trata credenciales).
- **Commit(s):** ver el PR de la rama feature/s1-inventario.
