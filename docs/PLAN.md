# Plan de desarrollo del MVP

Fuente: `Memoria_Sistema_Deception.pdf` y `CLAUDE.md`. Cada sesión es un issue, una rama,
tests primero (se revisan) y un PR con squash a `main`. Marcar con `[x]` al fusionar.

## Definición del MVP

El MVP recorre el flujo de la memoria (perfilar, generar, verificar, aprobar, desplegar,
detectar, responder) con una **base determinista y sin IA** (H2) más la capa de IA con
validación y respaldo (H3), en **modo simulación** por defecto. Todo se puede desarrollar y
probar sin el laboratorio gracias a dos reglas:

- La lógica pura (parsers, modelos, plantillas, comparación, puntuación, reglas de nftables)
  se prueba con salidas de ejemplo guardadas como ficheros (`tests/fixtures/`).
- La E/S real (SSH, nmap, Docker, Ollama) va detrás de interfaces (`Protocol`) con una
  implementación falsa para tests y una real que valida el usuario en VirtualBox.

Dentro del MVP: Linux, un orquestador por CLI, OpenCanary como motor de senuelos,
breadcrumbs por SFTP, respuesta en los tres modos y dashboard mínimo.
Fuera del MVP: Cowrie, Windows, Scapy, comparación de modelos y la API de Anthropic.

## Sesiones sin laboratorio

- [x] S0 Esqueleto del repo, CI, `HostProfile`, `OsFamily` y `HostProfiler` (PR #1, #2)
- [x] S1 Inventario: modelo `Host`, SQLite con SQLModel, alta y baja, credenciales SSH
      cifradas con Fernet (revisión línea a línea)
- [x] S2 Parsers de `LinuxProfiler`: `/etc/os-release`, `ss -tlnp`, directorios de primer
      nivel (entrada: texto, salida: modelos)
- [x] S3 Parser de nmap XML (`-sV -O`) y modelo de huella (`Fingerprint`); cálculo de IPs
      libres a partir de subred y hosts conocidos
- [ ] S4 Orquestación del perfilado sobre una interfaz `SshTransport` (falsa en tests) y
      perfil completo en JSON guardado en la base de datos
- [x] S5 `BreadcrumbCatalog` Linux: plantillas deterministas (.env, backup.sql,
      .bash_history, claves), lista blanca de rutas, sin permisos de ejecución, límite de
      tamaño y comprobación de colisiones contra el inventario
- [ ] S6 Generador determinista (H2): modelo `Campaign` y configuración de OpenCanary
      desde el perfil, con banners copiados del host real
- [ ] S7 Verificador (H4, parte pura): comparador de huellas, puntuación y umbral
- [ ] S8 Capa de LLM (H3): interfaz `LlmClient`, saneado del perfil (JSON delimitado,
      truncado, sin caracteres de control), seudonimización de IPs y dominios, validación
      con Pydantic estricto y plantilla de respaldo marcada como menor calidad. Cliente
      falso en tests
- [ ] S9 Plan de despliegue en modo simulación y aprobación manual del operador
      (`DeploymentPlan`); nunca sobrescribe ficheros; sin aprobación no se despliega
- [ ] S10 Eventos: parser de logs de OpenCanary, accesos a breadcrumbs y correlación por
      campaña
- [ ] S11 Respuesta: modos observación, contención y escalado; reglas de nftables como
      lista de argumentos (revisión línea a línea)
- [ ] S12 CLI del orquestador que une todo en modo simulación, y bucle de ajuste con el
      asistente (H4)
- [ ] S13 Dashboard mínimo (FastAPI, Jinja2, HTMX): inventario, campañas, puntuaciones,
      eventos y aprobación

## Sesiones con laboratorio (las valida el usuario en VirtualBox)

- [ ] L1 `AsyncSshTransport` (asyncssh) contra victima-01 y victima-02; perfiles reales
- [ ] L2 Ejecución real de nmap y comparación del señuelo con un host real
- [ ] L3 Contenedores OpenCanary con macvlan en deception-central
- [ ] L4 Plantado real de breadcrumbs por SFTP y alertas de extremo a extremo
- [ ] L5 Ollama: modelo local y tasa de salidas válidas
- [ ] L6 Docker Compose de autodespliegue y pruebas ofensivas desde Kali (H7)

## Criterios de MVP terminado

1. Dar de alta dos hosts, perfilarlos y ver su perfil JSON.
2. Generar una campaña (con IA o con respaldo) con breadcrumbs y un deception host.
3. Verificar el señuelo, obtener una puntuación y exigir umbral y aprobación manual.
4. Desplegar (simulación primero), recibir un evento y aplicar el modo de respuesta.
5. CI en verde con cobertura de al menos el 80 % en perfilador, generador y verificador.
