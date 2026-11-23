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
- [x] S4 Orquestación del perfilado sobre una interfaz `SshTransport` (falsa en tests) y
      perfil completo en JSON guardado en la base de datos
- [x] S5 `BreadcrumbCatalog` Linux: plantillas deterministas (.env, backup.sql,
      .bash_history, claves), lista blanca de rutas, sin permisos de ejecución, límite de
      tamaño y comprobación de colisiones contra el inventario
- [x] S6 Generador determinista (H2): modelo `Campaign` y configuración de OpenCanary
      desde el perfil, con banners copiados del host real
- [x] S7 Verificador (H4, parte pura): comparador de huellas, puntuación y umbral
- [x] S8 Capa de LLM (H3): interfaz `LlmClient`, saneado del perfil (JSON delimitado,
      truncado, sin caracteres de control), seudonimización de IPs y dominios, validación
      con Pydantic estricto y plantilla de respaldo marcada como menor calidad. Cliente
      falso en tests
- [x] S9 Plan de despliegue en modo simulación y aprobación manual del operador
      (`DeploymentPlan`); nunca sobrescribe ficheros; sin aprobación no se despliega
- [x] S10 Eventos: parser de logs de OpenCanary, accesos a breadcrumbs y correlación por
      campaña
- [x] S11 Respuesta: modos observación, contención y escalado; reglas de nftables como
      lista de argumentos (revisión línea a línea)
- [x] S12 CLI del orquestador que une todo en modo simulación, y bucle de ajuste con el
      asistente (H4) — núcleo de orquestación hecho y probado (`run_campaign_simulation`);
      falta el `main()` de línea de comandos de verdad, aparcado hasta que también exista
      la ejecución real de nmap (fuera de lo descrito para S12)
- [x] S13 Dashboard mínimo (FastAPI, Jinja2, HTMX): inventario, campañas, puntuaciones,
      eventos y aprobación — `CampaignStore`/`DeploymentPlanStore` (persistencia en SQLite,
      mismo patrón que `HostProfileStore`), `DeploymentPlan.differences` (motivo de la
      puntuación), rutas `/`, `/hosts`, `/hosts/{id}`, `/campaigns`, `/campaigns/{id}`,
      `POST /campaigns/{id}/approve` (usa `approve_plan`, respeta el umbral) y `/events`
      como aviso honesto (sin datos simulados; pendiente de L3). Probado con
      `TestClient` y arrancado de verdad con `uvicorn` contra el navegador.

## Sesiones con laboratorio (las valida el usuario en VirtualBox)

- [x] L1 `AsyncSshTransport` (asyncssh) contra victima-01 y victima-02; perfiles reales
      (validado el 2026-11-23 con `lab/profile_lab.py` contra las dos víctimas, con las
      credenciales del inventario cifrado; los campos de nmap —banner, versión, IPs
      libres— quedan vacíos hasta integrar L2)
- [x] L2 Ejecución real de nmap y comparación del señuelo con un host real
      (`AsyncNmapRunner`/`scan_host` validados el 2026-11-23 con Nmap 7.993 + Npcap en la
      torre, sin elevación, `-O` incluido. El escaneo cubre los puertos del perfil
      (`ports`/`profile_tcp_ports`: sin `-p` nmap no veía Redis 6379) y lanza los
      scripts `banner` y `http-server-header`: sin ellos todos los banners eran `None` y
      el verificador no detectaba ninguna diferencia. Comparación real con los señuelos
      de L3: 90/90 en ambas víctimas, con diferencias reales detectadas)
- [x] L3 Contenedores OpenCanary con macvlan en deception-central
      (`start_decoy`/`deploy_decoy` en `desplegador.py`, imagen oficial fijada por
      digest, MAC con OUI de VirtualBox, config completo con `render_opencanary_conf`
      sobre el config por defecto real de OpenCanary 0.9.10. Validado el 2026-11-23:
      perfil → `enrich_profile` con nmap → `build_campaign` → `start_decoy` → escaneo →
      `verify_decoy`. Hallazgos de la línea base H2 para H4: el saludo de MySQL del
      señuelo revela `5.5.43-0ubuntu0.14.04.1` y Redis no imita el modo protegido;
      ambos pasan justo en el umbral (90), así que el verificador pesa poco un banner
      que delata el SO. El 90 de web-01 está además inflado en HTTP: el real responde
      `200` con su página "Intranet" y el señuelo `302` a un login de NAS Synology
      (`http.skin: nasLogin`), pero nmap solo ve `nginx` en ambos y el verificador lo
      cuenta como coincidencia. El banner real de MariaDB incluye la IP del escáner
      (`Host '10.0.0.1' is not allowed`), así que ningún señuelo podrá igualarlo; y ese
      texto queda en el perfil guardado, así que antes de L5 hay que comprobar que
      `build_profile_payload` seudonimiza también las IPs que van dentro de los banners.
      Reproducible con `lab/e2e_l3.py` en la rama chore/h0-laboratorio-virtualbox)
- [x] L4 Plantado real de breadcrumbs por SFTP y alertas de extremo a extremo
      (validado el 2026-11-23. Los breadcrumbs se generan desde el `DecoyConfig`: solo
      llevan a servicios activos del señuelo, con credenciales propias de la campaña, y
      se plantan en el home del usuario de gestión, sin pisar ficheros existentes. Con
      los planes aprobados a mano se plantaron 7 en las dos víctimas; desde cada víctima
      se usaron sus credenciales contra el señuelo y las alertas reales se atribuyeron a
      su campaña y a su breadcrumb con `breadcrumb_service_used`: MySQL (8001), HTTP
      (3001), FTP (2000) y Redis (17001). Hallazgos: `redis-cli -u redis://...`, la forma
      natural de usar `REDIS_URL`, rompe el parser de OpenCanary y no deja la credencial;
      MySQL solo se atribuye por usuario, porque la clave llega cifrada. Fuera de alcance:
      detectar la mera lectura de un breadcrumb (requeriría auditd, es decir, modificar
      el host real))
- [ ] L5 Ollama: modelo local y tasa de salidas válidas
- [ ] L6 Docker Compose de autodespliegue y pruebas ofensivas desde Kali (H7)

## Criterios de MVP terminado

1. Dar de alta dos hosts, perfilarlos y ver su perfil JSON.
2. Generar una campaña (con IA o con respaldo) con breadcrumbs y un deception host.
3. Verificar el señuelo, obtener una puntuación y exigir umbral y aprobación manual.
4. Desplegar (simulación primero), recibir un evento y aplicar el modo de respuesta.
5. CI en verde con cobertura de al menos el 80 % en perfilador, generador y verificador.
