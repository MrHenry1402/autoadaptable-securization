# CLAUDE.md - autoadaptable-securization

## Que es este proyecto
Herramienta de deception autodesplegable (proyecto de la asignatura Proyectos de Ciberseguridad, U-Tad). Un orquestador sin agentes que se conecta por SSH a hosts dados de alta explicitamente en una LAN, los perfila y genera campanas de engano coherentes con el entorno real:

- Breadcrumbs: credenciales falsas y ficheros cebo (.env, backup.sql, historiales, claves) plantados en los hosts reales.
- Deception hosts: maquinas fantasma en IPs libres que replican la huella de la red real y a las que apuntan los breadcrumbs.
- Respuesta configurable por campana: observacion, contencion (bloqueo con nftables en los hosts registrados) o escalado.

Contribucion diferencial: bucle cerrado de verificacion de plausibilidad. Tras generar un senuelo, se escanea (nmap -sV -O) junto a un host real, se comparan huellas, se calcula una puntuacion y se ajusta el senuelo hasta que es indistinguible.

Alcance: SOLO deception. Bastionado y alertado no son fases propias (la alerta existe solo como consecuencia de interactuar con un senuelo). Esta herramienta NO securiza ni modifica la configuracion de los hosts: solo planta breadcrumbs y levanta senuelos. Solo se actua sobre hosts dados de alta explicitamente. Marco de referencia: MITRE Engage.

Alcance de sistema operativo: hosts Linux (Debian 12 en el laboratorio) hasta terminar el H4. Windows es una extension opcional posterior (ver "Soporte multi-SO"). No implementar nada especifico de Windows salvo que un issue lo pida expresamente.

## Principio de diseno innegociable
La IA solo genera contenido. Todo lo que toca hosts reales (conexiones, comandos, despliegue, nftables, rutas) lo decide y ejecuta codigo determinista y auditable. Ningun comando se construye con texto procedente del LLM.

## Stack
- Python 3.12
- asyncssh (SSH/SFTP concurrente), Nmap -sV -O invocado desde Python con salida XML, Scapy para comprobaciones puntuales
- OpenCanary (servicios de red) y Cowrie (SSH interactivo) como motores de senuelos, configurados por el generador
- Docker con red macvlan (cada deception host con su IP y MAC)
- LLM detras de una capa de abstraccion: Ollama (modelo local 7-8B cuantizado) por defecto; SDK de Anthropic solo para comparar calidad, con datos anonimizados
- Pydantic v2 (esquemas de perfil, campana y salidas del LLM), SQLite con SQLModel
- FastAPI + Jinja2 + HTMX + Chart.js (dashboard)
- Calidad: pytest, ruff, mypy, bandit, pip-audit, GitHub Actions
- Laboratorio: VirtualBox, Debian 12, Kali (red interna labnet)

## Estructura de modulos (paquete Python, uno por responsabilidad)
- inventario: alta/baja de hosts, almacenamiento cifrado (Fernet) de credenciales SSH de gestion
- perfilador: SSH + nmap a cada host: SO, servicios, banners exactos, directorios, IPs libres
- generador: campanas (breadcrumbs + deception hosts) via LLM, con plantillas deterministas de respaldo
- verificador: escaneo del senuelo y de un host real, comparacion de huellas, puntuacion de plausibilidad
- desplegador: plantado de breadcrumbs por SFTP y arranque de deception hosts en contenedores
- eventos: alertas de OpenCanary, Cowrie y accesos a breadcrumbs; correlacion por campana
- respuesta: modos observacion / contencion / escalado
- dashboard: inventario, campanas, puntuaciones, eventos y aprobacion de despliegues

Los modulos son independientes y se comunican a traves de la base de datos comun y de modelos Pydantic compartidos.

## Soporte multi-SO (disenar ahora, implementar Windows despues)
Todo el codigo que dependa del sistema operativo del host registrado debe ir detras de una interfaz por SO, para que anadir Windows no obligue a reescribir nada. Hoy solo se implementa Linux.

- perfilador: interfaz `HostProfiler` con `LinuxProfiler` (uname, /etc/os-release, ss -tlnp, ls de directorios de primer nivel, por SSH). Futuro `WindowsProfiler`: OpenSSH Server en Windows + PowerShell (Get-ComputerInfo, Get-NetTCPConnection, Get-Service). No usar WinRM salvo decision explicita.
- generador y desplegador: los breadcrumbs dependen del SO del host destino (rutas, formatos, permisos). Interfaz `BreadcrumbCatalog` por SO; el perfil del host indica cual aplicar. Linux: .env, backup.sql, .bash_history, claves SSH, etc. Futuro Windows: rutas C:\Users\..., ficheros .rdp, scripts .ps1, historial de PowerShell, permisos NTFS.
- respuesta: interfaz `ContainmentBackend` con `NftablesBackend` (Linux). Futuro backend con New-NetFirewallRule para Windows.
- El campo `os_family` del modelo `HostProfile` (enum: `linux`, `windows`) decide que implementacion se usa. Un `os_family` no soportado debe fallar con un error claro, nunca caer en un comportamiento por defecto.
- Los modelos Pydantic compartidos (perfil, campana, salidas del LLM) deben ser independientes del SO.

Riesgo conocido para Windows (no resolver ahora): los deception hosts corren en contenedores Linux y `nmap -O` detectara la pila TCP/IP de Linux aunque se copien los banners, por lo que el verificador los marcara como distinguibles frente a un Windows real. Opciones futuras: ajustar parametros de red del contenedor (TTL 128, etc.) o usar VMs Windows como senuelo. Registrar el resultado como hallazgo, no como fallo del proyecto.

## Reglas de codigo (obligatorias)
- Prohibido shell=True, os.system y construir comandos concatenando strings. Usar listas de argumentos.
- Nunca sobrescribir ficheros existentes en un host real. Comprobacion de colisiones contra el inventario antes de desplegar.
- Rutas de breadcrumbs limitadas a una lista blanca de directorios, sin permisos de ejecucion, con limite de tamano.
- Credenciales: nunca en claro, nunca en logs, nunca en el repositorio.
- Toda salida del LLM se valida contra un esquema Pydantic estricto; si falla, se usa la plantilla de respaldo y se marca como menor calidad.
- Los datos del perfil que van al LLM se tratan como no confiables (prompt injection indirecta): viajan como JSON en campo delimitado, truncados y sin caracteres de control. El modelo no tiene herramientas.
- Al LLM nunca se envia: contenido de ficheros reales, credenciales reales, nombres de usuarios reales ni datos personales. IPs y dominios internos se seudonimizan antes de enviar.
- Los banners de los senuelos se copian de hosts reales, no los inventa el modelo.
- Ningun senuelo se despliega sin superar el umbral de plausibilidad y sin aprobacion manual del operador (modo simulacion primero). El despliegue definitivo es `deploy_decoy`, que exige el plan aprobado.
- Unica excepcion, solo en el laboratorio aislado: `start_decoy` puede arrancar un senuelo sin aprobacion para que el bucle de verificacion lo escanee (no se puede puntuar un senuelo apagado). Fuera del laboratorio, siempre `deploy_decoy`.
- Tipado completo (mypy) y async donde haya E/S de red.

## Flujo de trabajo
1. Cada tarea es un issue de GitHub (objetivo, criterios de aceptacion, ficheros afectados). Tareas pequenas: un modulo o funcion con sus tests.
2. Una rama por issue. NUNCA trabajar sobre main.
3. Primero los tests (se revisan), despues la implementacion.
4. Revision humana del diff completo. Codigo que ejecute comandos remotos, construya reglas de cortafuegos o trate credenciales se revisa linea a linea.
5. CI: ruff, mypy, bandit, pip-audit, pytest (objetivo de cobertura 80% en perfilador, generador y verificador).
6. Pull request con squash merge a main referenciando el issue.

## Trazabilidad del uso de IA
- Los commits y las descripciones de PR no llevan ninguna marca de IA (ni `AI-Assisted`, ni `Co-Authored-By`, ni "Generated with"). La trazabilidad del uso de IA vive solo en AI_USAGE.md.
- Por cada tarea, anadir una entrada en AI_USAGE.md: fecha, herramienta, resumen del prompt, que se genero, que se modifico a mano y commit asociado.
- El usuario ha pedido explicitamente que Claude no aparezca en el GitHub publico del proyecto; por eso ningun commit ni PR lleva atribucion de IA.

## Hitos
- H0 Laboratorio (VirtualBox, red interna labnet: deception-central 10.0.0.5, victima-01 10.0.0.10, victima-02 10.0.0.11, kali-lab 10.0.0.20)
- H1 Inventario y perfilador (perfil completo en JSON de las victimas; incluir la interfaz `HostProfiler` y el campo `os_family` desde el inicio)
- H2 Deception hosts deterministas (OpenCanary desde el perfil, sin IA: linea base)
- H3 Generador con IA (LLM local, validacion por esquema, comparacion de modelos por tasa de salidas validas)
- H4 Bucle de verificacion (comparador de huellas, puntuacion, ajuste automatico)
- H5 Breadcrumbs, eventos y respuesta
- H6 Dashboard y autodespliegue con Docker Compose
- H7 Evaluacion (pruebas ofensivas desde Kali, comparacion H2 vs H4, memoria final)
- Opcional, solo si sobra tiempo tras H4 y el profesor lo aprueba: soporte Windows (WindowsProfiler, catalogo de breadcrumbs y backend de contencion)

## Estado actual
Desarrollo y laboratorio (VirtualBox, red interna labnet) ya en la torre. El agente tiene permiso explicito del usuario para conectarse por SSH a las VMs del laboratorio y gestionarlas (VBoxManage, aprovisionamiento, diagnostico) directamente desde esta maquina.

MVP completo (S0-S13, L1-L6, H0-H6) validado en el laboratorio real: inventario, perfilado, generador con IA (Ollama) y respaldo determinista, verificador y bucle de ajuste, despliegue, eventos, respuesta, CLI, dashboard y autodespliegue con Docker Compose. Entrega final (README como manual, memoria en Word, ensayo de la demo) tambien fusionada. Ver docs/PLAN.md y AI_USAGE.md para el detalle sesion a sesion.

## Idioma
Codigo, identificadores y commits en ingles; docstrings y documentacion en espanol.
