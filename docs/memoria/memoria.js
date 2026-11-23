// Genera docs/Memoria-final.docx (memoria final del proyecto).
// Uso: NODE_PATH=<carpeta con node_modules/docx> node docs/memoria/memoria.js
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, WidthType, ShadingType, BorderStyle, LevelFormat,
  TableOfContents, Header, Footer, PageNumber, PageBreak, ExternalHyperlink,
} = require("docx");

const AQUI = __dirname;
const SALIDA = path.join(AQUI, "..", "Memoria-final.docx");
const ANCHO = 9026; // A4 con márgenes de 1": ancho útil en DXA
const AZUL = "1F4E79";
const FUENTE = "Calibri";

// --- utilidades -------------------------------------------------------------

// Texto con **negrita** y `código` en línea.
function runs(texto, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let i = 0;
  let m;
  while ((m = re.exec(texto)) !== null) {
    if (m.index > i) out.push(new TextRun({ text: texto.slice(i, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(new TextRun({ text: t.slice(2, -2), bold: true, ...base }));
    else out.push(new TextRun({ text: t.slice(1, -1), font: "Consolas", size: 19, color: "7F2704", ...base }));
    i = m.index + t.length;
  }
  if (i < texto.length) out.push(new TextRun({ text: texto.slice(i), ...base }));
  return out;
}

const P = (texto, opts = {}) =>
  new Paragraph({ children: runs(texto), spacing: { after: 120, line: 276 }, alignment: AlignmentType.JUSTIFIED, ...opts });
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)], pageBreakBefore: true });
const H1c = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const B = (texto, nivel = 0) =>
  new Paragraph({ numbering: { reference: "vinetas", level: nivel }, children: runs(texto), spacing: { after: 60, line: 264 } });
const N = (texto, ref = "numeros") =>
  new Paragraph({ numbering: { reference: ref, level: 0 }, children: runs(texto), spacing: { after: 60, line: 264 } });
const Pie = (t) =>
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60, after: 200 },
    children: [new TextRun({ text: t, italics: true, size: 18, color: "595959" })] });

function Codigo(lineas) {
  return lineas.map((l, i) =>
    new Paragraph({
      shading: { type: ShadingType.CLEAR, fill: "F2F2F2", color: "auto" },
      spacing: { before: i === 0 ? 60 : 0, after: i === lineas.length - 1 ? 160 : 0, line: 240 },
      indent: { left: 144, right: 144 },
      children: [new TextRun({ text: l === "" ? " " : l, font: "Consolas", size: 17 })],
    }));
}

const borde = { style: BorderStyle.SINGLE, size: 4, color: "A6A6A6" };
const bordes = { top: borde, bottom: borde, left: borde, right: borde };

function Tabla(cabecera, filas, pesos) {
  const total = pesos.reduce((a, b) => a + b, 0);
  const anchos = pesos.map((p) => Math.floor((p / total) * ANCHO));
  anchos[anchos.length - 1] += ANCHO - anchos.reduce((a, b) => a + b, 0);
  const celda = (texto, i, cab) =>
    new TableCell({
      borders: bordes,
      width: { size: anchos[i], type: WidthType.DXA },
      shading: cab ? { fill: AZUL, type: ShadingType.CLEAR, color: "auto" } : undefined,
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
      children: String(texto).split("\n").map((linea) =>
        new Paragraph({
          spacing: { after: 0, line: 252 },
          children: cab ? [new TextRun({ text: linea, bold: true, color: "FFFFFF", size: 19 })] : runs(linea, { size: 19 }),
        })),
    });
  return new Table({
    width: { size: ANCHO, type: WidthType.DXA },
    columnWidths: anchos,
    rows: [
      new TableRow({ tableHeader: true, children: cabecera.map((t, i) => celda(t, i, true)) }),
      ...filas.map((f) => new TableRow({ children: f.map((t, i) => celda(t, i, false)) })),
    ],
  });
}
const Sep = () => new Paragraph({ spacing: { after: 120 }, children: [] });

function Imagen(fichero, anchoPx, altoPx) {
  return new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 120, after: 40 },
    children: [new ImageRun({ type: "png", data: fs.readFileSync(path.join(AQUI, fichero)),
      transformation: { width: anchoPx, height: altoPx },
      altText: { title: fichero, description: fichero, name: fichero } })],
  });
}

// --- contenido ----------------------------------------------------------------

const portada = [
  new Paragraph({ spacing: { before: 2400 }, children: [] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
    children: [new TextRun({ text: "Memoria final", size: 36, color: "595959" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
    children: [new TextRun({ text: "Sistema de deception autodesplegable y autoadaptable", bold: true, size: 48, color: AZUL })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 1200 },
    children: [new TextRun({ text: "autoadaptable-securization: señuelos de red con verificación automática de plausibilidad", size: 26, italics: true })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "Enrique Hedo Bravo", bold: true, size: 28 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "Proyectos de Ciberseguridad · U-Tad", size: 24 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "Noviembre de 2026", size: 24 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 600 },
    children: [new ExternalHyperlink({ link: "https://github.com/MrHenry1402/autoadaptable-securization",
      children: [new TextRun({ text: "github.com/MrHenry1402/autoadaptable-securization", style: "Hyperlink", size: 22 })] })] }),
];

const indice = [
  new Paragraph({ pageBreakBefore: true, spacing: { after: 240 },
    children: [new TextRun({ text: "Índice", bold: true, size: 32, color: AZUL })] }),
  new TableOfContents("Índice", { hyperlink: true, headingStyleRange: "1-2" }),
  P("(Si el índice aparece vacío, en Word: clic derecho sobre él y «Actualizar campo».)", { alignment: AlignmentType.LEFT }),
];

const resumen = [
  H1("1. Introducción"),
  P("Este documento recoge el desarrollo completo de **autoadaptable-securization**, la herramienta de deception construida en la asignatura Proyectos de Ciberseguridad, partiendo de la entrega intermedia (25 de octubre de 2026). En aquella fecha estaban terminadas 6 de las 14 sesiones de desarrollo sin laboratorio (S0-S5: inventario, perfilador y catálogo de breadcrumbs) y ninguna de las 6 sesiones con laboratorio. A fecha de esta memoria están terminados todos los hitos técnicos (H0-H7), validados en un laboratorio real de VirtualBox, y el código está integrado en la rama `main` del repositorio."),
  P("El problema de partida es conocido: un señuelo de red configurado de forma estática se distingue con un simple `nmap -sV -O`, porque sus servicios, versiones o sistema operativo no cuadran con el resto de la red. La aportación de este proyecto es un **bucle cerrado de verificación de plausibilidad**: el señuelo se genera a partir del perfil de un host real, se escanea junto a ese host, se comparan las huellas, se puntúa y se ajusta hasta superar un umbral. Nada se despliega sin superar el umbral y sin la aprobación de un operador."),
  P("La memoria sigue el orden pedido para la entrega final: la herramienta final y sus diferencias con el planteamiento inicial (apartado 2), las pruebas y la validación (3), el uso de la IA en el desarrollo (4), el componente de IA de la herramienta (5), las limitaciones y la continuidad (6) y el manual de instalación y uso (7)."),
];

const herramienta = [
  H1("2. Herramienta final"),
  H2("2.1. Qué hace"),
  P("Es un orquestador **sin agentes**: no instala nada en los hosts que protege. Se conecta por SSH solo a los hosts dados de alta explícitamente en su inventario y, a partir de lo que observa en ellos, monta campañas de engaño coherentes con la red real. Sus funcionalidades finales son:"),
  B("**Inventario** de hosts gestionados con las credenciales SSH cifradas con Fernet (la contraseña se pide por teclado y nunca se guarda en claro)."),
  B("**Perfilado real** de cada host por SSH (`/etc/os-release`, `ss -tlnp`, directorios de primer nivel y versiones de los paquetes de servicio con `dpkg-query`) y por nmap (`-sV -O` sobre los puertos del perfil, con los scripts `banner` y `http-server-header` para capturar los banners exactos)."),
  B("**Generación determinista de la campaña** (línea base H2): un señuelo OpenCanary que copia servicios y banners del host real y un conjunto de **breadcrumbs** (`.env`, `backup.sql`, `.bash_history`, `.my.cnf`…) con credenciales falsas propias de la campaña que apuntan al señuelo."),
  B("**Bucle de verificación y ajuste** (H4): arranca el señuelo en un contenedor, lo escanea con nmap junto al host real, compara las huellas (producto, versión, información extra, sistema operativo y banners que delatan otra distribución), calcula una puntuación de 0 a 100 y, si no llega al umbral (90), ajusta el señuelo solo con datos observados en el host real y repite."),
  B("**Despliegue con aprobación**: la campaña produce un plan de despliegue sin aprobar; el operador lo aprueba (la aprobación falla si la puntuación no supera el umbral) y solo entonces se plantan los breadcrumbs por SFTP, en modo de creación exclusiva (nunca se sobrescribe un fichero) y se arranca el señuelo definitivo."),
  B("**Señuelos en la LAN real**: cada deception host es un contenedor OpenCanary en una red Docker macvlan, con IP libre de la LAN y MAC propia con el OUI de VirtualBox, de modo que en la red aparece como una máquina más."),
  B("**Eventos**: recogida de las alertas de OpenCanary, atribución a su campaña y detección de cuándo el atacante ha usado una credencial que solo existía en un breadcrumb."),
  B("**Respuesta**: para cada evento se decide la acción según el modo de la campaña (observación, contención con una regla nftables o escalado). La acción se decide y se construye, pero no se aplica de forma automática (ver apartado 6)."),
  B("**Componente de IA**: un modelo local (Ollama, `qwen3:8b`) propone el hostname del señuelo para que encaje con la convención de nombres de la red; su salida se valida con un esquema estricto y, si falla, se usa una plantilla determinista."),
  B("**Interfaces**: una CLI (`securization`) que recorre todo el flujo y un dashboard web (FastAPI + Jinja2 + HTMX) con inventario, campañas, intentos del bucle, aprobación y eventos. Todo se autodespliega con Docker Compose."),

  H2("2.2. Arquitectura"),
  P("La herramienta es un paquete Python 3.12 con un módulo por responsabilidad. Los módulos no se llaman entre sí de forma arbitraria: comparten modelos Pydantic (perfil, huella, campaña, plan, evento) y una base de datos SQLite. Toda la E/S real (SSH, SFTP, nmap, Docker y Ollama) está detrás de interfaces (`Protocol`) con una implementación real y otra falsa para los tests."),
  Imagen("arquitectura.png", 600, 359),
  Pie("Figura 1. Arquitectura de la herramienta y del laboratorio en el que se ha validado."),
  Tabla(["Módulo", "Responsabilidad", "Piezas principales"], [
    ["inventario", "Alta y baja de hosts; credenciales SSH cifradas", "`Inventory`, `CredentialVault` (Fernet)"],
    ["perfilador", "Perfil del host por SSH, detrás de una interfaz por SO", "`HostProfiler`, `LinuxProfiler`, `AsyncSshTransport` (asyncssh)"],
    ["escaneo", "nmap real y huella de red", "`AsyncNmapRunner`, `scan_host`, `enrich_profile`, IPs libres"],
    ["generador", "Campaña: señuelo OpenCanary, breadcrumbs y ajuste", "`build_campaign`, `render_opencanary_conf`, `adjust_decoy`, `propose_decoy_hostname`"],
    ["llm", "Capa de abstracción del modelo", "`LlmClient`, `OllamaClient`, seudonimización, `generate_with_fallback`"],
    ["verificador", "Comparación de huellas y puntuación", "`verify_decoy`, normalización del saludo MySQL"],
    ["orquestador", "Bucle cerrado H4", "`run_verification_loop`, `VerificationResultStore`"],
    ["desplegador", "Plan, aprobación, SFTP y contenedores", "`DeploymentPlan`, `approve_plan`, `start_decoy`, `deploy_decoy`"],
    ["eventos", "Alertas de OpenCanary y correlación", "`collect_opencanary_events`, `breadcrumb_service_used`, `EventStore`"],
    ["respuesta", "Decisión de respuesta", "`decide_response`, `build_nftables_block_rule`"],
    ["dashboard / cli", "Interfaces de operador", "FastAPI + Jinja2 + HTMX; comando `securization`"],
  ], [16, 38, 46]),
  Sep(),
  P("El código que depende del sistema operativo del host está detrás de interfaces por SO (`HostProfiler`, `BreadcrumbCatalog`) y el campo `os_family` del perfil decide cuál se usa. Hoy solo existe la implementación Linux; un `os_family` no soportado falla con un error claro en lugar de caer en un comportamiento por defecto."),

  H2("2.3. Flujo de funcionamiento"),
  Imagen("flujo.png", 620, 155),
  Pie("Figura 2. Flujo de una campaña. El bucle de ajuste vuelve del paso 4 al 3 hasta superar el umbral o agotar los intentos."),
  N("**Alta** (`securization hosts add`): el operador registra el host con su IP y un usuario SSH; la contraseña se cifra en el inventario."),
  N("**Perfil** (`securization profile`): SSH al host y nmap a sus puertos; el perfil enriquecido con los banners reales se guarda en la base de datos."),
  N("**Campaña** (`securization campaign`): se construye el señuelo H2 a partir del perfil y los breadcrumbs a partir del señuelo, de modo que solo apuntan a servicios que el señuelo tiene activos y nunca chocan con ficheros que ya existen en el home del host."),
  N("**Verificación**: el señuelo se arranca en deception-central, se escanea con los mismos puertos que el host real y se puntúa. Si no llega a 90, `adjust_decoy` corrige el config con datos del host real (por ejemplo, el banner de MySQL derivado del paquete MariaDB instalado) y se repite, con un máximo de intentos y parada si el config se repite."),
  N("**Aprobación** (`securization approve` o el botón del dashboard): el plan se guarda sin aprobar; solo el operador lo aprueba y solo si supera el umbral."),
  N("**Despliegue** (`securization deploy`): se plantan los breadcrumbs por SFTP y se arranca el señuelo definitivo con `deploy_decoy`, que exige el plan aprobado."),
  N("**Eventos** (`securization events collect|list` y el dashboard): las alertas del señuelo se atribuyen a su campaña y, si el atacante usó una credencial de un breadcrumb, se indica cuál."),

  H2("2.4. Diferencias respecto al planteamiento inicial"),
  P("El planteamiento inicial está en la memoria informativa y en `docs/PLAN.md`. El alcance (solo deception, sin bastionar ni modificar los hosts, solo sobre hosts dados de alta) y el principio de diseño (la IA solo genera contenido; todo lo que toca hosts reales lo decide código determinista) se han mantenido. Los cambios son estos:"),
  Tabla(["Planteamiento inicial", "Resultado final", "Motivo"], [
    ["El LLM redacta el contenido de los breadcrumbs y propone las variaciones del bucle de ajuste", "El LLM solo propone el hostname del señuelo; breadcrumbs y ajuste son deterministas", "El ajuste que mejora la puntuación consiste en copiar datos observados del host real (la regla del proyecto prohíbe que el modelo invente banners), y eso es más fiable sin modelo. El contenido de los breadcrumbs depende del señuelo y de credenciales de campaña, que deben ser exactas para que la alerta se atribuya"],
    ["Comparar Ollama con el SDK de Anthropic", "Se compararon dos modelos locales (`qwen3:8b` y `qwen3:14b`)", "`docs/PLAN.md` dejó fuera del MVP la comparación con la API de Anthropic; con modelos locales ningún dato del perfil sale de la máquina y ambos alcanzaron el 100 % de salidas válidas"],
    ["OpenCanary y Cowrie como motores de señuelo", "Solo OpenCanary", "OpenCanary cubre SSH, HTTP, FTP, MySQL y Redis, los servicios del laboratorio. Cowrie (SSH interactivo) quedó fuera del MVP en `docs/PLAN.md`"],
    ["Respuesta: observación, contención con nftables y escalado", "Se decide la acción y se construye la regla nftables, pero no se aplica", "Bloquear en hosts reales exige una revisión y una aprobación que no daba tiempo a cerrar con garantías; se prioriza no tocar los hosts sin control"],
    ["Scapy para comprobaciones puntuales", "No se usa", "nmap con salida XML y los scripts `banner`/`http-server-header` fueron suficientes"],
    ["Laboratorio con Debian 12 y la VM `kali-lab`", "Debian 13 (Trixie) en las tres VMs y la VM Kali ya existente (`kali1`) como atacante", "Debian 13 es la versión estable disponible al crear las VMs; `kali1` ya estaba instalada y se adaptó a la red labnet con una instantánea previa"],
    ["Breadcrumbs y señuelos independientes", "Los breadcrumbs se generan desde el config del señuelo", "Así cada credencial lleva a un servicio activo del señuelo y la alerta se atribuye a su breadcrumb"],
    ["Trazabilidad de la IA con un trailer `AI-Assisted` en cada commit", "Los commits y PR no llevan marcas de IA; la trazabilidad vive en `AI_USAGE.md`", "Decisión del alumno durante el desarrollo, recogida en las reglas del proyecto (`CLAUDE.md`)"],
    ["Sin interfaz definida para el operador", "CLI `securization`, dashboard y Docker Compose", "Necesarios para usar la herramienta de punta a punta (H6)"],
  ], [30, 32, 38]),
  Sep(),
  P("También se añadieron piezas que el plan no detallaba y que la validación en el laboratorio hizo necesarias: guardar las versiones de los paquetes de servicio en el perfil (sin ellas no se puede derivar el banner real de MariaDB), limitar el escaneo a los puertos del perfil (sin `-p` nmap no veía Redis en el 6379) y validar el config de OpenCanary antes de arrancar (un banner de MySQL fuera de `3.x-6.x` hace que OpenCanary desactive el módulo sin avisar)."),
];

const pruebas = [
  H1("3. Pruebas y validación"),
  P("La validación tiene dos niveles: pruebas automáticas sin red, que se ejecutan en cada cambio y en la integración continua, y pruebas contra el laboratorio real, que validan lo que los dobles de prueba no pueden demostrar."),
  H2("3.1. Pruebas automáticas"),
  P("Cada tarea empezó por los tests y siguió con la implementación. La E/S real (SSH, SFTP, nmap, Docker, Ollama) se sustituye por dobles que registran exactamente qué comando o petición se habría enviado, lo que permite comprobar que los comandos son listas de argumentos fijas y que ninguno contiene texto del LLM. Los parsers se prueban con salidas reales guardadas en `tests/fixtures/` (nmap XML, `ss`, `os-release`, logs de OpenCanary)."),
  Tabla(["Control", "Herramienta", "Resultado en main"], [
    ["Tests unitarios y de integración", "pytest + pytest-asyncio", "601 tests en 27 ficheros, 0 fallos"],
    ["Cobertura", "pytest-cov", "99 % total; 100 % en perfilador, verificador y llm; 99 % en generador (objetivo: 80 %)"],
    ["Estilo y errores estáticos", "ruff check / ruff format", "Sin hallazgos"],
    ["Tipado", "mypy --strict", "Sin errores"],
    ["Seguridad del código", "bandit", "Sin hallazgos (prohíbe `shell=True` y `os.system`)"],
    ["Dependencias", "pip-audit", "Sin vulnerabilidades conocidas"],
    ["Integración continua", "GitHub Actions", "Las mismas comprobaciones en cada PR"],
  ], [28, 26, 46]),
  Sep(),
  P("Salida real de la suite de tests con cobertura sobre `main` (23 de noviembre de 2026):"),
  ...Codigo([
    "> pytest -q --cov",
    "src\\securization\\cli.py               108      1     14      0    99%",
    "src\\securization\\dashboard.py          71      0      0      0   100%",
    "src\\securization\\desplegador.py       139      0     20      0   100%",
    "src\\securization\\escaneo.py           170      7     60      4    95%",
    "src\\securization\\eventos.py           150      0     26      0   100%",
    "src\\securization\\generador.py         271      0     90      1    99%",
    "src\\securization\\inventario.py        104      3     14      0    97%",
    "src\\securization\\llm.py               113      0     20      0   100%",
    "src\\securization\\orquestador.py        95      0     22      0   100%",
    "src\\securization\\perfilador.py         86      0      4      0   100%",
    "src\\securization\\respuesta.py          26      0      6      0   100%",
    "src\\securization\\verificador.py        69      0     18      0   100%",
    "TOTAL                                1537     14    332      6    99%",
    "601 passed, 1 warning in 5.55s",
  ]),
  P("Entre las pruebas hay casos de seguridad explícitos: el cliente de Ollama rechaza cualquier URL que no sea local (`http://10.0.0.5:11434`, `https://api.ejemplo.com`, `http://localhost.evil.com`…); `deploy_decoy` no ejecuta nada con un plan sin aprobar o de otra campaña; un `node_id` con caracteres no válidos (`x;rm`, `--rm`) se rechaza antes de construir el comando `docker`; un config de OpenCanary con claves desconocidas falla antes de tocar el host; y el plantado por SFTP falla, sin escribir nada, si el fichero ya existe."),

  H2("3.2. Validación en el laboratorio"),
  P("El laboratorio es una red aislada de VirtualBox (`labnet`, 10.0.0.0/24) en la torre de desarrollo: dos víctimas con servicios reales distintos (victima-01 con nginx y MariaDB 11.8.9; victima-02 con vsftpd 3.0.5 y Redis), deception-central con Docker y una red macvlan para los señuelos, y una VM Kali como atacante. Todas las pruebas de esta sección se hicieron el 23 de noviembre de 2026 y son reproducibles con los scripts de `lab/`."),
  Tabla(["Sesión", "Qué se validó", "Resultado"], [
    ["L1", "Transporte SSH real contra las víctimas", "Perfiles reales de victima-01 y victima-02 con las credenciales del inventario cifrado"],
    ["L2", "nmap real y comparación con el host real", "nmap con Npcap en la torre, `-O` incluido y sin elevación; dos escaneos del mismo host dan 100"],
    ["L3", "Señuelos OpenCanary en macvlan", "Señuelos alcanzables en .50 y .51 con IP y MAC propias; alertas reales"],
    ["L4", "Breadcrumbs reales de extremo a extremo", "7 breadcrumbs plantados; las credenciales usadas desde cada víctima generaron alertas atribuidas a su campaña y breadcrumb (MySQL, HTTP, FTP y Redis)"],
    ["H4", "Bucle cerrado de verificación", "web-01: 50 (H2) → 90 (H4) en el segundo intento; files-02: 90 a la primera"],
    ["L5", "Modelo local y tasa de salidas válidas", "100 % válidas en `qwen3:8b` y `qwen3:14b` tras filtrar nombres delatores (ver 5.4)"],
    ["L6", "Docker Compose y pruebas ofensivas desde Kali", "Dashboard servido por `docker compose up -d`; las puntuaciones vistas desde Kali coinciden con las de la torre; ataques detectados"],
  ], [10, 34, 56]),

  H2("3.3. Resultados: línea base H2 frente a señuelo ajustado H4"),
  P("La comparación central del proyecto es la del señuelo determinista sin ajuste (H2) frente al mismo señuelo tras el bucle de verificación (H4), medida con nmap `-sV -O` tanto desde la torre como desde Kali:"),
  Tabla(["Señuelo (host real)", "H2", "H4", "Qué cambió el bucle"], [
    ["web-01 (victima-01)", "50", "90", "El saludo de MySQL del señuelo anunciaba `5.5.43-0ubuntu0.14.04.1`, que delata Ubuntu en una red Debian. El ajuste lo sustituyó por `5.5.5-11.8.9-MariaDB-0+deb13u1`, derivado del paquete instalado en el host real"],
    ["files-02 (victima-02)", "90", "90", "Supera el umbral a la primera; queda como diferencia que Redis no imita el modo protegido del real"],
  ], [22, 8, 8, 62]),
  Sep(),
  P("El bucle también corrigió una conclusión anterior: con el verificador de L3, web-01 puntuaba 90 y parecía aceptable. Al comparar producto, versión e información extra, y marcar como distinguible un banner que delata otra distribución, su puntuación real en H2 resultó ser 50. Un 90 sobre un umbral de 90 no significa que el señuelo sea indistinguible, sino que nmap ya no encuentra diferencias que pesen lo suficiente; las que quedan se documentan en el apartado 6."),
  H3("Vista del atacante (Kali)"),
  Tabla(["Ataque desde Kali", "Resultado"], [
    ["nmap -sV -O (puertos 1-1024 y servicios habituales)", "Misma puntuación que desde la torre: web-01 50 → 90, files-02 90"],
    ["hydra contra SSH de web-01", "5 de 5 intentos detectados y atribuidos a su campaña"],
    ["hydra contra FTP de files-02", "5 de 5 intentos detectados y atribuidos a su campaña"],
    ["Sondas de nmap a SSH y Redis", "Alertas generadas"],
    ["whatweb contra web-01", "Alerta generada, pero whatweb identifica el señuelo como «Synology RackStation» frente a la «Intranet» del host real"],
    ["Barrido de puertos", "Sin alerta: el módulo `portscan` de OpenCanary está desactivado"],
  ], [42, 58]),

  H2("3.4. Validación del código generado por IA"),
  P("Todo el código se generó con un agente de IA (apartado 4), así que la validación es la parte que da confianza en él. Además de las comprobaciones automáticas, se detectaron y corrigieron estos errores, la mayoría solo visibles al probar contra el laboratorio real:"),
  Tabla(["Error detectado", "Cómo se detectó", "Corrección"], [
    ["El perfilador devolvía un perfil parcial si fallaba un comando SSH", "Revisión de los tests (entrega intermedia)", "Cualquier fallo propaga `ProfilingError` con el host; test dedicado"],
    ["OpenCanary desactiva en silencio el módulo MySQL si el banner no empieza por 3.x-6.x", "Señuelo arrancado en L3 sin MySQL", "Prefijo `5.5.5-` de MariaDB y validación previa en `render_opencanary_conf`"],
    ["El verificador comparaba banners vacíos (`None`) y no veía ninguna diferencia", "Comparación real en L2", "Scripts `banner` y `http-server-header` en el escaneo"],
    ["nmap no detectaba Redis (6379)", "Perfil real frente a escaneo", "Escaneo limitado a los puertos del perfil"],
    ["El salt aleatorio del saludo MySQL hacía que dos escaneos del mismo host no coincidieran", "Dos escaneos seguidos en H4", "Normalización del saludo antes de comparar"],
    ["OpenSSH responde `FX_FAILURE` y no `FILE_ALREADY_EXISTS` al chocar con un fichero existente", "Plantado real en L4", "Comprobación con `exists()` y test que reproduce el caso"],
    ["Las IPs dentro de los banners (MariaDB incluye la IP del escáner) llegaban al LLM sin seudonimizar", "Revisión del perfil guardado antes de L5", "`build_profile_payload` seudonimiza también el texto de los servicios"],
    ["`qwen3:8b` proponía `victima-01-deco` en 24 de 25 casos, un nombre válido pero que delata el engaño; la plantilla de respaldo (`<host>-decoy`) tenía el mismo problema", "Medición de L5", "Filtro de palabras delatoras, instrucción en el prompt y respaldo `<host>-bak`"],
    ["Restaurar las VMs desde un estado guardado desfasaba su reloj (14 h) y el filtro por hora perdía eventos", "Pruebas de L6", "Recogida sin filtro por hora (deduplicación en `EventStore`) y ajuste del reloj"],
    ["La imagen Docker no se construía (README mal referenciado) y el volumen de datos no tenía permisos para el usuario sin root", "Construcción real en deception-central", "Corrección de `pyproject.toml` y preparación del volumen documentada"],
    ["Fallos de formato en la CI en dos PR", "GitHub Actions", "Commits de formato antes de fusionar"],
    ["Un commit generado llevaba una marca de IA contraria a las reglas del proyecto", "Revisión del alumno", "Commit corregido y regla guardada para el agente"],
  ], [38, 24, 38]),
  Sep(),
  P("La lección común es que la mayoría de estos errores no los detecta ninguna herramienta estática ni los tests con dobles: el código era correcto respecto a lo que el agente creía del entorno, pero el entorno real se comportaba de otra forma (OpenCanary, OpenSSH, nmap, MariaDB). Por eso la validación en el laboratorio ha sido imprescindible."),
];

const usoIA = [
  H1("4. Uso de IA en el desarrollo"),
  H2("4.1. Herramientas y agentes"),
  Tabla(["Herramienta", "Uso"], [
    ["Claude Code (Claude Sonnet 5 y Sonnet 5.5)", "Agente de desarrollo de las sesiones S0-S13 (octubre y noviembre de 2026)"],
    ["Claude Code (Claude Opus 5.5)", "Sesiones con laboratorio (L1-L6), bucle H4, CLI, Docker Compose, scripts del laboratorio y documentación final"],
    ["Subagentes y sesiones paralelas de Claude Code", "Tareas de búsqueda y preparación delegadas por el agente principal"],
    ["Asesor de Claude Code (comando /advisor, modelo Fable)", "Revisión del estado del proyecto y planificación de los pasos finales"],
  ], [40, 60]),
  Sep(),
  P("El agente trabajó dentro del repositorio siguiendo las reglas de `CLAUDE.md`, que actúa como contrato entre el alumno y el agente: alcance, principio de diseño, reglas de código obligatorias, flujo de trabajo y trazabilidad. Cada tarea tiene una entrada en `AI_USAGE.md` (fecha, herramienta, resumen del prompt, qué se generó, qué se modificó a mano y commit asociado): 32 entradas a fecha de esta memoria."),
  H2("4.2. Tareas en las que se ha usado"),
  B("Todo el código del paquete (12 módulos) y sus 601 tests."),
  B("Los scripts de aprovisionamiento y de prueba del laboratorio (`lab/`): creación de las VMs, IPs estáticas, servicios de las víctimas, Docker y macvlan, y las pruebas de L3 a L6."),
  B("La operación del laboratorio: el agente tenía permiso explícito del alumno para conectarse por SSH a las VMs y gestionarlas (VBoxManage), lo que le permitió diagnosticar problemas como el bloqueo de las VMs con Hyper-V o el modo promiscuo que necesitan los señuelos."),
  B("La documentación (README, `docs/PLAN.md`, `docs/lab-design.md`, `AI_USAGE.md`) y la preparación de esta memoria y de la presentación."),
  H2("4.3. Grado de automatización"),
  P("El desarrollo ha sido **agéntico casi por completo**: a partir de una descripción funcional, el agente escribía los tests, la implementación, ejecutaba las comprobaciones de calidad, creaba la rama y el commit y, en las sesiones con laboratorio, ejecutaba y diagnosticaba las pruebas reales. El alumno decidía el alcance de cada tarea, aprobaba los tests antes de implementar en las sesiones en las que así se pidió, aprobaba en el chat los planes de despliegue antes de plantar breadcrumbs reales, resolvía lo que requería interacción humana (control de cuentas de Windows al instalar Npcap, credenciales de la VM Kali) y fusionaba los PR."),
  H2("4.4. Valoración crítica, errores y límites"),
  P("**Lo que ha funcionado.** La combinación de tests primero, comprobaciones estrictas (mypy `--strict`, bandit) y dobles de prueba que registran los comandos ha mantenido el código generado dentro de las reglas: ningún comando se construye concatenando texto y todos los fallos esperados tienen un error claro. El agente fue además especialmente útil en el diagnóstico del laboratorio, donde un problema (señuelos que no responden, VMs que se bloquean) requería probar muchas hipótesis rápido."),
  P("**Errores de la IA.** Los recogidos en el apartado 3.4 tienen un patrón: el agente asumía un comportamiento del entorno que no era el real (códigos de error de OpenSSH, validación de banners de OpenCanary, puertos que nmap no escanea por defecto). Los tests con dobles no los detectaban porque los dobles reproducían la misma suposición. Hubo también un error de criterio en el componente de IA: aceptar como válida una salida que cumplía el esquema pero era inútil (`victima-01-deco`). Que una salida valide no significa que sirva."),
  P("**Optimismo en los resultados.** El agente dio por buena una puntuación de 90 en L3 que, con un verificador más estricto, era 50. Los resultados que produce la IA sobre su propio trabajo deben contrastarse con una medida independiente."),
  P("**Límite de proceso: la revisión humana.** `CLAUDE.md` exige revisar el diff completo antes de fusionar y línea a línea el código que ejecuta comandos remotos, construye reglas de cortafuegos o trata credenciales. Según `AI_USAGE.md`, la revisión línea a línea consta en el inventario (S1) y los tests se aprobaron antes de implementar en varias sesiones, pero en la mayoría de entradas el campo «qué se modificó a mano» es «nada» y en algunas la implementación figura como pendiente de revisión. Con el ritmo de las últimas semanas, la revisión humana fue el paso más débil del proceso: se confió sobre todo en las comprobaciones automáticas y en la validación en el laboratorio."),
  P("**Otros límites.** El agente no puede resolver lo que exige interacción humana en la máquina (UAC, asistentes gráficos) y algunas operaciones quedaron bloqueadas por las protecciones del propio agente (por ejemplo, forzar un push o borrar ramas remotas), lo que obligó a buscar alternativas seguras para fusionar los PR apilados."),
];

const componenteIA = [
  H1("5. Componente de IA"),
  H2("5.1. Modelo y proveedor"),
  Tabla(["Aspecto", "Decisión"], [
    ["Proveedor", "Ollama, ejecutado en local (en la torre durante las pruebas; en Docker Compose con el perfil `llm`, publicado solo en 127.0.0.1)"],
    ["Modelo por defecto", "`qwen3:8b` (configurable con `--model`); comparado con `qwen3:14b`"],
    ["Hardware de la medición", "GPU NVIDIA RTX 4070 SUPER; latencia de 0,25-0,3 s (8b) y 0,4-0,5 s (14b) por petición"],
    ["Proveedores externos", "Ninguno: el cliente solo acepta una URL local. No se ha usado la API de Anthropic en la herramienta"],
    ["Función", "Proponer el hostname del señuelo, coherente con la convención de nombres y los servicios de la red"],
  ], [28, 72]),
  Sep(),
  P("El papel del modelo se ha acotado deliberadamente a una tarea en la que aporta algo que una plantilla fija no da (variedad y coherencia del nombre con el entorno) y en la que un error es inocuo: el resultado es una etiqueta DNS que el operador usa como nombre del nodo del señuelo, y no se ejecuta ni se usa para construir ningún comando."),
  H2("5.2. Datos que se envían al modelo"),
  P("Al modelo solo llega un subconjunto del perfil (`ProfilePayload`), construido de forma determinista:"),
  Tabla(["Dato", "Cómo viaja"], [
    ["Identificador del host (`host_id`) y nombre del SO", "En claro, para que el modelo infiera la convención de nombres; no son datos personales ni credenciales"],
    ["IP del host e IPs libres de la red", "Seudonimizadas como `IP_1`, `IP_2`…"],
    ["Servicios (puerto, protocolo, producto, versión, banner)", "Con las IPs dentro del texto también seudonimizadas (el banner de MariaDB incluye la IP del escáner)"],
    ["Nombres de los directorios de primer nivel", "Solo los nombres, nunca su contenido"],
  ], [40, 60]),
  Sep(),
  P("Nunca se envían contenido de ficheros reales, credenciales (ni las reales ni las de los breadcrumbs), el usuario SSH de gestión, nombres de usuarios ni datos personales. El bloque se serializa como JSON, se eliminan los caracteres de control, se trunca a 4.096 caracteres y se envía entre las etiquetas `<perfil_host_no_confiable>`."),
  H2("5.3. Medidas de seguridad"),
  B("**Datos no confiables.** El perfil procede de hosts que un atacante podría controlar (un banner puede contener texto preparado para manipular al modelo), así que se trata como dato delimitado, saneado y truncado, nunca como instrucción."),
  B("**Modelo sin herramientas.** Solo devuelve texto; no tiene acceso a la red, a ficheros ni a comandos."),
  B("**Salida validada.** Se pide JSON (`format: json`, sin razonamiento visible) y se valida con un modelo Pydantic estricto (`extra=forbid`) cuyo único campo debe ser una etiqueta DNS válida (RFC 1123)."),
  B("**Filtro semántico.** Se rechazan los nombres que copian el del host real o contienen palabras que delatan el engaño (`decoy`, `deco`, `honey`, `canary`, `trap`, `fake`, `cebo`, `trampa`…)."),
  B("**Respaldo determinista.** Ante cualquier fallo (red, HTTP, JSON mal formado, esquema o filtro) se usa la plantilla `<host>-bak`, marcada como de menor calidad (`FALLBACK`)."),
  B("**Solo local.** El cliente rechaza cualquier URL que no sea `127.0.0.1` o `localhost`, incluidas variantes como `localhost.evil.com`."),
  B("**Separación de poderes.** Ningún comando que toque un host se construye con texto del modelo; los identificadores que llegan a comandos (`node_id`, IPs, rutas) se validan con expresiones estrictas antes de usarse."),
  H2("5.4. Resultados de la evaluación (L5)"),
  P("Con los perfiles reales de las dos víctimas y 25 semillas por víctima:"),
  Tabla(["Medida", "qwen3:8b", "qwen3:14b"], [
    ["JSON válido según el esquema (primera pasada)", "100 %", "100 %"],
    ["Nombres que delatan el engaño (primera pasada)", "24 de 25 con `victima-01-deco`", "Nombres variados"],
    ["Salidas válidas tras el filtro y el cambio de prompt", "100 %", "100 %"],
    ["Ejemplos de nombres", "`db-server-01`, a veces poco coherente (`db-server-02` para un servidor FTP/Redis)", "`servidor-datos-02`, `servidor-app-03`, más variados"],
    ["Latencia", "0,25-0,3 s", "0,4-0,5 s"],
  ], [40, 30, 30]),
  Sep(),
  H2("5.5. Riesgos residuales"),
  B("**Inyección indirecta acotada, no eliminada.** Un banner manipulado aún puede influir en el nombre propuesto; el daño posible se limita a una etiqueta DNS que pasa el filtro y que el operador revisa."),
  B("**Coherencia semántica no verificada.** El esquema garantiza la forma, no que el nombre encaje con los servicios (caso `db-server-02` para un servidor de ficheros)."),
  B("**Fuga de metadatos internos.** El `host_id` y el nombre del SO viajan en claro; con un modelo local no salen de la máquina, pero si se cambiara a un proveedor externo habría que seudonimizarlos también."),
  B("**Cadena de suministro del modelo.** Los pesos se descargan con Ollama; la imagen de Ollama está fijada por versión, pero el modelo no se verifica por hash."),
  B("**Nombres predecibles.** Un modelo pequeño tiende a repetir patrones (`db-server-NN`), que un atacante con varios señuelos a la vista podría reconocer."),
];

const limitaciones = [
  H1("6. Limitaciones y continuidad"),
  H2("6.1. Lo que la herramienta no hace"),
  B("**No aplica la respuesta.** El módulo de respuesta decide la acción y construye la regla nftables como lista de argumentos, pero no la ejecuta en los hosts ni está conectado a la CLI; el modo contención está implementado como decisión, no como acción."),
  B("**No detecta la lectura de un breadcrumb.** Solo se detecta cuando el atacante usa una credencial contra el señuelo; detectar la lectura exigiría auditd en el host real, es decir, modificarlo, lo que queda fuera del alcance."),
  B("**El contenido HTTP no se replica.** OpenCanary solo ofrece páginas de login predefinidas; whatweb distingue el señuelo («Synology RackStation») del host real («Intranet»), algo que nmap no ve y que el verificador no mide."),
  B("**Diferencias que OpenCanary no permite corregir.** El rechazo `unauthorized` de MariaDB (que incluye la IP del escáner), el modo protegido de Redis y MySQL 8, que OpenCanary no puede anunciar."),
  B("**Sin alerta de barridos de puertos**, porque el módulo `portscan` de OpenCanary está desactivado."),
  B("**El hostname del LLM no se aplica solo**: el operador lo pasa a `campaign` con `--decoy-node`."),
  B("**Seguridad de la propia herramienta pensada para el laboratorio.** El SSH usa contraseña y no verifica la clave del host (`known_hosts` desactivado porque las VMs se recrean), y el dashboard no tiene autenticación. En una red real habría que fijar las claves de host y proteger el dashboard."),
  B("**Solo Linux e IPv4**, un único host de señuelos y un umbral fijo (90). Una puntuación en el umbral no garantiza que el señuelo sea indistinguible."),
  H2("6.2. Líneas futuras"),
  N("Aplicar la contención con un `ContainmentBackend` (nftables en Linux) tras una confirmación del operador, con la regla ya construida y probada.", "futuro"),
  N("Añadir al verificador una sonda HTTP (título, cabeceras y estructura de la página) y permitir plantillas HTTP propias en el señuelo.", "futuro"),
  N("Integrar Cowrie para el SSH interactivo y activar `portscan` con un umbral razonable.", "futuro"),
  N("Proteger la herramienta: claves de host fijadas, autenticación por clave SSH y dashboard con autenticación.", "futuro"),
  N("Ampliar el papel del modelo con la misma disciplina: variedad en el contenido de los breadcrumbs, validado por esquema y con las credenciales fijadas por código.", "futuro"),
  N("Soporte Windows (perfilador con OpenSSH y PowerShell, catálogo de breadcrumbs y backend de contención), con el riesgo ya identificado de que `nmap -O` detecte la pila TCP/IP de Linux del contenedor.", "futuro"),
  H2("6.3. Continuidad en el Trabajo Fin de Grado"),
  P("El anteproyecto del TFG (tutor: Jorge Sánchez Cifuentes) usa esta herramienta como **instrumento** de un diseño experimental distinto, sin repetir su evaluación de ingeniería. La pregunta de investigación es si un bucle automático de verificación y ajuste de plausibilidad reduce de forma medible la tasa de detección de un señuelo, tanto frente a herramientas de escaneo convencionales como frente a agentes de pentesting autónomos basados en LLM (PentestGPT, ARACNE, CAI), y si hay diferencias entre ambos tipos de atacante."),
  P("Esta entrega deja preparada la base experimental: las dos configuraciones a comparar (línea base H2 y señuelo ajustado H4), un laboratorio aislado reproducible con scripts, la puntuación de plausibilidad como medida y la recogida de eventos atribuidos por campaña. El TFG añadirá la campaña de ataques controlada con agentes de IA, la recogida sistemática de si cada sesión detecta el señuelo y en qué paso, y el análisis comparativo."),
];

const manual = [
  H1("7. Manual de instalación y uso"),
  P("El manual completo y actualizado está en el `README.md` del repositorio. Este apartado resume lo necesario para instalar y usar la herramienta."),
  H2("7.1. Requisitos"),
  Tabla(["Para…", "Se necesita"], [
    ["CLI y dashboard", "Python 3.12 y `nmap` en el PATH"],
    ["Señuelos", "Un host Linux con Docker y una red macvlan (`labnet-decoys`) en la LAN"],
    ["IA (opcional)", "Ollama local con un modelo, por ejemplo `qwen3:8b`"],
    ["Autodespliegue", "Docker y Docker Compose"],
    ["Hosts gestionados", "Solo un servidor SSH y un usuario con contraseña; no se instala ningún agente"],
  ], [30, 70]),
  H2("7.2. Instalación"),
  P("**Opción A, entorno virtual:**"),
  ...Codigo([
    "python -m venv .venv",
    ".\\.venv\\Scripts\\Activate.ps1          # Linux/macOS: source .venv/bin/activate",
    "pip install -e \".[dev]\"",
    "python -c \"from securization.inventario import CredentialVault as V; open('securization.key','wb').write(V.generate_key())\"",
  ]),
  P("**Opción B, Docker Compose:** la imagen corre sin root (uid 10001), incluye nmap y guarda los datos en `./data`, que nunca se copia a la imagen."),
  ...Codigo([
    "mkdir -p data && sudo chown 10001:10001 data && chmod 700 data",
    "docker compose run --rm --entrypoint python securization -c \\",
    "  \"from securization.inventario import CredentialVault as V; open('/data/securization.key','wb').write(V.generate_key())\"",
    "docker compose up -d                   # dashboard en http://<host>:8000",
    "docker compose --profile llm up -d     # además, Ollama local",
  ]),
  P("La clave Fernet (`securization.key`) y la base de datos (`inventario.db`) están en `.gitignore` y no deben versionarse. Variables de entorno opcionales: `SECURIZATION_DB`, `SECURIZATION_KEY_FILE` (o la clave en `SECURIZATION_KEY`), `SECURIZATION_DECEPTION_HOST` (host que aloja los señuelos, por defecto `deception-central`) y `SECURIZATION_DECOY_DIR`."),
  H2("7.3. Uso"),
  ...Codigo([
    "securization hosts add victima-01 10.0.0.10 --user lab       # pide la contraseña",
    "securization hosts add deception-central 10.0.0.5 --user lab",
    "securization profile victima-01",
    "securization name victima-01 --model qwen3:8b                # opcional (IA)",
    "securization campaign victima-01 --decoy-node web-01 --decoy-ip 10.0.0.50",
    "securization approve campana-victima-01",
    "securization deploy campana-victima-01",
    "securization events collect",
    "securization events list",
    "securization dashboard --host 127.0.0.1 --port 8000",
  ]),
  P("`campaign` arranca el señuelo solo para verificarlo y deja el plan guardado sin aprobar; `approve` falla si la puntuación no supera el umbral; `deploy` exige el plan aprobado. El dashboard muestra el inventario, las campañas con los intentos del bucle y sus diferencias, el botón de aprobación y los eventos por campaña."),
  H2("7.4. Notas de operación"),
  B("Un host Docker no alcanza sus propios contenedores macvlan: `campaign` debe lanzarse desde una máquina distinta del host de señuelos."),
  B("Los señuelos necesitan el modo promiscuo en dos niveles: en el adaptador de VirtualBox (`allow-all`) y dentro del invitado (`ip link set <iface> promisc on`); `lab/provision_deception.py` lo deja configurado."),
  B("En VirtualBox sobre Hyper-V las VMs deben usar 1 vCPU sin IO-APIC; tras restaurar un estado guardado hay que ajustar el reloj antes de comparar horas de eventos."),
  B("Calidad: `ruff check .`, `ruff format --check .`, `mypy`, `bandit -r src -c pyproject.toml`, `pip-audit` y `pytest --cov`."),
];

// --- documento ------------------------------------------------------------------

const doc = new Document({
  creator: "Enrique Hedo Bravo",
  title: "Memoria final - autoadaptable-securization",
  features: { updateFields: true },
  styles: {
    default: { document: { run: { font: FUENTE, size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FUENTE, size: 32, bold: true, color: AZUL },
        paragraph: { spacing: { before: 240, after: 200 }, keepNext: true, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FUENTE, size: 26, bold: true, color: AZUL },
        paragraph: { spacing: { before: 280, after: 120 }, keepNext: true, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { font: FUENTE, size: 23, bold: true, color: "404040" },
        paragraph: { spacing: { before: 200, after: 100 }, keepNext: true, outlineLevel: 2 } },
    ],
  },
  numbering: {
    config: [
      { reference: "vinetas", levels: [
        { level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 540, hanging: 270 } } } },
        { level: 1, format: LevelFormat.BULLET, text: "–", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 1080, hanging: 270 } } } } ] },
      { reference: "numeros", levels: [
        { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 540, hanging: 300 } } } } ] },
      { reference: "futuro", levels: [
        { level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 540, hanging: 300 } } } } ] },
    ],
  },
  sections: [
    {
      properties: { page: { size: { width: 11906, height: 16838 },
        margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }, titlePage: true },
      headers: {
        default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT,
          children: [new TextRun({ text: "autoadaptable-securization · Memoria final", size: 16, color: "808080" })] })] }),
        first: new Header({ children: [new Paragraph({ children: [] })] }),
      },
      footers: {
        default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
          children: [new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "808080" })] })] }),
        first: new Footer({ children: [new Paragraph({ children: [] })] }),
      },
      children: [
        ...portada, ...indice, ...resumen, ...herramienta, ...pruebas,
        ...usoIA, ...componenteIA, ...limitaciones, ...manual,
      ],
    },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(SALIDA, buf);
  console.log("Escrito " + SALIDA + " (" + buf.length + " bytes)");
});
