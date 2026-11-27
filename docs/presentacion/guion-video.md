# Guion del vídeo y de la demo

Vídeo de 8-10 minutos (máximo 15), narrado por el alumno. El texto de narración es una
propuesta: léelo con tus palabras. Los tiempos de la demo son los medidos en el ensayo real
del 23 de noviembre de 2026 contra el laboratorio.

## Antes de grabar (15 minutos)

1. Arranca las cuatro VMs (victima-01, victima-02, deception-central, kali1) y comprueba el
   laboratorio: `python lab\check_lab.py` (todas deben responder al ping y por SSH).
2. Si las VMs vienen de un estado guardado, pon en hora su reloj antes de nada (ver
   `docs/lab-design.md`); si no, las horas de los eventos saldrán desfasadas.
3. Deja las víctimas sin breadcrumbs de ensayos anteriores (si no, `campaign` se negará a
   generar la campaña porque nunca sobrescribe un fichero): muévelos a `/tmp` o pídeselo a
   Claude.
4. Usa una base de datos limpia solo para la grabación, en la terminal de la torre:
   `$env:SECURIZATION_DB='grabacion.db'` (la clave `securization.key` es la misma).
5. Ten abiertas tres ventanas: PowerShell en la raíz del repositorio (torre), una terminal en
   Kali (la consola de la VM kali1 o SSH a 10.0.0.20) y el navegador.
6. Arranca el dashboard en otra terminal con la misma variable:
   `securization dashboard --port 8000` y ábrelo en `http://127.0.0.1:8000`.
7. Sube el tamaño de letra de las terminales (al menos 16 pt) y usa tema claro.

`campaign` tarda unos 100 s en victima-01: grábalo entero y acelera o corta esa parte al
editar, diciendo en voz lo que está pasando.

## Estructura y narración

### 1. Problema (0:00-0:45) · diapositivas 1-2

> Un honeypot o un señuelo de red solo sirve si el atacante no lo reconoce. El problema es
> que la mayoría se despliegan con una configuración estática y basta un nmap para ver que
> su sistema operativo o sus versiones no encajan con el resto de la red. Mi proyecto es una
> herramienta que genera señuelos a partir de los hosts reales de la red y comprueba
> automáticamente, con el mismo escaneo que haría un atacante, que no se distinguen de
> ellos antes de desplegarlos.

### 2. Cómo funciona (0:45-2:00) · diapositivas 3-4

> La herramienta no instala nada en los hosts: se conecta por SSH solo a los que doy de alta,
> los perfila con SSH y con nmap, y monta una campaña con dos piezas. Un señuelo, que es un
> contenedor OpenCanary con su propia IP y MAC en la red, y unos breadcrumbs, que son
> ficheros cebo con credenciales falsas plantados en los hosts reales y que apuntan al
> señuelo. Lo diferencial es el bucle: el señuelo se escanea junto al host real, se comparan
> las huellas, se puntúa de 0 a 100 y, si no llega a 90, se ajusta con datos del host real y
> se vuelve a probar. Y nada se despliega sin que yo lo apruebe.

### 3. Componente de IA (2:00-2:45) · diapositiva 5

> La IA tiene un papel pequeño y controlado a propósito. Un modelo local, qwen3 en Ollama,
> propone el nombre del señuelo para que encaje con la red. No sale ningún dato de la
> máquina: el cliente solo acepta una URL local. El perfil llega con las IPs seudonimizadas,
> truncado y marcado como dato no confiable, porque un banner podría intentar manipular al
> modelo. La respuesta se valida con un esquema estricto y, si falla o el nombre delata el
> engaño, se usa una plantilla fija. Y lo más importante: ningún comando se construye con
> texto del modelo; todo lo que toca los hosts lo decide código determinista.

### 4. Demo (2:45-8:00)

| # | Dónde | Qué hacer | Qué decir / qué se ve | Tiempo |
| --- | --- | --- | --- | --- |
| 1 | Torre | `securization hosts add victima-01 10.0.0.10 --user lab` y lo mismo para `deception-central 10.0.0.5`; después `securization hosts list` | La contraseña se pide por teclado y se guarda cifrada con Fernet; nunca va por argumentos ni a los logs | 30 s |
| 2 | Torre | `securization profile victima-01` | Debian 13 con nginx y MariaDB 11.8.9; las versiones de los paquetes salen por SSH, los banners por nmap | 40 s |
| 3 | Torre | `securization name victima-01` (opcional, requiere Ollama en marcha) | El modelo propone un hostname; si falla, se ve la plantilla de respaldo | 10 s |
| 4 | Torre | `securization campaign victima-01 --decoy-node web-01 --decoy-ip 10.0.0.50` | Intento 1: **50/90**, el señuelo delata Ubuntu en el saludo de MySQL. Intento 2: **90/90**, el banner se ha copiado del paquete MariaDB real. El plan queda guardado **sin aprobar** | ~100 s (acelerar) |
| 5 | Torre | `securization deploy campana-victima-01` | Se niega: el plan no está aprobado | 5 s |
| 6 | Navegador | Dashboard → Campañas → campana-victima-01 | Intentos del bucle con sus diferencias, breadcrumbs planeados y botón **Aprobar despliegue**: púlsalo | 40 s |
| 7 | Torre | `securization deploy campana-victima-01` | «Plantados 4 breadcrumbs en victima-01; señuelo decoy-web-01» | 12 s |
| 8 | Kali | `sudo nmap -sV -O -p 22,80,3306 10.0.0.10 10.0.0.50` | El real y el señuelo salen casi idénticos (OpenSSH Debian, nginx, MariaDB). Diferencia que queda: el texto de versión de MariaDB | 20 s |
| 9 | victima-01 (como si el atacante la hubiera comprometido; `ssh lab@10.0.0.10`) | `cat ~/.my.cnf` | Credenciales de base de datos que apuntan a 10.0.0.50 | 10 s |
| 10 | Kali | `mysql -h 10.0.0.50 -u app_svc -p<clave del .my.cnf> --skip-ssl -e 'show databases'` | Acceso denegado para el atacante, pero ya ha caído en el engaño | 10 s |
| 11 | Kali (opcional) | `hydra -l root -P /tmp/claves.txt -t 2 -I ssh://10.0.0.50` con 5 claves | Fuerza bruta típica contra el señuelo | 10 s |
| 12 | Torre | `securization events collect` y `securization events list` | La alerta de MySQL sale marcada **breadcrumb mysql** y atribuida a campana-victima-01; los intentos SSH también | 15 s |
| 13 | Navegador | Dashboard → Eventos | Alertas por campaña y cuántas usaron una credencial de breadcrumb | 20 s |

Notas de la demo:

- `--skip-ssl` es necesario: el cliente MariaDB de Kali exige TLS por defecto y, sin la
  opción, falla antes de enviar la credencial y no hay alerta de breadcrumb.
- Tipos de alerta de OpenCanary que aparecen: 4000 conexión SSH, 4001 versión del cliente
  SSH, 4002 intento de login SSH, 8001 login MySQL, 17001 comando Redis.
- Las alertas que vienen de 10.0.0.1 son los escaneos del propio bucle de verificación (la
  torre), no del atacante.
- Si `campaign` falla con «colisión de ruta», la víctima tiene breadcrumbs de un ensayo
  anterior: la herramienta nunca sobrescribe ficheros (paso 3 de la preparación).

### 5. Resultados y límites (8:00-9:30) · diapositivas 7-9

> Medido en el laboratorio, el bucle sube el señuelo de victima-01 de 50 a 90 y ve lo mismo
> desde Kali que desde la torre. Todos los ataques contra el señuelo generan alertas
> atribuidas a su campaña. Pero 90 no es indistinguible: whatweb ve en el señuelo un login de
> NAS Synology donde el host real tiene su página de Intranet, y hay respuestas, como el modo protegido de Redis, que OpenCanary no deja
> imitar. Tampoco aplica todavía la contención: decide la regla de nftables pero no la
> ejecuta. El código tiene 602 tests con un 99 % de cobertura, y casi todo lo escribió un
> agente de IA bajo mi supervisión; los errores que cometió los encontramos al probar contra
> el laboratorio real, no con los tests.

### 6. Cierre (9:30-10:00) · diapositiva 10

> Esta herramienta es la base de mi TFG: allí la usaré para medir si un señuelo ajustado así
> engaña más que uno estático, tanto a escáneres como a agentes de pentesting basados en IA.
