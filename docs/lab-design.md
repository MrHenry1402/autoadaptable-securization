# Laboratorio H0 (VirtualBox)

Topología real del laboratorio, sobre VirtualBox en la máquina de desarrollo (torre, no el
portátil que describía el estado inicial del proyecto). No incluye credenciales: están en
`lab-credentials.local.txt`, en la raíz del repositorio, ignorado por git (nunca se commitea).

## Red `labnet`

Adaptador Host-Only dedicado, separado del que usa cualquier otro proyecto en la misma
máquina (no reutiliza el adaptador Host-Only por defecto de VirtualBox):

- Nombre del adaptador: `VirtualBox Host-Only Ethernet Adapter #2`
- Subred: `10.0.0.0/24`
- IP del host en esa red: `10.0.0.1`

## Hosts

| Host | IP (labnet) | SO | RAM | CPU | Rol | Estado |
|---|---|---|---|---|---|---|
| `deception-central` | 10.0.0.5 | Debian 13 (Trixie) | 2 GB | 1 | Futuros deception hosts (H2+, OpenCanary/Cowrie) | Operativo: IP estática, SSH y ping cruzado verificados |
| `victima-01` | 10.0.0.10 | Debian 13 (Trixie) | 2 GB | 1 | Host real a perfilar | Operativo: IP estática, SSH y ping cruzado verificados |
| `victima-02` | 10.0.0.11 | Debian 13 (Trixie) | 2 GB | 1 | Host real a perfilar | Operativo: IP estática, SSH y ping cruzado verificados |
| `kali-lab` | 10.0.0.20 | Kali Linux 2024.4 | 4 GB | 1 | Host atacante (H7) | VM creada con el ISO montado; instalación del SO pendiente (manual, `VBoxManage unattended` no soporta el instalador de Kali) |

### Servicios de las víctimas

Cada víctima tiene un papel distinto, con servicios que OpenCanary sabe emular, para que
el señuelo no se reduzca a copiar un `sshd` y la comparación H2 vs H4 tenga sentido. Se
instalan con `lab/provision_services.py` (idempotente).

| Host | Papel | Servicios (todas las interfaces) |
|---|---|---|
| `victima-01` | Servidor web con base de datos | SSH 22, nginx 80 (página "Intranet"), MariaDB 3306 |
| `victima-02` | Servidor de ficheros y caché | SSH 22, vsftpd 21, Redis 6379 (modo protegido) |

MariaDB rechaza conexiones desde hosts no autorizados ("Host ... is not allowed") y Redis,
sin contraseña y fuera de loopback, responde en modo protegido; ambos comportamientos son
los de un servidor real y son los que verá `nmap -sV`.

`victima-01` se instaló antes de corregir el preseed y tiene un escritorio GNOME completo.
Arranca en `multi-user.target` con `gdm3` y `cups` desactivados (371 MB de RAM en uso), así
que no expone nada más; para dejarla limpia, reinstalarla con `lab/provision_vm.ps1`.

Cada VM Debian tiene dos adaptadores: `nic1` NAT (solo para `apt` durante la instalación y
actualizaciones puntuales) y `nic2` en `labnet` con la IP de la tabla. `kali-lab` sigue el
mismo patrón.

Estado verificado el 2026-11-23: las tres VMs Debian responden por SSH, tienen su IP de
`labnet` en `enp0s8`, se hacen ping entre sí y el host las alcanza en `10.0.0.5/.10/.11`.

### Configuración obligatoria de CPU (Hyper-V activo en la torre)

En esta máquina el hipervisor de Windows está activo, así que VirtualBox no puede usar
AMD-V directamente y cae al backend NEM (Windows Hypervisor Platform); en `VBox.log`
aparece `HM: HMR3Init: Attempting fall back to NEM: AMD-V is not available`. Con 2 vCPU,
IO-APIC y paravirtualización por defecto, los invitados se colgaban al arrancar
(`TM: Giving up catch-up attempt at a 60 00X ns lag`) o el kernel entraba en pánico
(`IO-APIC + timer doesn't work`). Todas las VMs del laboratorio usan por eso:

```
VBoxManage modifyvm <vm> --cpus 1 --ioapic off --paravirtprovider none
```

Si en el futuro se desactiva Hyper-V (y lo que lo arrastra: WSL2, Docker Desktop,
integridad de memoria/VBS) y VirtualBox vuelve a usar AMD-V, se puede volver a 2 vCPU con
IO-APIC activado.

### Scripts (`lab/`)

Todos se ejecutan desde la raíz del repositorio y leen usuario, contraseña, puerto NAT e IP
de `lab-credentials.local.txt`; ninguno imprime contraseñas.

| Script | Qué hace |
|---|---|
| `provision_vm.ps1` | Crea la VM, instala Debian desatendido con `debian_preseed_minimal.cfg` y añade el NIC2 de labnet |
| `debian_preseed_minimal.cfg` | Plantilla de VirtualBox con `tasksel/first` fijado (sin él, a veces instala GNOME) |
| `set_static_ip.py <host_id>` | Fija la IP estática de labnet en la VM |
| `provision_services.py` | Instala y configura los servicios de cada víctima |
| `retry_boot_until_ssh.ps1` | Reinicia una VM hasta que su SSH responde de forma estable |
| `check_lab.py` | SSH, IPs y ping cruzado entre las tres VMs |
| `register_lab.py` | Alta en `inventario.db` (clave en `securization.key`) y verificación SSH |
| `profile_lab.py` | Perfilado real con `AsyncSshTransport` (requiere el código de L1) |

### Pendiente de completar (pasos manuales)

1. Instalar Kali en `kali-lab` desde la ventana de VirtualBox (el ISO ya está montado;
   arranca con `VBoxManage startvm kali-lab --type gui` o desde la interfaz gráfica).
2. Dar de alta `victima-01` y `victima-02` en el `Inventory` del propio proyecto
   (credenciales SSH cifradas con Fernet) para poder probar el perfilador contra hosts
   reales (sesiones L1 en adelante de `docs/PLAN.md`).

## Por qué este diseño

- **Host-Only y no Internal Network**: el orquestador (este código) corre en el host, no
  dentro de una VM, y necesita SSH directo a las víctimas y poder lanzar `nmap` contra
  ellas. Una red Host-Only de VirtualBox conecta el host con las VMs sin exponerlas a la
  LAN física ni a internet; una red "Internal Network" (`intnet`) excluiría al host.
- **NAT temporal por VM**: el netinst de Debian necesita red para instalar `openssh-server`
  (no viene en el ISO base). Se usa una NAT efímera solo para eso; el tráfico real del
  proyecto va por `labnet`.
- **Debian 13 en vez de 12**: el único ISO de Debian ya descargado en la máquina era la
  13.7.0 (Trixie); se usó esa para no añadir una descarga innecesaria. No afecta a nada del
  código (los parsers de `perfilador`/`parsers_linux.py` son agnósticos a la versión exacta
  de Debian).
