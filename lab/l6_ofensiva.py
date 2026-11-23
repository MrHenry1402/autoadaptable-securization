"""L6/H7: pruebas ofensivas desde Kali contra víctimas y señuelos (H2 frente a H4).

EN CURSO (2026-11-23): sin validar todavía. La primera ejecución se paró a mano durante el
escaneo H2: `nmap -sV -O -p-` de 4 hosts llevaba más de 15 min con Kali a 1 vCPU. Antes de
repetirla, valorar `--top-ports 1000` más los puertos del perfil, o subir Kali a 2 vCPU.

Uso: python lab/l6_ofensiva.py lab   (desde la raíz; necesita kali-lab en
lab-credentials.local.txt y los señuelos de lab/e2e_l3.py)


Desde kali-lab (10.0.0.20), como atacante en labnet:
1. Para cada víctima, arranca el señuelo con el config H2 (línea base, sin ajustar) y lo
   escanea desde Kali junto al host real (nmap -sV -O -p- con scripts de banner); después
   igual con el config H4 (ajustado por el bucle). Compara con el verificador del proyecto.
2. Lanza ataques típicos contra los señuelos H4 (whatweb, hydra con pocas claves) y mide qué
   alertas de OpenCanary genera y si se atribuyen a su campaña.
"""

import asyncio
import json
import shlex
import sys
import time
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else "lab")  # _credenciales.py
import asyncssh
from _credenciales import load_lab_hosts
from sqlmodel import create_engine

from securization.desplegador import AsyncSftpTransport, start_decoy
from securization.escaneo import parse_nmap_xml
from securization.eventos import CampaignIndex, parse_opencanary_log
from securization.generador import CampaignStore, build_opencanary_config
from securization.inventario import CredentialVault, Inventory
from securization.modelos import Fingerprint
from securization.parsing import ParseError
from securization.perfilador import AsyncSshTransport, HostProfileStore
from securization.verificador import verify_decoy

ROOT = Path.cwd()
OUT = Path(__file__).parent / "l6_resultado"
PARES = {"victima-01": "10.0.0.10", "victima-02": "10.0.0.11"}


class Kali:
    def __init__(self) -> None:
        h = next(x for x in load_lab_hosts(ROOT) if x.host_id == "kali-lab")
        self.h = h

    async def run(self, argv: list[str], *, sudo: bool = False, limite_s: int = 1800) -> str:
        async with asyncssh.connect(
            "127.0.0.1",
            port=self.h.nat_port,
            username=self.h.user,
            password=self.h.password,
            known_hosts=None,
        ) as c:
            comando = shlex.join(["sudo", "-S", "-p", "", *argv] if sudo else argv)
            p = await c.create_process(comando)
            if sudo:
                p.stdin.write(self.h.password + "\n")
            p.stdin.write_eof()
            salida = await asyncio.wait_for(p.stdout.read(), limite_s)
            await p.wait()
            return str(salida)


async def escanear(kali: Kali, ips: list[str], nombre: str) -> dict[str, Fingerprint]:
    argv = [
        "nmap",
        "-sV",
        "-O",
        "-p-",
        "-T4",
        "--script",
        "banner,http-server-header",
        "-oX",
        "-",
        *ips,
    ]
    xml = await kali.run(argv, sudo=True)
    (OUT / f"{nombre}.xml").write_text(xml, encoding="utf-8")
    return {str(h.address): h for h in parse_nmap_xml(xml)}


async def main() -> None:
    OUT.mkdir(exist_ok=True)
    engine = create_engine(f"sqlite:///{ROOT / 'inventario.db'}")
    inv = Inventory(engine, CredentialVault((ROOT / "securization.key").read_bytes().strip()))
    perfiles, campanas = HostProfileStore(engine), CampaignStore(engine)
    dc = inv.get_host("deception-central")
    pw = inv.get_ssh_secret("deception-central")
    ssh_dc = AsyncSshTransport(dc.address, dc.ssh_port, dc.ssh_user, pw)
    sftp_dc = AsyncSftpTransport(dc.address, dc.ssh_port, dc.ssh_user, pw)
    kali = Kali()
    resultado: dict[str, object] = {}

    # --- 1. Distinguibilidad desde el atacante: H2 frente a H4 -----------------------
    camps = {h: campanas.load(f"campana-{h}") for h in PARES}
    for fase in ("H2", "H4"):
        for host_id, campana in camps.items():
            decoy = campana.decoy
            if fase == "H2":
                config = build_opencanary_config(perfiles.load(host_id), node_id=decoy.node_id)
                decoy = decoy.model_copy(update={"opencanary_config": config})
            await start_decoy(decoy, sftp=sftp_dc, ssh=ssh_dc, config_dir="/home/lab/decoys")
        await asyncio.sleep(12)
        ips = [*PARES.values(), *(str(c.decoy.address) for c in camps.values())]
        t0 = time.perf_counter()
        huellas = await escanear(kali, ips, f"nmap_kali_{fase}")
        print(f"{fase}: escaneo desde Kali en {time.perf_counter() - t0:.0f} s", flush=True)
        for host_id, ip_real in PARES.items():
            ip_senuelo = str(camps[host_id].decoy.address)
            real, senuelo = huellas[ip_real], huellas[ip_senuelo]
            informe = verify_decoy(real, senuelo)
            resultado[f"{fase}/{host_id}"] = {
                "puntuacion": informe.score,
                "aprobado": informe.passed,
                "puertos_real": [s.port for s in real.services],
                "puertos_senuelo": [s.port for s in senuelo.services],
                "so_real": real.os_matches[0].name if real.os_matches else None,
                "so_senuelo": senuelo.os_matches[0].name if senuelo.os_matches else None,
                "diferencias": informe.differences,
            }
            print(f"  {host_id}: {informe.score} {informe.differences}", flush=True)

    # --- 2. Ataques típicos contra los señuelos H4 y alertas -------------------------
    inicio = datetime.now()
    web, files = (str(camps[h].decoy.address) for h in PARES)
    real_web = PARES["victima-01"]
    whatweb = {
        ip: (await kali.run(["whatweb", "--color=never", "-a", "1", f"http://{ip}/"])).strip()
        for ip in (real_web, web)
    }
    claves = "123456\npassword\nadmin\nroot\nqwerty\n"
    lista = "/tmp/claves.txt"  # noqa: S108 - ruta dentro de Kali, no un fichero local
    await kali.run(["sh", "-c", f"printf '{claves}' > {lista}"])
    hydra = {}
    for objetivo in (f"ssh://{web}", f"ftp://{files}", f"ftp://{web}"):
        salida = await kali.run(
            ["hydra", "-l", "admin", "-P", lista, "-t", "2", "-f", "-I", objetivo]
        )
        hydra[objetivo] = [
            linea
            for linea in salida.splitlines()
            if "valid password" in linea or "completed" in linea
        ]
    redis = await kali.run(["redis-cli", "-h", files, "AUTH", "admin"])
    await asyncio.sleep(3)

    por_nodo = {c.decoy.node_id: c for c in camps.values()}
    indice = CampaignIndex(list(por_nodo.values()))
    alertas: dict[str, dict[str, int]] = {}
    for nodo in por_nodo:
        log = await ssh_dc.run(
            ["docker", "exec", f"decoy-{nodo}", "cat", "/var/tmp/opencanary.log"]  # noqa: S108 - ruta del contenedor
        )
        for linea in log.splitlines():
            try:
                ev = parse_opencanary_log(linea)
            except ParseError:
                continue
            if ev.src_host != IPv4Address("10.0.0.20") or ev.timestamp < inicio.replace(
                microsecond=0
            ):
                continue
            camp = indice.correlate_opencanary_event(ev).campaign_id
            alertas.setdefault(camp, {}).setdefault(str(ev.logtype), 0)
            alertas[camp][str(ev.logtype)] += 1
    resultado["ataques"] = {
        "whatweb": whatweb,
        "hydra": hydra,
        "redis": redis.strip(),
        "alertas_desde_kali_por_campana": alertas,
    }
    texto = json.dumps(resultado, indent=2, ensure_ascii=False)
    (OUT / "resultado.json").write_text(texto, encoding="utf-8")
    print(texto)


asyncio.run(main())
