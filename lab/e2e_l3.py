"""Validación de punta a punta de L3 contra el laboratorio real, con el código del proyecto.

Uso: python lab/e2e_l3.py   (desde la raíz; nmap en el PATH)

Requiere el código de L3 (`start_decoy`, `enrich_profile`, ...) y haber ejecutado antes
lab/register_lab.py, lab/profile_lab.py y lab/provision_deception.py. Para cada víctima:
escanea el host real con los puertos de su perfil, completa el perfil con nmap, genera la
campaña H2, arranca el señuelo en deception-central en una IP libre de labnet, lo escanea
igual que al real (y además sin `-p`, para ver puertos de más) y calcula el informe de
plausibilidad. Los señuelos quedan encendidos; se paran con `stop_decoy`.
"""

import asyncio
import json
from pathlib import Path

from sqlmodel import create_engine

from securization.desplegador import AsyncSftpTransport, start_decoy, stop_decoy
from securization.escaneo import (
    AsyncNmapRunner,
    build_ping_sweep_command,
    enrich_profile,
    find_free_ips,
    parse_alive_hosts,
    profile_tcp_ports,
    scan_host,
)
from securization.generador import build_campaign
from securization.inventario import CredentialVault, Inventory
from securization.perfilador import AsyncSshTransport, HostProfileStore
from securization.verificador import verify_decoy

CONFIG_DIR = "/home/lab/decoys"
NODOS = {"victima-01": "web-01", "victima-02": "files-02"}
PRIMERA_IP_SENUELO = 50


async def main() -> None:
    root = Path.cwd()
    engine = create_engine(f"sqlite:///{root / 'inventario.db'}")
    clave = (root / "securization.key").read_bytes().strip()
    inventory = Inventory(engine, CredentialVault(clave))
    store = HostProfileStore(engine)
    runner = AsyncNmapRunner()

    dc = inventory.get_host("deception-central")
    secreto = inventory.get_ssh_secret("deception-central")
    ssh = AsyncSshTransport(dc.address, dc.ssh_port, dc.ssh_user, secreto)
    sftp = AsyncSftpTransport(dc.address, dc.ssh_port, dc.ssh_user, secreto)

    vivos = parse_alive_hosts(await runner.run(build_ping_sweep_command("10.0.0.0/24")))
    usados = {*vivos, *(h.address for h in inventory.list_hosts())}
    libres = [
        ip
        for ip in find_free_ips("10.0.0.0/24", used=usados, limit=200)
        if int(str(ip).rsplit(".", 1)[1]) >= PRIMERA_IP_SENUELO
    ]

    for (host_id, nodo), ip in zip(NODOS.items(), libres, strict=False):
        perfil = store.load(host_id)
        puertos = profile_tcp_ports(perfil)
        real = await scan_host(perfil.address, runner, ports=puertos)
        enriquecido = enrich_profile(perfil, real)
        store.save(enriquecido)
        campana = build_campaign(
            enriquecido, campaign_id=f"campana-{host_id}", decoy_node_id=nodo, decoy_address=ip
        )
        print(f"\n== {host_id} -> {nodo} @ {ip}")
        print("config:", json.dumps(campana.decoy.opencanary_config, ensure_ascii=False))
        await stop_decoy(nodo, ssh=ssh)
        await start_decoy(campana.decoy, sftp=sftp, ssh=ssh, config_dir=CONFIG_DIR)
        await asyncio.sleep(10)
        senuelo = await scan_host(ip, runner, ports=puertos)
        extra = await scan_host(ip, runner)
        print("real   :", [(s.port, s.name, s.banner) for s in real.services])
        print("señuelo:", [(s.port, s.name, s.banner) for s in senuelo.services])
        print("SO real/señuelo:", real.os_matches[:1], senuelo.os_matches[:1])
        print("señuelo sin -p:", [s.port for s in extra.services])
        print("informe:", verify_decoy(real, senuelo).model_dump_json())


if __name__ == "__main__":
    asyncio.run(main())
