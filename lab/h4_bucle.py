"""H4 en el laboratorio: perfil real y bucle cerrado de verificación con los señuelos reales.

Uso: python lab/h4_bucle.py   (desde la raíz; nmap en el PATH)

Requiere el código de H4 y haber ejecutado antes lab/e2e_l3.py (campañas y señuelos). Para
cada víctima vuelve a perfilarla por SSH (incluidas las versiones de los paquetes), la
escanea, y lanza `run_verification_loop`: arranca el señuelo, lo escanea, lo puntúa y lo
ajusta hasta que supera el umbral o no queda nada que ajustar. Imprime cada intento.
"""

import asyncio
import json
from ipaddress import IPv4Address
from pathlib import Path

from sqlmodel import create_engine

from securization.desplegador import AsyncSftpTransport, start_decoy
from securization.escaneo import AsyncNmapRunner, enrich_profile, profile_tcp_ports, scan_host
from securization.generador import CampaignStore, DecoyConfig
from securization.inventario import CredentialVault, Inventory
from securization.modelos import Fingerprint
from securization.orquestador import run_verification_loop
from securization.perfilador import AsyncSshTransport, HostProfileStore, orchestrate_profiling

CONFIG_DIR = "/home/lab/decoys"
ESPERA_ARRANQUE = 10


async def main() -> None:
    root = Path.cwd()
    engine = create_engine(f"sqlite:///{root / 'inventario.db'}")
    clave = (root / "securization.key").read_bytes().strip()
    inventory = Inventory(engine, CredentialVault(clave))
    perfiles, campanas = HostProfileStore(engine), CampaignStore(engine)
    runner = AsyncNmapRunner()
    dc = inventory.get_host("deception-central")
    secreto = inventory.get_ssh_secret("deception-central")
    ssh_dc = AsyncSshTransport(dc.address, dc.ssh_port, dc.ssh_user, secreto)
    sftp_dc = AsyncSftpTransport(dc.address, dc.ssh_port, dc.ssh_user, secreto)

    async def arrancar(decoy: DecoyConfig) -> None:
        await start_decoy(decoy, sftp=sftp_dc, ssh=ssh_dc, config_dir=CONFIG_DIR)

    resumen = {}
    for host_id in ("victima-01", "victima-02"):
        h = inventory.get_host(host_id)
        ssh = AsyncSshTransport(
            h.address, h.ssh_port, h.ssh_user, inventory.get_ssh_secret(host_id)
        )
        perfil = await orchestrate_profiling(
            host_id=host_id,
            address=IPv4Address(h.address),
            os_family=h.os_family,
            transport=ssh,
            store=perfiles,
        )
        puertos = profile_tcp_ports(perfil)
        real = await scan_host(perfil.address, runner, ports=puertos)
        perfil = enrich_profile(perfil, real)
        perfiles.save(perfil)

        async def escanear(decoy: DecoyConfig, puertos: tuple[int, ...] = puertos) -> Fingerprint:
            await asyncio.sleep(ESPERA_ARRANQUE)
            return await scan_host(decoy.address, runner, ports=puertos)

        resultado = await run_verification_loop(
            perfil, real, campanas.load(f"campana-{host_id}"), start=arrancar, scan=escanear
        )
        campanas.save(resultado.campaign)
        resumen[host_id] = {
            "motivo": resultado.stop_reason,
            "intentos": [
                {"n": a.attempt, "puntuacion": a.report.score, "diferencias": a.report.differences}
                for a in resultado.attempts
            ],
        }
    print(json.dumps(resumen, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(main())
