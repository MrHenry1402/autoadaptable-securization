"""L4 en el laboratorio: plan, plantado, verificación de alertas y limpieza de breadcrumbs.

Uso (desde la raíz; requiere el código de L4 y los señuelos de lab/e2e_l3.py encendidos):
    python lab/l4_breadcrumbs.py plan     construye y guarda el plan SIN aprobar e imprime
                                          rutas y contenido para revisarlos
    python lab/l4_breadcrumbs.py plant    aprueba y planta (solo tras revisar el plan)
    python lab/l4_breadcrumbs.py verify   lee las alertas de los señuelos y muestra cuáles
                                          usan la credencial de un breadcrumb
    python lab/l4_breadcrumbs.py clean    borra de las víctimas solo las rutas del plan

Entre `plant` y `verify`, el "atacante" se simula en cada víctima con los scripts de
lab/atacante/, que leen las credenciales de los propios breadcrumbs:
    ssh -p <puerto_nat> lab@127.0.0.1 bash -s < lab/atacante/victima-01.sh
"""

import asyncio
import json
import sys
from ipaddress import IPv4Address
from pathlib import Path

from sqlmodel import create_engine

from securization.desplegador import (
    AsyncSftpTransport,
    DeploymentPlanStore,
    approve_plan,
    build_deployment_plan,
    plant_breadcrumbs,
)
from securization.escaneo import AsyncNmapRunner, profile_tcp_ports, scan_host
from securization.eventos import CampaignIndex, breadcrumb_service_used, parse_opencanary_log
from securization.generador import CampaignStore, build_campaign
from securization.inventario import CredentialVault, Inventory
from securization.parsing import ParseError
from securization.perfilador import AsyncSshTransport, HostProfileStore
from securization.verificador import verify_decoy

SENUELOS = {"victima-01": ("web-01", "10.0.0.50"), "victima-02": ("files-02", "10.0.0.51")}
# Ruta del log dentro del contenedor, fijada por el config por defecto de OpenCanary.
LOG = "/var/tmp/opencanary.log"  # noqa: S108


def _abrir() -> tuple[Inventory, HostProfileStore, CampaignStore, DeploymentPlanStore]:
    root = Path.cwd()
    engine = create_engine(f"sqlite:///{root / 'inventario.db'}")
    clave = (root / "securization.key").read_bytes().strip()
    return (
        Inventory(engine, CredentialVault(clave)),
        HostProfileStore(engine),
        CampaignStore(engine),
        DeploymentPlanStore(engine),
    )


def _ssh(inventory: Inventory, host_id: str) -> AsyncSshTransport:
    h = inventory.get_host(host_id)
    return AsyncSshTransport(h.address, h.ssh_port, h.ssh_user, inventory.get_ssh_secret(host_id))


async def plan() -> None:
    inventory, perfiles, campanas, planes = _abrir()
    runner = AsyncNmapRunner()
    resumen = {}
    for host_id, (nodo, ip) in SENUELOS.items():
        ssh = _ssh(inventory, host_id)
        home = (await ssh.run(["sh", "-c", 'getent passwd "$(id -un)" | cut -d: -f6'])).strip()
        conocidas = [f"{home}/{n}" for n in (await ssh.run(["ls", "-A", home])).split()]
        perfil = perfiles.load(host_id)
        campana = build_campaign(
            perfil,
            campaign_id=f"campana-{host_id}",
            decoy_node_id=nodo,
            decoy_address=IPv4Address(ip),
            home_dir=home,
            known_paths=conocidas,
        )
        puertos = profile_tcp_ports(perfil)
        real = await scan_host(perfil.address, runner, ports=puertos)
        senuelo = await scan_host(IPv4Address(ip), runner, ports=puertos)
        informe = verify_decoy(real, senuelo)
        borrador = build_deployment_plan(campana, informe, known_paths=conocidas)
        campanas.save(campana)
        planes.save(borrador)
        resumen[host_id] = {
            "puntuacion": f"{informe.score}/{informe.threshold}",
            "breadcrumbs": {a.path: a.content for a in borrador.actions},
        }
    print(json.dumps(resumen, indent=2, ensure_ascii=False))


async def plant() -> None:
    inventory, _, _, planes = _abrir()
    for host_id in SENUELOS:
        aprobado = approve_plan(planes.load(f"campana-{host_id}"))
        planes.save(aprobado)
        h = inventory.get_host(host_id)
        secreto = inventory.get_ssh_secret(host_id)
        sftp = AsyncSftpTransport(h.address, h.ssh_port, h.ssh_user, secreto)
        await plant_breadcrumbs(aprobado, sftp)
        print(host_id, "plantados:", [a.path for a in aprobado.actions])


async def verify() -> None:
    inventory, _, campanas, _ = _abrir()
    por_nodo = {c.decoy.node_id: c for c in campanas.list_all()}
    indice = CampaignIndex(list(por_nodo.values()))
    dc = _ssh(inventory, "deception-central")
    for nodo in por_nodo:
        salida = await dc.run(["docker", "exec", f"decoy-{nodo}", "cat", LOG])
        for linea in salida.splitlines():
            try:
                evento = parse_opencanary_log(linea)
            except ParseError:
                continue
            servicio = breadcrumb_service_used(evento, por_nodo[nodo].decoy)
            if servicio is not None:
                correlado = indice.correlate_opencanary_event(evento)
                print(
                    f"{evento.timestamp:%Y-%m-%d %H:%M:%S} {correlado.campaign_id}: "
                    f"breadcrumb {servicio} usado desde {correlado.source_host}"
                )


async def clean() -> None:
    inventory, _, _, planes = _abrir()
    for host_id in SENUELOS:
        rutas = [a.path for a in planes.load(f"campana-{host_id}").actions]
        if rutas:
            await _ssh(inventory, host_id).run(["rm", "-f", "--", *rutas])
        print(host_id, "borrados:", rutas)


if __name__ == "__main__":
    acciones = {"plan": plan, "plant": plant, "verify": verify, "clean": clean}
    if len(sys.argv) != 2 or sys.argv[1] not in acciones:
        sys.exit(f"uso: python lab/l4_breadcrumbs.py <{'|'.join(acciones)}>")
    asyncio.run(acciones[sys.argv[1]]())
