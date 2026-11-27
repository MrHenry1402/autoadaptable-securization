"""Muestra líneas en bruto del log de OpenCanary de cada señuelo (una por tipo de alerta)."""

import asyncio
import json
import sys
from pathlib import Path

import asyncssh

root = Path(sys.argv[1])
sys.path.insert(0, str(root / "lab"))
from _credenciales import load_lab_hosts  # noqa: E402

h = {x.host_id: x for x in load_lab_hosts(root)}["deception-central"]


async def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    async with asyncssh.connect(
        h.labnet_ip, username=h.user, password=h.password, known_hosts=None
    ) as c:
        for nodo in ("web-01", "files-02"):
            r = await c.run(f"docker logs decoy-{nodo} 2>&1")
            vistos: set[int] = set()
            print(f"== decoy-{nodo}: una línea por tipo de alerta (logtype)")
            for linea in str(r.stdout).splitlines():
                if not linea.startswith("{"):
                    continue
                try:
                    ev = json.loads(linea)
                except json.JSONDecodeError:
                    continue
                t = ev.get("logtype")
                if t in vistos or t in (1001, 1004):  # 1001/1004: arranque del propio OpenCanary
                    continue
                vistos.add(t)
                print(json.dumps(ev, ensure_ascii=False))
            print()


asyncio.run(main())
