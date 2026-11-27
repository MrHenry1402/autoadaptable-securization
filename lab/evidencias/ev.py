"""Ejecuta un comando y guarda su salida como evidencia en docs/evidencias/<nombre>.txt.

Uso: python ev.py <nombre> <comando> [args...]
La cabecera lleva fecha (UTC) y el comando; stdout y stderr van juntos, tal cual.
"""

import datetime
import os
import subprocess
import sys
from pathlib import Path

nombre, argv = sys.argv[1], sys.argv[2:]
destino = Path("docs/evidencias") / f"{nombre}.txt"
env = dict(os.environ, PYTHONIOENCODING="utf-8")
inicio = datetime.datetime.now(datetime.UTC)
# Script del operador en el laboratorio: ejecuta el comando que él mismo pasa, sin shell.
r = subprocess.run(argv, capture_output=True, env=env)  # noqa: S603
fin = datetime.datetime.now(datetime.UTC)
salida = (r.stdout + r.stderr).decode("utf-8", "replace").replace("\r\n", "\n")
comando = " ".join(argv)
for largo, corto in (
    (r".\.venv\Scripts\python.exe", "python"),
    (r".\.venv\Scripts\securization.exe", "securization"),
    (r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe", "VBoxManage"),
):
    comando = comando.replace(largo, corto)
cabecera = (
    f"# {inicio:%Y-%m-%d %H:%M:%S} UTC · {(fin - inicio).total_seconds():.0f} s · "
    f"código de salida {r.returncode}\n"
    f"$ {comando}\n\n"
)
destino.write_text(cabecera + salida, encoding="utf-8")
sys.stdout.reconfigure(encoding="utf-8")
print(cabecera + salida)
