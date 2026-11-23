"""Genera los diagramas de la memoria final (arquitectura y flujo) como PNG.

Uso: python docs/memoria/diagramas.py  (requiere matplotlib; no es dependencia del paquete)
"""

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

SALIDA = Path(__file__).parent

AZUL = "#1F4E79"
AZUL_CLARO = "#DCE6F2"
NARANJA = "#C55A11"
NARANJA_CLARO = "#FBE5D6"
VERDE = "#38761D"
VERDE_CLARO = "#E2F0D9"
GRIS = "#595959"
GRIS_CLARO = "#F2F2F2"


def caja(ax, x, y, w, h, titulo, sub="", borde=AZUL, fondo=AZUL_CLARO, tam=10):
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle="round,pad=0.02,rounding_size=0.08",
            linewidth=1.4,
            edgecolor=borde,
            facecolor=fondo,
        )
    )
    if sub:
        ax.text(
            x + w / 2,
            y + h * 0.64,
            titulo,
            ha="center",
            va="center",
            fontsize=tam,
            fontweight="bold",
            color=borde,
        )
        ax.text(
            x + w / 2, y + h * 0.3, sub, ha="center", va="center", fontsize=tam - 2, color="#262626"
        )
    else:
        ax.text(
            x + w / 2,
            y + h / 2,
            titulo,
            ha="center",
            va="center",
            fontsize=tam,
            fontweight="bold",
            color=borde,
        )


def flecha(ax, a, b, color=GRIS, texto="", estilo="-|>", ls="-", off=(0, 0.12)):
    ax.add_patch(
        FancyArrowPatch(
            a,
            b,
            arrowstyle=estilo,
            mutation_scale=14,
            linewidth=1.3,
            color=color,
            linestyle=ls,
            shrinkA=2,
            shrinkB=2,
        )
    )
    if texto:
        ax.text(
            (a[0] + b[0]) / 2 + off[0],
            (a[1] + b[1]) / 2 + off[1],
            texto,
            ha="center",
            va="center",
            fontsize=7.5,
            color=color,
            bbox={"facecolor": "white", "edgecolor": "none", "pad": 1},
        )


def arquitectura() -> None:
    fig, ax = plt.subplots(figsize=(11, 6.6), dpi=200)
    ax.set_xlim(0, 11)
    ax.set_ylim(0, 6.6)
    ax.axis("off")

    # Orquestador
    ax.add_patch(
        FancyBboxPatch(
            (0.2, 2.55),
            6.0,
            3.85,
            boxstyle="round,pad=0.02",
            linewidth=1.2,
            edgecolor=AZUL,
            facecolor="white",
            ls="--",
        )
    )
    ax.text(
        0.4,
        6.22,
        "Orquestador securization (CLI + dashboard, Docker Compose)",
        fontsize=9.5,
        fontweight="bold",
        color=AZUL,
    )
    caja(ax, 0.4, 4.95, 1.75, 0.95, "inventario", "Fernet, SQLite")
    caja(ax, 2.3, 4.95, 1.75, 0.95, "perfilador", "SSH: SO, ss, dpkg")
    caja(ax, 4.2, 4.95, 1.8, 0.95, "escaneo", "nmap -sV -O")
    caja(ax, 0.4, 3.75, 1.75, 0.95, "desplegador", "plan + aprobación")
    caja(ax, 2.3, 3.75, 1.75, 0.95, "verificador", "huellas, 0-100")
    caja(ax, 4.2, 3.75, 1.8, 0.95, "orquestador", "bucle H4")
    caja(ax, 0.4, 2.7, 1.75, 0.8, "generador", "OpenCanary, breadcrumbs", tam=9)
    caja(ax, 2.3, 2.7, 1.75, 0.8, "eventos", "alertas/campaña", tam=9)
    caja(ax, 4.2, 2.7, 1.8, 0.8, "respuesta", "decide acción", tam=9)

    # LLM
    caja(
        ax,
        0.2,
        0.9,
        2.6,
        1.15,
        "llm (Ollama local)",
        "qwen3:8b - solo 127.0.0.1\nsalida validada (Pydantic)",
        borde=NARANJA,
        fondo=NARANJA_CLARO,
    )
    flecha(ax, (1.0, 2.05), (1.0, 2.67), color=NARANJA, estilo="<|-|>")
    ax.text(
        1.12,
        2.36,
        "perfil seudonimizado / hostname",
        fontsize=7.5,
        color=NARANJA,
        va="center",
        bbox={"facecolor": "white", "edgecolor": "none", "pad": 1},
    )

    # BD
    caja(
        ax,
        3.2,
        0.9,
        3.0,
        1.15,
        "Base de datos SQLite",
        "hosts, perfiles, campañas,\nplanes, intentos, eventos",
        borde=GRIS,
        fondo=GRIS_CLARO,
    )

    # LAN
    ax.add_patch(
        FancyBboxPatch(
            (7.0, 0.3),
            3.8,
            6.1,
            boxstyle="round,pad=0.02",
            linewidth=1.2,
            edgecolor=VERDE,
            facecolor="white",
            ls="--",
        )
    )
    ax.text(7.15, 6.22, "LAN labnet 10.0.0.0/24", fontsize=9.5, fontweight="bold", color=VERDE)
    caja(
        ax,
        7.25,
        4.7,
        3.3,
        1.2,
        "Hosts reales (sin agente)",
        "victima-01 .10 nginx+MariaDB\nvictima-02 .11 vsftpd+Redis",
        borde=VERDE,
        fondo=VERDE_CLARO,
    )
    caja(
        ax,
        7.85,
        2.55,
        2.7,
        1.55,
        "deception-central .5",
        "Docker + macvlan\nweb-01 .50 / files-02 .51\nOpenCanary, IP y MAC propias",
        borde=VERDE,
        fondo=VERDE_CLARO,
    )
    caja(
        ax,
        7.25,
        0.55,
        3.3,
        1.2,
        "Atacante (Kali .20)",
        "nmap, whatweb, hydra",
        borde="#A61C00",
        fondo="#F4CCCC",
    )

    flecha(ax, (6.0, 5.42), (7.22, 5.42), color=VERDE, texto="SSH / nmap")
    flecha(ax, (6.0, 5.1), (7.22, 4.95), color=VERDE, texto="SFTP breadcrumbs", off=(0, -0.2))
    flecha(ax, (6.0, 3.2), (7.82, 3.2), color=VERDE, texto="docker run / logs", off=(-0.3, 0.12))
    flecha(ax, (9.2, 1.78), (9.2, 2.52), color="#A61C00", texto="ataca señuelo", off=(0.0, 0.0))
    flecha(ax, (7.5, 1.78), (7.5, 4.67), color="#A61C00", ls=":")
    ax.text(7.58, 3.32, "lee breadcrumb", rotation=90, fontsize=7.5, color="#A61C00", va="bottom")
    flecha(ax, (9.9, 4.67), (9.9, 4.13), color=GRIS, texto="credenciales\napuntan", off=(0.0, 0.0))
    flecha(ax, (3.3, 2.65), (4.0, 2.07), color=GRIS)

    fig.savefig(SALIDA / "arquitectura.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


def flujo() -> None:
    pasos = [
        ("1. Alta", "hosts add\n(Fernet)", AZUL, AZUL_CLARO),
        ("2. Perfil", "SSH + nmap\nbanners reales", AZUL, AZUL_CLARO),
        ("3. Campaña", "señuelo H2 +\nbreadcrumbs", AZUL, AZUL_CLARO),
        ("4. Verificar", "escaneo señuelo\nvs host real", NARANJA, NARANJA_CLARO),
        ("5. Aprobar", "umbral 90 +\noperador", VERDE, VERDE_CLARO),
        ("6. Desplegar", "SFTP + docker\n(deploy_decoy)", VERDE, VERDE_CLARO),
        ("7. Eventos", "alertas por\ncampaña", "#A61C00", "#F4CCCC"),
    ]
    fig, ax = plt.subplots(figsize=(12, 3.0), dpi=200)
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 3.0)
    ax.axis("off")
    w, h, sep = 1.45, 1.2, 0.27
    for i, (t, s, b, f) in enumerate(pasos):
        x = 0.1 + i * (w + sep)
        caja(ax, x, 1.2, w, h, t, s, borde=b, fondo=f, tam=9.5)
        if i < len(pasos) - 1:
            flecha(ax, (x + w, 1.8), (x + w + sep, 1.8))
    # bucle de ajuste 4 -> 3
    x3 = 0.1 + 2 * (w + sep) + w / 2
    x4 = 0.1 + 3 * (w + sep) + w / 2
    ax.add_patch(
        FancyArrowPatch(
            (x4, 1.18),
            (x3, 1.18),
            connectionstyle="arc3,rad=-0.55",
            arrowstyle="-|>",
            mutation_scale=14,
            color=NARANJA,
            linewidth=1.4,
        )
    )
    ax.text(
        (x3 + x4) / 2,
        0.38,
        "< umbral: adjust_decoy con datos del host real (máx. N intentos)",
        ha="center",
        fontsize=8,
        color=NARANJA,
    )
    ax.text(
        0.1 + 1 * (w + sep) + w / 2,
        2.62,
        "IA opcional: hostname (Ollama)",
        ha="center",
        fontsize=8,
        color=NARANJA,
        style="italic",
    )
    fig.savefig(SALIDA / "flujo.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    arquitectura()
    flujo()
