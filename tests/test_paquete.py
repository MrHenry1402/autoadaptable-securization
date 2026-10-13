"""Comprobación de humo: el paquete y todos sus módulos son importables."""

import importlib

import pytest

MODULOS = [
    "inventario",
    "perfilador",
    "generador",
    "verificador",
    "desplegador",
    "eventos",
    "respuesta",
    "dashboard",
]


@pytest.mark.parametrize("modulo", MODULOS)
def test_modulo_importable(modulo: str) -> None:
    importlib.import_module(f"securization.{modulo}")
