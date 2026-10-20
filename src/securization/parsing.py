"""Utilidades comunes de parseo: error de formato y saneado de texto no confiable."""

import unicodedata

DEFAULT_MAX_LEN = 256


class ParseError(Exception):
    """La salida de un comando o un fichero no tiene el formato mínimo esperado."""


def has_control_chars(text: str) -> bool:
    """Indica si el texto contiene algún carácter de control (categoría Unicode Cc)."""
    return any(unicodedata.category(c) == "Cc" for c in text)


def sanitize_text(text: str, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Quita caracteres de control y trunca; los datos de un host nunca se usan tal cual."""
    limpio = "".join(c for c in text if unicodedata.category(c) != "Cc")
    return limpio[:max_len]
