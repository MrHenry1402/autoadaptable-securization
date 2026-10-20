"""Tests de las utilidades comunes de parseo: saneado de texto no confiable."""

from securization.parsing import ParseError, has_control_chars, sanitize_text


def test_sanitize_quita_caracteres_de_control() -> None:
    assert sanitize_text("ab\x1b[31mc\x00d\n\te") == "ab[31mcde"


def test_sanitize_conserva_unicode_legible() -> None:
    assert sanitize_text("Ñandú — año 2026") == "Ñandú — año 2026"


def test_sanitize_trunca_a_256_por_defecto() -> None:
    assert len(sanitize_text("A" * 5000)) == 256


def test_sanitize_admite_otro_limite() -> None:
    assert sanitize_text("abcdef", max_len=3) == "abc"


def test_sanitize_vacio() -> None:
    assert sanitize_text("") == ""


def test_has_control_chars() -> None:
    assert has_control_chars("a\x1bb")
    assert has_control_chars("a\nb")
    assert not has_control_chars("etc-1_ñ")


def test_parse_error_es_una_excepcion() -> None:
    assert issubclass(ParseError, Exception)
