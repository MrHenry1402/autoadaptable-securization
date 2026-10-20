"""Tests de la interfaz HostProfiler y de la selección de implementación por os_family."""

import pytest

from securization.modelos import OsFamily
from securization.perfilador import (
    HostProfiler,
    LinuxProfiler,
    UnsupportedOsFamilyError,
    get_profiler,
)


def test_host_profiler_es_abstracto() -> None:
    with pytest.raises(TypeError):
        HostProfiler()  # type: ignore[abstract]


def test_subclase_sin_profile_no_se_instancia() -> None:
    class Incompleto(HostProfiler):
        os_family = OsFamily.LINUX

    with pytest.raises(TypeError):
        Incompleto()  # type: ignore[abstract]


def test_linux_profiler_declara_su_familia() -> None:
    assert LinuxProfiler.os_family is OsFamily.LINUX


def test_get_profiler_linux() -> None:
    profiler = get_profiler(OsFamily.LINUX)
    assert isinstance(profiler, LinuxProfiler)
    assert isinstance(profiler, HostProfiler)


def test_get_profiler_windows_falla_con_error_claro() -> None:
    with pytest.raises(UnsupportedOsFamilyError, match="windows"):
        get_profiler(OsFamily.WINDOWS)


def test_get_profiler_no_cae_en_comportamiento_por_defecto() -> None:
    with pytest.raises(UnsupportedOsFamilyError):
        get_profiler("macos")  # type: ignore[arg-type]
