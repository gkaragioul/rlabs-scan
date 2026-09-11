"""Conservative static classifications built from PE metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from collections.abc import Sequence

from .pe import PEImage


SYSTEM_DLLS = frozenset({
    "advapi32.dll", "comctl32.dll", "gdi32.dll", "kernel32.dll", "ntdll.dll",
    "ole32.dll", "shell32.dll", "user32.dll", "version.dll", "winmm.dll",
    "ws2_32.dll",
})


@dataclass(frozen=True)
class Observation:
    imports: tuple[str, ...]
    delay_imports: tuple[str, ...]
    runtime_signals: tuple[str, ...]
    missing_dependencies: tuple[str, ...]
    risks: dict[str, str]


def analyze(image: PEImage, executable: Path, search_paths: Sequence[Path]) -> Observation:
    imports = image.imports()
    delay_imports = image.delay_imports()
    all_imports = imports + tuple(name for name in delay_imports if name not in imports)
    lower = {name.lower() for name in all_imports}
    signals: list[str] = []
    directx = _directx_signal(lower)
    if directx:
        signals.append(directx)
    if any(name.startswith(("vcruntime", "msvcp", "msvcr")) for name in lower):
        signals.append("msvc-runtime")
    if "mscoree.dll" in lower:
        signals.append("dotnet")
    if any(name.startswith("xinput") for name in lower):
        signals.append("xinput")
    if any(name in lower for name in ("setupapi.dll", "winusb.dll", "hid.dll")):
        signals.append("driver-or-device-api")
    if "advapi32.dll" in lower:
        signals.append("service-api")

    locations = (executable.parent, *search_paths)
    missing = tuple(
        name for name in all_imports
        if name.lower() not in SYSTEM_DLLS and not any((location / name).is_file() for location in locations)
    )
    risks = {
        "simd": "unknown-static-inspection",
        "driverOrService": "possible" if any(signal in signals for signal in ("driver-or-device-api", "service-api")) else "not-observed",
        "arm64Status": "native" if image.architecture == "arm64" else "emulation-required",
        "protonRisk": "medium" if directx in ("directx-8", "directx-9") else "low",
        "modernWindowsRisk": "high" if directx in ("directx-8", "directx-9") or "msvc-runtime" in signals else "low",
    }
    return Observation(
        imports=imports,
        delay_imports=delay_imports,
        runtime_signals=tuple(signals),
        missing_dependencies=missing,
        risks=risks,
    )


def _directx_signal(imports: set[str]) -> str | None:
    for dll, signal in (("d3d8.dll", "directx-8"), ("d3d9.dll", "directx-9"), ("d3d11.dll", "directx-11"), ("d3d12.dll", "directx-12")):
        if dll in imports:
            return signal
    return None
