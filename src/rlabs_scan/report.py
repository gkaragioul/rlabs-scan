"""JSON report construction for static RLabs scan observations."""

from __future__ import annotations

from datetime import date
import hashlib
from pathlib import Path
import re

from .analyze import Observation
from .pe import PEImage


def build_report(path: Path, image: PEImage, observation: Observation) -> dict[str, object]:
    title = path.stem
    identifier = _identifier(title, image.architecture)
    return {
        "scanner": {"name": "rlabs-scan", "version": "0.1.0"},
        "target": {
            "path": str(path),
            "sha256": hashlib.sha256(image.data).hexdigest(),
        },
        "observations": {
            "fileFormat": "pe",
            "architecture": image.architecture,
            "subsystem": image.subsystem,
            "imports": list(observation.imports),
            "delayImports": list(observation.delay_imports),
            "runtimeSignals": list(observation.runtime_signals),
            "missingDependencies": list(observation.missing_dependencies),
            "heuristics": observation.risks,
        },
        "compatibility": {
            "id": identifier,
            "software": {"title": title, "kind": "application"},
            "environment": {"operatingSystem": "Windows", "architecture": image.architecture},
            "assessment": {
                "status": "research",
                "summary": "Generated from static inspection; runtime behavior has not been tested.",
            },
            "evidence": {"source": "rlabs-scan 0.1.0", "observedOn": date.today().isoformat()},
        },
    }


def _identifier(title: str, architecture: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-") or "unnamed"
    return f"{normalized}-windows-{architecture}"
