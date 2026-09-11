# RLabs Scan v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a dependency-free `rlabs scan` command that statically inspects a Windows PE executable and writes an evidence-led JSON report.

**Architecture:** A pure-Python package keeps parsing, static classification, report construction, and the command-line interface separate. The PE reader works directly on bytes and maps RVAs through section headers; it never invokes the Windows loader or the inspected program.

**Tech Stack:** Python 3.12 standard library, `argparse`, `unittest`, `tomllib`-free `pyproject.toml` metadata, GitHub Actions.

**Spec:** `docs/rlabs-scan-v0.1-spec.md`

## Global Constraints

- Target Python 3.12 or later with no runtime dependency outside the standard library.
- Do not execute, load, upload, patch, decompile, or modify the selected executable.
- Mark DirectX, SIMD, service/driver, Windows-on-ARM, Proton, and modern-Windows conclusions as static heuristics.
- Emit JSON to stdout by default and only write an output file when `--output` is specified.
- Use exit codes 0, 2, 3, 4, and 5 exactly as defined in the specification.

---

### Task 1: Package and command boundary

**Files:**
- Create: `pyproject.toml`, `src/rlabs_scan/__init__.py`, `src/rlabs_scan/cli.py`, `tests/test_cli.py`

**Interfaces:**
- Produces `rlabs_scan.cli.main(argv: Sequence[str] | None = None) -> int` and console command `rlabs`.

- [ ] **Step 1: Write a failing CLI test**

```python
from rlabs_scan.cli import main

def test_scan_requires_an_executable() -> None:
    assert main(["scan"]) == 2
```

- [ ] **Step 2: Run the test and confirm it fails because the package is absent**

Run: `python -m unittest tests.test_cli -v`

- [ ] **Step 3: Add minimal packaging and argument validation**

```python
def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan" and args.executable is None:
        return 2
```

- [ ] **Step 4: Run the command-boundary test and confirm it passes**

Run: `python -m unittest tests.test_cli -v`

### Task 2: Read PE headers safely

**Files:**
- Create: `src/rlabs_scan/pe.py`, `tests/pe_fixture.py`, `tests/test_pe.py`

**Interfaces:**
- Produces `PEImage.from_bytes(data: bytes) -> PEImage` and `PEFormatError`.

- [ ] **Step 1: Write failing tests for truncated input and x86/x64 machine values**

```python
with self.assertRaises(PEFormatError):
    PEImage.from_bytes(b"MZ")
self.assertEqual(PEImage.from_bytes(make_pe(machine=0x14C)).architecture, "x86")
```

- [ ] **Step 2: Run the PE tests and confirm missing parser failures**

Run: `python -m unittest tests.test_pe -v`

- [ ] **Step 3: Implement bounded byte reads, DOS/PE validation, optional-header parsing, and RVA mapping**

```python
class PEImage:
    @classmethod
    def from_bytes(cls, data: bytes) -> "PEImage": ...
    def rva_to_offset(self, rva: int) -> int: ...
```

- [ ] **Step 4: Re-run PE tests and confirm all pass**

Run: `python -m unittest tests.test_pe -v`

### Task 3: Imports and static classifications

**Files:**
- Create: `src/rlabs_scan/analyze.py`, `tests/test_analyze.py`
- Modify: `src/rlabs_scan/pe.py`, `tests/pe_fixture.py`

**Interfaces:**
- Consumes `PEImage`.
- Produces `analyze(image: PEImage, search_paths: Sequence[Path]) -> Observation` with normal imports, delay imports, runtime signals, missing dependencies, and labelled risks.

- [ ] **Step 1: Write failing tests for DLL imports, DX9, MSVC, and missing local dependency detection**

```python
observation = analyze(PEImage.from_bytes(make_pe(imports=["d3d9.dll", "VCRUNTIME140.dll"])), [])
self.assertIn("directx-9", observation.runtime_signals)
self.assertIn("msvc-runtime", observation.runtime_signals)
```

- [ ] **Step 2: Run analysis tests and confirm they fail before classification exists**

Run: `python -m unittest tests.test_analyze -v`

- [ ] **Step 3: Parse import tables and add conservative, documented static heuristics**

```python
def analyze(image, search_paths):
    return Observation(imports=image.imports(), delay_imports=image.delay_imports(), ...)
```

- [ ] **Step 4: Run analysis tests and confirm all pass**

Run: `python -m unittest tests.test_analyze -v`

### Task 4: Report generation and file output

**Files:**
- Create: `src/rlabs_scan/report.py`, `tests/test_report.py`
- Modify: `src/rlabs_scan/cli.py`

**Interfaces:**
- Produces `build_report(path: Path, image: PEImage, observation: Observation) -> dict` and valid JSON output.

- [ ] **Step 1: Write a failing report test for the scan contract**

```python
report = build_report(Path("Example.exe"), image, observation)
self.assertEqual(report["compatibility"]["assessment"]["status"], "research")
self.assertEqual(report["observations"]["architecture"], "x64")
```

- [ ] **Step 2: Run report tests and confirm missing builder failures**

Run: `python -m unittest tests.test_report -v`

- [ ] **Step 3: Add deterministic SHA-256, report skeleton, stdout output, and output-error exit handling**

```python
def build_report(path, image, observation):
    return {"scanner": ..., "target": ..., "observations": ..., "compatibility": ...}
```

- [ ] **Step 4: Run report and CLI tests and confirm all pass**

Run: `python -m unittest discover -s tests -v`

### Task 5: Public documentation and continuous verification

**Files:**
- Create: `README.md`, `LICENSE`, `.github/workflows/test.yml`
- Modify: `docs/rlabs-scan-v0.1-spec.md`

**Interfaces:**
- Produces install and privacy guidance plus CI that runs the complete test suite on Python 3.12.

- [ ] **Step 1: Write a failing documentation test for the public command and privacy promise**

```python
readme = Path("README.md").read_text(encoding="utf-8")
self.assertIn("rlabs scan", readme)
self.assertIn("never executes", readme)
```

- [ ] **Step 2: Run the documentation test and confirm it fails before README creation**

Run: `python -m unittest tests.test_docs -v`

- [ ] **Step 3: Document installation, JSON output, heuristic limits, and local-only behavior; add MIT license and CI**

```yaml
- run: python -m unittest discover -s tests -v
```

- [ ] **Step 4: Run all tests and confirm they pass**

Run: `python -m unittest discover -s tests -v`

- [ ] **Step 5: Commit, push the feature branch, and open a pull request for the verified v0.1 implementation**

Run: `git add . && git commit -m "feat: implement rlabs scan v0.1" && git push -u origin codex/rlabs-scan-v0.1 && gh pr create --base main --head codex/rlabs-scan-v0.1`
