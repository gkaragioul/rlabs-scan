# rlabs-scan

`rlabs-scan` is a small, local command-line tool for inspecting Windows `.exe` files and producing an evidence-led JSON compatibility report.

It never executes, loads, patches, uploads, or modifies the selected executable. v0.1 reads Portable Executable metadata only.

## Install

Requires Python 3.12 or newer.

```powershell
git clone https://github.com/gkaragioul/rlabs-scan.git
Set-Location rlabs-scan
python -m pip install .
```

## Scan an executable

```powershell
rlabs scan "C:\Games\Example\Example.exe"
```

If the Python Scripts folder is not on your `PATH`, run the equivalent command instead:

```powershell
python -m rlabs_scan scan "C:\Games\Example\Example.exe"
```

The command writes JSON to standard output. To save it:

```powershell
rlabs scan "C:\Games\Example\Example.exe" --output report.json
```

Use `--search-path` more than once to check named DLLs in additional read-only directories:

```powershell
rlabs scan "C:\Games\Example\Example.exe" --search-path "C:\Games\Example\bin"
```

## What the report contains

- PE architecture and subsystem;
- normal and delay-loaded DLL imports;
- static DirectX, MSVC runtime, .NET, input, service, and device-API signals;
- missing non-system DLL names from the executable directory and optional search paths;
- SHA-256 of the inspected file;
- a compatibility-report skeleton marked `research` until a person verifies runtime behavior.

DirectX generation, SIMD, driver/service, Windows-on-ARM, Proton, and modern-Windows fields are deliberately labelled static heuristics. They are clues for investigation, not compatibility guarantees.

## Privacy and boundaries

The scanner makes no network request and sends no telemetry. A report may include local paths, executable names, hashes, and DLL names; review it before sharing. Do not use it to bypass access controls or distribute proprietary software.

## Development

```powershell
$env:PYTHONPATH = "src"
py -3.14 -m unittest discover -s tests -v
```

The tests create inert synthetic PE fixtures; no game executable is run or committed.
