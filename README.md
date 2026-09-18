# rlabs-scan

**[Check your game in the browser](https://recompilelabs.com/#scanner)** — free to use, no installation or account required.

RLabs Scan inspects Windows executable metadata to help explain architecture, graphics-library dependencies, and runtime requirements. The website is the easiest starting point; this repository contains the original Python command-line scanner for developers and advanced workflows.

## Start with your game folder

1. Open [recompilelabs.com](https://recompilelabs.com/#scanner).
2. Click **Choose game folder** and select the game's installation folder.
3. If the folder contains one executable, it is inspected automatically. If several are found, choose the one you normally launch and click **Check this executable**.
4. Read the findings, then optionally **Save report** or **Copy summary**.

The browser lists filenames, then reads only the selected executable's contents on your device. It does not upload the game, run it, or modify files. A 50 GB installation does not mean a 50 GB upload or scan. Current limits are 128 MB per executable, 30,000 selected files, and a 30-second scan timeout. Listing a folder with many files can take time before scanning starts.

Findings are preliminary: the browser cannot check installed Windows components or prove gameplay, Windows-on-ARM, or Proton compatibility. A dependency absent from the selected folder may already be installed in Windows. The scan uses fixed inspection rules, not an AI service.

### Browser and command-line versions

| | Website | This repository's Python CLI |
| --- | --- | --- |
| Starting point | Choose a game folder | Specify an executable path |
| Processing | Locally in your browser | Locally in Python |
| Results | Readable findings, copy, JSON download | JSON report |
| Report format | `rlabs-browser-scan`, version 1 | CLI observation and compatibility skeleton |
| Sharing | Automatic minimized technical report; richer local export can be shared manually | Manual; review paths and metadata before sharing |

The website uses a separate JavaScript implementation maintained with the site; it does not run the Python CLI. Its export is supporting evidence, not a validated [hub compatibility record](https://github.com/gkaragioul/game-preservation-hub/tree/main/compatibility). The website automatically submits a small technical report, disclosed before folder selection: executable SHA-256, architecture, import count and allowlisted component observations. It excludes game files, filenames, paths and usernames. A hash identifies a build; this is not an anonymity guarantee. Automatic inspection of every executable is not implemented.

Explore the [preservation hub](https://github.com/gkaragioul/game-preservation-hub) for projects, shared records, and contribution guidance. Report browser or CLI issues in [this repository's issue tracker](https://github.com/gkaragioul/rlabs-scan/issues), identifying which version you used.

## Command-line scanner

It never executes, loads, patches, uploads, or modifies the selected executable. v0.1 reads Portable Executable metadata only.

### Install (advanced)

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

The Python CLI makes no network request and sends no telemetry. Its report may include local paths, executable names, hashes, and DLL names; review it before sharing. The website has the automatic technical-report submission described above. Do not use either version to bypass access controls or distribute proprietary software.

## Development

Before pushing, install the local hook and follow [publication checks](docs/PUBLICATION.md). Private implementation and internal workspace exports must remain outside this public repository. Pull requests must pass the publication-boundary check before merging.

```powershell
$env:PYTHONPATH = "src"
py -3.14 -m unittest discover -s tests -v
```

The tests create inert synthetic PE fixtures; no game executable is run or committed.
