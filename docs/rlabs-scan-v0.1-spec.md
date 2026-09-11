# `rlabs-scan` v0.1 specification

`rlabs-scan` is a local, read-only command-line utility for inspecting Windows Portable Executable files. It never executes the target, uploads a file, or sends telemetry.

The v0.1 command is:

```text
rlabs scan <executable> [--output <report.json>] [--format json] [--search-path <directory>...]
```

It returns a JSON discovery report with the target path and SHA-256, PE architecture and subsystem, normal and delay-loaded imports, static runtime signals, adjacent/search-path dependency findings, and clearly labelled heuristic compatibility risks. It also emits a `compatibility` skeleton that follows the public RLabs hub schema. Scanning a non-PE file returns exit code 3; invalid arguments return 2; output errors return 4; unexpected failures return 5.

The scanner supports x86, x64, and arm64 PE files. DirectX generation, SIMD hints, service/driver indicators, Windows-on-ARM status, Proton risk, and modern-Windows risk are non-authoritative static heuristics. They must be described as observations or risks, never as proof that software runs or fails.

Out of scope: binary patching, decompilation, executing the target, process-memory inspection, bypassing access controls, collecting personal data, and report upload. C2 remains separate private RLabs research.
