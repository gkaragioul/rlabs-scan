from pathlib import Path
import tempfile
import unittest

from rlabs_scan.analyze import analyze
from rlabs_scan.pe import PEImage
from tests.pe_fixture import make_pe


class AnalysisTests(unittest.TestCase):
    def test_detects_imports_runtime_signals_and_missing_dependencies(self) -> None:
        image = PEImage.from_bytes(make_pe(imports=["d3d9.dll", "VCRUNTIME140.dll", "custom.dll"]))
        with tempfile.TemporaryDirectory() as directory:
            observation = analyze(image, Path(directory) / "Example.exe", [])

        self.assertEqual(observation.imports, ("d3d9.dll", "VCRUNTIME140.dll", "custom.dll"))
        self.assertIn("directx-9", observation.runtime_signals)
        self.assertIn("msvc-runtime", observation.runtime_signals)
        self.assertIn("VCRUNTIME140.dll", observation.missing_dependencies)
        self.assertIn("custom.dll", observation.missing_dependencies)
        self.assertEqual(observation.risks["arm64Status"], "emulation-required")

    def test_reads_delay_loaded_dlls(self) -> None:
        image = PEImage.from_bytes(make_pe(delay_imports=["xinput1_3.dll"]))
        with tempfile.TemporaryDirectory() as directory:
            observation = analyze(image, Path(directory) / "Example.exe", [])

        self.assertEqual(observation.delay_imports, ("xinput1_3.dll",))


if __name__ == "__main__":
    unittest.main()
