from pathlib import Path
import tempfile
import unittest

from rlabs_scan.analyze import analyze
from rlabs_scan.pe import PEImage
from rlabs_scan.report import build_report
from tests.pe_fixture import make_pe


class ReportTests(unittest.TestCase):
    def test_builds_research_compatibility_skeleton(self) -> None:
        image = PEImage.from_bytes(make_pe(machine=0x8664, imports=["d3d9.dll"]))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "Example.exe"
            target.write_bytes(image.data)
            report = build_report(target, image, analyze(image, target, []))

        self.assertEqual(report["scanner"]["name"], "rlabs-scan")
        self.assertEqual(report["observations"]["architecture"], "x64")
        self.assertEqual(report["compatibility"]["assessment"]["status"], "research")
        self.assertEqual(report["compatibility"]["id"], "example-windows-x64")


if __name__ == "__main__":
    unittest.main()
