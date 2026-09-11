import unittest
import subprocess
import sys

from rlabs_scan.cli import main


class CliTests(unittest.TestCase):
    def test_scan_requires_an_executable(self) -> None:
        self.assertEqual(main(["scan"]), 2)

    def test_module_entry_point_returns_invalid_argument_exit_code(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "rlabs_scan", "scan"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
