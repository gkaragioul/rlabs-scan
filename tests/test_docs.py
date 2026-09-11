from pathlib import Path
import unittest


class DocumentationTests(unittest.TestCase):
    def test_readme_describes_command_and_privacy_boundary(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        self.assertIn("rlabs scan", readme)
        self.assertIn("never executes", readme)


if __name__ == "__main__":
    unittest.main()
