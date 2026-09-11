import unittest

from rlabs_scan.pe import PEFormatError, PEImage
from tests.pe_fixture import make_pe


class PEImageTests(unittest.TestCase):
    def test_rejects_truncated_dos_image(self) -> None:
        with self.assertRaises(PEFormatError):
            PEImage.from_bytes(b"MZ")

    def test_reads_x86_header_and_rva_mapping(self) -> None:
        image = PEImage.from_bytes(make_pe(machine=0x14C))
        self.assertEqual(image.architecture, "x86")
        self.assertEqual(image.subsystem, "windows-gui")
        self.assertEqual(image.rva_to_offset(0x1000), 0x200)

    def test_reads_x64_header(self) -> None:
        image = PEImage.from_bytes(make_pe(machine=0x8664))
        self.assertEqual(image.architecture, "x64")


if __name__ == "__main__":
    unittest.main()
