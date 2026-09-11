from __future__ import annotations

import struct


def make_pe(
    machine: int = 0x14C,
    subsystem: int = 2,
    imports: list[str] | None = None,
    delay_imports: list[str] | None = None,
) -> bytes:
    """Build a minimal, inert PE image for parser tests."""
    optional_size = 0xE0 if machine == 0x14C else 0xF0
    image = bytearray(0x600)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", image, coff, machine)
    struct.pack_into("<H", image, coff + 2, 1)
    struct.pack_into("<H", image, coff + 16, optional_size)
    optional = coff + 20
    struct.pack_into("<H", image, optional, 0x10B if machine == 0x14C else 0x20B)
    struct.pack_into("<I", image, optional + 60, 0x200)
    struct.pack_into("<H", image, optional + 68, subsystem)
    struct.pack_into("<I", image, optional + (92 if machine == 0x14C else 108), 16)
    section = optional + optional_size
    image[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<I", image, section + 8, 0x400)
    struct.pack_into("<I", image, section + 12, 0x1000)
    struct.pack_into("<I", image, section + 16, 0x400)
    struct.pack_into("<I", image, section + 20, 0x200)
    directory_offset = optional + (96 if machine == 0x14C else 112)
    _write_import_table(image, directory_offset, 1, 0x1000, 0x200, imports or [])
    _write_import_table(image, directory_offset, 13, 0x1200, 0x400, delay_imports or [], delay=True)
    return bytes(image)


def _write_import_table(
    image: bytearray,
    directory_offset: int,
    index: int,
    table_rva: int,
    table_offset: int,
    names: list[str],
    delay: bool = False,
) -> None:
    if not names:
        return
    struct.pack_into("<II", image, directory_offset + index * 8, table_rva, (len(names) + 1) * (32 if delay else 20))
    name_offset = table_offset + (len(names) + 1) * (32 if delay else 20)
    for position, name in enumerate(names):
        descriptor = table_offset + position * (32 if delay else 20)
        name_rva = 0x1000 + (name_offset - 0x200)
        struct.pack_into("<I", image, descriptor + (4 if delay else 12), name_rva)
        encoded = name.encode("ascii") + b"\0"
        image[name_offset : name_offset + len(encoded)] = encoded
        name_offset += len(encoded)
