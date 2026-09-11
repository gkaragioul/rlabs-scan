"""Read-only parsing helpers for Portable Executable headers and tables."""

from __future__ import annotations

from dataclasses import dataclass
import struct


class PEFormatError(ValueError):
    """Raised when bytes cannot safely be interpreted as a PE image."""


@dataclass(frozen=True)
class Section:
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int


@dataclass(frozen=True)
class PEImage:
    data: bytes
    architecture: str
    subsystem: str
    optional_magic: int
    size_of_headers: int
    sections: tuple[Section, ...]
    data_directories: tuple[tuple[int, int], ...]

    @classmethod
    def from_bytes(cls, data: bytes) -> "PEImage":
        if len(data) < 0x40 or data[0:2] != b"MZ":
            raise PEFormatError("missing or truncated DOS header")
        pe_offset = cls._u32(data, 0x3C)
        cls._require(data, pe_offset, 24, "COFF header")
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise PEFormatError("missing PE signature")

        coff = pe_offset + 4
        machine = cls._u16(data, coff)
        section_count = cls._u16(data, coff + 2)
        optional_size = cls._u16(data, coff + 16)
        optional = coff + 20
        cls._require(data, optional, optional_size, "optional header")
        optional_magic = cls._u16(data, optional)
        if optional_magic not in (0x10B, 0x20B):
            raise PEFormatError("unsupported optional header")

        directory_offset = 96 if optional_magic == 0x10B else 112
        if optional_size < directory_offset:
            raise PEFormatError("truncated optional header")
        declared_directories = cls._u32(data, optional + directory_offset - 4)
        available_directories = min(declared_directories, (optional_size - directory_offset) // 8)
        directories = tuple(
            (cls._u32(data, optional + directory_offset + index * 8), cls._u32(data, optional + directory_offset + index * 8 + 4))
            for index in range(available_directories)
        )

        section_offset = optional + optional_size
        cls._require(data, section_offset, section_count * 40, "section table")
        sections = tuple(
            Section(
                virtual_size=cls._u32(data, section_offset + index * 40 + 8),
                virtual_address=cls._u32(data, section_offset + index * 40 + 12),
                raw_size=cls._u32(data, section_offset + index * 40 + 16),
                raw_address=cls._u32(data, section_offset + index * 40 + 20),
            )
            for index in range(section_count)
        )
        architecture = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64"}.get(machine, "unknown")
        subsystem = {2: "windows-gui", 3: "windows-console"}.get(cls._u16(data, optional + 68), "unknown")
        return cls(
            data=data,
            architecture=architecture,
            subsystem=subsystem,
            optional_magic=optional_magic,
            size_of_headers=cls._u32(data, optional + 60),
            sections=sections,
            data_directories=directories,
        )

    def rva_to_offset(self, rva: int) -> int:
        if rva < self.size_of_headers and rva < len(self.data):
            return rva
        for section in self.sections:
            size = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + size:
                offset = section.raw_address + (rva - section.virtual_address)
                if offset < len(self.data):
                    return offset
        raise PEFormatError(f"RVA 0x{rva:08X} is not backed by file data")

    def directory(self, index: int) -> tuple[int, int]:
        return self.data_directories[index] if index < len(self.data_directories) else (0, 0)

    def imports(self) -> tuple[str, ...]:
        return self._dll_names(directory_index=1, descriptor_size=20, name_offset=12)

    def delay_imports(self) -> tuple[str, ...]:
        return self._dll_names(directory_index=13, descriptor_size=32, name_offset=4)

    def _dll_names(self, directory_index: int, descriptor_size: int, name_offset: int) -> tuple[str, ...]:
        table_rva, table_size = self.directory(directory_index)
        if table_rva == 0 or table_size == 0:
            return ()
        names: list[str] = []
        table_offset = self.rva_to_offset(table_rva)
        descriptor_count = table_size // descriptor_size
        for index in range(descriptor_count):
            offset = table_offset + index * descriptor_size
            self._require(self.data, offset, descriptor_size, "import descriptor")
            descriptor = self.data[offset : offset + descriptor_size]
            if descriptor == bytes(descriptor_size):
                break
            name_rva = self._u32(self.data, offset + name_offset)
            if name_rva:
                names.append(self._cstring_at_rva(name_rva))
        return tuple(dict.fromkeys(names))

    def _cstring_at_rva(self, rva: int) -> str:
        offset = self.rva_to_offset(rva)
        end = self.data.find(b"\0", offset)
        if end < 0:
            raise PEFormatError("unterminated import name")
        try:
            return self.data[offset:end].decode("ascii")
        except UnicodeDecodeError as error:
            raise PEFormatError("non-ASCII import name") from error

    @staticmethod
    def _require(data: bytes, offset: int, size: int, label: str) -> None:
        if offset < 0 or size < 0 or offset + size > len(data):
            raise PEFormatError(f"truncated {label}")

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        PEImage._require(data, offset, 2, "integer")
        return struct.unpack_from("<H", data, offset)[0]

    @staticmethod
    def _u32(data: bytes, offset: int) -> int:
        PEImage._require(data, offset, 4, "integer")
        return struct.unpack_from("<I", data, offset)[0]
