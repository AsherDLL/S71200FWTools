"""Parsing of the Siemens S7-1200 ``.upd`` firmware container.

Two container generations exist and are auto-detected:

==========  =============  ==============  ==========  ==========================
generation  releases       TOC endianness  name tags   sections
==========  =============  ==============  ==========  ==========================
legacy      V2.x           big             absent      cpu_it cpu_fw cpu_bu cpu_md
modern      V3.0 - V4.7    little          present     BG_ABL A00000 B00000 FW_SIG
==========  =============  ==============  ==========  ==========================

Both satisfy an exact completeness invariant, which is what the detector uses:
the declared layout must account for the file to the byte.

The payloads differ too. A modern code section is an LZP stream; a legacy one
is Intel HEX text, decoded by :mod:`s71200.ihex`.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple

from . import ihex
from .errors import TruncatedContainerError, UnknownLayoutError
from .lzp import CHUNK_SIZE, LzpDecoder, LzpStats

__all__ = ["Firmware", "Section", "Layout", "FirmwareVersion", "load", "discover"]

HEADER_SIZE = 0x2C
ENTRY_COUNT = 4
ENTRY_SIZE = 14
NAME_SIZE = 6
_DATA_START = HEADER_SIZE + ENTRY_COUNT * ENTRY_SIZE  # 0x64

CODE_SECTION = "A00000"
LEGACY_CODE_SECTION = "cpu_fw"


class Layout(Enum):
    """Container generation."""

    MODERN = "modern"
    LEGACY = "legacy"

    @property
    def endianness(self) -> str:
        return "little" if self is Layout.MODERN else "big"

    @property
    def tagged(self) -> bool:
        """Whether each payload repeats its name as a 6-byte in-stream tag."""
        return self is Layout.MODERN


@dataclass(frozen=True)
class FirmwareVersion:
    """The ``V<major>.<minor>.<patch>`` triple from the container header."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw: bytes) -> "FirmwareVersion":
        return cls(raw[1], raw[2], raw[3])

    def __str__(self) -> str:
        return f"V{self.major:02d}.{self.minor:02d}.{self.patch:02d}"



@dataclass(frozen=True)
class Section:
    """One entry of the table of contents and the payload it describes."""

    name: str
    size: int
    checksum: int
    tag_offset: int
    data_offset: int

    @property
    def end(self) -> int:
        return self.data_offset + self.size


@dataclass
class Firmware:
    """A parsed ``.upd`` container."""

    data: bytes
    source: Optional[Path] = None
    version: FirmwareVersion = field(init=False)
    mlfb: str = field(init=False)
    magic: int = field(init=False)
    layout: Layout = field(init=False)
    sections: List[Section] = field(init=False, default_factory=list)
    problems: List[str] = field(init=False, default_factory=list)
    declared_end: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        if len(self.data) < _DATA_START:
            raise TruncatedContainerError(
                f"{len(self.data)} bytes is smaller than the "
                f"{_DATA_START}-byte header and table of contents"
            )
        self.magic = struct.unpack_from("<I", self.data, 0)[0]
        if self.magic != 4:
            self.problems.append(
                f"leading dword is 0x{self.magic:08x}, expected 0x00000004"
            )
        self.version = FirmwareVersion.parse(self.data[0x0C:0x10])
        self.mlfb = self.data[0x10:0x24].decode("latin-1").strip()
        self._detect_layout()

    # Layout detection

    def _candidate(self, layout: Layout) -> Tuple[List[Section], int, List[str]]:
        fmt = "<II" if layout.endianness == "little" else ">II"
        tag_len = NAME_SIZE if layout.tagged else 0
        sections: List[Section] = []
        cursor = HEADER_SIZE
        data_offset = _DATA_START

        for _ in range(ENTRY_COUNT):
            size, checksum = struct.unpack_from(fmt, self.data, cursor)
            raw_name = self.data[cursor + 8 : cursor + 8 + NAME_SIZE]
            try:
                name = raw_name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise UnknownLayoutError(
                    f"non-ASCII TOC name at 0x{cursor:x}: {raw_name!r}"
                ) from exc
            sections.append(
                Section(name, size, checksum, data_offset, data_offset + tag_len)
            )
            cursor += ENTRY_SIZE
            data_offset += tag_len + size

        problems: List[str] = []
        if layout.tagged:
            for section in sections:
                tag = self.data[section.tag_offset : section.tag_offset + NAME_SIZE]
                if tag != section.name.encode("ascii"):
                    problems.append(
                        f"section {section.name}: in-stream tag at "
                        f"0x{section.tag_offset:x} is {tag!r}"
                    )
        return sections, data_offset, problems

    def _detect_layout(self) -> None:
        best: Optional[Tuple[int, int, Layout, List[Section], int, List[str]]] = None
        for layout in (Layout.MODERN, Layout.LEGACY):
            try:
                sections, end, problems = self._candidate(layout)
            except UnknownLayoutError:
                continue
            score = (abs(end - len(self.data)), len(problems))
            if best is None or score < (best[0], best[1]):
                best = (score[0], score[1], layout, sections, end, problems)

        if best is None:
            raise UnknownLayoutError("no recognisable table-of-contents layout")

        _, _, self.layout, self.sections, self.declared_end, problems = best
        self.problems.extend(problems)
        if self.declared_end != len(self.data):
            self.problems.append(
                f"declared layout ends at {self.declared_end} but the file is "
                f"{len(self.data)} bytes ({len(self.data) - self.declared_end:+d})"
            )

    # Accessors

    def __getitem__(self, name: str) -> Section:
        for section in self.sections:
            if section.name == name:
                return section
        raise KeyError(name)

    def __contains__(self, name: str) -> bool:
        return any(section.name == name for section in self.sections)

    def __len__(self) -> int:
        return len(self.data)

    @property
    def complete(self) -> bool:
        """Whether the declared structure accounts for the file exactly."""
        return not self.problems

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def code_section(self) -> str:
        """Name of the section holding the compressed firmware image."""
        if CODE_SECTION in self:
            return CODE_SECTION
        if LEGACY_CODE_SECTION in self:
            return LEGACY_CODE_SECTION
        return self.sections[1].name

    def payload(self, name: Optional[str] = None) -> bytes:
        section = self[name or self.code_section]
        return self.data[section.data_offset : section.end]

    def unpack(
        self,
        name: Optional[str] = None,
        *,
        strict: bool = True,
        reuse_table: bool = False,
    ) -> Tuple[bytes, LzpStats, Sequence[int]]:
        """Extract a section. Returns (image, stats, chunk header values).

        Modern containers hold an LZP stream. Legacy ones hold Intel HEX, which
        is not compressed, so the statistics come back zeroed.
        """
        payload = self.payload(name)
        if ihex.looks_like_ihex(payload):
            _, image = ihex.decode(payload)
            return image, LzpStats(), ()
        decoder = LzpDecoder(strict=strict)
        return decoder.decode_section(payload, strict=strict, reuse_table=reuse_table)

    def __repr__(self) -> str:
        name = self.source.name if self.source else "<bytes>"
        return (
            f"Firmware({name!r} {self.version} {self.mlfb!r} "
            f"{self.layout.value} {'complete' if self.complete else 'PROBLEMS'})"
        )


def load(path: "str | Path") -> Firmware:
    """Read and parse a ``.upd`` file."""
    path = Path(path)
    return Firmware(path.read_bytes(), path)


def discover(root: "str | Path") -> Iterator[Tuple[str, bytes]]:
    """Yield ``(label, data)`` for every ``.upd`` under *root*, ZIPs included."""
    root = Path(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix == ".upd":
            yield str(path), path.read_bytes()
        elif suffix == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in archive.namelist():
                        if member.lower().endswith(".upd"):
                            yield f"{path}::{member}", archive.read(member)
            except zipfile.BadZipFile:
                continue
