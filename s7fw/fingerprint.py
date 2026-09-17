"""Fingerprinting of unpacked S7-1200 firmware images.

Identifies the target architecture from the ARM exception vector table and
recovers the OMS+ protocol-stack build version.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Optional

__all__ = ["OmsVersion", "ArchInfo", "find_oms_version", "identify_arch",
           "LOAD_BASE"]

LOAD_BASE = 0x37FC0
"""virtual_address = file_offset + LOAD_BASE (confirmed via the reset vector)."""

VECTOR_TABLE_OFFSET = 0x40
_LDR_PC_BE = b"\xe5\x9f\xf0"  # LDR PC,[PC,#imm] in big-endian byte order

# V4.4 onwards: OMSP_12.00.01.08_35.08.00.01 ; through V4.3: OMSP.REL.8089.16
_OMS_MODERN = re.compile(rb"OMSP_(\d{2})\.\d{2}\.\d{2}\.\d{2}_(\d{2})\.(\d{2})\.[\d.]+")
_OMS_LEGACY = re.compile(rb"OMSP\.REL\.[\d.]+")


@dataclass(frozen=True)
class OmsVersion:
    """An OMS+ stack version recovered from an unpacked image."""

    raw: str
    major: Optional[int] = None
    minor: Optional[int] = None
    patch: Optional[int] = None

    @property
    def triple(self) -> Optional[tuple[int, int, int]]:
        if self.major is None:
            return None
        return (self.major, self.minor, self.patch)

    def __str__(self) -> str:
        triple = self.triple
        return f"{triple[0]}.{triple[1]}.{triple[2]}" if triple else self.raw


@dataclass(frozen=True)
class ArchInfo:
    """Result of architecture identification."""

    architecture: str
    bits: int
    endianness: str
    load_base: int
    vector_offset: Optional[int]
    entry_va: Optional[int]
    confident: bool

    @property
    def ghidra_language(self) -> str:
        return "ARM:BE:32:v7" if self.endianness == "big" else "ARM:LE:32:v7"

    def __str__(self) -> str:
        return (
            f"{self.architecture} {self.bits}-bit {self.endianness}-endian, "
            f"base 0x{self.load_base:x}"
        )


def find_oms_version(image: bytes) -> Optional[OmsVersion]:
    """Recover the OMS+ version string from an *unpacked* image.

    In a compressed container these strings are split by LZP tokens; they are
    contiguous only after decompression, which makes this a useful check that
    decompression succeeded.
    """
    match = _OMS_MODERN.search(image)
    if match:
        return OmsVersion(
            match.group(0).decode("ascii"),
            int(match.group(1)),
            int(match.group(2)),
            int(match.group(3)),
        )
    legacy = _OMS_LEGACY.search(image)
    if legacy:
        return OmsVersion(legacy.group(0).decode("ascii"))
    return None


def identify_arch(image: bytes) -> ArchInfo:
    """Identify the target architecture of an unpacked image.

    S7-1200 images carry an eight-entry ARM exception vector table at file
    offset 0x40, encoded big-endian. The reset entry resolves through a literal
    pool to the entry point, which cross-checks the load base.
    """
    window = image[VECTOR_TABLE_OFFSET : VECTOR_TABLE_OFFSET + 32]
    entries = sum(
        1 for i in range(0, 32, 4) if window[i : i + 3] == _LDR_PC_BE
    )
    big_endian = entries >= 4

    entry_va: Optional[int] = None
    if big_endian:
        try:
            (word,) = struct.unpack_from(">I", image, VECTOR_TABLE_OFFSET)
            # LDR PC,[PC,#imm] -- PC reads as instruction address + 8
            pool = VECTOR_TABLE_OFFSET + 8 + (word & 0xFFF)
            (entry_va,) = struct.unpack_from(">I", image, pool)
        except struct.error:
            entry_va = None

    return ArchInfo(
        architecture="ARM",
        bits=32,
        endianness="big" if big_endian else "unknown",
        load_base=LOAD_BASE,
        vector_offset=VECTOR_TABLE_OFFSET if big_endian else None,
        entry_va=entry_va,
        confident=big_endian,
    )
