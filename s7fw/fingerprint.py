"""Fingerprinting of unpacked S7-1200 firmware images.

Identifies the target architecture from the ARM exception vector table and
recovers the OMS+ protocol-stack build version.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import List, Optional, Sequence

__all__ = [
    "OmsVersion",
    "ArchInfo",
    "ArchCandidate",
    "find_oms_version",
    "identify_arch",
    "score_architectures",
    "LOAD_BASE",
    "HAVE_CAPSTONE",
]

try:  # optional: pip install "s7fw[disasm]"
    import capstone as _cs

    HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover
    _cs = None
    HAVE_CAPSTONE = False

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
class ArchCandidate:
    """One architecture scored by trial disassembly."""

    name: str
    instructions: int
    coverage: float

    @property
    def score(self) -> float:
        return self.instructions * self.coverage / 100.0


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
    evidence: str = "vector table"
    candidates: tuple = ()

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


_CANDIDATES = (
    ("ARM BE", "CS_ARCH_ARM", ("CS_MODE_ARM", "CS_MODE_BIG_ENDIAN")),
    ("ARM LE", "CS_ARCH_ARM", ("CS_MODE_ARM", "CS_MODE_LITTLE_ENDIAN")),
    ("Thumb BE", "CS_ARCH_ARM", ("CS_MODE_THUMB", "CS_MODE_BIG_ENDIAN")),
    ("Thumb LE", "CS_ARCH_ARM", ("CS_MODE_THUMB", "CS_MODE_LITTLE_ENDIAN")),
    ("x86-32", "CS_ARCH_X86", ("CS_MODE_32",)),
    ("x86-64", "CS_ARCH_X86", ("CS_MODE_64",)),
    ("MIPS BE", "CS_ARCH_MIPS", ("CS_MODE_MIPS32", "CS_MODE_BIG_ENDIAN")),
    ("PPC BE", "CS_ARCH_PPC", ("CS_MODE_32", "CS_MODE_BIG_ENDIAN")),
)


def _code_anchors(image: bytes, count: int = 5, window: int = 4096) -> List[int]:
    """Pick sample offsets that are likely to be code.

    Sampling uniformly across the image is actively misleading: most of a
    firmware image is data, and x86's dense variable-length encoding decodes
    almost any byte sequence, so it wins on noise. Anchoring on the entry point
    reached through the reset vector -- and on windows dense in ARM function
    prologues -- compares architectures on bytes that really are code.
    """
    anchors: List[int] = []
    try:
        (word,) = struct.unpack_from(">I", image, VECTOR_TABLE_OFFSET)
        pool = VECTOR_TABLE_OFFSET + 8 + (word & 0xFFF)
        (entry_va,) = struct.unpack_from(">I", image, pool)
        entry = entry_va - LOAD_BASE
        if 0 < entry < len(image) - window:
            anchors.append(entry)
    except (struct.error, IndexError):
        pass

    # Windows rich in `push {..,lr}` / `pop {..,pc}` are function-dense.
    step = max(len(image) // 400, window)
    scored = []
    for offset in range(0, len(image) - window, step):
        chunk = image[offset : offset + window]
        density = chunk.count(b"\xe9\x2d") + chunk.count(b"\xe8\xbd")
        if density:
            scored.append((density, offset))
    scored.sort(reverse=True)
    for _, offset in scored:
        if len(anchors) >= count:
            break
        if all(abs(offset - a) > window for a in anchors):
            anchors.append(offset)
    return anchors or [0]


def score_architectures(
    image: bytes,
    offsets: Optional[Sequence[int]] = None,
    window: int = 4096,
) -> List[ArchCandidate]:
    """Rank architectures by trial-disassembling sample windows.

    Requires capstone. Returns candidates sorted best-first. The score is
    instructions decoded weighted by window coverage, which penalises an
    architecture that decodes a few bytes then desynchronises.

    Sample windows default to :func:`_code_anchors`; passing uniformly-spaced
    offsets will favour x86 regardless of the true architecture.
    """
    if not HAVE_CAPSTONE:
        raise RuntimeError("capstone is not installed (pip install 's7fw[disasm]')")
    if offsets is None:
        offsets = _code_anchors(image, window=window)

    results: List[ArchCandidate] = []
    for name, arch_name, mode_names in _CANDIDATES:
        arch = getattr(_cs, arch_name)
        mode = 0
        for mode_name in mode_names:
            mode |= getattr(_cs, mode_name)
        engine = _cs.Cs(arch, mode)
        engine.detail = False
        count = 0
        covered = 0
        for offset in offsets:
            chunk = image[offset : offset + window]
            reach = 0
            for insn in engine.disasm(chunk, offset):
                count += 1
                reach = insn.address + insn.size - offset
            covered += reach
        results.append(
            ArchCandidate(name, count, 100.0 * covered / (len(offsets) * window))
        )
    return sorted(results, key=lambda c: c.score, reverse=True)


def identify_arch(image: bytes, *, disassemble: bool = True) -> ArchInfo:
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

    evidence = "ARM exception vector table at file 0x40"
    candidates: tuple = ()
    if disassemble and HAVE_CAPSTONE:
        ranked = score_architectures(image)
        candidates = tuple(ranked)
        best = ranked[0]
        runner_up = ranked[1].score if len(ranked) > 1 else 0.0
        margin = best.score / runner_up if runner_up else float("inf")
        if best.name == "ARM BE" and margin > 4:
            big_endian = True
            evidence = (
                f"vector table + capstone ({best.instructions} insns, "
                f"{best.coverage:.0f}% coverage, {margin:.0f}x next candidate)"
            )
        elif not big_endian:
            evidence = f"capstone only: best={best.name} (weak)"

    return ArchInfo(
        architecture="ARM",
        bits=32,
        endianness="big" if big_endian else "unknown",
        load_base=LOAD_BASE,
        vector_offset=VECTOR_TABLE_OFFSET if big_endian else None,
        entry_va=entry_va,
        confident=big_endian,
        evidence=evidence,
        candidates=candidates,
    )
