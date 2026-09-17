"""Recover C++ class symbols from an unpacked S7-1200 firmware image.

The firmware carries a custom RTTI-like registry -- roughly 7,000 records, one
per C++ class, each holding the class name and pointers to associated code.
Record layout, offsets relative to the tag word:

    -20  code pointer      (ARM prologue in ~50% of records)
    -12  code pointer      (~57%)
     -4  code pointer      (~68%)
     +0  tag               identical across every record in an image
     +4  pointer to name   -- points at +16 in 94% of records
     +8  sequential type id
    +12  pointer to a base-class record, or 0 (~70% non-zero)
    +16  NUL-terminated name, inline

Records are packed back to back and are variable length. The tag is a virtual
address, so it differs per build and is discovered per image rather than
hardcoded.

Only the names and record addresses are treated as facts. The code pointers are
*associated* with the class -- constructor, destructor and virtual slots are the
obvious candidates -- but which slot is which has not been established, so they
are reported as associations and never turned into invented function names.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from .fingerprint import LOAD_BASE

__all__ = ["Symbol", "find_record_tag", "extract_symbols"]

_NAME = re.compile(rb"[ -~]{3,160}\x00")
_ARM_PROLOGUE = frozenset((0xE0, 0xE1, 0xE2, 0xE3, 0xE5, 0xE8, 0xE9, 0xEA, 0xEB))

TAG_OFFSET_NAME = 4
TAG_OFFSET_ID = 8
TAG_OFFSET_BASE = 12
TAG_OFFSET_INLINE = 16
CODE_SLOTS = (-4, -12, -20)


@dataclass(frozen=True)
class Symbol:
    """One C++ class recovered from the RTTI registry."""

    name: str
    record_va: int
    type_id: int
    base_va: int = 0
    code_vas: tuple = ()


    def __str__(self) -> str:
        return self.name


def _be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def find_record_tag(image: bytes, base: int = LOAD_BASE) -> Optional[int]:
    """Discover the per-image record tag.

    A record whose name is stored inline satisfies ``name_ptr == record + 16``,
    which identifies records without needing a pointer index. The tag is then
    simply the most common word at those offsets.
    """
    counts: Dict[int, int] = {}
    for offset in range(0, len(image) - TAG_OFFSET_INLINE - 4, 4):
        if _be(image, offset + TAG_OFFSET_NAME) == offset + TAG_OFFSET_INLINE + base:
            tag = _be(image, offset)
            counts[tag] = counts.get(tag, 0) + 1
    if not counts:
        return None
    tag, hits = max(counts.items(), key=lambda kv: kv[1])
    return tag if hits >= 16 else None


def extract_symbols(
    image: bytes,
    base: int = LOAD_BASE,
    tag: Optional[int] = None,
) -> Iterator[Symbol]:
    """Yield every class symbol in the image, in address order."""
    tag = find_record_tag(image, base) if tag is None else tag
    if tag is None:
        return

    size = len(image)
    for offset in range(20, size - TAG_OFFSET_INLINE, 4):
        if _be(image, offset) != tag:
            continue
        name_va = _be(image, offset + TAG_OFFSET_NAME)
        if not base <= name_va < base + size:
            continue
        match = _NAME.match(image, name_va - base)
        if not match:
            continue

        code = tuple(
            va for va in (_be(image, offset + slot) for slot in CODE_SLOTS)
            if base <= va < base + size and image[va - base] in _ARM_PROLOGUE
        )
        yield Symbol(
            name=match.group()[:-1].decode("latin-1"),
            record_va=offset + base,
            type_id=_be(image, offset + TAG_OFFSET_ID),
            base_va=_be(image, offset + TAG_OFFSET_BASE),
            code_vas=code,
        )
