"""LZP decompression for Siemens S7-1200 firmware images.

The algorithm was reverse engineered black-box from a compressed firmware image
by Jean-Baptiste Bedrune (@jibeee) and released as ``s7unpack`` under the
Apache License 2.0 (https://github.com/jibeee/s7unpack). This module is an
independent Python reimplementation of *his* algorithm.

It is LZP, a hashed context predictor, rather than LZ77. A match token carries only
a length, and the source position is predicted from a hash of the preceding
four output bytes, so no offset is ever transmitted.

Three memory-safety defects in the original C are corrected here:

===============  ==========================================================
``lzp.c:57``     seeds the context from ``output_data - 4``, a four-byte heap
                 under-read that also populates the wrong hash slot
``lzp.c:64``     bounds-checks the input cursor once per eight symbols, so it
                 can over-read up to eight bytes
``lzp.c:85``     indexes with a match position of ``0xFFFFFFFF`` when the hash
                 slot was never populated, causing a wild read
===============  ==========================================================
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence

from .errors import CorruptStreamError

__all__ = ["LzpDecoder", "LzpStats", "Chunk", "iter_chunks", "ORDER", "CHUNK_SIZE"]

ORDER = 4
"""Number of preceding bytes forming the prediction context."""

CHUNK_SIZE = 0x10000
"""Uncompressed size of every chunk except the last."""

_HASH_SIZE = 0x10000
_NIL = 0xFFFFFFFF
_MASK32 = 0xFFFFFFFF


@dataclass(frozen=True)
class Chunk:
    """One framed LZP chunk within a compressed section."""

    index: int
    offset: int
    compressed_size: int
    header: int
    stream: bytes

    def __len__(self) -> int:
        return len(self.stream)


@dataclass
class LzpStats:
    """Counters gathered while decoding, used to validate a stream."""

    literals: int = 0
    matches: int = 0
    match_bytes: int = 0
    anomalous_matches: int = 0
    consumed: int = 0

    def __iadd__(self, other: "LzpStats") -> "LzpStats":
        self.literals += other.literals
        self.matches += other.matches
        self.match_bytes += other.match_bytes
        self.anomalous_matches += other.anomalous_matches
        self.consumed += other.consumed
        return self


def iter_chunks(blob: bytes) -> Iterator[Chunk]:
    """Yield the framed chunks of a compressed section.

    Framing is ``[uint32 compressed_size][uint16 header][stream]`` where
    ``compressed_size`` counts the header plus the stream but not itself.
    """
    offset = 0
    index = 0
    total = len(blob)
    while offset + 4 <= total:
        (size,) = struct.unpack_from("<I", blob, offset)
        if size == 0:
            break
        if size < 2 or offset + 4 + size > total:
            raise CorruptStreamError(
                f"chunk {index} at 0x{offset:x} declares {size} bytes, "
                f"only {total - offset - 4} remain"
            )
        (header,) = struct.unpack_from("<H", blob, offset + 4)
        yield Chunk(index, offset, size, header, blob[offset + 6 : offset + 4 + size])
        offset += 4 + size
        index += 1


class LzpDecoder:
    """Decoder for a single LZP stream.

    The hash table is per-instance. Reusing one instance across chunks
    reproduces the original C's behaviour; a fresh instance per chunk is
    equivalent, because any context occurring within a chunk overwrites a stale
    entry before it can be referenced.
    """

    __slots__ = ("_table", "strict")

    def __init__(self, *, strict: bool = True) -> None:
        self.strict = strict
        self._table: List[int] = [_NIL] * _HASH_SIZE

    def reset(self) -> None:
        """Clear the prediction table."""
        self._table = [_NIL] * _HASH_SIZE

    @staticmethod
    def _hash(context: int) -> int:
        return ((context >> 15) ^ context) & 0xFFFF

    def decode(
        self,
        source: bytes,
        limit: int = CHUNK_SIZE,
        stats: Optional[LzpStats] = None,
    ) -> bytes:
        """Decode ``source`` into at most ``limit`` bytes."""
        if len(source) < ORDER:
            raise CorruptStreamError(
                f"stream of {len(source)} bytes is shorter than the "
                f"{ORDER}-byte seed"
            )

        table = self._table
        out = bytearray(limit)
        out[:ORDER] = source[:ORDER]
        read = ORDER
        written = ORDER
        end = len(source)

        context = int.from_bytes(out[:ORDER], "big")
        table[self._hash(context)] = written

        literals = matches = match_bytes = anomalous = 0

        while written < limit and read < end:
            mask = source[read]
            read += 1
            for _ in range(8):
                if read >= end or written >= limit:
                    break
                token = source[read]
                read += 1
                slot = ((context >> 15) ^ context) & 0xFFFF

                if not mask & 0x80:
                    table[slot] = written
                    out[written] = token
                    written += 1
                    context = ((context << 8) | token) & _MASK32
                    literals += 1
                else:
                    position = table[slot]
                    table[slot] = written
                    if position == _NIL:
                        raise CorruptStreamError(
                            f"match at output offset {written} references "
                            f"unpopulated hash slot 0x{slot:04x}"
                        )
                    if position >= written:
                        # position == written is a degenerate self-copy;
                        # position > written reads data not yet produced.
                        # Neither occurs in genuine firmware.
                        anomalous += 1
                    length = min(token, limit - written)
                    stop = written + length
                    if position + length <= written:
                        out[written:stop] = out[position : position + length]
                        written = stop
                    else:
                        for step in range(length):
                            out[written] = out[position + step]
                            written += 1
                    context = int.from_bytes(out[written - ORDER : written], "big")
                    matches += 1
                    match_bytes += length

                mask = (mask << 1) & 0xFF

        if stats is not None:
            stats += LzpStats(literals, matches, match_bytes, anomalous, read)
        return bytes(out[:written])

    def decode_section(
        self,
        blob: bytes,
        *,
        strict: Optional[bool] = None,
        reuse_table: bool = False,
    ) -> tuple[bytes, LzpStats, Sequence[int]]:
        """Decode every chunk of a compressed section.

        Returns the image, aggregate statistics, and the set of distinct chunk
        header values encountered.
        """
        strict = self.strict if strict is None else strict
        chunks = list(iter_chunks(blob))
        out = bytearray()
        totals = LzpStats()
        headers: set[int] = set()

        for chunk in chunks:
            if not reuse_table:
                self.reset()
            piece_stats = LzpStats()
            piece = self.decode(chunk.stream, CHUNK_SIZE, piece_stats)
            totals += piece_stats
            headers.add(chunk.header)
            out += piece

            if strict:
                if piece_stats.anomalous_matches:
                    raise CorruptStreamError(
                        f"chunk {chunk.index} contains "
                        f"{piece_stats.anomalous_matches} self-referential or "
                        f"forward matches"
                    )
                if len(piece) != CHUNK_SIZE and chunk.index != len(chunks) - 1:
                    raise CorruptStreamError(
                        f"chunk {chunk.index}/{len(chunks)} produced "
                        f"{len(piece)} bytes, expected {CHUNK_SIZE}"
                    )

        if strict and not out:
            raise CorruptStreamError(
                f"no output from {len(blob)} bytes of payload across "
                f"{len(chunks)} chunks, wrong section or unknown layout"
            )
        return bytes(out), totals, sorted(headers)
