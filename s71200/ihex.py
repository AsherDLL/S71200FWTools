"""Intel HEX decoding, for the payload of legacy containers.

Legacy (V2.x) containers store the firmware image as Intel HEX text rather than
as an LZP stream. Records are CRLF separated and use only the three types this
needs: 0x00 data, 0x01 end of file, 0x04 extended linear address.
"""

from __future__ import annotations

from typing import Tuple

from .errors import CorruptStreamError

__all__ = ["decode", "looks_like_ihex"]

_DATA, _EOF, _EXT_LINEAR = 0x00, 0x01, 0x04


def looks_like_ihex(payload: bytes) -> bool:
    """Whether *payload* opens with something shaped like an Intel HEX record."""
    return payload[:1] == b":" and payload[1:9].isalnum()


def decode(payload: bytes) -> Tuple[int, bytes]:
    """Decode Intel HEX text. Returns (base address, contiguous image).

    Gaps between records are filled with 0xFF, the erased state of flash.
    """
    chunks = {}
    upper = 0

    for number, line in enumerate(payload.split(b"\n"), 1):
        line = line.strip()
        if not line:
            continue
        if not line.startswith(b":"):
            raise CorruptStreamError(f"line {number} does not start with ':'")
        try:
            record = bytes.fromhex(line[1:].decode("ascii"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CorruptStreamError(f"line {number} is not hexadecimal") from exc
        if len(record) < 5:
            raise CorruptStreamError(f"line {number} is too short to be a record")
        if sum(record) & 0xFF:
            raise CorruptStreamError(f"line {number} fails its checksum")

        count, address, kind = record[0], int.from_bytes(record[1:3], "big"), record[3]
        data = record[4:4 + count]
        if len(data) != count:
            raise CorruptStreamError(f"line {number} declares {count} data bytes")

        if kind == _DATA:
            chunks[upper + address] = data
        elif kind == _EXT_LINEAR:
            upper = int.from_bytes(data, "big") << 16
        elif kind == _EOF:
            break

    if not chunks:
        raise CorruptStreamError("no Intel HEX data records")

    base = min(chunks)
    end = max(offset + len(data) for offset, data in chunks.items())
    image = bytearray(b"\xff" * (end - base))
    for offset, data in chunks.items():
        image[offset - base:offset - base + len(data)] = data
    return base, bytes(image)
