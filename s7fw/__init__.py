"""s7fw -- Siemens SIMATIC S7-1200 firmware container parser and LZP unpacker.

    >>> from s7fw import load
    >>> fw = load("6ES7 211-1HE40-0XB0 V04.05.02.upd")
    >>> fw.version, fw.layout.value, fw.complete
    (V04.05.02, 'modern', True)
    >>> image, stats, headers = fw.unpack()
    >>> len(image)
    22839431

The LZP compression algorithm was reverse engineered black-box from a
compressed firmware image by Jean-Baptiste Bedrune (@jibeee) and published as
``s7unpack`` (Apache-2.0). This package is an independent Python
reimplementation of his algorithm.
"""

from __future__ import annotations

from .container import (
    Firmware,
    FirmwareVersion,
    Layout,
    Section,
    discover,
    load,
)
from .errors import (
    CorruptStreamError,
    S7FirmwareError,
    TruncatedContainerError,
    UnknownLayoutError,
)
from .fingerprint import (
    LOAD_BASE,
    ArchInfo,
    OmsVersion,
    find_oms_version,
    identify_arch,
)
from .lzp import CHUNK_SIZE, Chunk, LzpDecoder, LzpStats, iter_chunks
from .symbols import Symbol, extract_symbols, find_record_tag

__version__ = "1.0.0"

__all__ = [
    "Firmware",
    "FirmwareVersion",
    "Layout",
    "Section",
    "load",
    "discover",
    "LzpDecoder",
    "LzpStats",
    "Chunk",
    "iter_chunks",
    "CHUNK_SIZE",
    "find_oms_version",
    "identify_arch",
    "OmsVersion",
    "ArchInfo",
    "LOAD_BASE",
    "Symbol",
    "extract_symbols",
    "find_record_tag",
    "S7FirmwareError",
    "TruncatedContainerError",
    "UnknownLayoutError",
    "CorruptStreamError",
    "__version__",
]
