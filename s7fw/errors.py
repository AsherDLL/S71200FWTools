"""Exception hierarchy for :mod:`s7fw`."""

from __future__ import annotations

__all__ = [
    "S7FirmwareError",
    "ContainerError",
    "TruncatedContainerError",
    "UnknownLayoutError",
    "CompressionError",
    "CorruptStreamError",
    "UnsupportedFormatError",
]


class S7FirmwareError(Exception):
    """Base class for every error raised by this package."""


class ContainerError(S7FirmwareError):
    """The ``.upd`` container could not be interpreted."""


class TruncatedContainerError(ContainerError):
    """The file is shorter than the structure it declares."""


class UnknownLayoutError(ContainerError):
    """No known table-of-contents layout accounts for the file."""


class CompressionError(S7FirmwareError):
    """Decompression failed."""


class CorruptStreamError(CompressionError):
    """The LZP stream violates an invariant that holds for genuine firmware."""


class UnsupportedFormatError(S7FirmwareError):
    """The structure is understood but this tool cannot process it."""
