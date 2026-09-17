"""Exception hierarchy for :mod:`s7fw`."""

from __future__ import annotations

__all__ = [
    "S7FirmwareError",
    "TruncatedContainerError",
    "UnknownLayoutError",
    "CorruptStreamError",
]


class S7FirmwareError(Exception):
    """Base class for every error raised by this package."""


class TruncatedContainerError(S7FirmwareError):
    """The file is shorter than the structure it declares."""


class UnknownLayoutError(S7FirmwareError):
    """No known table-of-contents layout accounts for the file."""


class CorruptStreamError(S7FirmwareError):
    """The LZP stream violates an invariant that holds for genuine firmware."""
