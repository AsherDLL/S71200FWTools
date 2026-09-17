"""Test suite for :mod:`s71200`.

Runs standalone (``python3 tests/test_s71200.py``) or under pytest. Tests that
need real firmware are skipped unless ``S71200_CORPUS`` points at a tree
containing ``.upd`` files.
"""

from __future__ import annotations

import os
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from s71200 import (  # noqa: E402
    CHUNK_SIZE,
    CorruptStreamError,
    Firmware,
    Layout,
    LzpDecoder,
    TruncatedContainerError,
    UnknownLayoutError,
    discover,
    extract_symbols,
    find_oms_version,
    find_record_tag,
    identify_arch,
    iter_chunks,
)

CORPUS = os.environ.get("S71200_CORPUS")
_SEED = b"\x01\x02\x03\x04"


def _corpus_files():
    if not CORPUS or not Path(CORPUS).exists():
        return []
    return list(discover(CORPUS))


class TestLzpStreams(unittest.TestCase):
    def setUp(self) -> None:
        self.decoder = LzpDecoder()

    def test_stream_shorter_than_seed_rejected(self) -> None:
        for bad in (b"", b"\x01", b"\x01\x02\x03"):
            self.decoder.reset()
            with self.assertRaises(CorruptStreamError):
                self.decoder.decode(bad)

    def test_seed_only(self) -> None:
        self.assertEqual(self.decoder.decode(_SEED, 0x100), _SEED)

    def test_all_literal_group(self) -> None:
        out = self.decoder.decode(_SEED + b"\x00" + b"A" * 8, 0x100)
        self.assertEqual(out, _SEED + b"A" * 8)

    def test_output_never_exceeds_limit(self) -> None:
        out = self.decoder.decode(_SEED + b"\x00" + b"A" * 8, 6)
        self.assertEqual(len(out), 6)

    def test_match_on_unpopulated_slot_rejected(self) -> None:
        # Eight literals move the context off the seed-populated slot.
        stream = _SEED + b"\x00" + b"ABCDEFGH" + b"\x80" + b"\x10" * 8
        with self.assertRaises(CorruptStreamError):
            self.decoder.decode(stream, 0x1000)

    def test_truncated_group_stops_cleanly(self) -> None:
        out = self.decoder.decode(_SEED + b"\x00" + b"AAA", 0x100)
        self.assertEqual(out, _SEED + b"AAA")

    def test_seeded_match_is_self_copy(self) -> None:
        # The seed populates hash(context) so this match resolves to pos == 4.
        out = self.decoder.decode(_SEED + b"\x80" + b"\x40" * 8, 0x1000)
        self.assertEqual(out[:4], _SEED)
        self.assertGreater(len(out), 4)

    def test_decoder_reset_clears_table(self) -> None:
        self.decoder.decode(_SEED, 0x100)
        self.decoder.reset()
        stream = _SEED + b"\x00" + b"ABCDEFGH" + b"\x80" + b"\x10" * 8
        with self.assertRaises(CorruptStreamError):
            self.decoder.decode(stream, 0x1000)


class TestChunkFraming(unittest.TestCase):
    def test_empty_section(self) -> None:
        self.assertEqual(list(iter_chunks(b"")), [])

    def test_zero_size_terminates(self) -> None:
        self.assertEqual(list(iter_chunks(struct.pack("<I", 0))), [])

    def test_chunk_longer_than_buffer(self) -> None:
        with self.assertRaises(CorruptStreamError):
            list(iter_chunks(struct.pack("<I", 0xFFFF) + b"\x00\x00"))

    def test_chunk_shorter_than_header(self) -> None:
        with self.assertRaises(CorruptStreamError):
            list(iter_chunks(struct.pack("<I", 1) + b"\x00"))

    def test_well_formed_chunk(self) -> None:
        payload = b"\x00\x01" + _SEED
        blob = struct.pack("<I", len(payload)) + payload
        chunks = list(iter_chunks(blob))
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].index, 0)
        self.assertEqual(chunks[0].stream, _SEED)


class TestContainerRejection(unittest.TestCase):
    def test_empty(self) -> None:
        with self.assertRaises(TruncatedContainerError):
            Firmware(b"")

    def test_shorter_than_toc(self) -> None:
        with self.assertRaises(TruncatedContainerError):
            Firmware(b"\x04\x00\x00\x00" + b"\x00" * 0x30)

    def test_non_ascii_names_rejected(self) -> None:
        with self.assertRaises(UnknownLayoutError):
            Firmware(b"\x04\x00\x00\x00" + b"\xff" * 0x100)


@unittest.skipUnless(_corpus_files(), "set S71200_CORPUS to a firmware tree")
class TestRealFirmware(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.files = _corpus_files()
        cls.sample = None
        for label, data in cls.files:
            fw = Firmware(data)
            if fw.complete and fw.layout is Layout.MODERN:
                cls.sample = fw
                break

    def test_every_container_parses_complete(self) -> None:
        bad = []
        for label, data in self.files:
            fw = Firmware(data)
            if not fw.complete:
                bad.append((Path(label).name, fw.problems[0]))
        self.assertEqual(bad, [], f"{len(bad)} incomplete containers")

    def test_truncation_is_detected(self) -> None:
        data = self.sample.data
        for cut in (1 << 10, 1 << 20, len(data) - 1):
            self.assertFalse(Firmware(data[:cut]).complete)

    def test_corrupt_tag_is_detected(self) -> None:
        data = bytearray(self.sample.data)
        section = self.sample[self.sample.code_section]
        data[section.tag_offset : section.tag_offset + 6] = b"XXXXXX"
        self.assertFalse(Firmware(bytes(data)).complete)

    def test_framing_consumes_section_exactly(self) -> None:
        blob = self.sample.payload()
        framed = sum(4 + c.compressed_size for c in iter_chunks(blob))
        self.assertEqual(framed, len(blob))

    def test_decompression_invariants(self) -> None:
        image, stats, headers = self.sample.unpack(strict=True)
        self.assertEqual(stats.anomalous_matches, 0)
        self.assertGreater(len(image), len(self.sample.payload()))
        self.assertIn(b"ADONIS", image)

    def test_strings_are_contiguous_after_unpacking(self) -> None:
        image, _, _ = self.sample.unpack()
        # Fragmented by LZP tokens while compressed; whole once decoded.
        self.assertIn(b"OPCUA::Common::OMSP_DA::", image)
        self.assertIsNotNone(find_oms_version(image))

    def test_architecture_is_big_endian_arm(self) -> None:
        image, _, _ = self.sample.unpack()
        arch = identify_arch(image)
        self.assertTrue(arch.confident)
        self.assertEqual(arch.architecture, "ARM")
        self.assertEqual(arch.endianness, "big")
        self.assertEqual(arch.ghidra_language, "ARM:BE:32:v7")

    def test_symbols_are_recovered(self) -> None:
        image, _, _ = self.sample.unpack()
        tag = find_record_tag(image)
        self.assertIsNotNone(tag, "no RTTI record tag discovered")
        symbols = list(extract_symbols(image, tag=tag))
        self.assertGreater(len(symbols), 1000)
        names = {s.name for s in symbols}
        self.assertTrue(any(n.startswith("ACE_6_5_0::") for n in names))
        self.assertTrue(any("OMS" in n for n in names))
        for sym in symbols:
            self.assertTrue(sym.name)
            self.assertGreater(sym.record_va, 0)

    def test_symbol_code_pointers_land_in_image(self) -> None:
        image, _, _ = self.sample.unpack()
        base = 0x37FC0
        for sym in list(extract_symbols(image))[:500]:
            for va in sym.code_vas:
                self.assertTrue(base <= va < base + len(image))

    def test_entry_point_resolves_within_image(self) -> None:
        image, _, _ = self.sample.unpack()
        arch = identify_arch(image)
        self.assertIsNotNone(arch.entry_va)
        self.assertTrue(0 < arch.entry_va - arch.load_base < len(image))


if __name__ == "__main__":
    unittest.main(verbosity=2)
