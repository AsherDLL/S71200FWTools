# SIMATIC S7-1200 firmware format (`.upd`)

Derived from static analysis of 56 firmware images (V4.5.0 / V4.5.1 / V4.5.2 / V4.6.0,
19 CPU MLFBs) plus the container/LZP logic in Jean-Baptiste Bédrune's `s7unpack`.

All multi-byte fields in the **container** are little-endian.
Pointer tables inside the **decompressed image** are big-endian.

---

## 1. SD-card update layout

```
<root>/
  S7_JOB.S7S                     10 bytes, ASCII "FWUPDATE\r\n"  -- job trigger
  FWUPDATE.S7S/
    6ES7 <mlfb> V<ver>.upd       the firmware container
```

## 2. Container — two generations

Two TOC layouts exist. `s7fw.py` auto-detects by testing which one accounts for
the file size exactly.

| generation | releases | TOC fields | in-stream tags | section names |
|---|---|---|---|---|
| **legacy** | V2.x | **big-endian** | **none** | `cpu_it` `cpu_fw` `cpu_bu` `cpu_md` |
| **modern** | V3.0 – V4.7 | little-endian | 6-byte, repeated | `BG_ABL` `A00000` `B00000` `FW_SIG` |

Legacy completeness: `0x64 + sum(entry.size) == filesize`
(verified: `100 + 64 + 8503564 + 787654 + 2 = 9291384`).
Modern completeness: `0x64 + sum(6 + entry.size) == filesize`.

The legacy `cpu_fw` payload is **not** LZP-chunked the way modern `A00000` is;
V2 decompression is unsupported and fails loudly rather than returning nothing.

## 2b. Modern container

```
offset  size  field
0x00    4     magic / format version .... always 0x00000004
0x04    8     reserved (zero)
0x0C    4     version: 'V', major, minor, patch   e.g. 56 04 05 02 -> V04.05.02
0x10    20    MLFB, space-padded ASCII  e.g. "6ES7 211-1HE40-0XB0"
0x24    8     reserved
0x2C    56    table of contents: 4 x entry
```

### TOC entry (14 bytes, packed)

```c
struct fw_entry {
    uint32_t size;      // payload size, excluding the 6-byte in-stream tag
    uint32_t crc;       // proprietary checksum -- NOT a standard CRC-32 (see notes)
    char     name[6];   // "BG_ABL" / "A00000" / "B00000" / "FW_SIG"
};
```

> The size field comes **first**. Parsing this as name-first appears to work
> (the layout is self-similar) but mislabels every section by one slot.

### Section payloads

Payloads start at `0x2C + 4*14 = 0x64`, contiguous, each prefixed by its own
6-byte name tag repeating the TOC name:

```
0x64            "BG_ABL" + 32 bytes            device/build metadata
0x8A            "A00000" + <size> bytes        LZP-compressed firmware image
<...>           "B00000" + 2 bytes             end marker (0xFFFF)
<...>           "FW_SIG" + 72 bytes            signature
EOF
```

**Completeness invariant** — for a whole, untruncated file:

```
0x64 + sum(6 + entry.size for entry in TOC) == filesize
```

This holds to the byte on all 56 images examined.

### Checksums and signature

The 4-byte `crc` per entry is **not** CRC-32, CRC-32/MPEG-2, BZIP2, POSIX, JAMCRC,
or CRC-32C (all tested, none match). Every observed value has 0xFF as its high byte.
Algorithm unidentified; treated as opaque. `FW_SIG` is 72 bytes and was not
validated — structural integrity here is *not* a cryptographic authenticity proof.

---

## 3. LZP compression (`A00000`)

Algorithm reverse engineered black-box by **Jean-Baptiste Bédrune (@jibeee)**,
`s7unpack`, Apache-2.0. Order-4 hashed-context predictor (LZP), not LZ77:
a match token carries only a *length*, the *position* is predicted from a hash of
the preceding 4 bytes, so no offset is transmitted.

### Chunk framing

The section is a sequence of independently-decodable chunks:

```
[uint32 compressed_size][uint16 hdr][lzp stream ...]
       ^ counts hdr + stream, excludes itself
```

Each chunk decompresses to exactly `0x10000` bytes, except the last.
Framing consumes the section exactly, with zero trailing bytes.

`hdr` takes only four values across all images — as raw bytes `00 00`, `00 01`,
`00 02`, `00 03`. It is data-dependent, not a sequence counter. Purpose
undetermined; it is not required for decompression. `s7unpack` skips it.

### Stream format

```
seed:   4 literal bytes, copied verbatim, seeding the context
then repeating:
  1 mask byte, MSB first, describing the next 8 symbols
  for each of the 8 bits:
      bit == 0 -> next input byte is a literal
      bit == 1 -> next input byte is a match LENGTH; the source position is
                  hash_table[hash(last 4 output bytes)]
```

Context hash (`c` = big-endian value of the last 4 output bytes):

```
h = ((c >> 15) ^ c) & 0xFFFF
```

Both paths update `hash_table[h] = current_output_position` **before** writing.
Match copies are byte-at-a-time and may overlap the write cursor.

Table persistence across chunks is irrelevant: an encoder that resets per chunk
and a decoder that does not still agree, because any context occurring in the
current chunk overwrites the stale entry before it can be referenced. Measured
`forward_refs = 0` on all 8 unique payloads, confirming chunks are self-contained.

---

## 4. Decompressed image

| property | value |
|---|---|
| size | 22,839,431 bytes — identical across **all** versions and CPU classes (fixed flash region) |
| chunks | 349 (348 full + one 32,903-byte tail) |
| entropy | 5.82 bits/byte |
| **architecture** | **ARM 32-bit (ARMv7), BIG-ENDIAN** — confirmed V3.0.2 through V4.7.0 |
| load base | **0x37FC0** — `virtual_address = file_offset + 0x37FC0` |
| vector base | file `0x40` -> VA **0x38000** |
| reset handler | file `0x8080` -> VA **0x40040** |
| endianness | big-endian throughout: code *and* pointer tables |
| RTOS | ADONIS (`"ADONIS boot successful, starting first user thread"`) |

Load base was recovered from the trace/symbol table: every `OPCUA::Common::OMSP_DA::*`
name string is referenced by a big-endian pointer equal to `file_offset + 0x37FC0`.
Confirmed 13/13 symbols, identical constant in V4.5.1 and V4.5.2.

ARM code is sparse relative to image size (bulk is data/resources). Densest
regions in V4.5.2: `0x652d26–0x69470a` (262 KB), `0x6965a–0x6e9de` (20 KB).

## 7. C++ class symbol registry

The image carries a custom RTTI-like registry — ~7,100 records, one per C++
class. Records are packed back to back, are variable length, and store the name
inline. Offsets are relative to the tag word:

```
-20  code pointer      ARM prologue in ~50% of records
-12  code pointer      ~57%
 -4  code pointer      ~68%
 +0  tag               identical across every record in one image
 +4  pointer to name   points at +16 in 94% of records
 +8  sequential type id
+12  pointer to a base-class record, or 0  (~70% non-zero)
+16  NUL-terminated name, inline
```

All values are **big-endian**. The tag is a virtual address, so it differs per
build (`0x00fcd6a0` in V4.5.1, `0x00fcf3e0` in V4.5.2) and must be discovered
per image. `s7fw.symbols.find_record_tag` does that without a pointer index: a
record whose name is inline satisfies `name_ptr == record + 16`, and the tag is
the most common word at those offsets.

This is **not** the Itanium C++ ABI. Only one tag value exists per image rather
than the three `type_info` kinds, and the surrounding words do not match the
Itanium vtable shape (tested: 6 of 9,542 cross-references fit, i.e. noise).

Recovered per release (all versions, both CPU classes): **7,097 symbols**
(7,107 for the large class). Namespaces include `ACE_6_5_0::` — the ADAPTIVE
Communication Environment C++ framework, version 6.5.0 — plus `OMS::`,
`OPCUA::`, `xUMAC::`, `xS7PWEB::`. 886 classes are OMS-related.

**What is established and what is not.** The names and record addresses are
facts: every record resolves, and the same 7,097 appear in every release. The
code pointers at -4/-12/-20 do point at real ARM prologues, so they are
genuinely *associated* with the class — constructor, destructor and virtual
slots are the obvious candidates — but which slot is which has **not** been
established. `s7fw` therefore reports them as associations and the IDA loader
attaches them as comments; it never invents function names from them.

Recovered with `s7fw symbols`, and applied automatically by the IDA loader.

---

## 5. Version fingerprinting

Every image embeds the version of its OMS+ protocol stack, which identifies the
build independently of the firmware version in the container header:

| firmware | OMS+ long form | short |
|---|---|---|
| V4.2.0 | `OMSP.REL.8089.16` (older scheme) | - |
| V4.3.1 | `OMSP.REL.8089.26` (older scheme) | - |
| V4.4.0 | `OMSP_11.00.00.06_59.06.00.01` | 11.59.6 |
| V4.5.0 | `OMSP_12.00.00.02_35.02.00.01` | 12.35.2 |
| V4.5.1 | `OMSP_12.00.00.02_35.02.00.01` | 12.35.2 |
| V4.5.2 | `OMSP_12.00.01.08_35.08.00.01` | 12.35.8 |
| V4.6.0 | `OMSP_12.00.02.11_35.11.00.01` | 12.35.11 |
| V4.7.0 | `OMSP_14.00.00.08_66.08.00.02` | 14.66.8 |

Note that V4.5.0 and V4.5.1 ship the *same* OMS+ build, so the stack version and
the firmware version do not move in lockstep.

Note the OMS+ naming scheme itself changed twice: `OMSP.REL.<n>` through V4.3,
then `OMSP_<a>_<b>` from V4.4. A version scanner must handle both.

In a *compressed* `.upd` these strings are fragmented by LZP tokens and cannot be
found with a plain substring search; after decompression they are contiguous.
That contiguity is the strongest available correctness check on the unpacker.

---

## 6. Cross-release drift

Consecutive releases differ in ~77% of bytes at fixed offsets — each release is a
**full rebuild**, not a patch. Byte-offset diffing is therefore useless; diffing
must be symbol- or function-anchored.

Structure is stable despite the drift: the OMSP version string sits within ~3 KB
of the same offset across all four releases, and the symbol table within ~8 KB.
