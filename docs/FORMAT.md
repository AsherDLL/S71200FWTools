# SIMATIC S7-1200 firmware format (`.upd`)

Derived from static analysis of 109 firmware images covering 23 CPU order
numbers and ten releases, V2.2.0, V3.0.2, V4.2.0, V4.3.1, V4.4.0, V4.5.0,
V4.5.1, V4.5.2, V4.6.0 and V4.7.0, together with the container and LZP logic in
Jean-Baptiste Bédrune's `s7unpack`.

All multi-byte fields in the container are little-endian, except in the legacy
V2 generation described below. Pointer tables inside the decompressed image are
big-endian.

## 1. SD card update layout

```
<root>/
  S7_JOB.S7S                     10 bytes, ASCII "FWUPDATE\r\n", the job trigger
  FWUPDATE.S7S/
    6ES7 <mlfb> V<ver>.upd       the firmware container
```

## 2. Container, two generations

Two table of contents layouts exist. The parser detects which one applies by
testing which accounts for the file size exactly.

| Generation | Releases | TOC fields | In-stream tags | Section names |
|------------|----------|------------|----------------|---------------|
| legacy | V2.x | big-endian | none | `cpu_it` `cpu_fw` `cpu_bu` `cpu_md` |
| modern | V3.0 to V4.7 | little-endian | 6 bytes, repeated | `BG_ABL` `A00000` `B00000` `FW_SIG` |

Legacy completeness is `0x64 + sum(entry.size) == filesize`, verified as
`100 + 64 + 8503564 + 787654 + 2 = 9291384`.

Modern completeness is `0x64 + sum(6 + entry.size) == filesize`.

The legacy `cpu_fw` payload is not LZP chunked the way the modern `A00000`
section is. It is Intel HEX text, described in section 5.

## 3. Modern container

```
offset  size  field
0x00    4     magic and format version, always 0x00000004
0x04    8     reserved, zero
0x0C    4     version: 'V', major, minor, patch. 56 04 05 02 means V04.05.02
0x10    20    MLFB, space padded ASCII, for example "6ES7 211-1HE40-0XB0"
0x24    8     reserved
0x2C    56    table of contents, 4 entries
```

### Table of contents entry, 14 bytes, packed

```c
struct fw_entry {
    uint32_t size;      // payload size, excluding the 6-byte in-stream tag
    uint32_t crc;       // proprietary checksum, not a standard CRC-32
    char     name[6];   // "BG_ABL", "A00000", "B00000", "FW_SIG"
};
```

The size field comes first. Parsing this as name first appears to work, because
the layout is self similar, but it mislabels every section by one slot.

### Section payloads

Payloads start at `0x2C + 4*14 = 0x64` and are contiguous. Each is prefixed by
its own 6 byte name tag repeating the name from the table of contents.

```
0x64            "BG_ABL" + 32 bytes            device and build metadata
0x8A            "A00000" + <size> bytes        LZP compressed firmware image
<...>           "B00000" + 2 bytes             end marker, 0xFFFF
<...>           "FW_SIG" + 72 bytes            signature
EOF
```

For a whole, untruncated file the following invariant holds.

```
0x64 + sum(6 + entry.size for entry in TOC) == filesize
```

This was verified to the byte on every image examined.

### Checksums and signature

The 4 byte `crc` in each entry is not CRC-32, CRC-32/MPEG-2, BZIP2, POSIX,
JAMCRC or CRC-32C. All were tested and none match. Every observed value has
0xFF as its high byte. The algorithm has not been identified and the field is
treated as opaque.

`FW_SIG` is 72 bytes and is not validated. Structural integrity checking is
therefore not a cryptographic authenticity proof.

## 4. LZP compression, section `A00000`

The algorithm was reverse engineered from a compressed image by Jean-Baptiste
Bédrune and published as `s7unpack` under Apache 2.0. It is an order 4 hashed
context predictor, not LZ77. A match token carries only a length. The source
position is predicted from a hash of the preceding 4 bytes, so no offset is
transmitted.

### Chunk framing

The section is a sequence of independently decodable chunks.

```
[uint32 compressed_size][uint16 hdr][lzp stream ...]
       ^ counts hdr and stream, excludes itself
```

Each chunk decompresses to exactly `0x10000` bytes except the last. Framing
consumes the section exactly, with no trailing bytes.

`hdr` takes only four values across all images, as raw bytes `00 00`, `00 01`,
`00 02` and `00 03`. It is data dependent rather than a sequence counter. Its
purpose has not been determined and it is not required for decompression.
`s7unpack` skips it.

### Stream format

```
seed:   4 literal bytes, copied verbatim, seeding the context
then repeating:
  1 mask byte, MSB first, describing the next 8 symbols
  for each of the 8 bits:
      bit == 0 -> next input byte is a literal
      bit == 1 -> next input byte is a match LENGTH, and the source position is
                  hash_table[hash(last 4 output bytes)]
```

The context hash, where `c` is the big-endian value of the last 4 output bytes.

```
h = ((c >> 15) ^ c) & 0xFFFF
```

Both paths update `hash_table[h] = current_output_position` before writing.
Match copies proceed one byte at a time and may overlap the write cursor.

Table persistence across chunks does not matter. An encoder that resets per
chunk and a decoder that does not still agree, because any context occurring in
the current chunk overwrites the stale entry before it can be referenced.
Measured `forward_refs = 0` on all 8 unique payloads, which confirms that
chunks are self contained.

## 5. Legacy payload, Intel HEX

V2.x containers store the image as Intel HEX rather than as a compressed
stream, so extraction is a decode rather than a decompression. Records are CRLF
separated and use three of the standard types.

| Type | Meaning | Count in `6ES7 212-1BD30-0XB0 V02.02.00` |
|------|---------|------------------------------------------|
| `0x00` | data | 110,424 |
| `0x04` | extended linear address, the upper 16 address bits | 55 |
| `0x01` | end of file | 1 |

Every record checksum validates. The 8,503,564 bytes of hex text decode to
3,735,536 bytes of image starting with the `5D 1B 41 53` image magic. Gaps
between records are filled with `0xFF`.

The record addresses run `0x70000` to `0x3FFFF0` and describe the flash
position, not the load address. The load address comes from the image header.

## 6. Extracted image

| Property | Value |
|----------|-------|
| size | 22,839,431 bytes on V4.2 to V4.6, identical across CPU classes, a fixed flash region. 24,936,583 on V4.7.0, 10,256,453 on V3.0.2 and 3,735,536 on V2.2.0 |
| chunks | 349 in a V4.5.2 image, being 348 full chunks and one 32,903 byte tail |
| entropy | 5.82 bits per byte in a V4.5.2 image |
| architecture | ARM 32-bit, ARMv7, big-endian, confirmed V2.2.0 through V4.7.0 |
| load base | `0x37FC0` on V3.0 and later, so `virtual_address = file_offset + 0x37FC0` |
| vector base | file `0x40`, virtual address `0x38000` |
| reset handler | file `0x8080`, virtual address `0x40040` |
| endianness | big-endian for both code and pointer tables |
| RTOS | ADONIS, identified by the string `"ADONIS boot successful, starting first user thread"` |

### Image header

The image opens with `5D 1B 41 53` followed by fields whose layout differs
between the two generations. The version marker, the byte `0x56` (`'V'`)
followed by major, minor and patch, is what tells them apart.

| Offset | V2.x | V3.0 and later |
|--------|------|----------------|
| `+0x04` | entry point virtual address | entry point virtual address |
| `+0x10` | load base, `0x20000000` | `0x00040000` |
| `+0x20` | flash base, `0x10070000` | version marker |
| `+0x38` | version marker | zero |

So a V2.2.0 image is mapped at `0x20000000` with its entry point at
`0x20001D40`, which is file offset `0x1D40` and disassembles as
`PUSH {R4-R7,R10,R11}`. Later images are mapped at `0x37FC0`.

### Architecture determination

File offset `0x40` holds an eight entry ARM exception vector table, where
`E59FF0xx` decodes as `LDR PC,[PC,#imm]`, covering reset, undefined
instruction, SWI, prefetch abort, data abort, reserved, IRQ and FIQ. Decoded
little-endian the same bytes are incoherent.

Following the reset vector confirms the load base. `[0x128]` contains
`0x00040040`, and `0x40040 - 0x37FC0 = 0x8080`, where the disassembly is an
ARMv7 reset sequence performing a CP15 instruction cache invalidate
(`mcr p15,0,r0,c7,c5,0`), `dsb sy` and `isb sy` barriers, then a SCTLR read,
modify and write that sets bit 12 for the instruction cache and bit 2 for the
data cache.

Byte order matters when measuring code density. The same image scanned both
ways gives very different counts.

| Signature | Little-endian order | Big-endian order |
|-----------|---------------------|------------------|
| `bx lr` | 0 | 28,048 |
| `push {..,lr}` | 60 | 50,031 |
| `pop {..,pc}` | not counted | 55,738 |
| `BL`, 4 byte aligned | not counted | 239,615 |

About 13.5 MB of the 22.8 MB image is code, spanning file offsets `0x0` to
`0xF80000`. The rest is data and resources.

Load in Ghidra as `ARM:BE:32:v7` at base `0x37FC0`, or in IDA as the `ARM`
processor with big-endian byte order and the same base.

## 7. C++ class symbol registry

The image carries a custom RTTI style registry, one record per C++ class,
between 2,608 and 9,956 of them depending on the release. Records are packed
back to back, are variable length, and store the name inline. Offsets below are
relative to the tag word.

```
-20  code pointer      ARM prologue in about 50% of records
-12  code pointer      about 57%
 -4  code pointer      about 68%
 +0  tag               identical across every record in one image
 +4  pointer to name   points at +16 in 94% of records
 +8  sequential type id
+12  pointer to a base class record, or 0, non-zero in about 70%
+16  NUL terminated name, inline
```

All values are big-endian. The tag is a virtual address, so it differs per
build. It is `0x00fcd6a0` in V4.5.1 and `0x00fcf3e0` in V4.5.2, and must be
discovered per image. `find_record_tag` does this without building a pointer
index, because a record whose name is inline satisfies
`name_ptr == record + 16`, and the tag is then the most common word at those
offsets.

This is not the Itanium C++ ABI. Only one tag value exists per image rather
than the three `type_info` kinds, and the surrounding words do not match the
Itanium vtable shape. Testing found 6 of 9,542 cross references fitting, which
is noise.

Recovered counts, one image per release:

| Release | Symbols |
|---------|---------|
| V2.2.0 | 0, the generation carries no records this recognises |
| V3.0.2 | 2,608 |
| V4.2.0 | 8,927 |
| V4.3.1 | 9,219 |
| V4.4.0 | 9,956 |
| V4.5.0 to V4.6.0 | 7,097 small CPU class, 7,107 large |
| V4.7.0 | 7,192 |

The count is stable within a release across CPU order numbers and differs
between releases, so it is not a property of the parser. Why it falls by about
a quarter between V4.4.0 and V4.5.0 has not been investigated.

Namespaces include `ACE_6_5_0::`, which is the ADAPTIVE Communication
Environment C++ framework version 6.5.0, along with `OMS::`, `OPCUA::`,
`xUMAC::` and `xS7PWEB::`. 886 classes are OMS related in V4.5.2.

The names and record addresses are established facts. Every record resolves.
The code pointers at -4, -12 and -20 do point at real ARM prologues, so they
are associated with the class. Constructor, destructor and virtual slots are
the obvious candidates, but which slot is which has not been established. The
tooling therefore reports them as associations, and the IDA loader marks them
as offsets so they cross-reference. It never invents function names from them.

## 8. Version fingerprinting

Every image embeds the version of its OMS+ protocol stack, which identifies the
build independently of the firmware version in the container header.

| Firmware | OMS+ long form | Short form |
|----------|----------------|------------|
| V4.2.0 | `OMSP.REL.8089.16`, older scheme | none |
| V4.3.1 | `OMSP.REL.8089.26`, older scheme | none |
| V4.4.0 | `OMSP_11.00.00.06_59.06.00.01` | 11.59.6 |
| V4.5.0 | `OMSP_12.00.00.02_35.02.00.01` | 12.35.2 |
| V4.5.1 | `OMSP_12.00.00.02_35.02.00.01` | 12.35.2 |
| V4.5.2 | `OMSP_12.00.01.08_35.08.00.01` | 12.35.8 |
| V4.6.0 | `OMSP_12.00.02.11_35.11.00.01` | 12.35.11 |
| V4.7.0 | `OMSP_14.00.00.08_66.08.00.02` | 14.66.8 |

V4.5.0 and V4.5.1 ship the same OMS+ build, so the stack version and the
firmware version do not move in step.

The naming scheme itself changed twice, using `OMSP.REL.<n>` through V4.3 and
`OMSP_<a>_<b>` from V4.4 onwards. A version scanner must handle both.

In a compressed `.upd` these strings are fragmented by LZP tokens and cannot be
found with a plain substring search. After decompression they are contiguous,
which makes that contiguity a useful correctness check on the unpacker.

## 9. Cross release drift

Consecutive releases differ in about 77% of bytes at fixed offsets, because
each release is a full rebuild rather than a patch. Byte offset diffing is
therefore not useful, and diffing must be anchored on symbols or functions.

Structure is stable despite the drift. The OMS+ version string sits within
about 3 KB of the same offset across releases, and the symbol registry within
about 8 KB.
