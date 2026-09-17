# s7fw

Container parser, LZP unpacker and C++ symbol recovery for Siemens SIMATIC
S7-1200 firmware, with an IDA Pro loader.

Pure Python 3, no required dependencies, no build step.

```
$ s7fw identify V04.05.02_small.bin
architecture: ARM 32-bit big-endian, base 0x37fc0
confidence  : high
evidence    : vector table + capstone (3403 insns, 66% coverage, 57x next candidate)
vector table: file 0x40 -> VA 0x00038000
entry point : VA 0x00040040 (file 0x8080)
ghidra      : language ARM:BE:32:v7, base 0x37fc0
ida         : ARM processor, big-endian, ROM base 0x37fc0
OMS+        : 12.35.8 [OMSP_12.00.01.08_35.08.00.01]
```

## Install

```bash
pip install .                # provides the `s7fw` command
pip install ".[disasm]"      # + capstone, for architecture scoring
```

Or run in place without installing: `./s7fw-cli <command>`

## CLI

| command | purpose |
|---|---|
| `s7fw info <file\|dir>...` | container layout, TOC, structural integrity |
| `s7fw unpack <f.upd> -o out.bin` | decompress one container |
| `s7fw batch <tree> <outdir>` | dedupe by payload hash, unpack in parallel |
| `s7fw identify <image.bin>` | architecture, load base, entry point, OMS+ build |
| `s7fw symbols <image.bin>` | recover ~7,100 C++ class symbols |

```bash
s7fw symbols fw.bin --filter 'OMS::|ACE_6_5_0::'
s7fw symbols fw.bin --json > symbols.json
```

## Library

```python
from s7fw import load, identify_arch, find_oms_version, extract_symbols

fw = load("6ES7 211-1HE40-0XB0 V04.05.02.upd")
print(fw.version, fw.layout.value, fw.complete)   # V04.05.02 modern True

image, stats, headers = fw.unpack(strict=True)
print(identify_arch(image).ghidra_language)       # ARM:BE:32:v7
print(find_oms_version(image))                    # 12.35.8
print(len(list(extract_symbols(image))))          # 7097
```

## IDA Pro

Copy `ida/s7_1200_loader.py` into `$IDAUSR/loaders/` (`~/.idapro/loaders/`, or
`%APPDATA%\Hex-Rays\IDA Pro\loaders\`) and make `s7fw` importable by IDA's
Python. Opening a `.upd` **or** an unpacked `.bin` then configures everything:
big-endian ARM, load base `0x37FC0`, the eight exception vectors, the entry
point, and ~7,100 class symbols.

Headless:

```bash
idat -A -S"ida/s7_headless.py out.json" -o /tmp/fw.idb firmware.upd
```

No processor module is needed — the S7-1200 is ordinary big-endian ARM, which
IDA ships. See [`ida/README.md`](ida/README.md).

## Layout

```
s7fw/
  __init__.py      public API
  errors.py        exception hierarchy rooted at S7FirmwareError
  container.py     Firmware, Section, Layout, FirmwareVersion; auto-detects
                   the legacy (V2.x) and modern (V3.0-V4.7) generations
  lzp.py           LzpDecoder, Chunk, iter_chunks
  fingerprint.py   architecture identification, OMS+ build version
  symbols.py       C++ class symbol recovery
  cli.py           argparse front end
ida/               IDA loader, headless script, IDA-free loader test
tests/             26 tests
docs/FORMAT.md     format specification
```

## Tested

109 `.upd` images, 19 CPU MLFBs, every S7-1200 release from V2.2.0 to V4.7.0.

| | result |
|---|---|
| container parsing | 109/109, both TOC generations |
| decompression | V3.0.2 - V4.7.0, strict mode |
| V2.2.0 | container parses; payload is not LZP-chunked, so unpacking is unsupported and fails loudly |
| symbols | 7,097 per release (7,107 large class), consistent across versions |
| tests | 26/26 — `S7FW_CORPUS=/path/to/firmware python3 tests/test_s7fw.py` |
| reproducibility | byte-identical output across every refactor |

Not supported: S7-1500, ET200SP, Drive Controller, TIM 1531 — different product
lines, formats unknown.

The per-section checksum algorithm is unidentified and `FW_SIG` is not verified,
so integrity checking is **structural only**. This is not an authenticity check.

## Credit

The LZP algorithm was reverse engineered black-box from a compressed firmware
image by **Jean-Baptiste Bédrune** ([@jibeee](https://github.com/jibeee)) and
published as [`s7unpack`](https://github.com/jibeee/s7unpack) under Apache-2.0,
presented at SSTIC 2015 and HITB Amsterdam 2015. This package is an independent
Python 3 reimplementation of his algorithm — the reverse engineering is his.

It corrects three memory-safety defects in the original C (`lzp.c:57` heap
under-read, `lzp.c:64` input over-read, `lzp.c:85` wild read on an unpopulated
hash slot), adds the legacy V2 container, strict-mode corruption detection,
symbol recovery and the IDA loader. Upstream also does not compile on macOS/BSD
(`lzp.c` includes `<malloc.h>`).

Apache-2.0. Not affiliated with Siemens AG. No firmware is distributed here.
