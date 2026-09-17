# SIMATIC S7-1200 Firmware Unpacker and IDA Loader

Tools for working with Siemens SIMATIC S7-1200 PLC firmware.

The `.upd` files Siemens ships are a container holding a firmware image, LZP
compressed on V3.0 and later and Intel HEX encoded on V2.x. This project parses
that container, extracts the image, recovers the C++ class symbols from it,
7,107 of them in a V4.5.2 image, and optionally loads the result into IDA Pro
with the correct processor, byte order and load address already set.

The command line tools work on their own. IDA Pro is only needed for the
loader in `ida/`.

## What each part does

| Part | Needs IDA | Purpose |
|------|-----------|---------|
| `s71200` package and CLI | no | parse the container, extract the image, recover symbols |
| `ida/s7_1200_loader.py` | yes | open a firmware file directly in IDA Pro |
| `ida/s7_headless.py` | yes | run IDA in batch mode and export results as JSON |

## Install

```bash
pip install .
```

That provides the `s71200` command. To run without installing, use
`./s71200-cli` from the repository root.

Python 3.9 or later. There are no third party requirements.

## Command line

| Command | Purpose |
|---------|---------|
| `s71200 info <file or dir>...` | container layout, table of contents, structural integrity |
| `s71200 unpack <file.upd> -o out.bin` | extract the image from one container |
| `s71200 batch <tree> <outdir>` | deduplicate by payload hash, unpack in parallel |
| `s71200 identify <image.bin>` | architecture, load base, entry point, OMS+ build |
| `s71200 symbols <image.bin>` | recover C++ class symbols |

```
$ s71200 identify V04.05.02_small.bin
file        : V04.05.02_small.bin (22839431 bytes)
architecture: ARM 32-bit big-endian, base 0x37fc0
confidence  : high
vector table: file 0x40 -> VA 0x00038000
entry point : VA 0x00040040 (file 0x8080)
ghidra      : language ARM:BE:32:v7, base 0x37fc0
ida         : ARM processor, big-endian, ROM base 0x37fc0
OMS+        : 12.35.8 [OMSP_12.00.01.08_35.08.00.01]
```

```bash
s71200 symbols fw.bin --filter 'OMS::|ACE_6_5_0::'
s71200 symbols fw.bin --json > symbols.json
```

The `ghidra` and `ida` lines print settings for a manual import. There is no
Ghidra loader in this project. Only IDA Pro has one.

## Library

```python
from s71200 import load, identify_arch, find_oms_version, extract_symbols

fw = load("6ES7 211-1HE40-0XB0 V04.05.02.upd")
print(fw.version, fw.layout.value, fw.complete)   # V04.05.02 modern True

image, stats, headers = fw.unpack(strict=True)
print(identify_arch(image).ghidra_language)       # ARM:BE:32:v7
print(find_oms_version(image))                    # 12.35.8
print(len(list(extract_symbols(image))))          # 7097
```

## Repository layout

```
s71200/            Python package
  __init__.py      public API
  errors.py        exception hierarchy rooted at S7FirmwareError
  container.py     Firmware, Section, Layout, FirmwareVersion. Detects both
                   the legacy (V2.x) and modern (V3.0 to V4.7) container
                   generations
  lzp.py           LzpDecoder, Chunk, iter_chunks
  ihex.py          Intel HEX decoding, for legacy payloads
  fingerprint.py   architecture identification, OMS+ build version
  symbols.py       C++ class symbol recovery
  cli.py           command line front end
ida/               IDA Pro loader, headless script, and a test that runs
                   without IDA installed
tests/             33 tests
docs/FORMAT.md     container, compression and image format specification
```

## IDA Pro

Copy `ida/s7_1200_loader.py` into `$IDAUSR/loaders/`, which is
`~/.idapro/loaders/` on macOS and Linux or `%APPDATA%\Hex-Rays\IDA Pro\loaders\`
on Windows, then make the `s71200` package importable by the interpreter
IDAPython uses. [ida/README.md](ida/README.md) covers how to find it.

Opening a `.upd` file or an already unpacked `.bin` then sets up everything.
Big-endian ARM, the load base, the eight exception vectors, the entry point,
and the recovered class symbols. It also turns off IDA's automatic ARM/Thumb
switching, which otherwise mis-decodes about 3 MB of a V4.5.2 image.

No processor module is required. The S7-1200 is ordinary big-endian ARM, which
IDA ships as standard. See [ida/README.md](ida/README.md).

## Coverage

Tested against 109 `.upd` images covering 23 CPU order numbers and ten
releases: V2.2.0, V3.0.2, V4.2.0, V4.3.1, V4.4.0, V4.5.0, V4.5.1, V4.5.2,
V4.6.0 and V4.7.0.

| Area | Result |
|------|--------|
| container parsing | 109 of 109, both generations |
| extraction | V2.2.0 through V4.7.0 |
| symbols | 2,608 on V3.0.2 rising to 9,956 on V4.4.0, then 7,097 to 7,192 from V4.5.0 on. Stable within a release across CPU order numbers. V2.2.0 carries no records this recognises |
| IDA loading | V2.2.0, V3.0.2, V4.2.0, V4.3.1, V4.4.0, V4.5.2, V4.6.0, V4.7.0 and a pre-unpacked image, each verified in IDA 9.4 for processor, byte order, load base, entry point, vector labels and symbol count |
| tests | 33 of 33, run with `S71200_CORPUS=/path/to/firmware python3 tests/test_s71200.py` |
| reproducibility | output stays byte identical across refactors |

Other Siemens product lines are out of scope. That includes the S7-1500,
ET200SP, Drive Controller and TIM 1531.

The per section checksum algorithm has not been identified and the `FW_SIG`
block is not verified, so integrity checking here is structural only. It is not
an authenticity check.

## Credit

The LZP algorithm was reverse engineered from a compressed firmware image by
Jean-Baptiste Bédrune ([@jibeee](https://github.com/jibeee)) and published as
[s7unpack](https://github.com/jibeee/s7unpack) under Apache 2.0. It was
presented at SSTIC 2015 and HITB Amsterdam 2015. This project is an independent
Python reimplementation of that algorithm. The reverse engineering is his work.

This version corrects three memory safety defects in the original C code, a
heap under-read at `lzp.c:57`, an input over-read at `lzp.c:64`, and a wild read
on an unpopulated hash slot at `lzp.c:85`. It also adds support for the legacy
V2 container, including the Intel HEX payload encoding that generation uses,
strict mode corruption detection, symbol recovery and the IDA loader. The
original does not compile on macOS or BSD because `lzp.c` includes
`<malloc.h>`.

Licensed under Apache 2.0. Not affiliated with Siemens AG. No firmware is
distributed with this project.
