# IDA Pro support for S7-1200 firmware

## Install

Copy the loader into **`$IDAUSR/loaders/`**, not `$IDADIR/loaders/` — the user
directory survives IDA upgrades and needs no admin rights:

| OS | path |
|---|---|
| macOS / Linux | `~/.idapro/loaders/` |
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\loaders\` |

```bash
mkdir -p ~/.idapro/loaders && cp s7_1200_loader.py ~/.idapro/loaders/
"$IDADIR/python3" -m pip install /opt/SIEMENS_EXPL/s7fw
```

Then open a `.upd` **or** an already-unpacked `.bin` — the loader recognises
both. It decompresses when needed, maps at `0x37FC0`, selects big-endian ARM,
labels the eight exception vectors, sets the entry point reached through the
reset vector, and applies ~7,100 class symbols.

### Testing it without IDA

```bash
python3 test_loader.py "path/to/firmware.upd"
```

Stubs the `ida_*` modules and runs the real `accept_file` / `load_file`, so the
s7fw integration and the values handed to IDA are verified here. It cannot
verify IDA's own API semantics — run it once inside IDA for that.

### Notes on the API

Written against the IDA 9 API. `idc.set_inf_attr` is deprecated and
`get_inf_structure` was removed in 9.0, so this uses `ida_ida.inf_set_be()` and
`ida_ida.inf_set_start_ea()`, and the granular `ida_*` modules rather than the
monolithic `idaapi`. A Python loader is preferred over an SDK/C++ one (as in
`ida_gel`) because it needs no compilation and no rebuild per IDA release.

## You do not need a processor module

The S7-1200 is **ordinary 32-bit big-endian ARM**. IDA ships this: the `ARM`
processor with big-endian byte order. Nothing to write.

This is worth stating because `ghidra-adonis-processor` exists and is *not*
applicable here. That project modifies **x86** SLEIGH because x86 ADONIS uses an
unusual "x32-ish" ABI -- 32-bit pointers in long mode -- which stock Ghidra
mishandles. That is the **S7-1500** line. The S7-1200 has no such quirk; only
its *container* is unusual, and `s7fw` handles that.

For the record, IDA can define processors -- `processor_t` subclasses in
IDAPython, or C++ via the SDK -- and loaders via `loader_t` / `accept_file` /
`load_file`. Both capabilities exist, comparable to Ghidra's SLEIGH and
`Loader`. Neither is needed for this target.

## Headless / batch

```bash
idat -A -S"ida/s7_headless.py out.json" -o /tmp/fw.idb firmware.upd
```

`-A` runs non-interactively, `-S` runs the script after load, `-o` names the
database. Use `idat` (text mode), not `ida`. The script waits for auto-analysis
(`ida_auto.auto_wait()`) and exports every function plus the recovered classes
as JSON, so two firmware versions can be compared without opening the GUI.
`ida_pro.qexit()` is called in a `finally` block — without it `idat` hangs.

## Symbols

The loader applies ~7,100 recovered C++ class names, naming each RTTI record
`rtti_<ClassName>` and attaching the class name as a repeatable comment on the
code addresses the record points at.

Those code pointers are *associated* with the class but their exact role
(constructor, destructor, virtual slot) is not established, so the loader
comments them rather than inventing function names. See `docs/FORMAT.md`.

## On FLIRT

FLIRT is the wrong tool here, for a structural reason: signatures are generated
from **object code you already have** -- `pelf`/`plb`/`pcf` consume `.o`, `.a`,
`.lib` files and `sigmake` turns them into `.sig`. Siemens does not ship an
ADONIS SDK or its static libraries, so there is nothing to generate signatures
*from*. FLIRT identifies *known library* functions; it cannot name application
code it has never seen.

Three approaches that do work, best first:

**1. The embedded class registry — done, and it ships.** ~7,100 C++ class names
with their record addresses, recovered by `s7fw symbols` and applied
automatically by the loader. Ground truth from the vendor's own build, strictly
better than pattern matching. See `docs/FORMAT.md` for the record layout.

**2. Cross-version propagation.** Once one image is annotated, port names to
other releases with Diaphora or BinDiff. This is what FLIRT would have given
you, obtained a way that actually works on this target. Note that consecutive
releases differ in ~77% of bytes at fixed offsets (each is a full rebuild), so
matching must be structural, never offset-based.

**3. Standard library identification.** If any statically linked libc/newlib or
compiler runtime is present, FLIRT signatures built from a *matching*
toolchain's `.a` could name those. Speculative -- the toolchain and version are
unknown -- and it would only cover runtime helpers, not Siemens code.

## Load parameters

```
processor : ARM, big-endian
base      : 0x37FC0        (virtual_address = file_offset + 0x37FC0)
vectors   : VA 0x38000     (file 0x40)
entry     : VA 0x40040     (file 0x8080)
```

`s7fw identify <image.bin>` prints these for any unpacked image.

## Manual route, without the loader

```bash
s7fw unpack "6ES7 211-1HE40-0XB0 V04.05.02.upd" -o fw.bin
```

Then in IDA: open `fw.bin` as **Binary file**, processor **ARM**, and in
*Loading Segment* set ROM start `0x37FC0`, loading address `0x37FC0`. Set
big-endian byte order (Options > General > ... or `Edit > Segments`), then
`Analysis > Reanalyze`. Jump to `0x40040` and press `C` to start disassembly.
