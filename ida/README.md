# IDA Pro loader

## Install

Copy the loader into `$IDAUSR/loaders/` rather than `$IDADIR/loaders/`. The
user directory survives IDA upgrades and needs no administrator rights.

| OS | Path |
|----|------|
| macOS and Linux | `~/.idapro/loaders/` |
| Windows | `%APPDATA%\Hex-Rays\IDA Pro\loaders\` |

```bash
mkdir -p ~/.idapro/loaders && cp s7_1200_loader.py ~/.idapro/loaders/
```

The loader calls into the `s71200` package and does no parsing of its own, so
that package has to be importable by the interpreter IDAPython is built
against. That interpreter is not inside the IDA directory. Ask IDA which one it
is by running this in its Python console:

```python
import sys; print(sys.prefix)
```

Then install into it:

```bash
"<that prefix>/bin/python3" -m pip install /path/to/this/repository
```

Once installed, open a `.upd` file or an already unpacked `.bin`. The loader
recognises both. It extracts the image, maps it at the load base its header
implies, selects big-endian ARM, labels the eight exception vectors, sets the
entry point reached through the reset vector, and applies the recovered class
symbols.

The loader claims files with `ACCEPT_FIRST`. Without it, IDA's SNES loader wins
the format vote on V4.6 images, which match a SNES ROM on content alone.

## Load parameters

```
processor : ARM, big-endian
base      : 0x37FC0        virtual_address = file_offset + 0x37FC0
vectors   : VA 0x38000     file 0x40
entry     : VA 0x40040     file 0x8080
```

Those are the V3.0 and later values. V2.x images declare their own load base in
the image header and are mapped at `0x20000000`.

`s71200 identify <image.bin>` prints these for any unpacked image.

## ARM, never Thumb

The loader turns off IDA's automatic ARM/Thumb switching with
`ARM_NO_ARM_THUMB_SWITCH`. This firmware is ARM throughout, and left on, the
heuristic flips about 3 MB of a V4.5.2 image to Thumb, the entry point
included. Everything it flips then disassembles two bytes at a time as
nonsense. On a V4.5.2 image the setting is the difference between 9,780 Thumb
ranges and none.

The loader also sets `start_cs` alongside `start_ip`. IDA recomputes `start_ea`
from the pair after a loader returns, so setting `start_ea` alone is discarded
and an unset `start_cs` moves the entry point by `-0x10`.

## No processor module is needed

The S7-1200 is ordinary 32-bit big-endian ARM. IDA ships that already as the
`ARM` processor with big-endian byte order selected.

This is worth stating because the `ghidra-adonis-processor` project exists and
does not apply here. That project modifies x86 SLEIGH files, because x86 ADONIS
uses 32-bit pointers in long mode, which stock Ghidra handles poorly. That is
the S7-1500 line. The S7-1200 has no equivalent quirk. Only its container
format is unusual, and the `s71200` package handles that.

IDA can define custom processors through `processor_t` subclasses in IDAPython
or C++ through the SDK, and custom loaders through `loader_t` with
`accept_file` and `load_file`. Neither is needed for this target.

## Symbols

The loader names each RTTI record `rtti_<ClassName>` and marks the record's
code pointers as offsets. Each slot then renders as a reference to its target,
for example `DCD sub_CD15A8`, and carries a cross-reference, so the code is
reachable from the class and the class from the code. On a V4.5.2 image that is
7,107 names and 12,443 linked pointers.

Those code pointers belong to the class, but their exact role, such as
constructor, destructor or virtual slot, has not been established, so the
loader does not invent function names for them. See
[../docs/FORMAT.md](../docs/FORMAT.md) for the record layout.

The marking goes on the record slot, not on the target. Anything written to
the target address at load time, a comment or a manual cross-reference, is
discarded, because the target is still undefined bytes until auto-analysis
reaches it.

## Headless and batch mode

```bash
idat -A -S"ida/s7_headless.py out.json" -o /tmp/fw firmware.upd
```

`-A` runs non-interactively, `-S` runs the script after loading, and `-o` names
the database. Use `idat`, the text mode binary, not `ida`. IDA 9 writes `.i64`
whatever extension you give `-o`.

The script waits for auto-analysis with `ida_auto.auto_wait()` and exports
every function plus the recovered classes as JSON, so two firmware versions can
be compared without opening the GUI. It calls `ida_pro.qexit()` in a `finally`
block. Without that call `idat` does not terminate.

## The decompiler does not apply here

Hex-Rays decompiles 64-bit ARM, not 32-bit. Every function in these images
fails with `MERR_ONLY64`, and so does a four instruction ARM32 function in a
throwaway database, in either byte order. This is a property of the decompiler,
not of the loader or of this firmware. Disassembly, naming and cross-references
all work normally.

## Testing without IDA

```bash
python3 test_loader.py /path/to/firmware.upd
```

This stubs the `ida_*` modules and runs the real `accept_file` and `load_file`
functions, so the package integration and the values handed to IDA are checked
here. It cannot check IDA's own behaviour. Run the loader inside IDA once for
that.

## API notes

Written against the IDA 9 API. `idc.set_inf_attr` is deprecated and
`get_inf_structure` was removed in 9.0, so this loader uses
`ida_ida.inf_set_be()`, `ida_ida.inf_set_start_cs()`,
`ida_ida.inf_set_start_ip()` and `ida_ida.inf_set_start_ea()`, and the granular
`ida_*` modules rather than the older monolithic `idaapi`.

A Python loader was chosen over an SDK based C++ one because it needs no
compilation and no rebuild for each IDA release.

## Manual import, without the loader

```bash
s71200 unpack "6ES7 211-1HE40-0XB0 V04.05.02.upd" -o fw.bin
```

In IDA, open `fw.bin` as a Binary file and choose the `ARM` processor. In the
Loading Segment dialog set both ROM start address and loading address to
`0x37FC0`. Set big-endian byte order. In Options, Processor specific, tick
"No automatic ARM-THUMB switch", or the analysis will mis-decode several
megabytes. Then run Analysis and Reanalyze, jump to `0x40040` and press `C` to
begin disassembly there.
