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
"$IDADIR/python3" -m pip install /path/to/this/repository
```

The second command makes the `s71200` package importable by the Python that
IDA uses. The loader calls into that package and does no parsing of its own.

Once installed, open a `.upd` file or an already unpacked `.bin`. The loader
recognises both. It decompresses when needed, maps the image at `0x37FC0`,
selects big-endian ARM, labels the eight exception vectors, sets the entry
point reached through the reset vector, and applies the recovered class
symbols.

## Load parameters

```
processor : ARM, big-endian
base      : 0x37FC0        virtual_address = file_offset + 0x37FC0
vectors   : VA 0x38000     file 0x40
entry     : VA 0x40040     file 0x8080
```

`s71200 identify <image.bin>` prints these for any unpacked image.

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

The loader applies the recovered C++ class names, naming each RTTI record
`rtti_<ClassName>` and attaching the class name as a repeatable comment on the
code addresses that the record points at.

Those code pointers are associated with the class, but their exact role, such
as constructor, destructor or virtual slot, has not been established. The
loader therefore comments them rather than inventing function names. See
[../docs/FORMAT.md](../docs/FORMAT.md) for the record layout.

## Headless and batch mode

```bash
idat -A -S"ida/s7_headless.py out.json" -o /tmp/fw.idb firmware.upd
```

`-A` runs non-interactively, `-S` runs the script after loading, and `-o` names
the database. Use `idat`, the text mode binary, not `ida`.

The script waits for auto-analysis with `ida_auto.auto_wait()` and exports
every function plus the recovered classes as JSON, so two firmware versions can
be compared without opening the GUI. It calls `ida_pro.qexit()` in a `finally`
block. Without that call `idat` does not terminate.

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
`ida_ida.inf_set_be()` and `ida_ida.inf_set_start_ea()`, and the granular
`ida_*` modules rather than the older monolithic `idaapi`.

A Python loader was chosen over an SDK based C++ one because it needs no
compilation and no rebuild for each IDA release.

## Manual import, without the loader

```bash
s71200 unpack "6ES7 211-1HE40-0XB0 V04.05.02.upd" -o fw.bin
```

In IDA, open `fw.bin` as a Binary file and choose the `ARM` processor. In the
Loading Segment dialog set both ROM start address and loading address to
`0x37FC0`. Set big-endian byte order, then run Analysis and Reanalyze. Jump to
`0x40040` and press `C` to begin disassembly there.
