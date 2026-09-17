"""IDA loader for Siemens SIMATIC S7-1200 .upd firmware.

Install: copy to $IDAUSR/loaders/ (survives IDA upgrades)
    macOS/Linux  ~/.idapro/loaders/
    Windows      %APPDATA%\\Hex-Rays\\IDA Pro\\loaders\\
Needs s71200 importable by IDA's Python:
    "$IDADIR/python3" -m pip install /path/to/this/repository

Open a .upd and it decompresses, maps at the load base as big-endian ARM,
labels the exception vectors and sets the entry point.

LZP algorithm by Jean-Baptiste Bedrune (@jibeee), s7unpack, Apache-2.0.
"""

import ida_bytes
import ida_entry
import ida_ida
import ida_idp
import ida_loader
import ida_name
import ida_segment

import s71200

VECTORS = ("reset", "undef", "swi", "pabort", "dabort", "reserved", "irq", "fiq")
UNPACKED_MAGIC = b"\x5d\x1bAS"  # header of an already-decompressed image


def _peek(li):
    li.seek(0)
    return li.read(0x64)  # header + TOC; no need to read 15 MB to recognise it


def accept_file(li, filename):
    head = _peek(li)
    if head[:4] == UNPACKED_MAGIC:
        return {"format": "Siemens S7-1200 firmware (unpacked image)",
                "processor": "arm"}
    try:
        fw = s71200.Firmware(head)
    except s71200.S7FirmwareError:
        return 0
    if not fw.mlfb.startswith("6ES7"):
        return 0
    return {"format": "Siemens S7-1200 firmware %s %s" % (fw.mlfb, fw.version),
            "processor": "arm"}


def load_file(li, neflags, fmt):
    head = _peek(li)
    li.seek(0)
    raw = li.read(li.size())

    if head[:4] == UNPACKED_MAGIC:
        image, label = raw, "unpacked image"
    else:
        fw = s71200.Firmware(raw)
        for problem in fw.problems:
            print("[s71200] warning: %s" % problem)
        image, stats, _ = fw.unpack(strict=False)
        label = "%s %s (%d literals / %d matches)" % (
            fw.mlfb, fw.version, stats.literals, stats.matches)

    arch = s71200.identify_arch(image)
    base = arch.load_base

    ida_idp.set_processor_type("arm", ida_idp.SETPROC_LOADER)
    ida_ida.inf_set_be(True)

    ida_loader.mem2base(image, base, -1)
    ida_segment.add_segm(0, base, base + len(image), "FIRMWARE", "CODE")
    ida_segment.set_segm_addressing(ida_segment.getseg(base), 1)  # 32-bit

    if arch.vector_offset is not None:
        for i, name in enumerate(VECTORS):
            ea = base + arch.vector_offset + 4 * i
            ida_bytes.create_dword(ea, 4)
            ida_name.set_name(ea, "vec_%s" % name)

    if arch.entry_va:
        ida_entry.add_entry(arch.entry_va, arch.entry_va, "reset_handler", 1)
        ida_ida.inf_set_start_ea(arch.entry_va)

    print("[s71200] %s -> 0x%08X-0x%08X" % (label, base, base + len(image)))
    oms = s71200.find_oms_version(image)
    if oms:
        print("[s71200] OMS+ %s" % oms)
    print("[s71200] %d class symbols applied" % apply_symbols(image))
    return 1


def apply_symbols(image):
    """Name the RTTI records and cross-reference their associated code.

    Only the names are certain. Which code slot is constructor, destructor or
    virtual method has not been established, so associated code gets a comment
    rather than an invented function name.
    """
    count = 0
    for sym in s71200.extract_symbols(image):
        ida_name.set_name(sym.record_va, "rtti_" + _ident(sym.name),
                          ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        for va in sym.code_vas:
            ida_bytes.set_cmt(va, sym.name, True)
        count += 1
    return count


def _ident(name):
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)[:180]
