"""IDA loader for Siemens SIMATIC S7-1200 .upd firmware.

Install: copy to $IDAUSR/loaders/ (survives IDA upgrades)
    macOS/Linux  ~/.idapro/loaders/
    Windows      %APPDATA%\\Hex-Rays\\IDA Pro\\loaders\\
Needs s71200 importable by the interpreter IDAPython is built against, which
is not the one in the IDA directory. Print sys.prefix in IDA's Python console
to find it, then pip install this repository into it. See README.md.

Open a .upd and it extracts the image, maps it at the load base as big-endian
ARM, labels the exception vectors and sets the entry point.

LZP algorithm by Jean-Baptiste Bedrune (@jibeee), s7unpack, Apache-2.0.
"""

import ida_bytes
import ida_entry
import ida_ida
import ida_idp
import ida_loader
import ida_name
import ida_offset
import ida_segment

import s71200

VECTORS = ("reset", "undef", "swi", "pabort", "dabort", "reserved", "irq", "fiq")
UNPACKED_MAGIC = b"\x5d\x1bAS"  # header of an already-extracted image
CODE_SLOTS = (-20, -12, -4)  # code pointers, relative to the RTTI record tag


def _peek(li):
    li.seek(0)
    return li.read(0x64)  # header + TOC; no need to read 15 MB to recognise it


def accept_file(li, filename):
    head = _peek(li)
    if head[:4] == UNPACKED_MAGIC:
        return _accept("Siemens S7-1200 firmware (unpacked image)")
    try:
        fw = s71200.Firmware(head)
    except s71200.S7FirmwareError:
        return 0
    if not fw.mlfb.startswith("6ES7"):
        return 0
    return _accept("Siemens S7-1200 firmware %s %s" % (fw.mlfb, fw.version))


def _accept(description):
    # ACCEPT_FIRST, because generic loaders also match these files on content
    # alone. IDA's SNES loader claims V4.6 images otherwise.
    return {"format": description, "processor": "arm",
            "options": ida_loader.ACCEPT_FIRST}


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
    # This firmware is ARM throughout. Left on, IDA's automatic ARM/Thumb
    # switching mis-flips about 3 MB of it, including the entry point, and
    # every mis-flipped byte disassembles two bytes at a time as nonsense.
    ida_idp.process_config_directive("ARM_NO_ARM_THUMB_SWITCH=YES")

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
        # start_ea does not stick on its own: IDA recomputes it from cs:ip
        # after the loader returns, and an unset cs shifts it by -0x10.
        ida_ida.inf_set_start_cs(0)
        ida_ida.inf_set_start_ip(arch.entry_va)
        ida_ida.inf_set_start_ea(arch.entry_va)

    print("[s71200] %s -> 0x%08X-0x%08X" % (label, base, base + len(image)))
    oms = s71200.find_oms_version(image)
    if oms:
        print("[s71200] OMS+ %s" % oms)
    print("[s71200] %d class symbols applied" % apply_symbols(image))
    return 1


def apply_symbols(image):
    """Name the RTTI records and link them to the code they point at.

    Only the names are certain. Which slot is constructor, destructor or
    virtual method has not been established, so the slots are marked as
    offsets rather than given invented function names. IDA renders the slot as
    a reference to its target and generates the cross-reference, which is what
    makes the class reachable from the code and the code from the class.

    Marking the slot is what survives. Anything written to the target address
    instead, a comment or a manual dref, is discarded by auto-analysis, since
    at load time the target is still undefined bytes.
    """
    count = 0
    for sym in s71200.extract_symbols(image):
        ida_name.set_name(sym.record_va, "rtti_" + _ident(sym.name),
                          ida_name.SN_NOCHECK | ida_name.SN_FORCE)
        pointers = set(sym.code_vas)
        for slot in CODE_SLOTS:
            ea = sym.record_va + slot
            if ida_bytes.get_dword(ea) in pointers:
                ida_bytes.create_dword(ea, 4)
                ida_offset.op_plain_offset(ea, 0, 0)
        count += 1
    return count


def _ident(name):
    return "".join(c if c.isalnum() or c == "_" else "_" for c in name)[:180]
