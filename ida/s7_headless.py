"""Batch-mode IDA script: load firmware, run auto-analysis, export JSON.

    idat -A -S"s7_headless.py out.json" -o /tmp/fw.idb firmware.upd

  -A   non-interactive (never prompt)
  -S   run this script after loading
  -o   where to write the database

Use idat (text mode), not ida; on Windows it is idat.exe / idat64.exe.
The .upd or unpacked .bin is handled by s7_1200_loader.py, which must be in
$IDAUSR/loaders/.

Exports every function IDA found plus the recovered class symbols, so two
firmware versions can be compared without opening the GUI.
"""

import json
import sys

import ida_auto
import ida_funcs
import ida_name
import ida_pro
import idautils


def export(path):
    ida_auto.auto_wait()  # analysis must finish before anything is exported

    functions = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        functions.append({
            "ea": ea,
            "name": ida_name.get_name(ea),
            "size": func.end_ea - func.start_ea if func else 0,
        })

    named = {
        ea: name
        for ea, name in ((e, ida_name.get_name(e)) for e, _ in idautils.Names())
        if name.startswith("rtti_")
    }

    with open(path, "w") as handle:
        json.dump({"functions": functions, "classes": named}, handle, indent=1)
    print("[s7fw] exported %d functions, %d classes -> %s"
          % (len(functions), len(named), path))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "s7fw-export.json"
    try:
        export(out)
    finally:
        ida_pro.qexit(0)  # qexit is required, or idat hangs forever in batch
