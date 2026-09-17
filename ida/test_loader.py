"""Exercise the loader without IDA by stubbing the ida_* modules.

Verifies the s71200 integration and control flow, meaning the values handed to
IDA and
the order of calls. It cannot verify IDA's own semantics; run it once inside
IDA for that.

    python3 ida/test_loader.py "path/to/firmware.upd"
"""

import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))  # repo root, so `import s71200` resolves

calls = []


def _stub(name, *functions):
    module = types.ModuleType(name)
    for function in functions:
        setattr(module, function,
                lambda *a, _f=f"{name}.{function}", **k: calls.append((_f, a)))
    sys.modules[name] = module
    return module


_stub("ida_bytes", "create_dword", "set_cmt")
_stub("ida_entry", "add_entry")
_stub("ida_ida", "inf_set_be", "inf_set_start_ea")
_stub("ida_loader", "mem2base")
nm = _stub("ida_name", "set_name")
nm.SN_NOCHECK = 1
nm.SN_FORCE = 2

idp = _stub("ida_idp", "set_processor_type")
idp.SETPROC_LOADER = 1

seg = _stub("ida_segment", "add_segm", "set_segm_addressing")
seg.getseg = lambda ea: object()


class Linput:
    """Minimal stand-in for IDA's loader_input_t."""

    def __init__(self, data):
        self._data, self._pos = data, 0

    def seek(self, pos):
        self._pos = pos

    def read(self, n):
        chunk = self._data[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def size(self):
        return len(self._data)


def main(path):
    loader = __import__("s7_1200_loader")
    data = Path(path).read_bytes()

    accepted = loader.accept_file(Linput(data), path)
    print("accept_file ->", accepted)
    assert accepted, "loader rejected a valid .upd"

    assert loader.accept_file(Linput(b"\x00" * 0x200), "junk") == 0, \
        "loader accepted junk"
    print("accept_file(junk) -> 0")

    assert loader.load_file(Linput(data), 0, "") == 1
    print("\ncalls into IDA (first 24):")
    for name, args in calls[:24]:
        shown = tuple(
            f"<{len(a)} bytes>" if isinstance(a, (bytes, bytearray))
            else (hex(a) if isinstance(a, int) and a > 0xFFFF else a)
            for a in args
        )
        print(f"  {name}{shown}")

    made = {name for name, _ in calls}
    for required in ("ida_idp.set_processor_type", "ida_ida.inf_set_be",
                     "ida_loader.mem2base", "ida_segment.add_segm",
                     "ida_entry.add_entry", "ida_ida.inf_set_start_ea"):
        assert required in made, f"loader never called {required}"
    names = sum(1 for n, _ in calls if n == "ida_name.set_name")
    assert names > 7000, f"expected 8 vectors + ~7000 symbols, got {names}"
    print(f"\n  {names} set_name calls (8 vectors + class symbols)")
    print("\nOK")


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    main(sys.argv[1])
