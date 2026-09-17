"""Command-line interface for :mod:`s7fw`."""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .container import Firmware, discover, load
from .errors import S7FirmwareError
from .fingerprint import find_oms_version, identify_arch
from .symbols import extract_symbols

__all__ = ["main", "build_parser"]


def _iter_firmware(paths: Iterable[str]) -> Iterable[tuple[str, Firmware]]:
    for entry in paths:
        path = Path(entry)
        if path.is_dir():
            for label, data in discover(path):
                try:
                    yield label, Firmware(data, Path(label.split("::")[0]))
                except S7FirmwareError as exc:
                    print(f"{label}: {exc}", file=sys.stderr)
        else:
            yield entry, load(path)


def cmd_info(args: argparse.Namespace) -> int:
    failures = 0
    for label, fw in _iter_firmware(args.files):
        status = "OK" if fw.complete else "PROBLEMS"
        print(Path(label).name)
        print(f"    version : {fw.version}     MLFB: {fw.mlfb}")
        print(f"    layout  : {status} ({fw.layout.value}, "
              f"{fw.layout.endianness}-endian TOC, "
              f"{'tagged' if fw.layout.tagged else 'untagged'})")
        print(f"    size    : {len(fw)} bytes")
        if args.hash:
            print(f"    sha256  : {fw.sha256}")
        for section in fw.sections:
            print(f"        {section.name:<7} size={section.size:<10} "
                  f"cksum=0x{section.checksum:08x}  data@0x{section.data_offset:x}")
        for problem in fw.problems:
            failures += 1
            print(f"        !! {problem}")
        print()
    return 1 if failures and args.strict else 0


def cmd_unpack(args: argparse.Namespace) -> int:
    fw = load(args.file)
    if not fw.complete and not args.force:
        for problem in fw.problems:
            print(f"!! {problem}", file=sys.stderr)
        print("refusing to unpack a malformed container (use --force)",
              file=sys.stderr)
        return 1

    image, stats, headers = fw.unpack(
        args.section, strict=not args.no_strict, reuse_table=args.reuse_table
    )
    output = Path(args.output) if args.output else Path(args.file).with_suffix(".bin")
    output.write_bytes(image)

    section = fw[args.section or fw.code_section]
    print(f"{Path(args.file).name} -> {output}")
    print(f"    {section.size} -> {len(image)} bytes "
          f"({len(image) / section.size:.2f}x)")
    print(f"    literals={stats.literals} matches={stats.matches} "
          f"anomalies={stats.anomalous_matches}")
    print(f"    chunk headers: {', '.join(f'0x{h:04x}' for h in headers[:8])}")
    print(f"    sha256: {hashlib.sha256(image).hexdigest()}")

    oms = find_oms_version(image)
    if oms:
        print(f"    OMS+  : {oms} [{oms.raw}]")
    arch = identify_arch(image)
    if arch.confident:
        entry = f", entry VA 0x{arch.entry_va:08x}" if arch.entry_va else ""
        print(f"    arch  : {arch} ({arch.ghidra_language}){entry}")
    return 0


def _unpack_one(job: tuple[str, bytes, str]) -> Optional[tuple]:
    label, data, outdir = job
    fw = Firmware(data)
    try:
        image, stats, _ = fw.unpack(strict=True)
    except S7FirmwareError as exc:
        return (label, str(fw.version), None, 0, 0, str(exc))
    size_class = "small" if fw[fw.code_section].size < 15_300_000 else "large"
    name = f"{fw.version}_{size_class}.bin"
    Path(outdir, name).write_bytes(image)
    return (name, str(fw.version), size_class, fw[fw.code_section].size,
            len(image), hashlib.sha256(image).hexdigest())


def cmd_batch(args: argparse.Namespace) -> int:
    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)

    seen: dict[str, tuple[str, bytes]] = {}
    for label, data in discover(args.root):
        try:
            fw = Firmware(data)
            digest = hashlib.sha256(fw.payload()).hexdigest()
        except S7FirmwareError:
            continue
        seen.setdefault(digest, (label, data))
    print(f"{len(seen)} unique compressed payloads")

    jobs = [(label, data, str(outdir)) for label, data in seen.values()]
    workers = min(len(jobs), multiprocessing.cpu_count()) or 1
    with multiprocessing.Pool(workers) as pool:
        results = [r for r in pool.map(_unpack_one, jobs) if r]

    print(f"\n{'output':<24}{'version':<12}{'class':<7}{'compressed':>12}"
          f"{'unpacked':>12}")
    print("-" * 68)
    for row in sorted(results, key=lambda r: (r[2] or "", r[1])):
        if row[2] is None:
            print(f"{Path(row[0]).name:<24}{row[1]:<12}FAILED  {row[5]}")
        else:
            print(f"{row[0]:<24}{row[1]:<12}{row[2]:<7}{row[3]:>12}{row[4]:>12}")
    print()
    for row in sorted(results, key=lambda r: (r[2] or "", r[1])):
        if row[2] is not None:
            print(f"{row[5]}  {row[0]}")
    return 0


def cmd_identify(args: argparse.Namespace) -> int:
    image = Path(args.file).read_bytes()
    arch = identify_arch(image)
    oms = find_oms_version(image)
    print(f"file        : {Path(args.file).name} ({len(image)} bytes)")
    print(f"architecture: {arch}")
    print(f"confidence  : {'high' if arch.confident else 'LOW'}")
    if arch.vector_offset is not None:
        print(f"vector table: file 0x{arch.vector_offset:x} -> "
              f"VA 0x{arch.vector_offset + arch.load_base:08x}")
    if arch.entry_va:
        print(f"entry point : VA 0x{arch.entry_va:08x} "
              f"(file 0x{arch.entry_va - arch.load_base:x})")
    print(f"ghidra      : language {arch.ghidra_language}, "
          f"base 0x{arch.load_base:x}")
    print(f"ida         : ARM processor, big-endian, ROM base 0x{arch.load_base:x}")
    if oms:
        print(f"OMS+        : {oms} [{oms.raw}]")
    return 0


def cmd_symbols(args: argparse.Namespace) -> int:
    image = Path(args.file).read_bytes()
    symbols = list(extract_symbols(image))
    if args.filter:
        pattern = re.compile(args.filter, re.I)
        symbols = [s for s in symbols if pattern.search(s.name)]

    if args.json:
        json.dump(
            [
                {
                    "name": s.name,
                    "record_va": s.record_va,
                    "type_id": s.type_id,
                    "base_va": s.base_va,
                    "code_vas": list(s.code_vas),
                }
                for s in symbols
            ],
            sys.stdout,
            indent=1,
        )
        print()
        return 0

    for s in symbols:
        code = " ".join("0x%08x" % c for c in s.code_vas)
        print(f"0x{s.record_va:08x}  {s.name}" + (f"  [{code}]" if code else ""))
    print(f"\n{len(symbols)} symbols", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s7fw",
        description="Siemens SIMATIC S7-1200 firmware container tool",
        epilog="LZP algorithm reverse engineered by Jean-Baptiste Bedrune "
               "(@jibeee), s7unpack, Apache-2.0.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("info", help="show container layout")
    p.add_argument("files", nargs="+", help="files or directories")
    p.add_argument("--hash", action="store_true", help="include SHA-256")
    p.add_argument("--strict", action="store_true",
                   help="exit non-zero if any container has problems")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("unpack", help="decompress one container")
    p.add_argument("file")
    p.add_argument("-o", "--output")
    p.add_argument("--section")
    p.add_argument("--force", action="store_true")
    p.add_argument("--no-strict", action="store_true",
                   help="salvage mode: continue past corrupt chunks")
    p.add_argument("--reuse-table", action="store_true",
                   help="carry the hash table across chunks (original C behaviour)")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("batch", help="unpack every unique payload under a tree")
    p.add_argument("root")
    p.add_argument("output")
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("symbols", help="extract C++ class symbols from an image")
    p.add_argument("file")
    p.add_argument("--filter", help="only names matching this regex")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_symbols)

    p = sub.add_parser("identify", help="identify arch/OMS+ of an unpacked image")
    p.add_argument("file")
    p.set_defaults(func=cmd_identify)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except S7FirmwareError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
