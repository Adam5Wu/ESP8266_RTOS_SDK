#!/usr/bin/env python3
"""Create a copy of GCC's active multilib libgcc.a with Mask ROM symbols removed."""

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


def parse_rom_symbols(rom_ld_path: Path) -> set[str]:
    text = rom_ld_path.read_text(encoding="utf-8", errors="ignore")
    return set(re.findall(r"(?:PROVIDE\s*\(\s*)?(\w+)\s*=\s*0x[0-9a-fA-F]+", text))


def find_pure_rom_objects(nm_tool: str, archive_path: Path, rom_syms: set[str]) -> list[str]:
    proc = subprocess.run(
        [nm_tool, "-g", "--defined-only", str(archive_path)],
        capture_output=True, text=True, check=True,
    )
    objs: dict[str, list[str]] = {}
    cur_obj: str | None = None
    for line in proc.stdout.splitlines():
        if line.endswith(".o:"):
            cur_obj = line[:-1]
            objs.setdefault(cur_obj, [])
        elif cur_obj is not None and len(parts := line.split()) == 3:
            objs[cur_obj].append(parts[2])
    return sorted(obj for obj, syms in objs.items() if syms and all(s in rom_syms for s in syms))


def main() -> int:
    ap = argparse.ArgumentParser(description="Strip Mask ROM objects from libgcc.a")
    ap.add_argument("--cc", required=True)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--nm", required=True)
    ap.add_argument("--rom-ld", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--cflag", action="append", default=[])
    args = ap.parse_args()

    src_libgcc = Path(subprocess.check_output(
        [args.cc, *args.cflag, "-print-file-name=libgcc.a"], text=True,
    ).strip())
    if not src_libgcc.is_file():
        raise FileNotFoundError(f"GCC returned invalid libgcc.a path: {src_libgcc}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(src_libgcc, out_path)

    pure_rom_objs = find_pure_rom_objects(args.nm, out_path, parse_rom_symbols(Path(args.rom_ld)))
    if pure_rom_objs:
        subprocess.run([args.ar, "d", str(out_path), *pure_rom_objs], check=True)
        subprocess.run([args.ar, "s", str(out_path)], check=True)

    print(f"strip_rom_libgcc: stripped {len(pure_rom_objs)} ROM objects from {src_libgcc} -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
