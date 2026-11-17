#!/usr/bin/env python3
"""Create a copy of GCC's active multilib libgcc.a with Mask ROM symbols removed."""

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def _build_env(cc: str) -> tuple[dict[str, str], Path | None]:
    env = os.environ.copy()
    resolved = shutil.which(cc, path=env.get("PATH")) or cc
    cc_path = Path(resolved)
    tc_root = cc_path.parent.parent if cc_path.parent.name == "bin" else None
    if tc_root is not None:
        lib_dir = tc_root / "lib"
        dynconfig = lib_dir / "xtensa_esp8266.so"
        if dynconfig.is_file():
            env.setdefault("XTENSA_GNU_CONFIG", str(dynconfig))
        if lib_dir.is_dir():
            env["PATH"] = str(lib_dir) + os.pathsep + env.get("PATH", "")
        if (tc_root / "bin").is_dir():
            env["PATH"] = str(tc_root / "bin") + os.pathsep + env["PATH"]
    return env, tc_root


def _resolve_tool(
    tool_arg: str | None,
    tc_root: Path | None,
    prefix: str,
    suffix: str,
    search_path: str | None = None,
) -> str:
    if tool_arg and Path(tool_arg).exists():
        return tool_arg
    if tool_arg:
        found = shutil.which(tool_arg, path=search_path)
        if found:
            return found
    for cand_name in (f"{prefix}{suffix}.exe", f"{prefix}{suffix}"):
        if tc_root is not None:
            cand = tc_root / "bin" / cand_name
            if cand.is_file():
                return str(cand)
        found = shutil.which(cand_name, path=search_path)
        if found:
            return found
    raise FileNotFoundError(f"Could not locate {suffix} tool (arg={tool_arg!r})")


def parse_rom_symbols(rom_ld_path: Path) -> set[str]:
    text = rom_ld_path.read_text(encoding="utf-8", errors="ignore")
    return set(re.findall(r"(?:PROVIDE\s*\(\s*)?(\w+)\s*=\s*0x[0-9a-fA-F]+", text))


def find_pure_rom_objects(nm_tool: str, archive_path: Path, rom_syms: set[str], env: dict[str, str]) -> list[str]:
    proc = subprocess.run(
        [nm_tool, "-g", "--defined-only", str(archive_path)],
        env=env,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nm failed on {archive_path} (exit {proc.returncode}): {proc.stderr}")

    objs: dict[str, list[str]] = {}
    cur_obj: str | None = None
    for line in proc.stdout.splitlines():
        if line.endswith(".o:"):
            cur_obj = line[:-1]
            objs.setdefault(cur_obj, [])
            continue
        parts = line.split()
        if cur_obj is not None and len(parts) == 3:
            objs[cur_obj].append(parts[2])

    return sorted(obj for obj, syms in objs.items() if syms and all(s in rom_syms for s in syms))


def main() -> int:
    parser = argparse.ArgumentParser(description="Strip Mask ROM objects from libgcc.a")
    parser.add_argument("--cc", required=True)
    parser.add_argument("--ar")
    parser.add_argument("--nm")
    parser.add_argument("--rom-ld", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--cflag", action="append", default=[])
    args = parser.parse_args()

    env, tc_root = _build_env(args.cc)
    cc_name = Path(args.cc).name
    prefix = "xtensa-esp-elf-" if "xtensa-esp-elf" in cc_name else "xtensa-lx106-elf-"
    ar_tool = _resolve_tool(args.ar, tc_root, prefix, "ar", env.get("PATH"))
    nm_tool = _resolve_tool(args.nm, tc_root, prefix, "nm", env.get("PATH"))

    libgcc_query = subprocess.run(
        [args.cc, *args.cflag, "-print-file-name=libgcc.a"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    src_libgcc = Path(libgcc_query.stdout.strip())
    if not src_libgcc.is_file():
        raise FileNotFoundError(f"GCC returned invalid libgcc.a path: {libgcc_query.stdout!r}")

    rom_syms = parse_rom_symbols(Path(args.rom_ld))
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_libgcc, out_path)

    pure_rom_objs = find_pure_rom_objects(nm_tool, out_path, rom_syms, env)
    if pure_rom_objs:
        subprocess.run([ar_tool, "d", str(out_path), *pure_rom_objs], env=env, check=True)
        subprocess.run([ar_tool, "s", str(out_path)], env=env, check=True)

    print(f"strip_rom_libgcc: stripped {len(pure_rom_objs)} ROM objects from {src_libgcc} -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
