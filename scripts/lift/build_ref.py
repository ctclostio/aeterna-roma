"""Build the reference side of the lifted tier (see docs/lifted_tier.md).

Produces generated/lifted/ref/ref_dbg.exe and ref_child.exe, both 32-bit:

    python scripts/lift/build_ref.py [--force]

The debugger is an ordinary console program. The child is linked without the
CRT, at a fixed low base with DEP on and kernel32 as its only import, so its
address space stays clear of the guest image (0x10000000) and arena
(0x20000000..0x60000000).
"""
from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "tests" / "lift_ref"
MODEL = ROOT / "port" / "lifted_runtime"
OUT = ROOT / "generated" / "lifted" / "ref"
REF_DBG = OUT / "ref_dbg.exe"
REF_CHILD = OUT / "ref_child.exe"

VCVARS_NAMES = ("vcvarsamd64_x86.bat", "vcvars32.bat")
VCVARS_GLOBS = (
    r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Auxiliary\Build",
    r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build",
)

CHILD_CL = "/nologo /std:c17 /W4 /WX /O1 /GS- /Zl /c"
CHILD_LINK = ("/nologo /NODEFAULTLIB /ENTRY:ref_child_entry /SUBSYSTEM:WINDOWS /MACHINE:X86 "
              "/NXCOMPAT /DYNAMICBASE:NO /FIXED /BASE:0x00400000 /STACK:0x10000")
DBG_CL = "/nologo /std:c17 /W4 /WX /O2 /MT"
DBG_LINK = "/nologo /SUBSYSTEM:CONSOLE /MACHINE:X86 /NXCOMPAT /DYNAMICBASE"


def find_vcvars() -> Path:
    """An x86-targeting vcvars script; LIFT_VCVARS_X86 overrides the search."""
    override = os.environ.get("LIFT_VCVARS_X86")
    if override:
        return Path(override)
    for pattern in VCVARS_GLOBS:
        for folder in sorted(glob.glob(pattern), reverse=True):
            for name in VCVARS_NAMES:
                candidate = Path(folder) / name
                if candidate.exists():
                    return candidate
    raise FileNotFoundError("no x86 vcvars script found; set LIFT_VCVARS_X86")


def sources() -> list[Path]:
    return [SRC / "ref_dbg.c", SRC / "ref_child.c", MODEL / "lift_model.h", Path(__file__)]


def up_to_date() -> bool:
    if not (REF_DBG.exists() and REF_CHILD.exists()):
        return False
    built = min(REF_DBG.stat().st_mtime, REF_CHILD.stat().st_mtime)
    return all(src.stat().st_mtime <= built for src in sources())


def build(force: bool = False) -> tuple[Path, Path]:
    """Build both programs if needed and return (ref_dbg.exe, ref_child.exe)."""
    if not force and up_to_date():
        return REF_DBG, REF_CHILD
    OUT.mkdir(parents=True, exist_ok=True)
    check = 'if not "%ERRORLEVEL%"=="0" exit /b 1'
    lines = [
        "@echo off",
        f'call "{find_vcvars()}" >nul 2>nul',
        check,
        f'cd /d "{OUT}"',
        f'cl {CHILD_CL} /Foref_child.obj "{SRC / "ref_child.c"}"',
        check,
        f"link {CHILD_LINK} /OUT:ref_child.exe ref_child.obj kernel32.lib",
        check,
        f'cl {DBG_CL} /I"{MODEL}" /Foref_dbg.obj /Feref_dbg.exe "{SRC / "ref_dbg.c"}" /link {DBG_LINK}',
        check,
    ]
    script = OUT / "build_ref.bat"
    script.write_text("\r\n".join(lines) + "\r\n", encoding="ascii", newline="")
    done = subprocess.run(["cmd", "/c", str(script)], capture_output=True, text=True)
    if done.returncode != 0 or not (REF_DBG.exists() and REF_CHILD.exists()):
        sys.stderr.write(done.stdout + done.stderr)
        raise RuntimeError("building the reference side failed")
    return REF_DBG, REF_CHILD


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="rebuild even when the binaries are newer than the sources")
    args = parser.parse_args()
    dbg, child = build(force=args.force)
    print(dbg)
    print(child)
    return 0


if __name__ == "__main__":
    sys.exit(main())
