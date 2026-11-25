"""MSVC command-line toolchain access for the lifted tier.

cl and link are not on PATH until vcvars has run. The environment vcvars
produces is captured once per architecture and cached under generated/lifted/,
so later compiles start cl directly.
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
from pathlib import Path

from image import GENERATED, ROOT

VCVARS_GLOBS = (
    r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Auxiliary\Build",
    r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Auxiliary\Build",
)
VCVARS = {"x64": "vcvars64.bat", "x86": "vcvarsamd64_x86.bat"}
RUNTIME_DIR = ROOT / "port" / "lifted_runtime"


class BuildError(RuntimeError):
    pass


def find_vcvars(arch: str) -> Path:
    """The vcvars script for arch; LIFT_VCVARS_X64 / LIFT_VCVARS_X86 override the search."""
    override = os.environ.get(f"LIFT_VCVARS_{arch.upper()}")
    if override:
        return Path(override)
    for pattern in VCVARS_GLOBS:
        for folder in sorted(glob.glob(pattern), reverse=True):
            candidate = Path(folder) / VCVARS[arch]
            if candidate.exists():
                return candidate
    raise BuildError(f"no {arch} vcvars script found; set LIFT_VCVARS_{arch.upper()}")


def msvc_env(arch: str = "x64") -> dict[str, str]:
    cache = GENERATED / f"vcvars_{arch}.json"
    bat = find_vcvars(arch)
    if cache.exists() and cache.stat().st_mtime >= bat.stat().st_mtime:
        return json.loads(cache.read_text(encoding="utf-8"))
    # cmd parses the line itself: no list2cmdline quoting, which would mangle the nested quotes.
    out = subprocess.run(f'cmd /d /s /c ""{bat}" >nul && set"', capture_output=True, text=True, check=True).stdout
    env = dict(line.split("=", 1) for line in out.splitlines() if "=" in line and not line.startswith("="))
    if not any(k.upper() == "VCINSTALLDIR" for k in env):
        raise BuildError(f"{bat} did not set up a compiler environment")
    GENERATED.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(env), encoding="utf-8", newline="\n")
    return env


def run_tool(args: list[str], cwd: Path, arch: str = "x64") -> str:
    """Runs cl/link/lib from the cached environment; returns its output or raises BuildError."""
    env = msvc_env(arch)
    path = next(v for k, v in env.items() if k.upper() == "PATH")
    exe = next((Path(d) / (args[0] + ".exe") for d in path.split(os.pathsep) if (Path(d) / (args[0] + ".exe")).exists()), None)
    if exe is None:
        raise BuildError(f"{args[0]} not found in the {arch} toolchain")
    proc = subprocess.run([str(exe), *args[1:]], cwd=cwd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise BuildError(f"{' '.join(args)}\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout + proc.stderr


# Hand-written sources: C17, /W4 with warnings as errors, optimised, no control-flow
# guard (thunks are called through data pointers). /Z7 keeps debug information in
# the object, so concurrent builds share no PDB.
RUNTIME_CFLAGS = ["/nologo", "/std:c17", "/TC", "/W4", "/WX", "/O2", "/Z7", "/guard:cf-", "/GS-", "/D_CRT_SECURE_NO_WARNINGS"]
# Generated C: no optimisation (fast to compile), no warnings.
GENERATED_CFLAGS = ["/nologo", "/std:c17", "/TC", "/W0", "/Od", "/guard:cf-", "/GS-", "/bigobj"]
RUNNER_SOURCES = ("lift_rt.c", "lift_main.c")
# Lifted functions keep every temporary in their frame; the largest need more than the default 1 MiB.
RUNNER_STACK = 64 << 20


def build_runtime_objs(out_dir: Path, sources: tuple[str, ...] = RUNNER_SOURCES) -> list[Path]:
    """Compiles runtime sources into out_dir; skips objects newer than every runtime source.

    An object is written under a private name and renamed into place, so
    parallel batch builds sharing out_dir never link a half-written file.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    newest = max(p.stat().st_mtime for p in RUNTIME_DIR.iterdir() if p.suffix in (".c", ".h"))
    objs = []
    for name in sources:
        obj = out_dir / (Path(name).stem + ".obj")
        if not obj.exists() or obj.stat().st_mtime < newest:
            tmp = out_dir / f"{Path(name).stem}.{os.getpid()}.tmp.obj"
            run_tool(["cl", *RUNTIME_CFLAGS, "/c", f"/I{RUNTIME_DIR}", f"/Fo{tmp}", str(RUNTIME_DIR / name)], cwd=out_dir)
            os.replace(tmp, obj)
        objs.append(obj)
    return objs


def link_exe(out: Path, objs: list[Path], stack: int = 0) -> None:
    args = ["link", "/nologo", "/DEBUG", "/INCREMENTAL:NO", "/OPT:REF", "/GUARD:NO", f"/OUT:{out}"]
    if stack:
        args.append(f"/STACK:{stack}")
    run_tool(args + [str(o) for o in objs], cwd=out.parent)
