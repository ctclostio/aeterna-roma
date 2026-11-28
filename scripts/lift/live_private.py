"""A live.exe of this checkout's own, to run beside the working build.

build(root, work) compiles a copy of <root>/port/lifted_live/live_main.c in work/ and links it against
<root>'s lifted functions. Two things differ from the working live.exe:

  - this checkout's shim modules (every source of port/lifted_live but the runner's own) lie next to the
    copy, so an include by name finds them before <root>'s: a module is tried in the real runner before it
    is merged;
  - port/lifted_live/private_instance.h is force-included, so the game's one-instance check does not see the
    working build, nor the working build this one.

snapshot(root, work) copies what such an exe loads at run time. <root> is only read: the working build can go on
being edited, rebuilt and run meanwhile.
"""
from __future__ import annotations

import ast
import re
import shutil
from pathlib import Path

import toolchain
from image import ROOT

LIVE_DIR = ROOT / "port" / "lifted_live"
RUNNER_OWN = ("live_main.c", "live_rt.c", "live.h")  # taken from <root>
RUN_PARTS = ("lifted.dll", "image.bin")
STACK = 64 << 20


def build(root: Path, work: Path, edit=None, lib: Path | None = None) -> tuple[Path, str]:
    """Returns the exe and the compiler's output. edit, when given, changes the text of the copy first; lib is
    the import library of the lifted.dll to run with (default: <root>'s)."""
    source = root / "port" / "lifted_live" / "live_main.c"
    text = source.read_text(encoding="utf-8")
    work.mkdir(parents=True, exist_ok=True)
    copy = work / "live_main_private.c"
    copy.write_text(edit(text) if edit else text, encoding="utf-8", newline="\n")
    for part in [*LIVE_DIR.glob("*.c"), *LIVE_DIR.glob("*.h")]:
        if part.name not in RUNNER_OWN:
            shutil.copyfile(part, work / part.name)
    # The flags that checkout builds live.exe with.
    flags = re.search(r"^EXE_CFLAGS = (\[.*\])$", (root / "scripts" / "lift" / "build_live.py").read_text(encoding="utf-8"), re.M)
    cflags = ast.literal_eval(flags.group(1)) if flags else [f for f in toolchain.RUNTIME_CFLAGS if f not in ("/W4", "/WX")] + ["/W3"]
    obj, exe = work / "live_main.obj", work / "live.exe"
    log = toolchain.run_tool(["cl", *cflags, "/c", f"/FI{work / 'private_instance.h'}", f"/I{source.parent}",
                              f"/I{root / 'port' / 'lifted_runtime'}", f"/Fo{obj}", str(copy)], cwd=work)
    lib = lib or root / "generated" / "lifted" / "live" / "lifted.lib"
    if not lib.exists():
        return obj, log
    toolchain.run_tool(["link", "/nologo", "/INCREMENTAL:NO", "/DEBUG", f"/STACK:{STACK}", f"/OUT:{exe}", str(obj), str(lib)], cwd=work)
    return exe, log


def snapshot(root: Path, work: Path) -> None:
    """Copies lifted.dll and the image next to the exe; a file that changes while it is copied (a link in
    progress) is copied again."""
    live = root / "generated" / "lifted" / "live"
    work.mkdir(parents=True, exist_ok=True)
    for _ in range(5):
        before = [(live / p).stat() for p in RUN_PARTS]
        for p in RUN_PARTS:
            shutil.copyfile(live / p, work / p)
        after = [(live / p).stat() for p in RUN_PARTS]
        if all((a.st_size, a.st_mtime_ns) == (b.st_size, b.st_mtime_ns) for a, b in zip(before, after)):
            return
    raise toolchain.BuildError(f"{live} kept changing while it was copied")


def use_modules(text: str) -> str:
    """The edit port/lifted_live/shim_modules.h asks of live_main.c, made to the copy."""
    old = '#define D3D11_BRIDGE_LIVE\n#include "d3d11_bridge.c"\n'
    if "LIVE_SHIM_MODULE_ROWS" in text:
        return text
    if text.count(old) != 1 or text.count("D3D11_BRIDGE_SHIMS") != 1:
        raise toolchain.BuildError("live_main.c does not include d3d11_bridge.c the way shim_modules.h replaces")
    return text.replace(old, '#include "shim_modules.h"\n').replace("D3D11_BRIDGE_SHIMS", "LIVE_SHIM_MODULE_ROWS")


if __name__ == "__main__":
    import argparse
    import sys

    from image import GENERATED

    ap = argparse.ArgumentParser(description="Builds a live.exe of this checkout's own in generated/lifted/live_private/.")
    ap.add_argument("--root", type=Path, default=ROOT, help="checkout whose runner and lifted functions are used")
    ap.add_argument("--modules", action="store_true", help="include the shim modules through shim_modules.h")
    args = ap.parse_args()
    try:
        built, log = build(args.root.resolve(), GENERATED / "live_private", use_modules if args.modules else None)
    except toolchain.BuildError as error:
        sys.exit(str(error)[-4000:])
    print(log.strip() + "\n" + str(built) if "warning" in log else built)
