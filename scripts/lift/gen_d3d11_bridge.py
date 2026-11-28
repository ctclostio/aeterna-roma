"""Generates the interface tables of port/lifted_live/d3d11_bridge.c from the Windows SDK headers.

The bridge gives the 32-bit guest a vtable for every bridged COM interface. The
slot order, the interface that declares each method and the number of stack
dwords a 32-bit caller pushes are facts of the SDK headers, so they are read
from the C-style vtable declarations there instead of being typed by hand:

    typedef struct ID3D11BufferVtbl { BEGIN_INTERFACE
        DECLSPEC_XFGVIRT(ID3D11DeviceChild, GetDevice)
        void ( STDMETHODCALLTYPE *GetDevice )( ID3D11Buffer * This, ID3D11Device **ppDevice);
        ...

A method is only accepted when every parameter is one dword on x86 (a pointer,
a handle, an enumeration or a 32-bit scalar), so "stack dwords" is the
parameter count including This. The generated block also lists the exported
entry points with the parameter counts of their prototypes.

The hand-written part of d3d11_bridge.c must define one function
m_<declaring interface>_<method> per generated method: a missing one is a
compile error, and the slot numbers are checked against the SDK vtable structs
with static assertions.

    python scripts/lift/gen_d3d11_bridge.py          rewrite the generated block
    python scripts/lift/gen_d3d11_bridge.py --check  fail if the block is out of date
    python scripts/lift/gen_d3d11_bridge.py --test   --check, then:
        the 32-bit structure layouts, proved by an x86 compile;
        test_d3d11_bridge.c built twice (x64): linked with the bridge, and including it the way
        live_main.c does; each is run as it is and with --debug-layer;
        this checkout's live_main.c compiled with the two lines that include the bridge, and linked
        when generated/lifted/live/lifted.lib is there.
    python scripts/lift/gen_d3d11_bridge.py --test --runner <checkout>   the last step on another checkout
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from image import GENERATED  # noqa: E402
from toolchain import RUNTIME_CFLAGS, BuildError, msvc_env, run_tool  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / "port" / "lifted_live" / "d3d11_bridge.c"
BEGIN = "/* ---- BEGIN GENERATED (scripts/lift/gen_d3d11_bridge.py) ---- */"
END = "/* ---- END GENERATED ---- */"

# Parents come before children. Interfaces beyond the ones the game is known to
# use are here because ID3D11Device / ID3D11DeviceContext methods take or return them.
BRIDGED = (
    "IUnknown",
    "IDXGIObject", "IDXGIDeviceSubObject", "IDXGIFactory", "IDXGIFactory1", "IDXGIAdapter", "IDXGIAdapter1",
    "IDXGIOutput", "IDXGISwapChain", "IDXGIDevice", "IDXGIDevice1",
    "ID3D10Blob",
    "ID3D11DeviceChild", "ID3D11Resource", "ID3D11Buffer", "ID3D11Texture1D", "ID3D11Texture2D", "ID3D11Texture3D",
    "ID3D11View", "ID3D11RenderTargetView", "ID3D11DepthStencilView", "ID3D11ShaderResourceView",
    "ID3D11UnorderedAccessView", "ID3D11InputLayout", "ID3D11VertexShader", "ID3D11PixelShader",
    "ID3D11GeometryShader", "ID3D11HullShader", "ID3D11DomainShader", "ID3D11ComputeShader", "ID3D11SamplerState",
    "ID3D11RasterizerState", "ID3D11BlendState", "ID3D11DepthStencilState", "ID3D11Asynchronous", "ID3D11Query",
    "ID3D11Predicate", "ID3D11Counter", "ID3D11ClassInstance", "ID3D11ClassLinkage", "ID3D11CommandList",
    "ID3D11DeviceContext", "ID3D11Device",
)
# (import DLL the 32-bit game names, export, header that declares it)
EXPORTS = (
    ("dxgi.dll", "CreateDXGIFactory", "dxgi.h"),
    ("dxgi.dll", "CreateDXGIFactory1", "dxgi.h"),
    ("d3d11.dll", "D3D11CreateDevice", "d3d11.h"),
    ("d3d11.dll", "D3D11CreateDeviceAndSwapChain", "d3d11.h"),
    ("D3DCompiler_42.dll", "D3DCompile", "d3dcompiler.h"),
    ("D3DCompiler_42.dll", "D3DReflect", "d3dcompiler.h"),
    ("D3DCompiler_42.dll", "D3DDisassemble", "d3dcompiler.h"),
)
HEADERS = ("unknwnbase.h", "dxgiformat.h", "dxgicommon.h", "dxgitype.h", "dxgi.h", "d3dcommon.h", "d3d11.h", "d3dcompiler.h")

SCALAR4 = frozenset({"UINT", "INT", "BOOL", "FLOAT", "UINT8", "SIZE_T", "ULONG", "DWORD", "LONG", "HRESULT"})
POINTER4 = frozenset({"REFIID", "REFGUID", "LPCSTR", "LPSTR", "LPCWSTR", "LPWSTR", "LPVOID", "LPCVOID", "HWND", "HMODULE", "HANDLE"})
HANDLES = frozenset({"HWND", "HMODULE", "HANDLE"})
# One SAL / MIDL annotation, with an optional argument list nested at most two deep.
ANNOTATION = re.compile(r"\b_{1,2}[A-Za-z]\w*\s*(\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?")


class GenError(RuntimeError):
    pass


def sdk_headers() -> tuple[dict[str, str], str]:
    """The text of each needed header, comments removed, and the SDK version they came from."""
    env = msvc_env("x64")
    include = next(v for k, v in env.items() if k.upper() == "INCLUDE")
    found: dict[str, str] = {}
    version = ""
    for folder in include.split(";"):
        for name in HEADERS:
            path = Path(folder) / name
            if name not in found and path.exists():
                text = path.read_text(encoding="latin-1")
                text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
                found[name] = re.sub(r"//[^\n]*", " ", text)
                if name == "d3d11.h":
                    version = path.parent.parent.name
    missing = [n for n in HEADERS if n not in found]
    if missing:
        raise GenError(f"SDK headers not found on the INCLUDE path: {missing}")
    return found, version


def split_params(text: str) -> list[str]:
    out, depth, cur = [], 0, []
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


class Types:
    """Knows which by-value types are one dword on x86."""

    def __init__(self, headers: dict[str, str]):
        everything = "\n".join(headers.values())
        self.enums = set(re.findall(r"\benum\s+(\w+)", everything))
        self.alias = dict((new, old) for old, new in re.findall(r"\btypedef\s+(\w+)\s+(\w+)\s*;", everything))
        self.interfaces = set(re.findall(r"\btypedef\s+interface\s+(\w+)\s+\1\s*;", everything))

    def resolve(self, name: str) -> str:
        seen = set()
        while name in self.alias and name not in SCALAR4 and name not in POINTER4 and name not in seen:
            seen.add(name)
            name = self.alias[name]
        return name

    def is_dword(self, decl: str) -> bool:
        decl = ANNOTATION.sub(" ", decl)
        if "*" in decl or "[" in decl:
            return True
        words = [w for w in decl.split() if w not in ("const", "CONST")]
        if not words:
            return False
        base = self.resolve(words[0])
        return base in SCALAR4 or base in POINTER4 or base in self.enums

    def arg_class(self, decl: str) -> str:
        """How a record of the call shows this argument: v a value, h a handle (its value belongs to one run), g a
        pointer to a GUID, s a string, i an interface pointer, o a pointer to pointers, p any other pointer."""
        decl = ANNOTATION.sub(" ", decl)
        words = [w for w in re.sub(r"[*\[\]]", " ", decl).split() if w not in ("const", "CONST", "struct")]
        base = self.resolve(words[0])
        if decl.count("*") >= 2:
            return "o"
        if "*" in decl or "[" in decl:
            return "i" if words[0] in self.interfaces else "p"
        if base in ("REFIID", "REFGUID"):
            return "g"
        if base in HANDLES:
            return "h"
        if base == "LPCSTR":  # LPSTR is a buffer the call fills
            return "s"
        return "p" if base in POINTER4 else "v"

    def ret_class(self, ret: str) -> str:
        ret = " ".join(ANNOTATION.sub(" ", ret).split())
        if ret == "void":
            return "V"
        if "*" in ret or ret in ("LPVOID", "LPCVOID"):
            return "P"  # a host pointer: the bridge must hand the guest something it can address
        base = self.resolve(ret.split()[-1])
        if base == "FLOAT":
            return "F"  # x87 st(0) on x86: a host shim returning a dword cannot produce it
        if base == "SIZE_T":
            return "Z"  # 8 bytes on the host, a dword for the guest
        if base in SCALAR4 or base in self.enums:
            return "D"
        raise GenError(f"return type {ret!r} is not understood")


METHOD = re.compile(
    r"(?:DECLSPEC_XFGVIRT\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*)?([\w\s\*]+?)\(\s*STDMETHODCALLTYPE\s*\*\s*(\w+)\s*\)\s*\((.*?)\)\s*;",
    re.S,
)


def parse_interfaces(headers: dict[str, str], types: Types) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for text in headers.values():
        parents = dict(re.findall(r'MIDL_INTERFACE\("[0-9A-Fa-f-]{36}"\)\s*(\w+)\s*:\s*public\s+(\w+)', text))
        for m in re.finditer(r"typedef\s+struct\s+(\w+)Vtbl\s*\{\s*BEGIN_INTERFACE(.*?)END_INTERFACE\s*\}\s*\1Vtbl\s*;", text, re.S):
            name = m.group(1)
            if name not in BRIDGED:
                continue
            methods = []
            for slot, mm in enumerate(METHOD.finditer(m.group(2))):
                decl, tagged, ret, method, params = mm.groups()
                if tagged is not None and tagged != method:
                    raise GenError(f"{name}: DECLSPEC_XFGVIRT names {tagged}, the declaration {method}")
                plist = split_params(params)
                bad = [p for p in plist if not types.is_dword(p)]
                if bad:
                    raise GenError(f"{name}::{method}: parameter is not one dword on x86: {bad}")
                methods.append({"decl": decl, "name": method, "slot": slot, "nargs": len(plist), "ret": types.ret_class(ret),
                                "sig": "t" + "".join(types.arg_class(p) for p in plist[1:])})
            out[name] = {"parent": parents.get(name, name), "methods": methods}
    missing = [n for n in BRIDGED if n not in out]
    if missing:
        raise GenError(f"no C vtable declaration found for {missing}")
    for name in BRIDGED:
        info = out[name]
        parent = info["parent"]
        if parent != name and parent not in out:
            raise GenError(f"{name} derives from {parent}, which is not bridged")
        inherited = 0 if parent == name else len(out[parent]["methods"])
        for method in info["methods"]:
            # Older headers have no DECLSPEC_XFGVIRT: the declaring interface is then the first one whose vtable reaches the slot.
            expect = out[parent]["methods"][method["slot"]]["decl"] if method["slot"] < inherited else name
            method["decl"] = method["decl"] or expect
            if method["decl"] != expect:
                raise GenError(f"{name}::{method['name']}: declared by {method['decl']}, slot order says {expect}")
            if method["slot"] < inherited and out[parent]["methods"][method["slot"]]["name"] != method["name"]:
                raise GenError(f"{name} slot {method['slot']} does not repeat {parent}")
    return out


def parse_exports(headers: dict[str, str], types: Types) -> list[tuple[str, str, int, str]]:
    out = []
    for dll, name, header in EXPORTS:
        m = re.search(r"\bHRESULT\s+WINAPI\s+" + name + r"\s*\((.*?)\)\s*;", headers[header], re.S)
        if m is None:
            raise GenError(f"{header} does not declare {name}")
        plist = split_params(m.group(1))
        bad = [p for p in plist if not types.is_dword(p)]
        if bad:
            raise GenError(f"{name}: parameter is not one dword on x86: {bad}")
        out.append((dll, name, len(plist), "".join(types.arg_class(p) for p in plist)))
    return out


def render(interfaces: dict[str, dict], exports: list[tuple[str, str, int, str]], version: str) -> str:
    lines = [
        BEGIN,
        f"/* From the Windows SDK {version} headers. Do not edit: rerun the script.",
        " * I(interface, parent); the root is its own parent.",
        " * M(interface, declaring interface, method, vtable slot, x86 stack dwords including This, return class):",
        " *   V void, D dword, Z SIZE_T, P host pointer, F float in x87 st(0).",
        " * D(interface, method, vtable slot, x86 stack dwords, return class, arguments): the methods an interface",
        " *   declares itself, which is the name a method is registered under. One letter for each argument dword:",
        " *   t This, v value, h handle, g pointer to a GUID, s string, i interface pointer, o pointer to pointers,",
        " *   p other pointer.",
        " * E(import DLL, export, x86 stack dwords, arguments). */",
        "#define B11_IFACES(I) \\",
    ]
    lines += [f"    I({name}, {interfaces[name]['parent']}) \\" for name in BRIDGED]
    lines[-1] = lines[-1][:-2]
    for name in BRIDGED:
        lines.append(f"#define B11_METHODS_{name}(M) \\")
        lines += [
            f"    M({name}, {m['decl']}, {m['name']}, {m['slot']}, {m['nargs']}, '{m['ret']}') \\" for m in interfaces[name]["methods"]
        ]
        lines[-1] = lines[-1][:-2]
    lines.append("#define B11_DECLARED(D) \\")
    lines += [
        f"    D({name}, {m['name']}, {m['slot']}, {m['nargs']}, '{m['ret']}', \"{m['sig']}\") \\"
        for name in BRIDGED
        for m in interfaces[name]["methods"]
        if m["decl"] == name
    ]
    lines[-1] = lines[-1][:-2]
    lines.append("#define B11_EXPORTS(E) \\")
    lines += [f'    E("{dll}", {name}, {nargs}, "{sig}") \\' for dll, name, nargs, sig in exports]
    lines[-1] = lines[-1][:-2]
    lines.append(END)
    return "\n".join(lines)


SHIM_TABLE = "static const shim g_shims[] = {\n"


def check_runner(root: Path, out: Path) -> None:
    """Compiles root's live_main.c with the bridge included, as section 7 of d3d11_bridge.c says to; links it
    against the lifted functions when that checkout has built them. root is only read."""
    source = root / "port" / "lifted_live" / "live_main.c"
    text = source.read_text(encoding="utf-8")
    if "D3D11_BRIDGE_SHIMS" not in text:  # not included yet: add the two lines to a copy
        if text.count(SHIM_TABLE) != 1:
            raise GenError(f"{source} has no shim table to add the bridge to")
        text = text.replace(SHIM_TABLE, f'#define D3D11_BRIDGE_LIVE\n#include "{TARGET.as_posix()}"\n\n{SHIM_TABLE}    D3D11_BRIDGE_SHIMS\n')
    work = out / "runner"
    work.mkdir(parents=True, exist_ok=True)
    copy = work / "live_main_with_bridge.c"
    copy.write_text(text, encoding="utf-8", newline="\n")
    # This checkout's bridge, next to the copy: an include by name finds it there before the runner's own.
    for part in (TARGET, TARGET.with_suffix(".h")):
        shutil.copyfile(part, work / part.name)
    # The flags that checkout builds live.exe with.
    flags = re.search(r"^EXE_CFLAGS = (\[.*\])$", (root / "scripts" / "lift" / "build_live.py").read_text(encoding="utf-8"), re.M)
    cflags = ast.literal_eval(flags.group(1)) if flags else [f for f in RUNTIME_CFLAGS if f not in ("/W4", "/WX")] + ["/W3"]
    obj = work / "live_main.obj"
    log = run_tool(["cl", *cflags, "/c", f"/I{source.parent}", f"/I{TARGET.parent}", f"/I{root / 'port' / 'lifted_runtime'}", f"/Fo{obj}",
                    str(copy)], cwd=work)
    if "warning" in log:
        raise GenError(f"{source} with the bridge included compiles with warnings:\n{log}")
    lib = root / "generated" / "lifted" / "live" / "lifted.lib"
    if lib.exists():
        exe = work / "live_with_bridge.exe"
        run_tool(["link", "/nologo", "/INCREMENTAL:NO", "/DEBUG", f"/STACK:{64 << 20}", f"/OUT:{exe}", str(obj), str(lib)], cwd=work)
        print(f"{source} with the bridge included: compiles and links, {exe}", flush=True)
    else:
        print(f"{source} with the bridge included: compiles (that checkout has no lifted.lib to link against)", flush=True)


def run_test(runner: Path) -> int:
    """The x86 layout proof, the WARP end-to-end test in both configurations, and the real live_main.c."""
    out = GENERATED / "d3d11_bridge"
    out.mkdir(parents=True, exist_ok=True)
    test = TARGET.with_name("test_d3d11_bridge.c")
    # The bridge's 32-bit structures are asserted field by field against the SDK's own under _M_IX86.
    run_tool(["cl", "/nologo", "/std:c17", "/TC", "/W4", "/WX", "/Zs", "/D_CRT_SECURE_NO_WARNINGS", str(TARGET)], cwd=out, arch="x86")
    print("d3d11_bridge.c: 32-bit structure layouts match the x86 SDK headers", flush=True)
    builds = (
        ("test_d3d11_bridge.exe", [str(test), str(TARGET)]),  # the bridge as a source of its own
        ("test_d3d11_bridge_live.exe", ["/DTEST_LIVE", str(test)]),  # the bridge included, as in live_main.c
    )
    for name, sources in builds:
        exe = out / name
        objs = out / exe.stem  # the two builds compile the same test source: keep their objects apart
        objs.mkdir(exist_ok=True)
        run_tool(["cl", *RUNTIME_CFLAGS, f"/Fo{objs}\\", f"/Fe{exe}", *sources, "/link", "/INCREMENTAL:NO"], cwd=out)
        for args in ([], ["--debug-layer"]):
            code = subprocess.run([str(exe), *args], cwd=out).returncode
            if code != 0:
                print(f"{' '.join([name, *args])} failed: exit code {code & 0xffffffff:#x}", file=sys.stderr)
                return 1
    check_runner(runner, out)
    return 0


def main(argv: list[str]) -> int:
    headers, version = sdk_headers()
    types = Types(headers)
    block = render(parse_interfaces(headers, types), parse_exports(headers, types), version)
    text = TARGET.read_text(encoding="utf-8")
    start, end = text.find(BEGIN), text.find(END)
    if start < 0 or end < start:
        raise GenError(f"{TARGET} has no generated-block markers")
    current = text[start:end + len(END)]
    strip = lambda s: re.sub(r"Windows SDK \S+ headers", "Windows SDK headers", s)  # noqa: E731
    if "--check" in argv or "--test" in argv:
        if strip(current) != strip(block):
            print("d3d11_bridge.c: generated block is out of date", file=sys.stderr)
            return 1
        print(f"d3d11_bridge.c: generated block matches the Windows SDK {version} headers", flush=True)
        runner = Path(argv[argv.index("--runner") + 1]).resolve() if "--runner" in argv else ROOT
        return run_test(runner) if "--test" in argv else 0
    if current != block:
        TARGET.write_text(text[:start] + block + text[end + len(END):], encoding="utf-8", newline="\n")
    methods = sum(len(re.findall(r"^    M\(", block, re.M)) for _ in (0,))
    print(f"d3d11_bridge.c: {len(BRIDGED)} interfaces, {methods} vtable slots, {len(EXPORTS)} exports (Windows SDK {version})")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (GenError, BuildError) as e:
        print(f"gen_d3d11_bridge: {e}", file=sys.stderr)
        sys.exit(1)
