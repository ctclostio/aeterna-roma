"""Image and function inventory for the lifted tier (see docs/lifted_tier.md)."""
from __future__ import annotations

import csv
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IMAGE_PATH = ROOT / "Total War Rome II" / "empire.retail.dll"
CONTRACTS = ROOT / "work" / "binary_contracts"
GENERATED = ROOT / "generated" / "lifted"
IMAGE_BASE = 0x10000000
PAGE = 4096
FP_RETURN_TYPES = frozenset({"float", "double", "float10"})


@dataclass(frozen=True)
class Function:
    addr: int
    name: str
    ranges: tuple[tuple[int, int], ...]  # (lo, hi_exclusive), ascending
    sha256: str
    pop_bytes: int
    fp_ret: bool

    @property
    def size(self) -> int:
        return sum(hi - lo for lo, hi in self.ranges)

    def contains(self, addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in self.ranges)


def map_image(raw: bytes) -> bytes:
    """Lay the PE file out as the loader maps it at its preferred base.

    No relocations are applied and no imports are resolved. Each section gets
    its raw bytes up to its virtual size rounded to the section alignment; the
    rest is zero.
    """
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    n_sections, = struct.unpack_from("<H", raw, pe + 6)
    opt_size, = struct.unpack_from("<H", raw, pe + 20)
    opt = pe + 24
    if struct.unpack_from("<H", raw, opt)[0] != 0x10B:
        raise ValueError("not a PE32 image")
    base, section_align = struct.unpack_from("<II", raw, opt + 28)
    size_of_image, size_of_headers = struct.unpack_from("<II", raw, opt + 56)
    if base != IMAGE_BASE:
        raise ValueError(f"unexpected image base {base:#x}")
    size = (size_of_image + PAGE - 1) & ~(PAGE - 1)
    out = bytearray(size)
    out[:size_of_headers] = raw[:size_of_headers]
    table = opt + opt_size
    for i in range(n_sections):
        virtual_size, rva, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, table + 40 * i + 8)
        span = (max(virtual_size, 1) + section_align - 1) & ~(section_align - 1)
        n = min(raw_size, span, len(raw) - raw_ptr)
        out[rva:rva + n] = raw[raw_ptr:raw_ptr + n]
    return bytes(out)


@lru_cache(maxsize=1)
def load_image() -> bytes:
    return map_image(IMAGE_PATH.read_bytes())


def flat_image_path() -> Path:
    """Write the mapped image once so the C tools load it without parsing PE."""
    path = GENERATED / "image.bin"
    if not path.exists():
        GENERATED.mkdir(parents=True, exist_ok=True)
        path.write_bytes(load_image())
    return path


def parse_ranges(text: str) -> tuple[tuple[int, int], ...]:
    out = []
    for part in text.split(";"):
        lo, hi = part.split("-")
        out.append((int(lo, 16), int(hi, 16) + 1))
    return tuple(sorted(out))


@lru_cache(maxsize=1)
def load_functions() -> tuple[Function, ...]:
    rows = []
    for part in ("function_contracts_part1.tsv", "function_contracts_part2.tsv"):
        with open(CONTRACTS / part, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh, delimiter="\t"):
                rows.append(Function(
                    addr=int(r["address"], 16),
                    name=r["name"],
                    ranges=parse_ranges(r["body_ranges"]),
                    sha256=r["sha256"],
                    pop_bytes=int(r["callee_pop_bytes"] or 0),
                    fp_ret=r["return_type"] in FP_RETURN_TYPES,
                ))
    rows.sort(key=lambda f: f.addr)
    return tuple(rows)


@lru_cache(maxsize=1)
def function_index() -> dict[int, Function]:
    return {f.addr: f for f in load_functions()}
