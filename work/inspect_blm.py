import struct
from pathlib import Path

ROOT = Path("X:/decompilation")
pack_path = ROOT / "Total War Rome II" / "data" / "terrain2_rome2.pack"

with open(pack_path, "rb") as f:
    f.seek(1187586438)
    magic = f.read(4)
    version, layer_count, width, height = struct.unpack("<IIII", f.read(16))
    print(f"BLM Magic={magic}, version={version}, layers={layer_count}, dims={width}x{height}")
    for i in range(layer_count):
        str_len = struct.unpack("<H", f.read(2))[0]
        layer_name = f.read(str_len).decode("latin1")
        entry_count = struct.unpack("<I", f.read(4))[0]
        print(f"  Layer {i}: name=\"{layer_name}\", entries={entry_count}")
        # Each entry
        points = []
        for j in range(min(entry_count, 3)):
            x, y = struct.unpack("<II", f.read(8))
            points.append((x, y))
        if entry_count > 3:
            f.seek((entry_count - 3) * 8, 1)
        print(f"    sample points: {points}")
