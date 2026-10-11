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
        print(f"Layer {i}: '{layer_name}', count={entry_count}")
        # Skip entries
        f.seek(entry_count * 36, 1)

    print("Remaining bytes in file after layers:", len(f.read()))
