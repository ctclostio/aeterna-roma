import struct
from pathlib import Path

path = Path("Total War Rome II/data/campaigns/main_rome/startpos.esf")
with open(path, "rb") as f:
    f.seek(12)
    tbl_off = struct.unpack("<I", f.read(4))[0]
    f.seek(tbl_off)
    tag_count = struct.unpack("<H", f.read(2))[0]
    tags = []
    for _ in range(tag_count):
        l = struct.unpack("<H", f.read(2))[0]
        tags.append(f.read(l).decode("latin1"))

    f.seek(16)
    
    def read_vlq(f):
        val = 0
        while True:
            b = f.read(1)[0]
            val = (val << 7) | (b & 0x7f)
            if not (b & 0x80):
                break
        return val

    # Root record
    tag_byte = f.read(1)[0] # 0x80
    tag_idx = struct.unpack("<H", f.read(2))[0] # 0
    ver = f.read(1)[0] # 9
    payload_len = read_vlq(f)
    print(f"ROOT: tag='{tags[tag_idx]}', ver={ver}, payload_len={payload_len}")

    # Now let's inspect the next token inside ROOT
    for i in range(10):
        pos = f.tell()
        tb = f.read(1)[0]
        if tb == 0x80 or tb == 0x81:
            t_idx = struct.unpack("<H", f.read(2))[0]
            t_ver = f.read(1)[0]
            p_len = read_vlq(f)
            t_name = tags[t_idx] if t_idx < len(tags) else f"UNKNOWN_{t_idx}"
            print(f"  CHILD RECORD: tag='{t_name}' (idx={t_idx}), ver={t_ver}, len={p_len} at {pos}")
        elif tb >= 0x80:
            print(f"  TAG 0x{tb:02x} at {pos}")
        else:
            # Primitive value
            print(f"  PRIMITIVE 0x{tb:02x} at {pos}")
            # Rewind and skip or inspect
            break
