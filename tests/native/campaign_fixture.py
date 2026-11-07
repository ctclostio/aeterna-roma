"""Exercise the campaign/VFS loader with a synthetic ESF, without game assets."""
from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    runner = Path(sys.argv[1]).resolve(strict=True)
    tags = [b"CAMPAIGN_STARTPOS", b"SAVE_GAME_HEADER"]
    tags.extend(f"SYNTHETIC_TAG_{index}".encode("ascii") for index in range(48))
    payload = struct.pack("<IIII", 0xABCA, 0, 1532349743, 64) + bytes(48)
    payload += struct.pack("<H", len(tags))
    payload += b"".join(struct.pack("<H", len(tag)) + tag for tag in tags)
    with tempfile.TemporaryDirectory(prefix="rome2-synthetic-campaign-") as directory:
        fixture = Path(directory) / "Total War Rome II/data/campaigns/main_rome/startpos.esf"
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(payload)
        print("Campaign/VFS test input: synthetic ESF; this is not a retail-asset oracle.",
              flush=True)
        return subprocess.run([str(runner)], cwd=directory, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
