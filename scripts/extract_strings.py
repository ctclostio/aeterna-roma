#!/usr/bin/env python3
"""Fast string extraction from PE sections, categorized by engine subsystem.
Usage: python extract_strings.py <binary> <out_txt>"""
import struct, sys, re
from pathlib import Path

SUBSYSTEMS = {
    'render':   r'render|d3d|shader|texture|vertex|pixel|mesh|model|camera|viewport|dx9|dx11|opengl|gpu|draw',
    'battle':   r'battle|unit|formation|melee|charge|moral|regroup|artillery|cavalry|siege|gatling',
    'campaign': r'campaign|faction|settlement|province|diplomat|character|family|army_muster|turn_|region',
    'ai':       r'\bai\b|pathfind|behavi|goal|plan_|navmesh|influence_map',
    'ui':       r'\bui\b|panel|button|menu|hud|tooltip|layout|component',
    'audio':    r'audio|sound|music|voice|\bvo\b|mixer|wavebank',
    'anim':     r'anim|skeleton|rig|bone|facefx|motion',
    'net':      r'\bnet\b|steam|lobby|matchmak|socket|packet|multiplayer',
    'fs':       r'pack|file|stream|archive|vfs',
    'script':   r'script|lua|trigger|event_queue',
}

def main():
    path = Path(sys.argv[1]); out = Path(sys.argv[2])
    data = path.read_bytes()
    # ASCII strings >= 6 chars
    pat = re.compile(rb'[\x20-\x7e]{6,200}')
    seen = set()
    lines = []
    for m in pat.finditer(data):
        s = m.group().decode('ascii')
        if s in seen: continue
        seen.add(s)
        off = m.start()
        lines.append((off, s))
    with open(out, 'w', encoding='utf-8', errors='replace') as f:
        for off, s in lines:
            f.write(f"0x{off:08x}\t{s}\n")
    print(f"{len(lines)} unique strings -> {out}")

    # Subsystem categorization
    counts = {}
    samples = {}
    for off, s in lines:
        for name, rx in SUBSYSTEMS.items():
            if re.search(rx, s, re.I):
                counts[name] = counts.get(name, 0) + 1
                samples.setdefault(name, [])
                if len(samples[name]) < 8: samples[name].append(hex(off) + " " + s[:80])
                break
    print("\nSubsystem string hits:")
    for name, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {name:10} {c}")
        for s_ in samples[name][:4]: print(f"      {s_}")

if __name__ == '__main__':
    main()
