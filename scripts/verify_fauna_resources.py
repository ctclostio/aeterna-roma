"""Independent installed-asset oracle for the native unit-card resource path.

Reads only PFH4 indices plus the requested payload, parses XML with Python's
ElementTree, and compares every semantic word and climate byte to the native
factory probe. No copyrighted XML payload is written into source control.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PATH = 'script/fauna_config.xml'
PINNED = {
    'data.pack': 'd8b2b4cd6b6396557b4562dab565ead806ba8cdbf46c97bb89c0519f24918072',
    'data_rome2.pack': '6b35620de7d8fbed424d8ed2c993270e576e42dca9745826d72dd07c8a02a464',
}
PROBABILITY_BITS = {'0.0': 0, '1.0': 0x3f800000, '0.5': 0x3f000000, '0.25': 0x3e800000,
                    '0.2': 0x3e4ccccd, '0.4': 0x3ecccccd, '0.6': 0x3f19999a, '0.3': 0x3e99999a}
ANIMALS = ('deer', 'wolf', 'lion', 'elephant', 'camel', 'boar', 'horse', 'milan',
           'turtle_dove', 'crow', 'vulture', 'ibis', 'peasant', 'whale', 'seagull')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def ascii_lower(s: str) -> str:
    return s.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))


def payload(pack: Path) -> tuple[bytes, dict]:
    with pack.open('rb') as f:
        header = f.read(28)
        magic, flags, dependencies, dep_bytes, count, index_bytes, _ = struct.unpack('<4s6I', header)
        require(magic == b'PFH4' and flags & ~0x47 == 0 and flags & 7 <= 4, 'unsupported oracle archive')
        deps, index = f.read(dep_bytes), f.read(index_bytes)
        require(len(deps) == dep_bytes and deps.count(b'\0') == dependencies, 'bad dependency index')
        require(len(index) == index_bytes, 'short file index')
        cursor = 0
        offset = 28 + dep_bytes + index_bytes
        found = []
        for _ in range(count):
            length, = struct.unpack_from('<I', index, cursor)
            cursor += 8 if flags & 0x40 else 4
            end = index.index(b'\0', cursor)
            name = ascii_lower(index[cursor:end].decode('utf-8').replace('\\', '/'))
            cursor = end + 1
            if name == PATH:
                found.append((offset, length))
            offset += length
        require(cursor == len(index) and offset <= pack.stat().st_size, 'invalid archive bounds')
        require(len(found) == 1, 'expected one fauna asset')
        start, length = found[0]
        f.seek(start)
        data = f.read(length)
    require(len(data) == length, 'short asset')
    sha = hashlib.sha256(data).hexdigest()
    require(sha == PINNED[pack.name], 'installed fauna asset changed; admit a new oracle explicitly')
    return data, {'archive': pack.name, 'archive_bytes': pack.stat().st_size,
                  'header_and_index_sha256': hashlib.sha256(header + deps + index).hexdigest(),
                  'path': PATH, 'payload_offset': start, 'payload_bytes': length, 'payload_sha256': sha}


def expected(data: bytes) -> list[dict]:
    root = ET.fromstring(data)
    require(root.tag == 'fauna_config', 'unexpected root')
    result = []
    for animal in root:
        name = ascii_lower(animal.tag)
        words = [ANIMALS.index(name) if name in ANIMALS else 0]
        for key in ('min_entities', 'max_entities'):
            text = animal.findtext(key, '')
            words.append((int(text or '0') & 0xffffffff) if re.fullmatch('[0-9]*', text) else 0)
        # Independent golden bit table for the actual shipped finite tokens.
        # This does not reuse/approximate the native normalized CRT algorithm.
        words.append(PROBABILITY_BITS[animal.findtext('spawn_probability', '0.0')])
        spawn = animal.find('spawn_conditions')
        for key, values, any_mask in (
            ('tile', {'inland': 1, 'open_sea': 2, 'coastal': 4}, 0),
            ('season', {'spring': 1, 'summer': 2, 'autumn': 4, 'winter': 8}, 15),
            ('time_of_day', {'day': 1, 'night': 2}, 3),
            ('precipitation', {'dry': 1, 'rain': 2, 'snow': 4, 'fog': 8}, 15),
        ):
            mask = 0
            for node in (() if spawn is None else spawn):
                if node.tag == key:
                    value = ascii_lower(node.text or '')
                    mask = any_mask if value == 'any' and any_mask else mask | values.get(value, 0)
            words.append(mask)
        climates = []
        for node in (() if spawn is None else spawn):
            if node.tag == 'climate':
                units = (node.text or '').encode('utf-16le')
                encoded = b''.join(chr(u).encode('utf-8', errors='surrogatepass')
                                   for (u,) in struct.iter_unpack('<H', units))
                climates.append(encoded.lower().hex())
        result.append({'words': words, 'climates_hex': climates})
    return result


def check(probe: Path, packs: list[Path], records: list[dict]) -> None:
    proc = subprocess.run([str(probe), *map(str, packs)], capture_output=True, text=True, check=True)
    actual = json.loads(proc.stdout)
    require(actual == {'selected_archive': 0, 'records': records}, 'native decoded records differ from asset oracle')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--data-root', type=Path, default=ROOT / 'Total War Rome II/data')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    archives = [args.data_root / name for name in PINNED]
    report = {'schema': 'rome2-fauna-assets-v1', 'verified': True, 'archives': []}
    decoded = []
    for pack in archives:
        data, entry = payload(pack)
        records = expected(data)
        check(args.probe.resolve(), [pack.resolve()], records)
        entry['record_count'] = len(records)
        entry['semantic_records_sha256'] = hashlib.sha256(json.dumps(records, sort_keys=True).encode()).hexdigest()
        report['archives'].append(entry)
        decoded.append(records)
    check(args.probe.resolve(), [archives[1].resolve(), archives[0].resolve()], decoded[1])
    check(args.probe.resolve(), [archives[0].resolve(), archives[1].resolve()], decoded[0])
    report['explicit_precedence_orders_checked'] = 2
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
