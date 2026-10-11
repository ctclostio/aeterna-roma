"""End-to-end oracle for the compiled native diagnostic (not native teardown)."""
import json
from pathlib import Path
import subprocess
import sys

# Literal instruction-derived expectations, independent of the C tables.
TAIL = [
    [1, 0x100edf41, 7, 0, 0, 12, 8, -4, 0xffffffff, 4],
    [2, 0x100edf48, 2, 0x100edf94, 0, 0, 0, 0, 0, 2],
]
EPILOGUE = [
    [3, 0x100edf94, 6, 0x1172f934, 0, 0, 0, 0, 0, 0],
    [4, 0x100edf9a, 5, 0, 0x119f3144, 11, 1, 0, 0, 1],
    [5, 0x100edf9f, 3, 0, 0, 8, 2, -16, 0, 4],
    [6, 0x100edfa2, 7, 0, 0, 2, 9, 0, 0, 4],
    [7, 0x100edfa9, 1, 0, 0, 10, 3, 0, 0, 4],
    [8, 0x100edfaa, 1, 0, 0, 10, 4, 0, 0, 4],
    [9, 0x100edfab, 1, 0, 0, 10, 5, 0, 0, 4],
    [10, 0x100edfac, 2, 0, 0, 7, 6, 0, 0, 4],
    [11, 0x100edfae, 1, 0, 0, 10, 7, 0, 0, 4],
    [12, 0x100edfaf, 1, 0, 0, 0, 0, 0, 0, 0],
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    exe = Path(sys.argv[1]).resolve()
    runs = 0
    for policy, argument in enumerate(('install', 'skip')):
        expected = dict(mode='inert-transcript', policy=policy,
                        tail_count=2 if policy == 0 else 0, epilogue_count=10,
                        tail=TAIL if policy == 0 else [[0] * 10, [0] * 10],
                        epilogue=EPILOGUE, return_source_identity=0x119f3144,
                        return_original_pc=0x100edfaf)
        previous = None
        for _ in range(2):
            result = subprocess.run([str(exe), argument], capture_output=True,
                                    timeout=10)
            require(result.returncode == 0, repr(result))
            require(result.stderr == b'', result.stderr)
            # MSVC stdout is in text mode: the runner's newline emits CRLF.
            canonical = (json.dumps(expected, separators=(',', ':')) + '\r\n').encode('ascii')
            require(result.stdout == canonical,
                    f'unexpected stdout bytes: {result.stdout!r}')
            if previous is not None:
                require(result.stdout == previous, 'nondeterministic output')
            else:
                print(f'{argument}: exit={result.returncode} stdout={result.stdout.decode("ascii").strip()}')
            previous = result.stdout
            runs += 1
    for args in ([], ['invalid'], ['INSTALL'], ['install', 'skip']):
        result = subprocess.run([str(exe), *args], capture_output=True,
                                timeout=10)
        require(result.returncode == 2, repr(result))
        require(result.stdout == b'', 'invalid input emitted a transcript')
        require(result.stderr == b'usage: terminal_runner install|skip\r\n', result.stderr)
        runs += 1
    print(f'PASS: {runs} native process runs; all output fields and exit codes checked')


if __name__ == '__main__':
    main()
