#!/usr/bin/env python3
"""Dispatch N parallel pi -p workers to classify/name decompiled functions.
v2: absolute paths, imperative first-action, per-worker timeout.
Usage: python dispatch_funcid.py <addr_list> <n_shards>
"""
import subprocess, sys, os, shutil
from pathlib import Path

ROOT = Path('X:/decompilation')
ADDRS = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'work/batch1_addrs.txt'
N = int(sys.argv[2]) if len(sys.argv) > 2 else 10
TIMEOUT = int(sys.argv[3]) if len(sys.argv) > 3 else 3600

PI = shutil.which('pi') or 'pi'
work = ROOT / 'work'; work.mkdir(exist_ok=True)

addrs = [a.strip() for a in ADDRS.read_text().split() if a.strip()]
shards = [addrs[i::N] for i in range(N)]

PROMPT_TMPL = """You are the funcid analyst (reverse-engineering decompiled C). Execute this mission NOW, solo.

FIRST ACTION (mandatory, do not skip, do not ask questions): use your read tool on:
{shard_file_abs}

That file lists function addresses, one per line. For each address A in it, analyze the file:
{decomp_dir}\\{{A}}_FUN_{{A}}.c
If missing, run: ls "{decomp_dir}" | grep -i "^{{A}}"

ANALYST RULES:
{agent_prompt}

OUTPUT CONTRACT (mandatory): append TSV lines to exactly this path as you go (every 5-10 functions):
{out_file_abs}
Line format: {{addr}}<TAB>{{proposed_name}}<TAB>{{subsystem}}<TAB>{{short evidence}}
Use bash echo >> or a python one-liner to append. Never hold all results until the end.

When every address is processed, reply with exactly: SHARD COMPLETE <count>
If you cannot access files, reply SHARD FAILED <reason>.
"""

agent_md = (Path('C:/Users/Clayton/.pi/agent/agents/funcid.md')).read_text()
AGENT_PROMPT = agent_md.split('---', 2)[-1].strip()

procs = []
for i, shard in enumerate(shards):
    shard_file = work / f'shard_{i:02d}.txt'
    shard_file.write_text('\n'.join(shard))
    out_file = work / f'funcid_{i:02d}.tsv'
    out_file.write_text('')
    prompt = PROMPT_TMPL.format(
        shard_file_abs=str(shard_file).replace('/', '\\'),
        decomp_dir=str(ROOT / 'src_out/empire.retail.dll/decomp'),
        agent_prompt=AGENT_PROMPT,
        out_file_abs=str(out_file).replace('/', '\\'),
    )
    log = open(work / f'worker_{i:02d}.log', 'w', encoding='utf-8')
    p = subprocess.Popen([PI, '-p', '--no-session', prompt],
                         stdout=log, stderr=subprocess.STDOUT, cwd=str(ROOT))
    procs.append((i, p))
print(f"launched {len(procs)} workers", flush=True)

import time
deadline = time.time() + TIMEOUT
alive = dict(procs)
while alive and time.time() < deadline:
    # ⚡ Bolt: Reduced polling interval from 20s to 0.5s for faster completion detection
    time.sleep(0.5)
    for i, p in list(alive.items()):
        if p.poll() is not None:
            done = sum(1 for _, pp in procs if pp.poll() is not None)
            print(f"worker {i:02d} exited code={p.returncode} ({done}/{len(procs)} done)", flush=True)
            del alive[i]
for i, p in alive.items():
    print(f"worker {i:02d} TIMEOUT - killing", flush=True)
    p.kill()
print("ALL WORKERS FINISHED", flush=True)
