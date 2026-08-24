#!/usr/bin/env python3
"""Dispatch N parallel pi -p workers to classify/name decompiled functions.
Each worker gets one shard file (100 addrs) + writes TSV results.
Usage: python dispatch_funcid.py <addr_list> <n_shards>
"""
import subprocess, sys, os, math, shutil
from pathlib import Path

PI = shutil.which('pi') or 'pi'

ADDRS = Path(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 10

addrs = ADDRS.read_text().split()
shards = [addrs[i::N] for i in range(N)]
work = Path('work'); work.mkdir(exist_ok=True)

PROMPT_TMPL = """You are acting as the 'funcid' analyst defined below. Work solo, do not spawn subagents.

{agent_prompt}

YOUR SHARD: read addresses from {shard_file} (one per line).
For each address A: the function source is src_out/empire.retail.dll/decomp/{pfx}A_FUN_A.c
where {{pfx}} is empty (files are named like 101f9770_FUN_101f9770.c).
If that exact file is missing, find it with: ls src_out/empire.retail.dll/decomp | grep -i "^A"

Write TSV lines (append every 10) to: {out_file}
Format: <addr>\t<proposed_name>\t<subsystem>\t<evidence>
Skip any function whose file contains DECOMPILATION FAILED.
Process ALL addresses in your shard, then reply with just: SHARD COMPLETE <count>
"""

AGENT_PROMPT = Path('C:/Users/Clayton/.pi/agent/agents/funcid.md').read_text()
# strip frontmatter
AGENT_PROMPT = AGENT_PROMPT.split('---',2)[-1].strip()

procs = []
for i, shard in enumerate(shards):
    shard_file = work / f'shard_{i:02d}.txt'
    shard_file.write_text('\n'.join(shard))
    out_file = work / f'funcid_{i:02d}.tsv'
    out_file.write_text('')
    prompt = PROMPT_TMPL.format(agent_prompt=AGENT_PROMPT, shard_file=shard_file,
                                pfx='', out_file=out_file)
    log = open(work / f'worker_{i:02d}.log', 'w')
    p = subprocess.Popen([PI, '-p', '--no-session', prompt],
                         stdout=log, stderr=subprocess.STDOUT, cwd='X:/decompilation')
    procs.append((i, p))
    print(f"launched worker {i:02d}: {len(shard)} addrs pid={p.pid}")

codes = [(i, p.wait()) for i, p in procs]
print("exit codes:", codes)
