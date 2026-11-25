"""End-to-end self-test of the lifted tier: both sides on the same synthetic images.

    python scripts/lift/selftest_e2e.py

No game image is needed. Hand-encoded snippets are lifted and built into a
runner, and the same job file goes through the reference debugger and the
runner. For every trial that is comparable the two result lines must be the
same text (terminal, digest, steps), and the two traces must be the same apart
from page lines. Three suites run:

  events    snippets written for this test: one per kind of event, terminal
            and memory record, including the cases that once differed between
            the sides;
  core, fp  the lifted side's own synthetic suites (selftest_lift.py), here
            checked against the reference instead of against expectations.

Every fast trial also runs in step mode. At the end the test requires that
each kind was actually seen in a trial that matched, so a suite that silently
stopped exercising something fails instead of passing vacuously.

Everything is written under generated/lifted/selftest_e2e/.
"""
from __future__ import annotations

import collections
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_batch  # noqa: E402
import build_ref  # noqa: E402
import selftest_lift as sl  # noqa: E402
from image import GENERATED  # noqa: E402
from selftest_lift import FAST, SENTINEL, STACK_TOP, STEP, T_EXC, T_FAULT, T_LEAVE, T_STEP, Checker, Suite, le32  # noqa: E402

WORK = GENERATED / "selftest_e2e"
S_OK, S_FOREIGN, S_UNSUPPORTED, S_HARNESS = 0, 2, 4, 5
STEP_TWIN_BUDGET = 100000
MODEL_TEB = sl.MODEL_TEB
GP_ADDRESS = 0xFFFFFFFF
LOW_ZONE_END = 0x1000000
EXC_NAMES = {1: "div", 2: "bkpt", 3: "ill", 4: "priv", 5: "fp", 6: "trap"}
TERMINAL_NAMES = {T_LEAVE: "leave", T_FAULT: "fault", T_EXC: "exc", T_STEP: "step"}

# Trials that are excluded by the protocol, by function name: (reference status, lifted status).
# None stands for LM_S_OK with whatever terminal that side reports.
BY_DESIGN = {
    "high_zone": (None, S_FOREIGN),        # the address is in the zone that is always foreign
    "fs_access": (S_HARNESS, None),        # reaches the TEB page by flat address
    "self_modify": (None, S_UNSUPPORTED),  # rewrites an instruction of its own body
}

# Kinds that must be seen in at least one matching trial.
REQUIRED = (
    ["fast:" + k for k in ("leave", "fault", "exc")]
    + ["step:" + k for k in ("leave", "fault", "exc", "step")]
    + ["exc:" + k for k in EXC_NAMES.values()]
    + ["fault:gp", "leave:sentinel", "leave:elsewhere", "call", "call:fp_ret", "call:fast", "call:step"]
    + [f"insn:{k}" for k in (1, 2, 4, 5)]
    + ["mem:arena", "mem:image", "mem:teb"]
)


def build_events_suite() -> Suite:
    """One snippet per kind of event, terminal and memory record."""
    s = Suite("events")

    def each(f, **exp):
        for seed in (1, 2, 3):
            s.expect(f, seed=seed, **exp)

    callee = s.fn("ev_callee", "c3 | ret")
    callee_fp = s.fn("ev_callee_fp", "c2 04 00 | ret 4", pop_bytes=4, fp_ret=True)

    f = s.fn("clean_return", """
        b8 2a 00 00 00    | mov eax, 0x2a
        c3                | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL, b=0)

    f = s.fn("jmp_register", "ff e1 | jmp ecx")
    for seed in (1, 2, 3):
        s.expect(f, seed=seed, kind=T_LEAVE, a=sl.init_gpr(seed)[1], b=0)

    f = s.fn("direct_call", """
        6a 07                           | push 7
        e8 {rel32:ev_callee_fp}         | call {ev_callee_fp}
        dd d8                           | fstp st(0)
        c3                              | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)

    # An indirect call has no contract row: its stub pops nothing and returns a
    # float because the instruction after it consumes ST(0).
    f = s.fn("indirect_call", """
        bf 00 01 00 30                  | mov edi, 0x30000100
        ff 15 {abs32:EV_PTRS}           | call dword ptr [{EV_PTRS}]
        d9 1f                           | fstp dword ptr [edi]
        ff d0                           | call eax
        c3                              | ret
    """)
    s.synth.table("EV_PTRS", [callee.addr])
    each(f, kind=T_LEAVE, a=SENTINEL)

    # A ret that leaves the body with a call site on top of the stack is a call
    # event like any other: only the target and [ESP] decide.
    f = s.fn("ret_as_call", """
        31 db                           | xor ebx, ebx
        e8 {rel32:ev_callee}            | call {ev_callee}
        @a: 43                          | inc ebx
        83 fb 02                        | cmp ebx, 2
        74 {rel8:@done}                 | je {@done}
        68 {abs32:@a}                   | push {@a}
        68 {abs32:ev_callee}            | push {ev_callee}
        c3                              | ret
        @done: c3                       | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)

    # The call is the last instruction and its return address is the jump table
    # behind the body, which is a data window: the stub returns outside the
    # body and the trial ends there without executing table bytes.
    f = s.fn("return_into_window", """
        31 c0                           | xor eax, eax
        ff 24 85 {abs32:EV_WINDOW}      | jmp dword ptr [eax*4 + {EV_WINDOW}]
        @c: e8 {rel32:ev_callee}        | call {ev_callee}
    """)
    window = f.addr + f.size
    s.synth.symbols["EV_WINDOW"] = window
    s.synth.put(window, le32(f.at("@c")))
    s.synth.cursor += 16
    each(f, kind=T_LEAVE, a=window, b=0)

    f = s.fn("stubbed_all", """
        0f a2             | cpuid
        89 c6             | mov esi, eax
        0f 31             | rdtsc
        89 d7             | mov edi, edx
        0f 01 f9          | rdtscp
        89 cb             | mov ebx, ecx
        31 c9             | xor ecx, ecx
        0f 01 d0          | xgetbv
        c3                | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)

    f = s.fn("trap_insn", """
        40                | inc eax
        @f: cd 29         | int 0x29
        c3                | ret
    """)
    each(f, kind=T_EXC, a=f.at("@f"), b=6)
    for name, code, text, cls in (("bkpt", "cc", "int3", 2), ("illegal", "0f 0b", "ud2", 3), ("privileged", "f4", "hlt", 4)):
        f = s.fn(name, f"40 | inc eax\n @f: {code} | {text}\n c3 | ret")
        each(f, kind=T_EXC, a=f.at("@f"), b=cls)

    f = s.fn("divide_error", """
        31 c9             | xor ecx, ecx
        @f: f7 f1         | div ecx
        c3                | ret
    """)
    each(f, kind=T_EXC, a=f.at("@f"), b=1)

    f = s.fn("x87_exception", """
        6a 00                   | push 0
        66 c7 04 24 7b 02       | mov word ptr [esp], 0x27b
        d9 2c 24                | fldcw word ptr [esp]
        d9 e8                   | fld1
        d9 ee                   | fldz
        de f9                   | fdivp st(1)
        @w: 9b                  | wait
        c3                      | ret
    """)
    each(f, kind=T_EXC, a=f.at("@w"), b=5)

    f = s.fn("fault_read", """
        b8 00 00 00 70    | mov eax, 0x70000000
        @f: 8b 00         | mov eax, dword ptr [eax]
        c3                | ret
    """)
    each(f, kind=T_FAULT, a=f.at("@f"), b=0x70000000)

    f = s.fn("fault_gp", """
        bf 01 00 00 30    | mov edi, 0x30000001
        @f: 0f 28 07      | movaps xmm0, xmmword ptr [edi]
        c3                | ret
    """)
    each(f, kind=T_FAULT, a=f.at("@f"), b=GP_ADDRESS)

    f = s.fn("stores", """
        bf 00 02 00 30                      | mov edi, 0x30000200
        c7 07 44 33 22 11                   | mov dword ptr [edi], 0x11223344
        50                                  | push eax
        c7 05 {abs32:EV_DATA} 78 56 34 12   | mov dword ptr [{EV_DATA}], 0x12345678
        c6 05 {abs32:EV_TAIL} 5a            | mov byte ptr [{EV_TAIL}], 0x5a
        58                                  | pop eax
        c3                                  | ret
    """)
    s.synth.table("EV_DATA", [0])
    s.synth.symbols["EV_TAIL"] = f.addr + f.size + 3  # on the body's own page, outside the body
    s.synth.cursor += 16
    each(f, kind=T_LEAVE, a=SENTINEL)

    # FS-relative accesses only; reaching the TEB page by flat address is excluded on the reference.
    f = s.fn("teb", """
        64 a1 30 00 00 00           | mov eax, dword ptr fs:[0x30]
        64 89 0d 00 07 00 00        | mov dword ptr fs:[0x700], ecx
        64 8b 1d 00 07 00 00        | mov ebx, dword ptr fs:[0x700]
        64 ff 05 04 07 00 00        | inc dword ptr fs:[0x704]
        c3                          | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)

    # PUSHFD must not show the reference's trap flag in step mode; POPFD sets DF for the terminal.
    f = s.fn("flags_image", """
        9c                | pushfd
        58                | pop eax
        68 02 06 00 00    | push 0x602
        9d                | popfd
        c3                | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)

    f = s.fn("rep_string", """
        bf 00 03 00 30    | mov edi, 0x30000300
        b9 06 00 00 00    | mov ecx, 6
        b0 a5             | mov al, 0xa5
        f3 aa             | rep stosb byte ptr es:[edi], al
        c3                | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)
    s.expect(f, seed=1, mode=STEP, budget=5, kind=T_STEP)

    # A page-straddling operand that a thunk only reads must not be written
    # back later: the integer store between the two SSE instructions stays.
    f = s.fn("straddling_load", """
        bf fe 0f 00 30                  | mov edi, 0x30000ffe
        f3 0f 10 07                     | movss xmm0, dword ptr [edi]
        c7 07 44 33 22 11               | mov dword ptr [edi], 0x11223344
        f3 0f 11 05 00 20 00 30         | movss dword ptr [0x30002000], xmm0
        8b 07                           | mov eax, dword ptr [edi]
        c3                              | ret
    """)
    each(f, kind=T_LEAVE, a=SENTINEL)

    # Shared user data: real memory in the reference child, outside the model.
    f = s.fn("high_zone", """
        a1 00 00 fe 7f    | mov eax, dword ptr [0x7ffe0000]
        c3                | ret
    """)
    each(f)

    # The original runs the byte it stored (a nop where inc eax was); the
    # translation cannot, so the lifted side gives the trial up.
    f = s.fn("self_modify", """
        c6 05 {abs32:@p} 90     | mov byte ptr [{@p}], 0x90
        @p: 40                  | inc eax
        c3                      | ret
    """)
    each(f)

    f = s.fn("endless", """
        @l: 40            | inc eax
        eb {rel8:@l}      | jmp {@l}
    """)
    s.expect(f, seed=1, mode=STEP, budget=50, kind=T_STEP, a=f.at("@l"))
    s.expect(f, seed=1, mode=STEP, budget=51, kind=T_STEP)
    return s


def run_tool(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run([str(x) for x in cmd], capture_output=True, text=True)


def split_trace(text: str) -> list[list[str]]:
    """Trace output -> one list of lines per trial, page lines left out."""
    trials: list[list[str]] = []
    for line in text.splitlines():
        if line.startswith("trial "):
            trials.append([])
        if trials and not line.startswith("page "):
            trials[-1].append(line)
    return trials


def fixed_environment(path: Path) -> list[str]:
    """Environment file lines without the low-zone foreign ranges, which describe one child."""
    return [line for line in path.read_text(encoding="ascii").splitlines()
            if not (line.startswith("foreign ") and int(line.split()[1], 16) < LOW_ZONE_END)]


def call_sites(job_file: Path) -> dict[int, int]:
    """Return address -> fp_ret, over the whole job file."""
    out = {}
    for line in job_file.read_text(encoding="ascii").splitlines():
        if line.startswith("C "):
            _, site, _, fp_ret = line.split()
            out[int(site, 16)] = int(fp_ret)
    return out


def note_kinds(seen: collections.Counter, mode: int, fields: list[str], trace: list[str], sites: dict[int, int],
               image_range: tuple[int, int]) -> None:
    tkind, a, b = int(fields[4]), int(fields[5], 16), int(fields[6], 16)
    prefix = "fast" if mode == FAST else "step"
    seen[f"{prefix}:{TERMINAL_NAMES[tkind]}"] += 1
    if tkind == T_EXC:
        seen[f"exc:{EXC_NAMES.get(b, b)}"] += 1
    if tkind == T_FAULT and b == GP_ADDRESS:
        seen["fault:gp"] += 1
    if tkind == T_LEAVE:
        seen["leave:sentinel" if a == SENTINEL else "leave:elsewhere"] += 1
    for line in trace:
        tok = line.split()
        if tok[0] == "call":
            site = int(dict(t.split("=", 1) for t in tok[2:])["site"], 16)
            seen["call"] += 1
            seen[f"call:{prefix}"] += 1
            if sites.get(site):
                seen["call:fp_ret"] += 1
        elif tok[0] == "insn":
            seen["insn:" + tok[2].split("=")[1]] += 1
        elif tok[0] == "mem":
            addr = int(tok[1], 16)
            if image_range[0] <= addr < image_range[1]:
                seen["mem:image"] += 1
            elif addr & ~0xFFF == MODEL_TEB:
                seen["mem:teb"] += 1
            else:
                seen["mem:arena"] += 1


def run_suite(c: Checker, suite: Suite, ref_dbg: Path, seen: collections.Counter) -> dict:
    synth = suite.synth
    name = synth.name
    work = WORK / name
    work.mkdir(parents=True, exist_ok=True)
    synth.path = work / "image.bin"
    synth.finish(c)

    trials: dict[int, list] = {}
    expectations: dict[int, list] = {}
    names = {f.addr: f.name for f in synth.fns.values()}
    for f, seed, mode, budget, exp in suite.cases:
        trials.setdefault(f.addr, []).append((seed, mode, budget))
        expectations.setdefault(f.addr, []).append(exp)
        if mode == FAST:  # the same trial, stepped
            trials[f.addr].append((seed, STEP, STEP_TWIN_BUDGET))
            expectations[f.addr].append({k: v for k, v in exp.items() if k in ("kind", "a", "b", "status")})
    with synth.installed() as meta_for:
        batch = build_batch.build_batch(list(trials), work, trials, meta_for=meta_for)
    for info in batch.functions.values():
        c.eq(f"{name} {names[info.entry]}: untranslated instructions", info.unsupported, [])
    order = [(entry, t, exp) for entry in sorted(trials) for t, exp in zip(trials[entry], expectations[entry])]
    sites = call_sites(batch.job_file)

    env = work / "env.txt"
    common = ["--image", synth.path, "--jobs", batch.job_file]
    runs = {
        "ref": run_tool([ref_dbg, *common, "--out", work / "ref.out", "--env", env]),
        "ref_traced": run_tool([ref_dbg, *common, "--out", work / "ref_traced.out", "--env", work / "env_traced.txt",
                                "--trace", "0", "0"]),
    }
    if not c.eq(f"{name}: ref_dbg exit status", (runs["ref"].returncode, runs["ref_traced"].returncode), (0, 0)):
        print(runs["ref"].stderr[-2000:], runs["ref_traced"].stderr[-2000:])
        return {}
    # Each runner run takes the environment of the reference run it is compared with.
    runs["lift"] = run_tool([batch.runner, *common, "--env", env, "--out", work / "lift.out"])
    runs["lift_traced"] = run_tool([batch.runner, *common, "--env", work / "env_traced.txt",
                                    "--out", work / "lift_traced.out", "--trace", "0", "0"])
    if not c.eq(f"{name}: runner exit status", (runs["lift"].returncode, runs["lift_traced"].returncode), (0, 0)):
        print(runs["lift"].stderr[-2000:], runs["lift_traced"].stderr[-2000:])
        return {}
    c.eq(f"{name}: the environment is the same for every reference run", fixed_environment(env),
         fixed_environment(work / "env_traced.txt"))
    (work / "ref.trace").write_text(runs["ref_traced"].stdout, encoding="ascii", newline="\n")
    (work / "lift.trace").write_text(runs["lift_traced"].stdout, encoding="ascii", newline="\n")

    lines = {k: (work / f"{k}.out").read_text(encoding="ascii").splitlines()
             for k in ("ref", "ref_traced", "lift", "lift_traced")}
    for k, got in lines.items():
        c.eq(f"{name}: {k} result lines", len(got), len(order))
    c.eq(f"{name}: reference results do not depend on tracing", lines["ref"], lines["ref_traced"])
    c.eq(f"{name}: lifted results do not depend on tracing", lines["lift"], lines["lift_traced"])
    traces = {"ref": split_trace(runs["ref_traced"].stdout), "lift": split_trace(runs["lift_traced"].stdout)}
    c.eq(f"{name}: traced trials", (len(traces["ref"]), len(traces["lift"])), (len(order), len(order)))
    if any(len(got) != len(order) for got in lines.values()) or any(len(t) != len(order) for t in traces.values()):
        return {}

    image_range = (sl.IMAGE_BASE, sl.IMAGE_BASE + len(synth.buf))
    stats = collections.Counter()
    for n, (entry, (seed, mode, budget), exp) in enumerate(order):
        what = f"{name}/{names[entry]} seed {seed:x} mode {mode} budget {budget}"
        ref, lift = lines["ref"][n].split(), lines["lift"][n].split()
        key = [f"{entry:x}", f"{seed:x}", str(mode)]
        c.eq(f"{what}: reference line is this trial's", ref[:3], key)
        c.eq(f"{what}: lifted line is this trial's", lift[:3], key)
        statuses = (int(ref[3]), int(lift[3]))
        if names[entry] in BY_DESIGN:
            want = BY_DESIGN[names[entry]]
            c.eq(f"{what}: excluded by design, statuses", statuses, tuple(w if w is not None else S_OK for w in want))
            stats["excluded by design"] += 1
            continue
        if not c.eq(f"{what}: both sides finished the trial", statuses, (S_OK, S_OK)):
            continue
        same = c.eq(f"{what}: result line", " ".join(lift), " ".join(ref))
        c.eq(f"{what}: trace", traces["lift"][n], traces["ref"][n])
        for field, index in (("kind", 4), ("a", 5), ("b", 6)):
            if field in exp:
                c.eq(f"{what}: terminal {field}", int(ref[index], 16), exp[field])
        if same:
            stats["matched"] += 1
            note_kinds(seen, mode, ref, traces["ref"][n], sites, image_range)
    return dict(stats)


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    ref_dbg, _ = build_ref.build()
    c = Checker()
    seen: collections.Counter = collections.Counter()
    for build in (build_events_suite, sl.build_core_suite, sl.build_fp_suite):
        since = len(c.failures)
        suite = build()
        stats = run_suite(c, suite, ref_dbg, seen)
        print(f"  {suite.synth.name}: {len(suite.synth.fns)} functions; "
              + ", ".join(f"{k} {v}" for k, v in sorted(stats.items())))
        c.report(suite.synth.name, since)
    since = len(c.failures)
    for kind in REQUIRED:
        c.ok(f"kind {kind} seen in a matching trial", seen[kind] > 0)
    print("  kinds seen in matching trials: " + ", ".join(f"{k} {seen[k]}" for k in sorted(seen)))
    c.report("kinds", since)
    print(f"{c.checks} checks, {len(c.failures)} failures")
    return 1 if c.failures else 0


if __name__ == "__main__":
    sys.exit(main())
