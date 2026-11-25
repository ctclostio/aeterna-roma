# Lifted tier: mechanically lifted functions, verified against the original bytes

The handwritten tier in `port/recovered_types/` models functions by hand with
named layouts. This tier is generated: every canonical function is translated
instruction by instruction into C, and the C is differential-tested against
the original machine code running on the host CPU. It pins behaviour with raw
offsets, not named types, and is always reported separately from handwritten
work.

`port/lifted_runtime/lift_model.h` is the authoritative contract for trial
inputs, stubs and the digest. This document describes everything around it.

## What a verified function means

For a function `F` and a seed, both sides start from the same register,
x87/SSE and memory state, run until control leaves `F` for good, and produce a
64-bit digest over every call `F` made (target, registers, stack words,
x87/SSE state), the terminal event, the final machine state and every memory
byte that changed. `F` is **verified** when

- every instruction in its body ranges was translated,
- at least 8 trials were comparable (see "Excluded trials"), and
- every comparable trial has the same terminal record and digest on both sides.

Callees are never executed. Each call is an event followed by a deterministic
stub, so every function is verified in isolation. Instruction coverage
(executed instruction addresses / instructions in the body, over matching
trials) is recorded per function; a verified function with low coverage is a
weaker claim and the ledger says so.

x87 and SIMD instructions are not re-expressed in C. The generated code
executes the same instruction on the host through a small thunk, so their
semantics are the CPU's on both sides. Integer, control-flow, stack, string and
memory semantics are plain C and are what the differential test checks.

## Layout

| Path | Role |
| --- | --- |
| `port/lifted_runtime/lift_model.h` | Shared model (both sides) |
| `port/lifted_runtime/lift_rt.h`, `lift_rt.c` | Lifted-side runtime: CPU context, guest memory, flags, events, thunk support |
| `port/lifted_runtime/lift_main.c` | Lifted runner: links one generated batch, runs jobs, prints results |
| `tests/lift_ref/ref_dbg.c` | Reference debugger (32-bit) |
| `tests/lift_ref/ref_child.c` | Inert 32-bit child the reference hijacks |
| `scripts/lift/` | Lifter (Python + capstone), job/metadata writer, batch verification, driver and ledger, self-tests |
| `scripts/test_lift_*.py` | Public Python tests (no image needed) |
| `generated/lifted/` | Generated C, binaries, per-batch results (git-ignored, regenerable) |
| `port/lifted/ledger_part*.tsv`, `manifest.json` | Committed result ledger |

Generated C is never committed: it is a mechanical transformation of the
original code and stays local, like `src_canonical_out/`.

Function inventory: `work/binary_contracts/function_contracts_part{1,2}.tsv`
(81,280 rows; `address`, `body_ranges` as `lo-hi` inclusive joined by `;`,
`sha256`, `callee_pop_bytes`, `return_type`). Image:
`Total War Rome II/empire.retail.dll`, mapped at `0x10000000` as the loader
would lay it out, with no relocation or import processing.

## Trial protocol (both sides)

Setup for `(function, seed)`:

- General registers from `lm_init_gpr`; `EIP` = entry; `EFLAGS` =
  `LM_EFLAGS_INIT`; x87/SSE state from `lm_init_fx`.
- Memory: image pages hold image bytes; arena pages hold `lm_fill_page(seed)`;
  the TEB page at `fs_base` holds the page given in the environment file (zeros
  when `fs_base == 0`). Arena and image pages materialise on first access. `FS`
  addresses are `fs_base + offset`; every other segment has base 0.

Running:

1. Control stays inside the body ranges until an instruction transfers outside
   them, faults, or raises an exception. A `call`/`jmp`/`ret` whose target is
   inside the body is ordinary control flow (recursion runs for real).
2. **Leaving the body** at target `T`: let `w` be the dword at `[ESP]` (read
   only when model-valid). If `w` is the return address of a `call` instruction
   in the body (a *call site*), this is a **call event**: hash `lm_hash_call`
   (with `r[ESP]` as it is now, and the eight stack words above the return
   address), then apply the stub: `EAX/ECX/EDX` from `lm_stub_call_regs`,
   `ESP += 4 + pop_bytes(site)`, `lm_fx_push(lm_stub_call_st0)` when
   `fp_ret(site)`, `EIP = w`, stub counter `n += 1`. Otherwise the trial ends
   with `LM_T_LEAVE(T)`. The classification depends only on `(T, [ESP])`, so
   both sides classify identically without knowing which instruction left.
3. **Stubbed instructions** (`cpuid`, `rdtsc`, `rdtscp`, `xgetbv`): hash
   `lm_hash_insn`, write `lm_stub_insn_regs` (`cpuid`: all four; `rdtsc` and
   `xgetbv`: `EAX`, `EDX`; `rdtscp`: `EAX`, `EDX`, `ECX`), skip the
   instruction, `n += 1`. `int n` (other than `int3`), `syscall` and
   `sysenter` end the trial with `LM_T_EXC(LM_X_TRAP)`; they are never executed.
4. **Faults**: an access to a page that is not model-valid ends the trial with
   `LM_T_FAULT(eip, lm_access_fault address)`. A general-protection fault (for
   example an aligned SSE access to an unaligned address) is
   `LM_T_FAULT(eip, 0xffffffff)`. Instructions are atomic: a faulting
   instruction changes nothing (a `rep` instruction keeps completed
   iterations). Divide errors, `int3` in the body, illegal and privileged
   instructions and unmasked FP exceptions end the trial with `LM_T_EXC`.
5. At the end: hash `lm_hash_terminal`, then the memory record over all bytes
   that differ from their pristine value, ascending by address.

**Step mode** runs the same protocol with a step budget `B`. Every completed
instruction counts one step (each `rep` iteration is one step; a `rep` with
`ECX == 0` is one step; a stubbed instruction is one step; a faulting
instruction is none). After each step: handle leaving the body (rule 2), then
if `steps >= B` end with `LM_T_STEP(eip)`. The budget is only looked at after a
step, so `B = 0` behaves like `B = 1`. The host CPU counts the same way under
the trap flag (measured: `rep movsd` with `ECX = 3` is 3 steps, with `ECX = 0`
1 step, `rep stosb` with `ECX = 0x2800` is 0x2800 steps).

### Per-function metadata

Computed once by the lifter and given to both sides:

- body ranges;
- call sites: return address -> `pop_bytes`, `fp_ret`. For a direct call to a
  contract row, `pop_bytes` = `callee_pop_bytes` and `fp_ret` = return type is
  `float`, `double` or `float10`. For every other call `pop_bytes` = 0 and
  `fp_ret` = the instruction at the return address is an x87 instruction that
  consumes `ST(0)` (anything starting with `f` except loads, constants and
  control-word instructions). These only shape what the code after the call
  sees; both sides read the same table, so the choice cannot cause a mismatch;
- stubbed instructions: address, length, kind (`LM_INSN_*`);
- data windows: ranges on the body's pages, outside the body, that the function
  addresses through an absolute memory-operand displacement (jump and lookup
  tables in `.text`), each extended to the next function start or 1024 bytes.

### Job, result and environment files

Plain text, one record per line, hex without `0x` unless noted.

Job file:

```
F <entry> <n_ranges> <n_calls> <n_stubs> <n_windows>
R <lo> <hi_exclusive>
C <return_addr> <pop_bytes_dec> <fp_ret 0|1>
I <addr> <len_dec> <kind_dec>
W <lo> <hi_exclusive>
T <seed> <mode 0=fast 1=step> <budget_dec>
E
```

`F` opens a function, `E` closes it, `T` lines are its trials.

Result line, same on both sides:

```
<entry> <seed> <mode> <status_dec> <tkind_dec> <a> <b> <digest 16 hex> <steps_dec>
```

Hex fields are lowercase without padding; the digest always has 16 digits.
`steps` is 0 in fast mode. A line whose status is not `LM_S_OK` carries no
terminal record (the reference prints zeros), so lines are compared only when
both statuses are `LM_S_OK`. One line is written per `T` line, in job order.

Both tools accept `--trace <entry> <seed>`. They then run only the trials of
that function and seed (their result lines are still written; an entry of 0
selects every trial of the job file) and print, on standard output, every
event, the terminal state and each differing memory byte, so a mismatch can be
diffed:

```
trial <entry %08x> <seed %08x> <mode>
page <addr %08x>                               lazy page materialised (not compared, see below)
call <n> target=%08x site=%08x eax=%08x ecx= edx= ebx= esp= ebp= esi= edi= df=<0|1> fx=<16 hex> stack=<w0>,...,<w7>
insn <n> kind=<dec> addr=%08x
step <steps so far> <eip %08x> eax=... df=     state before each step (step mode)
term kind=<dec> a=%08x b=%08x eax=... df=
fx fcw=%04x fsw=%04x ftw=%02x mxcsr=%08x
st<0..7> <20 hex>                              FXSAVE register slots, in image order
xmm<0..7> <32 hex>
mem <addr %08x> <byte %02x>                    one per differing byte, ascending
end status=<dec> digest=<16 hex> steps=<dec>
```

`n` is the stub counter before the event, `site` the return address, `esp` on
a `call` line the value hashed by `lm_hash_call`, and `fx=` the FNV-1a 64 of
`lm_hash_fx` over the x87/SSE state alone. Registers on the `term` line are the
ones hashed by `lm_hash_terminal`. For a trial without `LM_S_OK` the lines
between `trial` and `end` are whatever happened before it was given up. Both
sides print `page` lines, but when a page materialises is a detail of each
side (the reference touches a page when the CPU faults on it, the runner when
it checks an access), so a comparison leaves them out; every other line is the
same text on both sides.

Environment file, written by the reference when its run ends and read by the
lifted runner (`--env`):

```
fs_base <hex>
image_size <hex>                 image file size rounded up to a page
teb <8192 hex digits>            the TEB page
foreign <lo> <hi_exclusive>      one line per range, ascending
```

`fs_base` is `7efdd000`. The TEB page is zero except for the dwords 32-bit
code reads through `FS`: `+0` `ffffffff` (empty handler chain), `+4`
`60000000` and `+8` `5fe00000` (stack bounds), `+18` `7efdd000` (self),
`+20`/`+24` `1000`/`1004` (ids), `+2c` `5fd00000` (thread-local storage array)
and `+30` `5fc00000` (PEB), the last two in the arena, so what they point at
is seed-shaped like any other arena memory. These three records are the same
in every run.

The reference refuses a child that keeps accessible memory of its own outside
two zones, `10000-1000000` and `7e000000-80000000`. The foreign ranges are

- every range of the low zone in which a child of this run had accessible
  memory (system views, its TEB and PEB, the read-only top of the 64-bit
  stack), merged over all children the run started, and
- the whole high zone. The TEB page lies in it on purpose, so an `FS`-relative
  access that misses the page is foreign rather than a fault (the reference
  child has unrelated memory next to its real TEB).

A model-valid page is never foreign. An address of the low zone that is not
listed has nothing accessible behind it in any child of the run, so it faults
there exactly as the model says and the trial is compared. Which low ranges
are listed depends on where the system placed things in the child, so a trial
that faults in the low zone can be comparable in one run and excluded in
another; its result never differs.

### Excluded trials

- `LM_S_TIMEOUT`: the reference ran past its wall-clock limit (fast mode).
- `LM_S_FOREIGN`: on the lifted side a faulting address lies in a foreign range,
  where the reference child has real memory instead of a fault.
- `LM_S_BUDGET`: the lifted side's safety limits (50,000,000 instructions in
  fast mode, 8,192 materialised pages, 250,000 call and stub events).
- `LM_S_UNSUPPORTED`: the lifted side reached an instruction that was not
  translated, control entered the middle of an instruction, or the trial
  changed bytes of the function's own body. The original then runs the new
  bytes, which the translation of the old ones cannot follow; the lifted side
  checks for it when the trial ends.
- `LM_S_HARNESS`. On the reference side it covers a child that died or could
  not be trusted any more (it is replaced and the run goes on), a function
  whose description cannot be used (no body range, a range or window outside
  the image, a stubbed instruction outside the body), and an access to the TEB
  page by flat address: the reference serves the TEB only through `FS`.

A function with fewer than 8 comparable fast trials is retried in step mode,
and with more seeds when that is not enough (see "Driver and ledger").
A fast trial that does not match is re-run in step mode too, because the
reference's fast mode has known differences from the model (see "Reference
side"). When the step trial of the same seed ends at a terminal other than
`LM_T_STEP` and matches, the fast difference was the reference's and the trial
counts as matched; otherwise the mismatch stands.

## Reference side

`ref_dbg.exe` (32-bit) starts `ref_child.exe` under `DEBUG_ONLY_THIS_PROCESS`,
takes the thread at the loader breakpoint and never lets the child run its own
code again. It then:

- reserves the image range and the arena in the child, writes the image, and
  keeps image pages `PAGE_NOACCESS` and arena pages uncommitted so the first
  touch of a page is a debug event (commit, fill, record, continue). The child
  is linked without a CRT at a fixed low base (`0x00400000`, `/NXCOMPAT`,
  `/DYNAMICBASE:NO`); a child that has anything in either range is discarded
  and another one started;
- **takes all access away from every other region of the child** (its image,
  the system DLLs, stacks and heaps become `PAGE_NOACCESS`). The committed top
  of the 64-bit stack stays read-only because the system reads it when it gets
  or sets a WOW64 thread context. What the system does not allow to be
  re-protected (shared read-only views, the PEB/TEB block, shared user data)
  must be non-executable and lie inside the two zones. It then walks the
  whole address space with `VirtualQueryEx`, again every time an exec view is
  installed, and requires that nothing outside the current exec view is
  executable, and it checks that jumping to a non-executable page raises an
  execute fault (DEP active). It refuses to run trials otherwise. Guest code
  can therefore only ever execute bytes of the function under test. The same
  walk records what is still accessible in the low zone; those ranges go into
  the environment file as foreign;
- checks once per child that an x87/SSE state from `lm_init_fx` survives a
  resume unchanged (the hashed FXSAVE fields round-trip bit for bit through
  `CONTEXT_EXTENDED_REGISTERS`);
- writes the model TEB page over the child's real TEB page, which is where
  `FS`-relative accesses land. The real page is at a different address in
  every child; the address `fs_base` itself is only reserved, and a trial that
  touches it by flat address ends as `LM_S_HARNESS`. Memory differences on the
  page are reported at `fs_base` addresses;
- for each function installs the *exec view* on the body's pages: original
  bytes inside body ranges and data windows, `0xCC` everywhere else and on the
  first byte of each stubbed instruction (step mode: original bytes on the whole
  page, stubbed instructions still `0xCC`); pages are `PAGE_EXECUTE_READWRITE`;
- drives each trial through debug events only and never passes an exception on
  to the child: execute faults and filler breakpoints are "left the body" (in
  step mode `EIP` is checked after every step instead), read/write faults are
  lazy pages or `LM_T_FAULT`, other exceptions map through `lm_exc_class`.
  `a` is the exception address for breakpoints and `EIP` otherwise. An execute
  fault at an address other than `EIP` (an instruction that runs off the end
  of the body's pages) is `LM_T_FAULT(eip, address)`. When a stub hands
  control to an address outside the body (a call whose return address is a
  jump table), rule 2 is applied again before the thread is resumed;
- in fast mode gives up a trial `--timeout-ms` (default 50) after it started:
  the thread is suspended and sent to an unmapped address, where it also waits
  between trials. Step mode has no wall-clock limit, only the budget;
- sets and reads x87/SSE state through `CONTEXT_EXTENDED_REGISTERS` (FXSAVE
  image), and restores touched pages, the TEB page and the exec view between
  trials;
- reports `LM_S_HARNESS` for a trial during which the child died or stopped
  answering, starts a new child and goes on. A new child is equivalent to the
  old one except for what it keeps in the low zone, which is added to the
  foreign ranges, so results do not depend on when that happens.

Trap flag: in step mode the flags image stored by `pushf`/`pushfd` is
corrected so the harness's trap flag never reaches guest memory; in fast mode
a single-step trap caused by the guest setting the flag itself is absorbed and
the flag cleared.

Known differences from the model, all of which show up as a mismatch or an
excluded trial rather than silently:

- fast mode: a read of a byte on a body page that is outside the body ranges
  and data windows sees `0xCC`, not the image byte, and a write of `0xCC` to
  such a byte is not reported as a difference. Step mode has neither
  restriction, so the driver re-runs a fast trial that does not match in step
  mode (see "Excluded trials");
- fast mode: a jump or return from inside the body into a data window executes
  the window's bytes instead of ending with `LM_T_LEAVE` (a stub's return into
  a window is handled, see above);
- a trial that overwrites instructions of the function itself runs the new
  bytes. The lifted side cannot and reports `LM_S_UNSUPPORTED`;
- an `FS`-relative access outside the TEB page reaches whatever the child has
  next to its real TEB (foreign on the lifted side when it is within the high
  zone of `fs_base`); a write there is not undone;
- `popfd` that sets `AC` makes later unaligned accesses raise an alignment
  exception (`LM_X_OTHER`);
- the upper halves of `YMM` registers are not reset between trials (the image
  has no VEX code).

The reference CPU is the host CPU. Undefined-flag behaviour and the results of
approximate instructions are therefore the host's; `manifest.json` records the
CPU brand string. On a hybrid CPU the core classes are not identical: on the
development machine (Raptor Lake) an access that wraps past `0xffffffff` is
reported at its first byte on a performance core, as the model has it, and at
address 0 or as a general-protection fault on an efficiency core. `ref_dbg`
therefore restricts itself and the child to the most capable core class among
the processors it may use; the lifted runner has to run on the same class.

`ref_dbg` instances are independent, so several can run at once. Build with
`python scripts/lift/build_ref.py` (output in `generated/lifted/ref/`); test
with `python scripts/lift/selftest_ref.py` (hand-encoded snippets checked
against an independent Python port of the model, then a few thousand functions
of the game image when it is present). Two reference runs of the same job
agree on every line except where a wall-clock timeout or a child's own memory
in the low zone is involved; the self-test checks exactly that.

## Lifted side

Each function becomes `void lifted_<entry>(lift_ctx *c)`: a dispatch `switch`
on the guest instruction address with one label per instruction, so direct
jumps are `goto` and indirect transfers re-enter the dispatch. Requirements:

- set `c->eip` before each instruction (fault reporting, coverage, steps);
- probe every memory access of an instruction before changing any state, so a
  fault leaves the pre-instruction state;
- compute documented flags exactly; where the manual says undefined, follow
  the host CPU (the differential test decides);
- x87 instructions run through generated leaf thunks (`<bytes with the memory
  operand rewritten to [rcx]>; ret`) against the live host x87 state, which is
  the guest x87 state for the duration of a trial;
- SIMD instructions run through generated thunks that load guest `XMM0..7`
  from the context, execute the original instruction with its memory operand
  rewritten to `[r8]` and any general register loaded into the same-numbered
  host register, then store the registers (and returned flags or general
  register) back. Thunks are leaf code in an executable section and keep `rsp`
  unchanged; host faults inside a thunk are caught and reported as the guest
  fault at `c->eip`;
- guest pages are host allocations aligned to 4096 so alignment-sensitive
  instructions fault exactly when they would natively;
- when a trial ends, check whether a changed byte lies in the function's own
  body; such a trial is `LM_S_UNSUPPORTED`.

The runtime builds without `/guard:cf` (thunks are called through data
pointers) and is not part of the handwritten test graph. Test with
`python scripts/lift/selftest_lift.py` (hand-encoded snippets against expected
results, then the whole inventory lifted and a sample of it built and run when
the game image is present).

## Driver and ledger

`python scripts/lift/driver.py run` selects functions (`--all`, `--index`,
`--addr`, `--list`, `--entries`, `--smallest`, `--stride`; the union of what
is given), splits them into batches of 400 (`--batch-size`) and verifies the
batches in a pool of 24 worker processes (`--workers`). One batch
(`scripts/lift/batch_verify.py`):

1. lifts its functions, writes the job file with 16 fast trials per function
   (`meta.seed_for(address, 0..15)`, `--seeds`) and builds the runner;
2. runs `ref_dbg` on the job file, then the runner, with the reference's
   environment file, on the trials the reference finished with `LM_S_OK` (the
   others are excluded whatever the lifted side would report);
3. compares the result lines: a trial is *comparable* when both statuses are
   `LM_S_OK` and *matched* when terminal kind, `a`, `b`, digest and steps are
   all equal;
4. re-runs in step mode every seed of a function with fewer than 8 comparable
   fast trials (budget 4000, `--step-budget`) and every fast trial that did
   not match (budget 100000, `--confirm-budget`);
5. writes `result.json` with one row per function, including the result lines
   of every mismatching trial.

Functions that come out of this with fewer than 8 comparable trials go through
a second round: the same steps with 64 seeds (`--retry-seeds`;
`meta.seed_for(address, 0..63)`, so the first 16 are the trials already run).
Nothing else changes: the function is verified when at least 8 of those trials
are comparable and every comparable one matches. The round exists for
functions most of whose trials are excluded, for example because they fault at
an address where the reference child has memory of its own.

A batch lives in `generated/lifted/batches/<key>/`. The key hashes the sources
of both sides, the lifter and `batch_verify.py`, the contract tables, the
mapped image, the trial parameters and the batch's function list; a finished
batch is skipped until one of them changes. `driver.py clean` removes the
directories of other tool versions. Where two results cover a function, the
second round's replaces the first round's and a newer one an older one, except
that a mismatch is never replaced.

Function status:

- `unsupported`: an instruction of the body was not translated (`note` names
  the mnemonics). Trials still run and are counted;
- `mismatch`: a comparable trial differs and its step-mode re-run did not
  clear it;
- `verified`: at least 8 comparable trials and all of them match. `mode` is
  `fast` when the fast trials carry the claim and `step` when the step-mode
  retry does; a step trial that ends at its budget verifies only the steps it
  ran;
- `uncomparable`: fewer than 8 comparable trials in both modes, in the second
  round too (`note` gives the exclusion counts);
- `untested`: no batch result for the current tools.

`driver.py ledger` merges the batch results of the current tools into
`port/lifted/ledger_part1.tsv` and `ledger_part2.tsv` (every inventory row,
ascending by address, split where the contract tables are split):

```
address  bytes_sha256  lift_sha256  status  mode  trials  matched  insn_total  insn_covered  note
```

`bytes_sha256` is the contract row's hash and `lift_sha256` hashes the
generated C of the function. `trials` and `matched` count the comparable and
the matching trials of `mode`; `insn_covered` counts the instructions reached
by matching trials. `note` starts with `64 seeds` for a row of the second
round; an empty field is written as `-`. `port/lifted/manifest.json` records
the counts per status, the coverage histogram of verified functions, the
instruction totals (all instructions, those reached by matching trials of
verified functions, and the number of verified functions reached in full), the
model version, the trial parameters with
the number of functions per seed count, the reference CPU's brand string, the
Python, capstone and MSVC versions and the hash of every tool source.

Results are not bit-reproducible between runs: which fast trials the reference
times out depends on machine load, and which low-zone faults are comparable
depends on the reference child (see the environment file). Both only move
trials between comparable and excluded, so `trials`, `matched`,
`insn_covered` and, for a function near the limit of 8, the seed count can
differ from run to run; a trial that is comparable in two runs has the same
result in both.

`driver.py report` prints the same counts with throughput, exclusion totals
and the untranslated mnemonics ranked by the functions they block.
`driver.py mismatches` rebuilds the mismatching functions, traces the first
mismatching trial of each on both sides (in step mode, and in fast mode when
that is where it differed) and groups the functions by the instruction that
ran last before the traces part and the first field that differs.

`python scripts/lift/selftest_e2e.py` is the end-to-end test that needs no game
image: hand-encoded snippets for every kind of event, terminal and memory
record go through both sides, and result lines and traces must be equal.
`scripts/test_lift_driver.py` covers the comparison and status rules.
