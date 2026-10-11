# Original evidence authority for `0x100ea4d0`

Status: the original x86 body remains fully evidence-pinned, and a separate
bounded injected x64 model now composes its six registrations. The executable
model does not weaken or replace this authority: original behavior and port
policy are verified as distinct layers.

## Authenticated original behavior

The adjacent call `0x100df489 -> 0x100ea4d0` and the complete 265-byte body
`[0x100ea4d0, 0x100ea5d9)` are authenticated against the pinned original PE.
The method derives an argument identity at `receiver + 0x824` and a common
vector receiver at `receiver + 0x854`. It then performs six unrolled sequences:

1. call native wrapper `0x100d12b0(4)`;
2. if the result is non-null, store the corresponding vtable identity;
3. call `0x100e2460(vector, handler, argument)`; and
4. if that call reports zero, deliberately reach a null-write trap.

The six vtable identities are `0x1173f20c`, `0x1173f214`, `0x1173f21c`,
`0x1173f224`, `0x1173f2ec`, and `0x1173f2dc`. Their slot-4 method identities,
in registration order, are `0x100e8d00`, `0x100e85d0`, `0x100e8580`,
`0x100e9340`, `0x100e92c0`, and `0x100e87a0`.

There is no branch before the first allocation. A null allocation skips only
the vtable store; it does not provide a safe allocation-free return path. This
is why the earlier read-only milestone correctly kept `0x100ea4d0`
evidence-only.

## Pinned evidence

`scripts/test_x64_startup_100ea4d0_evidence_provenance.py` parses the original
PE strictly as data and authenticates:

- original file size `28,278,272` and SHA-256
  `d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`;
- the full body at raw offset `0x000e98d0`, SHA-256
  `582b4c4324650b88f969c1af5fac0dce0d6ffd69e1043ee99d834e6b102c7af3`;
- the prologue `push esi; push edi; push 4; mov edi, ecx`;
- all six `push 4` sites and allocation calls to `0x100d12b0`;
- the exact 15-byte allocation wrapper and its call to core `0x100fcc80`;
- all six conditional vtable stores with the identities above;
- all six calls to `0x100e2460` and their failure traps; and
- the single terminal return with no earlier return path.

Canonical decompilations for `0x100ea4d0`, `0x100d12b0`, and `0x100fcc80`, plus
the canonical function-index row for the 265-byte entry, are pinned as semantic
cross-checks. Canonical C is not treated as an ABI oracle.

The later
`scripts/test_x64_startup_100ea4d0_executable_provenance.py` source-pins this
authority and additionally authenticates the receiver derivations and all six
vtable slot-4 targets. It explicitly does not claim that injected callbacks,
alias rules, finite budgets, status values, or rollback policy came from the
original bytes.

## Executable boundary added later

`rome2_port_100ea4d0_run_injected` is a bounded guest32 composition of the
authenticated shape. It replaces native allocation with a total injected
`(4, 0)` allocator, writes vtable identities only into validated guest spans,
and invokes the already bounded `0x100e2460` router. It never loads or calls the
original image.

That API deliberately narrows behavior by requiring mapped argument/vector and
active-backing spans; rejecting logical and physical aliases; requiring a
finite nonzero Peek budget; auditing the accumulated handler graph after every
router call; and replacing invalid allocations, router failure, zero AL, and
the original null-write trap with explicit statuses. Effects after iteration
begins are prefix-committing and are not rolled back.

The exact executable contract, including its failure taxonomy, is documented
in `docs/x64_startup_100ea4d0_injected.md`.

## Completed bounded handler boundary

All six slot-4 identities now have executable bounded models:

- `0x100e8d00`: injected six-step transcript;
- `0x100e85d0`: effect-free adapter;
- `0x100e8580`: injected nine-step transcript with an explicit dependent
  `0x100e8240` result;
- `0x100e9340`: injected four-step lookup/singleton/helper transcript;
- `0x100e92c0`: injected predicate/getter/final-call transcript with exact
  3/4/6-step routes; and
- `0x100e87a0`: injected listener allocation, guest32 vtable publication,
  global-publication, and FaceFX-startup transcript.

Both headless dispatch adapters now invoke all six bounded implementations;
neither contains a synthetic method-success route. Original allocators,
Steam, FaceFX, TLS, platform, singleton, and global effects remain outside the
native call graph and are represented only by checked injected effects.

The historical evidence provenance remains in the fixture chain alongside the
new executable provenance, runtime oracle, and static containment gates. The
handler-completion chain contained 136 CTests and terminated at the
`0x100e87a0` reload fixture. The later 148-test chain continued through the
bounded `0x100df270` suffix and platform-prefix transcript. The current
empty-preloop parent checkpoint registers 154 tests and terminates at
`startup_100ed3c0_empty_preloop_reload_verified` before the composed headless
lifecycle runs.
