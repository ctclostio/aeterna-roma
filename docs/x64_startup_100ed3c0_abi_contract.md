# Static ABI evidence contract for `0x100ed3c0`

Status: frozen evidence and verifier contract for the original x86 body. This
document alone does not authorize executing or entering that body, freezing a
full semantic ABI, or linking recovered startup code. A later, separately
contained adapter admits only the bounded empty-input interval
`[0x100ed3c0,0x100ed471)`; see
[`x64_startup_100ed3c0_empty_preloop.md`](x64_startup_100ed3c0_empty_preloop.md).

The authority for machine bytes is
`scripts/x64_startup_100ed3c0_abi_fixture.json`, authenticated against the
original PE by `scripts/test_x64_startup_100ed3c0_abi_provenance.py`. Canonical
C is a cross-check, not an x86 ABI oracle.

## Canonical requirements

- `ABI-PROV-001`: authenticate the pinned original DLL, PE32 mapping, complete
  400-byte callee body, both caller packets and continuations, canonical
  sources, and canonical index before accepting conclusions.
- `ABI-CALL-001`: prove both rel32 targets and the four physical pushes. The
  directly authenticated operand order is `[ebp+0x24]`, `edi`, `[ebp+0x0c]`,
  `esi`; the callee observes those operands in reverse stack order. Earlier
  loads of ESI from `[ebp+0x08]` and EDI from `[ebp+0x10]` are authenticated
  prior-load observations, not yet a complete def/use proof across every path.
  Therefore the shorthand caller-position order 8, 3, 2, 1 remains conditional
  on proving no intervening clobber. Semantic parameter types are not implied.
- `ABI-STACK-001`: let `E0` be ESP on callee entry. The return address is at
  `E0+0`; supplied positions 1 through 4 are at `E0+4`, `E0+8`, `E0+12`, and
  `E0+16`. The direct body reads positions 1 and 3 once each and does not read
  positions 2 or 4. Positive-looking decompiler stack names must be normalized
  before classification.
- `ABI-REG-001`: authenticate the delayed ESI save and restore. Incoming ECX is
  overwritten; EAX, ECX, EDX, flags, and a return value are not stable outputs.
  Do not infer a broader register contract without new raw evidence.
- `ABI-RET-001`: authenticate `pop esi; add esp,0x90c; ret`, zero callee
  argument cleanup, and the callers' delayed grouped `add esp,0x18`. The exact
  mechanics are caller-cleanup-like, but no cdecl/stdcall name or native x64
  ABI is frozen. The return value is unspecified and ignored, and termination
  is not guaranteed.
- `ABI-ORACLE-001`: fail closed on changed bytes, rel32 targets, push order,
  stack positions, hidden position-4 use, callee-cleanup `ret`, unsupported
  decoding, stale sources, malformed PE mapping, and malformed artifacts. Each
  accepted test needs a reciprocal mutant that it kills.
- `ABI-CONT-001`: auditors are deterministic, standard-library-only, read-only
  over pinned inputs, isolated from production DLL/host linkage, and contained
  to their declared workspaces. Guest addresses remain 32-bit identities and
  are never cast to native pointers.
- `ABI-NOGO-001`: do not execute the original `0x100ed3c0` x86 body, freeze a
  full semantic prototype, expose a legacy export, link startup/gameplay, or
  promote unbounded platform, allocator, callback, or ownership paths. This
  does not prohibit the separately authenticated, fail-closed empty-preloop
  adapter linked above. The one-byte `0x100d6560` node is only a private no-op
  negative control and proves no name or arity.

## Original bounded decision and later admission

The first useful GO was the authenticated empty-source path through
`0x100f1aa0 -> 0x100ef330`. On the zero-length branch, the destination becomes
`{0, 0, 0x11af4090}` without allocation. `0x11af4090` is a guest identity, not
a native pointer. That leaf now participates in the admitted empty-input parent
adapter for `[0x100ed3c0,0x100ed471)`, which stops before the first loop and
does not execute either indirect call.

The following remain NO-GO outside their separately bounded injected adapters:

- full/nonempty `0x100f1aa0`, because `0x100ef330` allocates through
  `0x100fcc80`;
- `0x100f1bb0`, because its UTF-16 terminator scan is unbounded without an
  external length;
- full `0x100f1cc0`, because its owning branch releases memory and may invoke a
  mutable global callback;
- the original native `0x100df270`, because it owns Win32, singleton, global,
  and virtual-dispatch seams; only its bounded injected composition is admitted;
- the full parent `0x100ed3c0` lifecycle, including interval
  `[0x100ed471,0x100ed550)` and both indirect calls at `0x100ed49e` and
  `0x100ed4fe`; the admitted empty-preloop adapter ends before them.

## Structured-artifact rules

Evidence `claim.value` fields are plain strings. Implementation and integration
manifest `files` arrays list payload files only and exclude the manifest itself.
Reviewer `candidate_sha256` is the admitted SHA-256 of that candidate's
`submission.json`, not a payload-file or ad hoc package hash.
