# Injected final suffix transcript for `0x100df270`

Status: admitted, native, and `BUILD_TESTING`-only. The baseline entry models
the complete deterministic final interval of original `0x100df270` as bounded
guest32 state plus ordered injected effects. An additive delegated entry now
provides the typed substitution point needed at the observed `0x100f2750`
position. Neither entry calls an original x86 address, virtual function,
allocator, platform API, or process global.

## Authenticated boundary

The pinned original is `empire.retail.dll`, exactly 28,278,272 bytes with
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
The admitted suffix is the 131-byte interval
`[0x100df46d, 0x100df4f0)`, at `.text` raw offset `0x000de86d`, with SHA-256
`27ee666d2327c9360be2f4175ee5ea58bf49e112a6a29af6760451d6a7341b75`.
It begins immediately after the admitted 298-byte post-platform projection and
ends with the original `mov eax, edi` / register restore / `ret 8` epilogue.

The provenance test authenticates the complete parent body, every direct-call
relocation, both `call [eax+0x0c]` virtual sites, the selector comparison and
branch, four ordered conditional calls, the final marker store, and the exact
epilogue. It also pins the owner vtable installed earlier at receiver `+0x874`,
the selector implementation at `0x100d7cb0`, exact canonical rows and sources,
and the admitted `0x100e8240` completed return of crash-record identity
`0x119f3a38` before the shared slow-route rejoins.

## Executable transcript

```c
rome2_guest_status rome2_port_100df270_run_suffix_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100df270_suffix_effects *effects,
    rome2_guest_addr32 *return_receiver_out);

rome2_guest_status rome2_port_100df270_run_suffix_transcript_delegated(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100df270_suffix_effects *effects,
    const rome2_100df270_suffix_100f2750_delegate *delegate,
    rome2_guest_addr32 *return_receiver_out);
```

After complete pre-effect validation and snapshotting, the already-marked route
emits seven ordered steps:

1. publish `(0x119f3140, receiver)`;
2. represent `0x100e8240(original_argument)` returning `0x119f3a38`;
3. represent `0x100f2750(0x119f3aa0, original_argument)`;
4. represent `0x100ea4d0(receiver)`;
5. query selector `2` through vtable `0x1173dc18`, slot `+0x0c`, on
   `receiver + 0x874`;
6. repeat the same selector query; and
7. store marker `0x4e3b` to the second injected query result.

If the first injected result cell did not contain `0x4e3b` before any callback,
four ordered `0x101046d0` effects with arguments `0x2d`, `0x12`, `0x16`, and
`0x21` are inserted between the two queries, producing eleven steps. The
marker write completes before the final callback, and the receiver output is
published only after that callback returns.

The delegated entry preserves those step payloads and route rules. Immediately
after emitting step 3, it invokes one snapshotted, status-returning callback as
`delegate(destination=0x119f3aa0, source=original_argument)`. Success resumes
with step 4, `CALL_100EA4D0`. Failure returns the delegate status immediately:
the first three observer steps are a committed prefix, while later steps, the
marker store, and receiver-output publication do not occur. The baseline entry
remains observation-only and its body and behavior are unchanged.

The original argument is deliberately opaque and is forwarded unchanged.
Guest identities remain 32-bit values. The two injected selector results may
name the same complete four-byte cell, matching the repeated query shape, or
distinct cells, allowing the harness to expose the exact first-observation and
second-store ordering without deriving or calling a guest function pointer.

## Validation and commit contract

The state view, effects descriptor, and output must be complete, naturally
aligned, pairwise-disjoint host objects. The state backing interval must not
wrap, must remain inside the guest32 address space, and must not overlap a
control object. The callback and context are required; receiver `+0x874` and
crash-record result `+0x68` use checked 32-bit addition; the injected crash
record must equal `0x119f3a38`; and each selector result must name a complete
four-byte span.

Validation failure emits nothing and preserves the state and output. Once
emission starts, callbacks form an observable committed prefix. The complete
effects descriptor and first marker value are snapshotted before the first
callback, so callback-side mutation cannot redirect later calls or alter the
chosen branch. Callbacks are total, non-reentrant, retain no borrowed object,
and may mutate only their disjoint context. The port adds these containment
rules intentionally; it does not claim the unchecked x86 code performed them.

The delegated entry additionally validates and snapshots its descriptor before
the first observer. Its declared nonempty context range must not wrap and must
be disjoint from the state backing, state/effects/delegate control objects, and
receiver output. Objects reached transitively through that opaque context are
the caller's typed responsibility and must obey the same separation. Observer
and delegate contexts may intentionally be the same recorder, which gives a
later composed oracle one total event order. Delegate failure does not roll
back writes performed through the delegate's separate authority.

## Headless composition and containment

`rome2_headless64` runs the eleven-step mismatch route after the complete
injected six-handler graph. It verifies every transcript field, observes the
marker store before the final callback, confirms the receiver output is still
unpublished during callbacks, and reports
`startup-100df270-suffix=injected-transcript-complete` only after success.
At this historical checkpoint the suffix runtime was the final direct headless
link dependency and established
`startup_100df270_suffix_transcript_reload_verified` before the composed
lifecycle test. The current headless harness reaches it through the admitted
empty-preloop parent, whose terminal fixture is
`startup_100ed3c0_empty_preloop_reload_verified`.

The runtime library and executable test exist only under `BUILD_TESTING`. The
only runtime-library consumers are its independent test, `rome2_headless64`,
and the empty-preloop runtime. No symbol is admitted to the production DLL,
probe DLL, export manifest, or either DEF surface. A testing-disabled
configuration still contains only the production bootstrap pair.

The existing headless and empty-preloop consumers continue to call the
observation-only entry. The delegated entry currently has no composition
consumer beyond its independent oracle; it is admitted as the prerequisite for
the bounded nonempty `0x100ed3c0` parent described in
`docs/x64_startup_100ed3c0_nonempty_preloop_spec.md`.

## Frozen authorities and verification

| Authority | SHA-256 |
|---|---|
| `ported_100df270_suffix_transcript.h` | `c340cb925096a87be9ee0a7edba3ef86af80a669de5ed5335c39032a54d782ff` |
| `ported_100df270_suffix_transcript.c` | `ee40bb59780e2f9a5f88116472a406393017f7049766be34acb45c172bd929f1` |
| `test_startup_100df270_suffix_transcript.c` | `290c6fe7c579cc311279d8671b072ef21088af1fcb14550383c46e4341dbdcbf` |
| executable provenance test | `917c38c1ea7ec9cc41c6d3b0689fdfcc099c8c1f1b52f0d78312fb02c3e29bcc` |
| fail-closed static gate | `503a226319800b32ab30cd50e3f7ecda4665fe7d492b7bf19994996494553043` |
| reciprocal mutant suite | `067777cb9e4eaf1c08510068d798594ac521266e4ad86092e0135422627e2a42` |

The independent strict runtime oracle passes 76/76 cases: the original 30-case
coverage, all 25 precommit failures replayed through the delegated entry, four
ordinary delegated successes, one delegated effects-snapshot adversary, one
exact delegate-failure prefix, and fifteen
delegate-specific descriptor/context boundaries. It covers both routes, exact
step fields and order, same-cell result aliases, bytewise unaligned access,
address-space edges, output/store publication order, snapshot adversaries,
checked arithmetic, range and every control alias, malformed views, and
no-effect failures. The provenance suite passes 9/9, the reciprocal static
gate suite passes 12/12, and the live gate reports zero findings. Strict MSVC
analysis and the `/MT /fsanitize=address` runtime are also clean.

This suffix checkpoint originally established 142 CTests. The later
platform-prefix, empty-preloop, ordinary-lifecycle, owned-descriptor, and
sentinel-owned milestones extend the current testing-enabled tree to 168
CTest registrations. The next behavior boundary is the separately specified
nonempty parent interval `[0x100ed3c0,0x100ed471)`; the delegated seam resolves
its former mid-suffix execution blocker without yet admitting that parent.
