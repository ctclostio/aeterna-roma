# `0x100edd70` entry-decision composition evidence

Status: evidence frozen for the next `BUILD_TESTING`-only composition. No new
runtime code, native handler installation, original-address execution, export,
or production/headless consumer is authorized by this record.

## Bounded successor

The proposed successor joins two already admitted components in original
control-flow order:

1. bounded UTF-16LE policy selector `[0x100edecc,0x100edf05)`;
2. on mismatch only, typed data for registration interval
   `[0x100edf05,0x100edf20)`;
3. the admitted policy-selected caller window
   `[0x100edf20,0x100edf41)` or `[0x100edf73,0x100edf94)`.

The exact hard stops remain `0x100edf41` and `0x100edf94`. The selector's
command-line identity and caller position three must be the same guest32 value
and use the same caller-owned read view. The composition must still call the
whole nonempty parent exactly once.

The evidence-freeze token is
`startup-100edd70-entry-decision=evidence-frozen`. It is not an implementation
completion token.

## Original-byte authority

The authority is `Total War Rome II/empire.retail.dll`, 28,278,272 bytes,
SHA-256
`d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528`.
All ranges below are half-open and map uniquely into executable `.text`.

| Role | VA range | Raw offset | Bytes | SHA-256 |
| --- | --- | ---: | ---: | --- |
| excluded pre-selector prefix | `[0x100edd70,0x100edecc)` | `0x0ed170` | 348 | `5c66148eb32e3f84f45c115d520fc4e02844ed4aa3e4441bae750b029a4a2f7b` |
| admitted selector | `[0x100edecc,0x100edf05)` | `0x0ed2cc` | 57 | `11bc65f6b73602d0b4a7c974728793ca5d817cc974a5c8ff91ab1e98b64e7ebc` |
| typed registration candidate | `[0x100edf05,0x100edf20)` | `0x0ed305` | 27 | `207f89cc1284f85df0955249dd435c83e869d52a33903b2cf25c3adf6ac677fb` |
| excluded installed-branch tail | `[0x100edf41,0x100edf4a)` | `0x0ed341` | 9 | `ebcf3ccb829383d74c54f505a857df1ea3fb5913165c50c70fecf6a987b67f02` |
| excluded exception-only gap | `[0x100edf4a,0x100edf73)` | `0x0ed34a` | 41 | `48fa1bded5911a24a9980288ef3a9470d56277c0a3636946cae77a4bb327ff77` |
| excluded common epilogue | `[0x100edf94,0x100edfb0)` | `0x0ed394` | 28 | `490afcdfb5d7f9ee30342e409c8b657875d504f7fe6ce7c29822bcb204795f1c` |

The pre-selector prefix owns COM, IGameExplorer, `VirtualFree`, process-global,
and early-return behavior and remains excluded. The installed tail and exception
gap converge on the common epilogue but remain outside the proposed seam. The
epilogue calls imported `CoUninitialize`, reads `0x119f3144`, restores the x86
exception chain through `fs:[0]`, and returns; all of that remains excluded.

## Registration call shape

The 27-byte interval is exactly:

```text
68d0e50e10 e83b9b5901 83c404
c745e000000000 c745fc00000000
```

It encodes, in order:

1. `0x100edf05`: push inert handler identity `0x100ee5d0`;
2. `0x100edf0a`: rel32 call to `0x11687a4a`;
3. `0x100edf0f`: grouped four-byte caller cleanup;
4. `0x100edf12`: write dword zero to frame-local displacement `-0x20`;
5. `0x100edf19`: write dword zero to frame-local displacement `-0x04`.

The two store PCs are therefore `0x100edf12` and `0x100edf19`; later-looking
addresses inferred from immediates or instruction ends are not accepted.

The registration callee is the exact 48-byte function
`[0x11687a4a,0x11687a7a)`, SHA-256
`9e14f09ccd77390a9228d00b088fe5d948452a3e6dfb060aed8c6ae831b1c95a`.
Its canonical identity is `__set_invalid_parameter_handler`; it mutates CRT
state and calls another CRT helper, so the composition may expose only its
address and call shape as data.

The handler identity `[0x100ee5d0,0x100ee5e2)` is 18 bytes, SHA-256
`c7e16cde3d599ee4de8d9da66aeffef459087ace2e703d07b9b735789727a73a`:

```text
6a006a006a0068050000c0ff1590f17211c3
```

It would call the `KERNEL32.dll!RaiseException` IAT cell at `0x1172f190`
with exception code `0xc0000005`. It is an excluded callback identity, never a
guest or host function pointer to invoke.

## Provisional typed transaction

The installed route will represent the interval with exactly three by-value
records before invoking the admitted caller closure:

1. one registration call-shape record carrying push PC, call PC, callee,
   handler argument, cleanup PC, and cleanup byte count;
2. one frame-local zero-store record for displacement `-0x20`;
3. one frame-local zero-store record for displacement `-0x04`.

The selector route emits no record. A likely outer alias universe is fourteen
controls, seven guest backings, and eight callback contexts: the caller
closure's seven views, parent and continuation effects, two owners, lifecycle,
plus registration effects and the outer result. This count remains a design
input until the independent contract review freezes the exact API.

All deterministic object, range, alignment, host/guest backing, context, and
private-state checks must finish before the first registration or child effect.
Effects and views must be snapshotted. Selector failure emits nothing and
leaves the result unchanged. An inherited child failure preserves the exact
committed prefix, adds no later event, performs no rollback, and leaves the
outer result unchanged. Success publishes the combined result once and last.

## Hard exclusions

- no call to `0x11687a4a`, `0x100ee5d0`, or any original address;
- no native invalid-parameter handler or CRT state mutation;
- no pre-selector COM, IGameExplorer, `VirtualFree`, or process-global work;
- no `CoUninitialize`, x86 SEH restoration, common epilogue, or return-global
  read;
- no native `wchar_t`, guest-to-host pointer cast, recovered callback,
  production/headless linkage, probe, or export;
- no result-one synthesis inside the already frozen ordinary parent.

`scripts/test_x64_startup_100edd70_entry_decision_provenance.py` independently
parses the PE32 and import table as inert bytes, authenticates every interval
and identity above, pins the two admitted child snapshots, and fails closed on
changed authority.
