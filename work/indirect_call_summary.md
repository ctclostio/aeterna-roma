# Indirect call resolution - empire.retail.dll (Total War: Rome II)

Input: `work/indirect_calls.tsv` (Ghidra enumeration, 59,012 indirect call sites),
`src_canonical_out/empire.retail.dll/canonical_decomp/` (63,326 canonical C files),
PE `Total War Rome II/empire.retail.dll` (PE32, image base 0x10000000),
`work/registrar_roots.tsv`, `src_out/empire.retail.dll/vftables.txt`.

Outputs: `work/indirect_call_resolutions.tsv` (59,012 rows), `work/indirect_call_vtables.tsv` (120941 rows), this file.

## 1. Site population and expression coverage

| metric | sites | share |
|---|---:|---:|
| total indirect call sites | 59,012 | 100.00% |
| containing function has a canonical C file | 52,973 | 89.77% |
| exact/near call expression recovered from C | 48,979 | 83.00% |
| no containing function recorded by Ghidra | 5,898 | 9.99% |
| no matching call expression in the C body | 3,965 | 6.72% |
| canonical C file missing for the function | 141 | 0.24% |
| not an indirect call at all (`INT3`/`INT` padding) | 29 | 0.05% |

Sites are matched to C call expressions per function. When the number of C expressions equals
the number of asm sites the pairing is 1:1 in program order (97% of matched functions); otherwise
the two sequences are aligned on their slot-offset sequences (1575 rows) and the row is flagged
`| expression aligned by offset` in `evidence`.

## 2. Resolution by kind and confidence

| kind | sites | high | medium | low | unresolved |
|---|---:|---:|---:|---:|---:|
| register_offset | 35,328 | 35 | 941 | 308 | 34,044 |
| register | 23,653 | 40 | 395 | 123 | 23,095 |
| other | 31 | 0 | 0 | 0 | 31 |
| **total** | **59,012** | **75** | **1,336** | **431** | **57,170** |

* **high (75, 0.13%)** - target read directly from the PE (absolute pointer or a slot of a
  vtable whose address the function itself stores at `[param_1]`, or a global whose value is
  proven by a corpus-wide initializer).
* **medium (1336, 2.26%)** - vtable offset match with a single candidate: the containing
  function is itself a slot of one or more known vtables, and the slot at the observed offset
  resolves to one .text address in all of them (devirtualization by class membership).
* **low (431, 0.73%)** - ambiguous: candidate vtables for `this` disagree at that offset.
  No target is emitted; candidates are listed in `evidence`.
* **unresolved (57170, 96.88%)** - base cannot be tied to a known vtable/pointer.

Net statically-resolved (high + medium): **1411 sites (2.39%)** across **892 distinct functions**.

## 3. Vtable inventory used

| source | vtables | slots |
|---|---:|---:|
| c_vtable_store | 8800 | 120078 |
| registrar_roots | 23 | 780 |
| vftables.txt | 28 | 83 |
| **total** | **8851** | **120941** |

Slot extents are bounded by the next known vtable address in `.rdata` (and by the first
non-`.text` slot), so slot offsets are exact. Vtable bases come from (a) the 23 app_init hub
vtables in `registrar_roots.tsv` (780 slots, 100% agreement with the PE image), (b) `vftables.txt`,
and (c) 8,800 additional bases recovered from `*obj = &PTR_...` vtable stores in the corpus.
Mean vtable size 13.7 slots (max 265).

## 4. Top unresolved clusters

By base shape (47,137 unresolved sites that had a recovered expression):

| sites | share | base shape |
|---:|---:|---|
| 23,942 | 50.8% | virtual call through local object pointer (`*var + off`) |
| 9,209 | 19.5% | call through embedded sub-object (`**(param_N + off)`) |
| 4,217 | 8.9% | function pointer in local/parameter `var` |
| 3,152 | 6.7% | virtual call on `this` (param_1), dynamic vtable unknown |
| 2,366 | 5.0% | virtual call on `this` (param_2), dynamic vtable unknown |
| 1,232 | 2.6% | call through global-held pointer (BSS / runtime initialised) |
| 1,110 | 2.4% | other base shapes |
| 986 | 2.1% | inline fn-ptr field at [param_N + off] (object type unknown) |

By base shape + slot offset (top 15):

| sites | cluster | offset |
|---:|---|---|
| 9,209 | call through embedded sub-object (`**(param_N + off)`) | - |
| 7,987 | virtual call through local object pointer (`*var + off`) | - |
| 4,217 | function pointer in local/parameter `var` | - |
| 2,390 | virtual call through local object pointer (`*var + off`) | 0x18 |
| 2,358 | virtual call through local object pointer (`*var + off`) | 0x1c |
| 1,695 | virtual call through local object pointer (`*var + off`) | 0x4 |
| 1,200 | virtual call through local object pointer (`*var + off`) | 0x8 |
| 1,041 | other base shapes | - |
| 843 | virtual call through local object pointer (`*var + off`) | 0x10 |
| 691 | virtual call through local object pointer (`*var + off`) | 0xc |
| 425 | virtual call on `this` (param_1), dynamic vtable unknown | - |
| 419 | virtual call on `this` (param_2), dynamic vtable unknown | 0x18 |
| 405 | virtual call through local object pointer (`*var + off`) | 0x24 |
| 385 | virtual call through local object pointer (`*var + off`) | 0x14 |
| 364 | call through global-held pointer (BSS / runtime initialised) | - |

Observations:

* The dominant unresolved shape (23,942 sites, 50.8%) is `(**(code **)(*localVar + off))()` /
  `(*pcVar)(...)`: the object lives in a local variable assigned in several branches (usually
  loaded from a container/array). Its dynamic type is not recoverable from the single function
  body, so no vtable can be attached.
* 9,209 sites call through an embedded sub-object (`**(param_N + off)`) and 6,052 are plain
  `*param_1`/`*param_2` virtual calls in functions that are not themselves registered in any
  known vtable, so no class can be attached. These need cross-function type propagation
  (section 6).
* 5,898 sites have **no containing function** in Ghidra's enumeration (code reached only as
  tail/inline fragments, or functions Ghidra never created); 141 sites sit in 12 functions whose
  canonical C export is missing (`100e9490` alone accounts for 127).

## 5. Resolved target concentration

| calls | target | name |
|---:|---|---|
| 43 | 0x10fca230 | FUN_10fca230 |
| 28 | 0x1026ce40 | FUN_1026ce40 |
| 28 | 0x11443c50 | FUN_11443c50 |
| 24 | 0x100d6770 | stub_return_0_100d6770 |
| 22 | 0x113fe130 | FUN_113fe130 |
| 20 | 0x101d95d0 | FUN_101d95d0 |
| 17 | 0x1168d0a8 | FUN_1168d0a8 |
| 17 | 0x110a7be0 | FUN_110a7be0 |
| 16 | 0x100dbc00 | ConstructObject |
| 15 | 0x116bd8af | FUN_116bd8af |

686 distinct targets were resolved; the top 10 account for 230 of the 1411 resolved sites, which is
consistent with a small number of hot virtual methods (allocation, refcount, container ops).

## 6. Recommended next actions

1. **Type propagation for `this`.** Most remaining `*param_1 + off` sites are virtual calls in
   functions that never appear in a vtable. Propagating the concrete type from direct call sites
   (`decomp_fn_X(&obj)` where `obj` is a known constructed type) would convert a large share of
   them into medium-confidence rows without touching Ghidra.
2. **Local object-pointer tracing.** ~9.7k sites are `*var + off` with `var` assigned 2-5 times.
   A small dataflow pass (SSA over the C body) that keeps a set of possible vtable bases per
   local would let those be resolved when all reaching definitions agree.
3. **Fill the 12 missing canonical exports** (`100e9490` and 11 small functions, 141 sites) and
   re-run; the pipeline picks them up automatically.
4. **Recover the 5,898 function-less sites** by re-running function creation around those
   addresses (`work/gap_addresses*.tsv` already lists recovered entries); they currently have no
   C body to match against.
5. **Resolve the `low` bucket (431)** by adding RTTI base-class links from
   `src_out/empire.retail.dll/vftables.txt` (`RTTI_Base_Class_Array` rows) so that derived-vtable
   disagreement can be collapsed to the base implementation.
6. **Sanity gate for new rows:** every emitted target is inside `.text`
   (`0x10001000..0x1172e4ea`) and every vtable slot was read as a 4-byte PE pointer - both are
   asserted by the generator.

## 7. Reproducibility / validation

* `work/indirect_call_resolutions.tsv`: 59012 data rows + header, one per input site, site IDs match
  the input set exactly (asserted).
* `work/indirect_call_vtables.tsv`: 120941 data rows + header; 8851 distinct vtables; every target is a
  `.text` address (asserted).
* Confidence labels are mutually exclusive and exhaustive; `unresolved` rows never carry a
  `resolved_target`.
