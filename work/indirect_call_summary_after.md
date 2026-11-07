# Indirect call resolution - empire.retail.dll (Total War: Rome II)

Second pass over the regenerated canonical corpus.

Input: `work/indirect_calls_after.tsv` (Ghidra enumeration, 59,079 indirect call sites),
`src_canonical_out/empire.retail.dll/canonical_decomp/` (81,280 canonical C files),
PE `Total War Rome II/empire.retail.dll` (PE32, image base 0x10000000),
`work/registrar_roots.tsv`, `src_out/empire.retail.dll/vftables.txt`.

Outputs: `work/indirect_call_resolutions_after.tsv` (59,079 rows), `work/indirect_call_vtables_after.tsv` (121,692 rows), this file.

## 1. Site population and expression coverage

| metric | sites | share |
|---|---:|---:|
| total indirect call sites | 59,079 | 100.00% |
| containing function recorded by Ghidra | 58,446 | 98.93% |
| containing function has a canonical C file | 58,446 | 98.93% |
| exact/near call expression recovered from C | 52,862 | 89.48% |
| no containing function recorded by Ghidra | 608 | 1.03% |
| no matching call expression in the C body | 5,584 | 9.45% |
| canonical C file missing for the function | 0 | 0.00% |
| not an indirect call at all (`INT3`/`INT` padding) | 25 | 0.04% |

Sites are matched to C call expressions per function. When the number of C expressions equals
the number of asm sites the pairing is 1:1 in program order; otherwise the two sequences are
aligned on their slot-offset sequences and the row is flagged
`| expression aligned by offset` in `evidence`.

## 2. Resolution by kind and confidence

| kind | sites | high | medium | low | unresolved |
|---|---:|---:|---:|---:|---:|
| register_offset | 35,370 | 37 | 1,525 | 394 | 33,414 |
| register | 23,678 | 39 | 556 | 168 | 22,915 |
| other | 31 | 0 | 0 | 0 | 31 |
| **total** | **59,079** | **76** | **2,081** | **562** | **56,360** |

* **high** - target read directly from the PE (absolute pointer or a slot of a
  vtable whose address the function itself stores at `[param_1]`, or a global whose value is
  proven by a corpus-wide initializer), or a function/label symbol.
* **medium** - vtable offset match with a single candidate: the containing function is itself
  a slot of one or more known vtables, and the slot at the observed offset resolves to one
  .text address in all of them (devirtualization by class membership).
* **low** - ambiguous: candidate vtables for `this` disagree at that offset. No target is
  emitted; candidates are listed in `evidence`.
* **unresolved** - base cannot be tied to a known vtable/pointer.

Net statically-resolved (high + medium): **2,157 sites (3.65%)** across **1,337 distinct functions** and **926 distinct targets**.

## 3. Delta vs the first pass

| metric | first pass | this pass | delta |
|---|---:|---:|---:|
| input sites | 59,012 | 59,079 | +67 |
| high | 75 | 76 | +1 |
| medium | 1,336 | 2,081 | +745 |
| low | 431 | 562 | +131 |
| unresolved | 57,170 | 56,360 | -810 |
| **resolved (high+medium)** | **1,411** | **2,157** | **+746** |

Resolved sites by kind:

| kind | first pass | this pass | delta |
|---|---:|---:|---:|
| register_offset | 976 | 1,562 | +586 |
| register | 435 | 595 | +160 |
| other | 0 | 0 | 0 |
| **total** | **1,411** | **2,157** | **+746** |

The resolved set covers **1,337 distinct functions** and **926 distinct targets**, up from
**892 functions** and **686 targets** (+445 functions, +240 targets).

Of the net **+746** resolved sites, **747** were sites that had no containing function at all
in the first pass (previously unmatchable), **51** came from old unresolved/low rows, and **1**
is a new site. **53** old resolved sites were lost because the regenerated function bodies changed shape
(secondary-vtable expressions, extra local assignments) or because the larger vtable inventory
turned an old single-candidate match into a disagreement (now `low`).

### 3.1 Sites that gained a containing function

The first pass had **5,898** sites with no containing function. **5,303** of
those now sit in a Ghidra function and have a canonical C file; **595** are
still function-less. The new enumeration has **608** function-less sites in
total (595 carried over, 13 are new sites).

| outcome for the newly-contained sites | sites | share |
|---|---:|---:|
| high | 0 | 0.00% |
| medium | 747 | 14.09% |
| low | 140 | 2.64% |
| unresolved | 4,416 | 83.27% |
| **total** | **5,303** | **100.00%** |

Resolved among them: **0 high + 747 medium = 747 sites**; 140 more are ambiguous (`low`).
The remaining unresolved sites are dominated by:

| reason | sites |
|---|---:|
| base expression not resolvable (complex pointer chain) | 2,157 |
| local object pointer with unknown vtable | 752 |
| local function pointer with unresolved assignment | 604 |
| virtual call on param_2+ (only param_1 is devirtualized) | 328 |
| no matching indirect-call expression in the C body | 288 |
| secondary/embedded vtable unknown | 209 |
| inline function-pointer field | 65 |
| mnemonic INT3: not an indirect call (padding/trap) | 2 |

## 4. Vtable inventory used

| source | vtables | slots |
|---|---:|---:|
| c_vtable_store | 9,000 | 120,829 |
| registrar_roots | 23 | 780 |
| vftables.txt | 28 | 83 |
| **total** | **9,051** | **121,692** |

Slot extents are bounded by the next known vtable address in `.rdata`/`.data` (and by the
first non-`.text` slot), so slot offsets are exact. Vtable bases come from the 23 app_init
hub vtables in `registrar_roots.tsv`, `vftables.txt`, and corpus `&PTR_...` vtable stores.

## 5. Resolved target concentration

| calls | target | name |
|---:|---|---|
| 62 | 0x1035be10 | FUN_1035be10 |
| 58 | 0x10fca230 | FUN_10fca230 |
| 38 | 0x113fe130 | FUN_113fe130 |
| 35 | 0x10ee0ed0 | FUN_10ee0ed0 |
| 32 | 0x1026ce40 | FUN_1026ce40 |
| 28 | 0x10ee5d00 | FUN_10ee5d00 |
| 28 | 0x11443c50 | FUN_11443c50 |
| 26 | 0x110a7be0 | FUN_110a7be0 |
| 25 | 0x100d6770 | FUN_100d6770 |
| 21 | 0x1168d0a8 | FUN_1168d0a8 |

926 distinct targets were resolved.

## 6. Validation

* `work/indirect_call_resolutions_after.tsv`: 59,079 data rows + header, one per input site;
  site IDs match the input set exactly (asserted).
* `work/indirect_call_vtables_after.tsv`: 121,692 data rows + header; 9,051 distinct vtables; every target is a `.text` address (asserted).
* Confidence labels are mutually exclusive and exhaustive; `low` and `unresolved` rows never
  carry a `resolved_target`; every emitted target is inside `.text`.

