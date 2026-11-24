# Decompiler warning triage and switch-table recovery - empire.retail.dll

Complete classification and evidence verification for all **9,856** decompiler warning rows across **6,765** canonical functions, plus PE-verified machine-code recovery of all **47** jump tables across the **16** functions with switch-table failures.

Inputs (read-only): `work/decomp_defects_after.tsv` (9,856 rows), `work/_jumptable_dump_after.tsv` (1,086 addressed jump sites), `work/switch_table_repairs_after.tsv` (21 addressed + 6 selector-normalization functions), `Total War Rome II/empire.retail.dll`, `src_canonical_out/empire.retail.dll/canonical_decomp/`.

Outputs: `work/decomp_defects_triaged_after.tsv` (9,856 rows), `work/switch_tables_recovered_after.tsv` (47 jump tables), this report.

## 1. Triage coverage and confidence

| metric | warnings | share |
|---|---:|---:|
| total decompiler warnings | 9,856 | 100.00% |
| affected functions | 6,765 | 100.00% of warned |
| classified / triaged (`high`) | 9,856 | 100.00% |
| untriaged | 0 | 0.00% |
| recovered true switch-table sites (PE `.reloc` verified) | 47 (across 16 functions) | 21 addressed + 26 selector-norm |

## 2. Breakdown by disposition

| disposition | warnings | share |
|---|---:|---:|
| `benign_symbol_aliasing` | 4,348 | 44.12% |
| `benign_compiler_or_eh_deadcode` | 1,959 | 19.88% |
| `benign_virtual_tailcall` | 1,698 | 17.23% |
| `benign_expected_control_flow` | 584 | 5.93% |
| `benign_iat_tailcall` | 450 | 4.57% |
| `benign_decompiler_artifact` | 382 | 3.88% |
| `benign_expected_prologue_helper` | 276 | 2.80% |
| `verify_stack_frame_on_port` | 73 | 0.74% |
| `switch_table_recovered` | 57 | 0.58% |
| `benign_indirect_tailcall` | 10 | 0.10% |
| `benign_expected_inline` | 8 | 0.08% |
| `benign_callback_tailcall` | 4 | 0.04% |
| `benign_default_case_fold` | 2 | 0.02% |
| `body_exported_verify_on_port` | 2 | 0.02% |
| `benign_label_shift_cases_intact` | 2 | 0.02% |
| `benign_intentional_halt` | 1 | 0.01% |

## 3. Complete category and triage breakdown

| category | severity | triage_class | disposition | warnings |
|---|---|---|---|---:|
| `global_overlap` | low | `ghidra_overlapping_global_symbol` | `benign_symbol_aliasing` | 4,348 |
| `unreachable_block` | low | `dead_or_eh_unreachable_block` | `benign_compiler_or_eh_deadcode` | 1,959 |
| `indirect_jump_as_call` | high | `virtual_vtable_tailcall` | `benign_virtual_tailcall` | 691 |
| `jumptable_failure` | high | `virtual_vtable_tailcall` | `benign_virtual_tailcall` | 691 |
| `noreturn_call` | low | `noreturn_callee_termination` | `benign_expected_control_flow` | 584 |
| `type_propagation` | medium | `decompiler_type_prop_nonconvergence` | `benign_decompiler_artifact` | 331 |
| `injection` | low | `compiler_runtime_helper_injection` | `benign_expected_prologue_helper` | 276 |
| `indirect_jump_as_call` | high | `iat_dispatch_tailcall` | `benign_iat_tailcall` | 225 |
| `jumptable_failure` | high | `iat_dispatch_tailcall` | `benign_iat_tailcall` | 225 |
| `indirect_jump_as_call` | high | `virtual_vtable_reg_tailcall` | `benign_virtual_tailcall` | 158 |
| `jumptable_failure` | high | `virtual_vtable_reg_tailcall` | `benign_virtual_tailcall` | 158 |
| `spacebase` | medium | `stack_frame_spacebase_uncertainty` | `verify_stack_frame_on_port` | 73 |
| `restart_deadcode` | low | `delayed_deadcode_restart` | `benign_decompiler_artifact` | 41 |
| `indirect_jump_as_call` | high | `true_switch_table_addressed` | `switch_table_recovered` | 21 |
| `jumptable_failure` | high | `true_switch_table_addressed` | `switch_table_recovered` | 21 |
| `inlined` | low | `inlined_function_marker` | `benign_expected_inline` | 8 |
| `jumptable_failure` | high | `true_switch_table_selector_norm` | `switch_table_recovered` | 8 |
| `jumptable_degraded` | medium | `switch_table_truncation_linked` | `switch_table_recovered` | 7 |
| `readonly_write` | high | `ghidra_ssa_rodata_alias` | `benign_decompiler_artifact` | 6 |
| `indirect_jump_as_call` | high | `register_indirect_tailcall` | `benign_indirect_tailcall` | 5 |
| `jumptable_failure` | high | `register_indirect_tailcall` | `benign_indirect_tailcall` | 5 |
| `heritage_dead_removal` | low | `ssa_heritage_after_dead_removal` | `benign_decompiler_artifact` | 4 |
| `indirect_jump_as_call` | high | `global_fnptr_tailcall` | `benign_callback_tailcall` | 2 |
| `jumptable_failure` | high | `global_fnptr_tailcall` | `benign_callback_tailcall` | 2 |
| `restart_limit` | high | `decompiler_restart_cap` | `body_exported_verify_on_port` | 2 |
| `switch_case_unlabeled` | medium | `switch_label_base_shift` | `benign_label_shift_cases_intact` | 2 |
| `switch_degraded` | low | `switch_collapsed_default_case` | `benign_default_case_fold` | 2 |
| `infinite_loop_block` | low | `intentional_spin_trap` | `benign_intentional_halt` | 1 |

## 4. Recovered switch tables (16 functions, 47 PE-verified sites)

| function_entry | function_name | kind | sites | total_entries | unique_targets | byte_lut_sites |
|---|---|---|---:|---:|---:|---:|
| `0x103e76a0` | `battle_entity_dispatch_combat_anim_by_quadrant_and_stance_103e76a0` | `addressed_jump` | 6 | 84 | 84 | 0 |
| `0x103e7c70` | `battle_unit_candidate_filter` | `addressed_jump` | 2 | 12 | 12 | 0 |
| `0x103e96c0` | `battle_proximity_random_trigger_check` | `addressed_jump` | 6 | 84 | 84 | 0 |
| `0x10445310` | `audio_anim_event_post_sound_by_kind_10445310` | `addressed_jump` | 1 | 9 | 4 | 0 |
| `0x104c1fb0` | `battle_entity_select_facing_slot_for_target_point_104c1fb0` | `addressed_jump` | 1 | 6 | 6 | 0 |
| `0x1068cea0` | `battle_calc_inv_square_factor_by_thresholds_1068cea0` | `addressed_jump` | 1 | 4 | 4 | 0 |
| `0x107ca950` | `campaign_audio_play_character_pair_event_107ca950` | `addressed_jump` | 1 | 14 | 8 | 0 |
| `0x10a054b0` | `crt_static_init_or_dtor_chain` | `selector_normalization` | 2 | 9 | 9 | 2 |
| `0x10f1f890` | `unknown_calls_strtol` | `selector_normalization` | 4 | 42 | 37 | 3 |
| `0x10fbb5e0` | `net_webapi_client_update_op_state_machines_10fbb5e0` | `addressed_jump` | 1 | 9 | 8 | 0 |
| `0x10fe9050` | `pugixml_utf8_encode_codepoint` | `addressed_jump` | 1 | 4 | 4 | 0 |
| `0x11299e70` | `battle_ui_unit_status_icon_update` | `addressed_jump` | 1 | 11 | 11 | 0 |
| `0x1130aa70` | `png_check_fp_number` | `selector_normalization` | 2 | 18 | 10 | 1 |
| `0x114b7d80` | `render_dispatch_object_by_type_code_114b7d80` | `selector_normalization` | 8 | 59 | 59 | 8 |
| `0x116b8ebc` | `unknown_calls_fill_fpieee_record` | `selector_normalization` | 5 | 25 | 21 | 4 |
| `0x116ba4ba` | `crt_parse_floating_point_strtod_engine` | `selector_normalization` | 5 | 28 | 24 | 4 |

## 5. High-severity non-dispatch audit (`readonly_write` & `restart_limit`)

* All **6** `readonly_write` warnings trace to read-only `.rdata` 16-byte SSE constants read by valid SSE vector load/logic instructions (zero machine-code writes to `.rdata`):
  * `0x11317860` @ `0x118a0210`: .rdata VA 0x118a0210 (u32=0x00ff00ff); read-only SSE refs: 0x11317a99:PAND XMM1,[0x118a0210], 0x11317aef:PAND XMM1,[0x118a0210]
  * `0x11317860` @ `0x118a0210`: .rdata VA 0x118a0210 (u32=0x00ff00ff); read-only SSE refs: 0x11317a99:PAND XMM1,[0x118a0210], 0x11317aef:PAND XMM1,[0x118a0210]
  * `0x11317860` @ `0x118a0210`: .rdata VA 0x118a0210 (u32=0x00ff00ff); read-only SSE refs: 0x11317a99:PAND XMM1,[0x118a0210], 0x11317aef:PAND XMM1,[0x118a0210]
  * `0x11317860` @ `0x118a0210`: .rdata VA 0x118a0210 (u32=0x00ff00ff); read-only SSE refs: 0x11317a99:PAND XMM1,[0x118a0210], 0x11317aef:PAND XMM1,[0x118a0210]
  * `0x114270b0` @ `0x118c0860`: .rdata VA 0x118c0860 (u32=0x6c078965); read-only SSE refs: 0x114270f2:MOVAPS XMM2,[0x118c0860]
  * `0x116a0b30` @ `0x119135f0`: .rdata VA 0x119135f0 (u32=0x00000000); read-only SSE refs: 0x116a0c09:CMPPD XMM3,[0x119135f0],1, 0x116a0c12:ORPD XMM3,[0x119135f0]
* Both **2** `restart_limit` functions compiled/exported completely (`Export result: success`, zero `halt_baddata`):
  * `0x10c6afa0`: Canonical C `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_10c6afa0.c` exported cleanly (421 lines, 17232 bytes, Export result: success, no halt_baddata)
  * `0x11472bd0`: Canonical C `src_canonical_out/empire.retail.dll/canonical_decomp/decomp_fn_11472bd0.c` exported cleanly (444 lines, 14415 bytes, Export result: success, no halt_baddata)

## 6. Validation

* `work/decomp_defects_triaged_after.tsv`: 9,856 data rows + header, exact 1:1 row-order bijection with `work/decomp_defects_after.tsv`.
* `work/switch_tables_recovered_after.tsv`: 47 jump tables across 16 functions (`21` addressed + `26` selector-normalization), every slot PE `.reloc`-backed and every target verified inside `.text` (`0x10001000..0x1172e4ea`).
* `1,043 / 1,043` functions with addressed jump-table warnings exhibit an exact 1:1 pairing between addressed `jumptable_failure` and `indirect_jump_as_call` rows (`0` mismatches).
