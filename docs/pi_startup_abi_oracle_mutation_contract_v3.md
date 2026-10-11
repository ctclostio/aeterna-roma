# Pi startup ABI oracle mutation contract v3

Status: normative design contract for the revised O stage. This document defines
the complete closed-world set of 32 paired mutations. It does not authorize
execution, loading, linking, translation, or emulation of recovered code.

## Frozen authority pins

- Original PE: "Total War Rome II/empire.retail.dll", 28,278,272 bytes,
  SHA-256 "d0d9805f41b69f2e5e9a54fbe07c327f18e311e76116e219512ad328bde43528".
- 0x100ed3c0 ABI fixture: "scripts/x64_startup_100ed3c0_abi_fixture.json",
  11,506 bytes, SHA-256
  "d1f129b03e19fded78c19d8211f3a943a68004d2ff8c12a1530ce1f276a6f8d0".
- 0x100f1aa0 empty fixture:
  "scripts/x64_startup_100f1aa0_empty_fixture.json", 5,087 bytes, SHA-256
  "434a0665d70907f2ab69c197796349e97ea84c48583f19c17aa78a793816a5ac".
- Startup ABI contract: "docs/x64_startup_100ed3c0_abi_contract.md",
  4,080 bytes, SHA-256
  "55c04124e21849bda5eec68e2502045776bc2db7c33d1ff6ab3d69fd8d7906f8".
- Production CMake authority: "CMakeLists.txt", 30,474 bytes, SHA-256
  "a165e1a7164b794ca12be4ebc18120ebb47e3644aafd7db4f7ec79eaf9fcc114".

The revised O04 context must preserve its existing ten evidence authorities in
their existing order, append the original PE as evidence-authority index 10
with the exact size and hash above, and then pin this mutation contract as
control document index 11. O04 therefore authenticates twelve supervisor
context pins. Its disposable mutation subject is the eleven-entry evidence-
authority array only; the control document is excluded from that subject. This
ordering is part of the contract because the pin-removal mutation below uses
evidence-array index 8.

## Global anti-wrong-reason rules

1. Authority files are authenticated completely before derivation and remain
   read-only. Every mutation subject is created only below its worker's isolated
   disposable directory.
2. A raw-byte subject is copied from the exact authenticated authority extent
   named below. A derived JSON subject is canonically generated from the exact
   pinned fixture or raw facts named below.
3. The unchanged checker must PASS the pristine subject before the paired
   mutation is applied.
4. The mutation engine must assert the exact before value, perform exactly the
   one declared operation at the one declared locus, and prove every byte or
   field outside that locus unchanged. A JSON replacement of one aggregate
   object is one operation at one RFC 6901 pointer.
5. A deliberately mutated subject is checked by lineage: all bytes or fields
   outside the declared locus must match the authenticated pristine subject.
   Rejecting it merely because its whole-file hash differs from the pristine
   hash is not an acceptable mutant kill.
6. Before and after enum values are both syntactically and structurally valid
   unless truncation or malformed structure is the declared semantic subject.
   JSON parse, schema, enum-type, missing-file, or unrelated size failures do
   not count as kills.
7. Every mutant run must reach and return its exact required kill code below.
   Any different failure code, any early failure, or a mutant PASS is an oracle
   failure.
8. Raw x86 is parsed only as inert bytes. No original or recovered code is
   executed, loaded, imported, linked, translated, or emulated.
9. The O04 outside-write sentinel is outside the nested disposable sandbox but
   remains inside O04's isolated writable worker root. Its guarded attempted
   write must be denied before an operating-system mutation occurs.
10. O04 malformed-PE cases are independent test corpus inputs, each created by
    one exact disposable-copy edit. They are not additional paired mutants.

Each mutant below has six normative mutation values. The document label
"subject_path_authority" names the exact value serialized under the v3
transport key "subject_path"; the other transport keys are "subject_kind",
"operation", "locus", "before", and "after". The exact description, kill
code, and anti-wrong-reason clause are also normative.

## O01 raw boundary and calling convention

### O01.M1

- exact_description: "EXACT_SINGLE_MUTATION: O01_M1_FLIP_HANDLER_PACKET_BYTE"
- subject_kind: "authenticated_pe_packet_copy"
- subject_path_authority: "mutants/O01_M1/handler_packet.bin", derived from
  "Total War Rome II/empire.retail.dll" raw bytes [0x000ed320, 0x000ed32d)
  and fixture "/caller_packets/0".
- operation: "replace_bytes"
- locus: "subject byte offset 0, length 1; original-PE raw offset 0x000ed320"
- before: "ff"
- after: "fe"
- required_kill_code: "PACKET_OPCODE_MISMATCH_AT_0"
- anti_wrong_reason: The mutant remains exactly 13 bytes. The packet parser must
  reach the byte-zero opcode comparison; PE hash, packet length, or generic
  decode failure is not an acceptable kill.

### O01.M2

- exact_description: "EXACT_SINGLE_MUTATION: O01_M2_SWAP_PUSHES_3_AND_4"
- subject_kind: "authenticated_pe_packet_copy"
- subject_path_authority: "mutants/O01_M2/handler_packet.bin", derived from
  original-PE raw bytes [0x000ed320, 0x000ed32d) and fixture
  "/caller_packets/0/pushes".
- operation: "replace_bytes"
- locus: "subject byte offset 4, length 4; original-PE raw offset 0x000ed324"
- before: "ff750c56"
- after: "56ff750c"
- required_kill_code: "PUSH_ORDER_SLOTS_3_4_SWAPPED"
- anti_wrong_reason: The packet remains 13 bytes and all four push instructions
  decode. The checker must reject only the changed machine-order and
  callee-position mapping, not hash, length, or decode.

### O01.M3

- exact_description: "EXACT_SINGLE_MUTATION: O01_M3_PROMOTE_ESI_PRIOR_LOAD_TO_PROVEN"
- subject_kind: "derived_claim_record"
- subject_path_authority: "mutants/O01_M3/prior_loads.json", derived from
  fixture "/caller_source_loads" and authenticated original-PE bytes at raw
  offsets 0x000ed268 and 0x000ed2c9.
- operation: "json_replace"
- locus: "/claims/esi_prior_load/status"
- before: "\"observation\""
- after: "\"proven_def_use\""
- required_kill_code: "UNSUPPORTED_ESI_DEF_USE_PROMOTION"
- anti_wrong_reason: Both classifications are valid enum values and the
  underlying load bytes remain unchanged. Schema or missing-evidence failure is
  not accepted.

### O01.M4

- exact_description: "EXACT_SINGLE_MUTATION: O01_M4_USE_CALL_VA_AS_REL32_BASE"
- subject_kind: "derived_rel32_policy"
- subject_path_authority: "mutants/O01_M4/rel32.json", derived from fixture
  "/caller_packets/*/call" and the authenticated raw call bytes.
- operation: "json_replace"
- locus: "/base_mode"
- before: "\"NEXT_VA\""
- after: "\"CALL_VA\""
- required_kill_code: "REL32_TARGET_MISMATCH"
- anti_wrong_reason: Both modes are valid and both E8 records decode. The
  mutated calculation must reach 0x100ed3bb instead of 0x100ed3c0; token,
  schema, or hash rejection is not accepted.

### O01.M5

- exact_description: "EXACT_SINGLE_MUTATION: O01_M5_REPLACE_BARE_RET_WITH_RET4"
- subject_kind: "authenticated_epilogue_slice"
- subject_path_authority: "mutants/O01_M5/epilogue.bin", derived from
  original-PE raw bytes [0x000ec948, 0x000ec950), pristine hex
  "5e81c40c090000c3", and the fixture critical-instruction tail.
- operation: "splice_bytes"
- locus: "epilogue byte offset 7, remove length 1; callee-body offset 399;
  original-PE raw offset 0x000ec94f"
- before: "c3"
- after: "c20400"
- required_kill_code: "CALLEE_CLEANUP_4_NOT_0"
- anti_wrong_reason: The ten-byte result must fully decode as pop ESI, add
  ESP,0x90c, ret 4. A whole-body size or pristine-hash failure is not an
  acceptable semantic kill.

### O01.M6

- exact_description: "EXACT_SINGLE_MUTATION: O01_M6_TRUNCATE_HANDLER_PACKET_TO_12_BYTES"
- subject_kind: "authenticated_pe_packet_copy"
- subject_path_authority: "mutants/O01_M6/handler_packet.bin", derived from
  original-PE raw bytes [0x000ed320, 0x000ed32d), pristine hex
  "ff752457ff750c56e893f4ffff".
- operation: "delete_bytes"
- locus: "subject byte offset 12, length 1; original-PE raw offset 0x000ed32c"
- before: "ff"
- after: "ABSENT"
- required_kill_code: "HANDLER_PACKET_TRUNCATED_12_NOT_13"
- anti_wrong_reason: The result is valid 12-byte binary data with hex
  "ff752457ff750c56e893f4ff". JSON or hex syntax failure is not accepted.

### O01.M7

- exact_description: "EXACT_SINGLE_MUTATION: O01_M7_SWAP_CONTINUATION_IDENTITY"
- subject_kind: "derived_branch_digest_map"
- subject_path_authority: "mutants/O01_M7/branches.json", derived from fixture
  "/caller_packets/*/grouped_cleanup" and original-PE continuation slices
  [0x000ed32d, 0x000ed341) and [0x000ed380, 0x000ed394).
- operation: "json_replace"
- locus: "/continuation_sha256_by_branch"
- before: "{\"handler_registered\":\"16059cc15e0932ce776ddaeb4f7e5e991eb8fe6776f279d8b3dacc4238826954\",\"no_exception_handler\":\"2bb4e7d91eb623e2d1bb5e99c1c71431bd06fb60fb1ae5316da895dcdad3e7ba\"}"
- after: "{\"handler_registered\":\"2bb4e7d91eb623e2d1bb5e99c1c71431bd06fb60fb1ae5316da895dcdad3e7ba\",\"no_exception_handler\":\"16059cc15e0932ce776ddaeb4f7e5e991eb8fe6776f279d8b3dacc4238826954\"}"
- required_kill_code: "BRANCH_CONTINUATION_IDENTITIES_SWAPPED"
- anti_wrong_reason: Both values remain distinct, valid SHA-256 strings. The
  checker must recompute both continuation hashes and reject their reciprocal
  identity mapping; digest syntax or count failure is not accepted.

### O01.M8

- exact_description: "EXACT_SINGLE_MUTATION: O01_M8_CORRUPT_PE_OPTIONAL_MAGIC"
- subject_kind: "disposable_full_pe_copy"
- subject_path_authority: "mutants/O01_M8/empire.retail.dll", copied from the
  fully authenticated original PE.
- operation: "replace_bytes"
- locus: "raw file offset 0x000001a8, length 2; e_lfanew 0x190 plus PE/COFF
  prefix length 0x18"
- before: "0b01"
- after: "5901"
- required_kill_code: "UNSUPPORTED_OPTIONAL_MAGIC"
- anti_wrong_reason: The parser must first accept MZ, e_lfanew, PE signature,
  and COFF bounds, then reject optional magic 0x0159. Whole-file hash rejection
  or premature VA mapping is not accepted.

## O02 complete-body static oracle

### O02.M1

- exact_description: "EXACT_SINGLE_MUTATION: O02_M1_TREAT_SPARSE_ROWS_AS_GLOBAL_FLOW"
- subject_kind: "derived_decode_policy"
- subject_path_authority: "mutants/O02_M1/decode_policy.json", derived from
  fixture "/critical_instructions" and the authenticated 400-byte callee body.
- operation: "json_replace"
- locus: "/fixture_rows_semantics"
- before: "\"LOCAL_OBSERVATIONS_ONLY\""
- after: "\"COMPLETE_INSTRUCTION_STREAM\""
- required_kill_code: "SPARSE_ROWS_PROMOTED_TO_GLOBAL_FLOW"
- anti_wrong_reason: Both policy values are valid and an independent full-body
  decode must still cover all 400 bytes. A gap, decode, or schema failure is not
  accepted.

### O02.M2

- exact_description: "EXACT_SINGLE_MUTATION: O02_M2_USE_CALL_VA_AS_REL32_BASE"
- subject_kind: "derived_rel32_policy"
- subject_path_authority: "mutants/O02_M2/rel32.json", derived from the pinned
  caller records and complete authenticated body.
- operation: "json_replace"
- locus: "/base_mode"
- before: "\"NEXT_VA\""
- after: "\"CALL_VA\""
- required_kill_code: "REL32_TARGET_MISMATCH"
- anti_wrong_reason: Both values are valid, the calls decode, and the mutant
  targets are deterministically five bytes low. Schema or hash rejection is
  not accepted.

### O02.M3

- exact_description: "EXACT_SINGLE_MUTATION: O02_M3_MARK_EBX_STABLE"
- subject_kind: "derived_register_contract"
- subject_path_authority: "mutants/O02_M3/registers.json", derived from the
  fixture delayed ESI save/restore and authenticated raw body.
- operation: "json_replace"
- locus: "/registers/ebx"
- before: "\"UNPROVEN\""
- after: "\"STABLE\""
- required_kill_code: "UNPROVEN_EBX_PROMOTED_STABLE"
- anti_wrong_reason: Both classifications are valid and all byte evidence is
  unchanged. Enum or schema rejection is not accepted.

### O02.M4

- exact_description: "EXACT_SINGLE_MUTATION: O02_M4_REPLACE_100ED3ED_DISP_0910_WITH_091C_P4"
- subject_kind: "authenticated_400_byte_body_copy"
- subject_path_authority: "mutants/O02_M4/body.bin", derived from original-PE
  raw bytes [0x000ec7c0, 0x000ec950), SHA-256
  "b606895706a18f44d27babaef870efc60b362733d01af389b96a10e7c0e5d206".
- operation: "replace_bytes"
- locus: "body byte offset 48, length 2; original-PE raw offset 0x000ec7f0;
  operand VA 0x100ed3f0 in the instruction beginning at 0x100ed3ed"
- before: "1009"
- after: "1c09"
- required_kill_code: "DIRECT_POSITION_4_READ_AT_100ED3ED"
- anti_wrong_reason: The body remains exactly 400 bytes and decodes gap-free.
  The instruction becomes "8b84241c090000", whose normalized entry offset is
  16. Hash or decode rejection is not accepted. Byte offset 45 is invalid for
  this mutation and must be rejected by the gate.

### O02.M5

- exact_description: "EXACT_SINGLE_MUTATION: O02_M5_REPLACE_100ED4D2_75ED_WITH_9090"
- subject_kind: "authenticated_400_byte_body_copy"
- subject_path_authority: "mutants/O02_M5/body.bin", derived from the same
  authenticated 400-byte body.
- operation: "replace_bytes"
- locus: "body byte offset 274, length 2; original-PE raw offset 0x000ec8d2"
- before: "75ed"
- after: "9090"
- required_kill_code: "MISSING_BACK_EDGE_100ED4D2_TO_100ED4C1"
- anti_wrong_reason: The body remains 400 bytes and decodes gap-free. Only the
  named conditional back edge is neutralized. Hash, decode, or a claim that the
  entire CFG is acyclic is not accepted.

### O02.M6

- exact_description: "EXACT_SINGLE_MUTATION: O02_M6_USE_ZERO_ESP_DELTA_FOR_ALL_ROWS"
- subject_kind: "derived_critical_row_vector"
- subject_path_authority: "mutants/O02_M6/esp_deltas.json", derived from
  fixture "/critical_instructions" and the complete authenticated decode.
- operation: "json_replace"
- locus: "/esp_delta_before"
- before: "[0,-2316,-2316,-2316,-2320,-2320,-2320,-2320,-2320,-2320,-2320,-2316,0]"
- after: "[0,0,0,0,0,0,0,0,0,0,0,0,0]"
- required_kill_code: "ESP_DELTA_VECTOR_MISMATCH"
- anti_wrong_reason: Both arrays have the same valid length and element types,
  while the independent body decode remains valid. Array or schema rejection
  is not accepted.

### O02.M7

- exact_description: "EXACT_SINGLE_MUTATION: O02_M7_REPLACE_100ED3C0_81EC0C090000_WITH_0F0B90909090"
- subject_kind: "authenticated_400_byte_body_copy"
- subject_path_authority: "mutants/O02_M7/body.bin", derived from the
  authenticated 400-byte body.
- operation: "replace_bytes"
- locus: "body byte offset 0, length 6; original-PE raw offset 0x000ec7c0"
- before: "81ec0c090000"
- after: "0f0b90909090"
- required_kill_code: "FORBIDDEN_UD2_AT_ENTRY"
- anti_wrong_reason: "0f0b" is the valid UD2 instruction, not an unsupported
  opcode. The decoder must consume UD2, four NOPs, and the rest of the 400-byte
  body gap-free before policy rejection. Unsupported-opcode, hash, or a second
  399-byte truncation failure is not accepted. The paired marker must be
  "FORBIDDEN_INSTRUCTION_CASE=UD2_AT_100ED3C0_PLUS_FOUR_NOPS"; no independent
  final-C3 truncation belongs in this test.

### O02.M8

- exact_description: "EXACT_SINGLE_MUTATION: O02_M8_REPLACE_FINAL_C3_WITH_C20400"
- subject_kind: "authenticated_epilogue_slice"
- subject_path_authority: "mutants/O02_M8/epilogue.bin", derived from
  original-PE raw bytes [0x000ec948, 0x000ec950), pristine hex
  "5e81c40c090000c3".
- operation: "splice_bytes"
- locus: "epilogue byte offset 7, remove length 1; callee-body offset 399;
  original-PE raw offset 0x000ec94f"
- before: "c3"
- after: "c20400"
- required_kill_code: "CALLEE_CLEANUP_4_NOT_0"
- anti_wrong_reason: The complete ten-byte epilogue must decode and expose
  cleanup 4. Whole-body size or hash rejection is not accepted.

## O03 empty-path and containment oracle

### O03.M1

- exact_description: "EXACT_SINGLE_MUTATION: O03_M1_TRUNCATE_100F1AA0_BODY_TO_31_BYTES"
- subject_kind: "authenticated_100f1aa0_body_copy"
- subject_path_authority: "mutants/O03_M1/body.bin", derived from original-PE
  raw bytes [0x000f0ea0, 0x000f0ec0), pristine hex
  "8b44240456578bf98b1089178b70088d04565056e877d8ffff8bc75f5ec20400",
  SHA-256 "cec1214bba5a2c2c8c45487abf0da2412df9dcb634da206f6f6e74f6c619e92e".
- operation: "delete_bytes"
- locus: "body byte offset 31, length 1; original-PE raw offset 0x000f0ebf"
- before: "00"
- after: "ABSENT"
- required_kill_code: "BODY_EXTENT_31_NOT_32"
- anti_wrong_reason: The exact 31-byte lineage must be established first.
  JSON, full-PE hash, or unrelated function-boundary failure is not accepted.

### O03.M2

- exact_description: "EXACT_SINGLE_MUTATION: O03_M2_RETARGET_100F1AB4_TO_100F1C10"
- subject_kind: "authenticated_100f1aa0_body_copy"
- subject_path_authority: "mutants/O03_M2/body.bin", derived from the same
  authenticated 32-byte body and fixture "/copy_wrapper/helper_call".
- operation: "replace_bytes"
- locus: "body byte offset 21, length 4; original-PE raw offset 0x000f0eb5;
  rel32 operand following E8 at body offset 20"
- before: "77d8ffff"
- after: "57010000"
- required_kill_code: "ORIGINAL_CALL_TARGET_NOT_100EF330"
- anti_wrong_reason: The body remains 32 bytes and decodes gap-free. Next VA
  0x100f1ab9 plus 0x157 must resolve exactly to 0x100f1c10. A fixture
  target-value or hash mismatch is not accepted; the old target-only JSON
  mutation must be rejected by the gate.

### O03.M3

- exact_description: "EXACT_SINGLE_MUTATION: O03_M3_TRUNCATE_ZERO_PREFIX_TO_22_BYTES"
- subject_kind: "authenticated_zero_prefix_copy"
- subject_path_authority: "mutants/O03_M3/zero_prefix.bin", derived from
  original-PE raw bytes [0x000ee730, 0x000ee747), pristine hex
  "578bf98b0789470485c0750bc747089040af115fc20800", SHA-256
  "4453992ce0b1a2df255117ba5d3a67c837b9f9b582dbc178fd42d5cd65533db2".
- operation: "delete_bytes"
- locus: "prefix byte offset 22, length 1; original-PE raw offset 0x000ee746"
- before: "00"
- after: "ABSENT"
- required_kill_code: "ZERO_PREFIX_22_NOT_23"
- anti_wrong_reason: The result is exact 22-byte binary data ending at
  0x100ef346. JSON or wholesale authority-hash rejection is not accepted.

### O03.M4

- exact_description: "EXACT_SINGLE_MUTATION: O03_M4_MOVE_STOP_TO_100EF348"
- subject_kind: "derived_slice_boundary_record"
- subject_path_authority: "mutants/O03_M4/empty_slice.json", derived from empty
  fixture "/sequence_helper/empty_prefix", the branch bytes, and first excluded
  original-PE byte "53" at raw offset 0x000ee747.
- operation: "json_replace"
- locus: "/va_end_exclusive"
- before: "\"0x100ef347\""
- after: "\"0x100ef348\""
- required_kill_code: "STOP_INCLUDES_JNE_TARGET_BYTE_100EF347"
- anti_wrong_reason: Both coordinates are valid and raw bytes are unchanged.
  The checker must reject inclusion of the first target byte, not schema, hash,
  or address syntax.

### O03.M5

- exact_description: "EXACT_SINGLE_MUTATION: O03_M5_INCLUDE_ALLOCATOR_CALL_AT_100EF354"
- subject_kind: "derived_slice_boundary_record"
- subject_path_authority: "mutants/O03_M5/empty_slice.json", derived from the
  empty fixture and original-PE interval [0x000ee747, 0x000ee759), which
  contains "e827d90000" at raw offset 0x000ee754.
- operation: "json_replace"
- locus: "/va_end_exclusive"
- before: "\"0x100ef347\""
- after: "\"0x100ef359\""
- required_kill_code: "ALLOCATOR_CALL_100EF354_INCLUDED"
- anti_wrong_reason: The bounded scanner must parse the selected raw interval,
  find the complete E8, and resolve target 0x100fcc80. Repository-wide scan,
  hash, or bounds-syntax failure is not accepted.

### O03.M6

- exact_description: "EXACT_SINGLE_MUTATION: O03_M6_DROP_PARENT_SITE_100ED427"
- subject_kind: "disposable_empty_fixture_copy"
- subject_path_authority: "mutants/O03_M6/fixture.json", copied from the pinned
  empty fixture and checked against the authenticated original-PE parent
  window.
- operation: "json_remove"
- locus: "/parent_window/calls/1"
- before: "{\"va\":\"0x100ed427\",\"bytes\":\"e874460000\",\"next_va\":\"0x100ed42c\",\"rel32\":18036,\"target_va\":\"0x100f1aa0\"}"
- after: "ABSENT"
- required_kill_code: "PARENT_SITE_SET_MISSING_100ED427"
- anti_wrong_reason: The remaining array is schema-valid and the raw parent scan
  still finds both calls. Array, schema, or hash rejection is not accepted.

### O03.M7

- exact_description: "EXACT_SINGLE_MUTATION: O03_M7_CAST_11AF4090_TO_HOST_POINTER"
- subject_kind: "derived_guest_identity_classification"
- subject_path_authority: "mutants/O03_M7/guest_identity.json", derived from
  empty-fixture sentinel-store bytes "c747089040af11" at VA 0x100ef33c and the
  corresponding authenticated original-PE bytes.
- operation: "json_replace"
- locus: "/classification"
- before: "\"OPAQUE_GUEST32\""
- after: "\"HOST_POINTER\""
- required_kill_code: "HOST_POINTER_CLASSIFICATION_FORBIDDEN"
- anti_wrong_reason: Both enum values are valid, while value "0x11af4090" and
  the raw store remain unchanged. No dereference occurs. Token width, schema,
  or the old malformed 15-hex-digit value is not accepted.

### O03.M8

- exact_description: "EXACT_SINGLE_MUTATION: O03_M8_PROMOTE_RET8_TO_NATIVE_ABI"
- subject_kind: "derived_return_classification"
- subject_path_authority: "mutants/O03_M8/ret8.json", derived from empty-fixture
  and original-PE bytes "5fc20800" at VA 0x100ef343 with x86 cleanup immediate
  8.
- operation: "json_replace"
- locus: "/classification"
- before: "\"X86_STACK_FACT_ONLY\""
- after: "\"NATIVE_ABI\""
- required_kill_code: "NATIVE_ABI_PROMOTION_FORBIDDEN"
- anti_wrong_reason: Both classifications are valid, and raw bytes and cleanup
  8 remain unchanged. Cleanup mismatch, schema rejection, or the old
  "callee_cleanup_bytes" change from 8 to 0 is not accepted.

## O04 provenance and containment oracle

### O04.M1

- exact_description: "EXACT_SINGLE_MUTATION: O04_M1_SKIP_ONE_PINNED_SOURCE_HASH"
- subject_kind: "disposable_pin_array"
- subject_path_authority: "mutants/O04_M1/pins.json", generated from the exact
  ordered eleven-entry O04 evidence-authority array.
- operation: "json_remove"
- locus: "/pins/8"
- before: "{\"path\":\"port/x64_exports/export_manifest.tsv\",\"sha256\":\"e1df5a9e9e20c555a7d1d97a106b469e961c4abf88dcd03889c3a126d152b117\",\"byte_count\":116429}"
- after: "ABSENT"
- required_kill_code: "MISSING_PIN_port/x64_exports/export_manifest.tsv"
- anti_wrong_reason: The remaining ten records are valid and match live files.
  The checker must report the missing path, not stale hash, schema, or the old
  zero-hash corruption.

### O04.M2

- exact_description: "EXACT_SINGLE_MUTATION: O04_M2_USE_CALL_VA_AS_REL32_BASE"
- subject_kind: "derived_rel32_policy"
- subject_path_authority: "mutants/O04_M2/rel32.json", derived from the newly
  pinned original-PE E8 bytes at raw offset 0x000ed328.
- operation: "json_replace"
- locus: "/caller_packets/0/base_mode"
- before: "\"NEXT_VA\""
- after: "\"CALL_VA\""
- required_kill_code: "REL32_TARGET_MISMATCH"
- anti_wrong_reason: Both modes are valid and the E8 decodes. The mutant result
  must be 0x100ed3bb rather than 0x100ed3c0; schema or hash rejection is not
  accepted.

### O04.M3

- exact_description: "EXACT_SINGLE_MUTATION: O04_M3_TRUST_POSITIVE_DECOMPILER_STACK_NAME"
- subject_kind: "derived_stack_evidence_record"
- subject_path_authority: "mutants/O04_M3/stack_evidence.json", derived from the
  pinned ABI contract and authenticated raw-PE position evidence.
- operation: "json_replace"
- locus: "/position_1/authority_kind"
- before: "\"RAW_BYTES\""
- after: "\"DECOMPILER_NAME\""
- required_kill_code: "DECOMPILER_NAME_NOT_STACK_AUTHORITY"
- anti_wrong_reason: Both authority-kind values are valid and the position fact
  remains unchanged. Missing fact, enum, or schema rejection is not accepted.

### O04.M4

- exact_description: "EXACT_SINGLE_MUTATION: O04_M4_MARK_EBX_STABLE"
- subject_kind: "derived_register_contract"
- subject_path_authority: "mutants/O04_M4/registers.json", derived from the
  pinned ABI contract and authenticated raw ESI save/restore evidence.
- operation: "json_replace"
- locus: "/registers/ebx"
- before: "\"UNPROVEN\""
- after: "\"STABLE\""
- required_kill_code: "UNPROVEN_EBX_PROMOTED_STABLE"
- anti_wrong_reason: Both values are valid and all underlying evidence remains
  unchanged. Enum, schema, or negative-prose matching is not accepted.

### O04.M5

- exact_description: "EXACT_SINGLE_MUTATION: O04_M5_WARN_AND_ACCEPT_MALFORMED_PE"
- subject_kind: "derived_malformed_policy"
- subject_path_authority: "mutants/O04_M5/policy.json", derived from the newly
  pinned full original PE and four independent disposable malformed cases:
  raw 0x3c length 1 "90" to "9c"; raw 0 length 2 "4d5a" to "0000";
  raw 0x1f8 length 4 "00001000" to "deadbeef"; and raw 0x196 length 2
  "0700" to "ffff".
- operation: "json_replace"
- locus: "/malformed_policy"
- before: "\"FAIL_CLOSED\""
- after: "\"WARN_AND_ACCEPT\""
- required_kill_code: "MALFORMED_PE_ACCEPTANCE_POLICY"
- anti_wrong_reason: Both policies are valid. Each malformed parser must first
  reach its exact structural error and the mutant must then reach the policy
  acceptance branch. Parser, hash, schema, or the old DOS-offset-0x06 e_crlc
  case is not accepted.

### O04.M6

- exact_description: "EXACT_SINGLE_MUTATION: O04_M6_ALLOW_ORIGINAL_DLL_LOAD_POLICY"
- subject_kind: "derived_containment_policy"
- subject_path_authority: "mutants/O04_M6/policy.json", derived from the pinned
  containment documents and newly pinned original-PE identity.
- operation: "json_replace"
- locus: "/dll_load_policy"
- before: "\"NO_LOAD\""
- after: "\"LOAD_ALLOWED\""
- required_kill_code: "ORIGINAL_DLL_LOAD_POLICY_NOT_FORBIDDEN"
- anti_wrong_reason: Both values are valid and only static policy validation is
  performed. No LoadLibrary, import, link, translation, or execution attempt is
  allowed. Schema failure is not accepted. The former
  "O04_M6_LOAD_ORIGINAL_DLL" description is forbidden because it cannot be
  exercised safely or consistently with the containment contract.

### O04.M7

- exact_description: "EXACT_SINGLE_MUTATION: O04_M7_APPEND_PRODUCTION_CONSUMER_EDGE"
- subject_kind: "disposable_cmake_copy"
- subject_path_authority: "mutants/O04_M7/CMakeLists.txt", copied from the
  exact 30,474-byte pinned CMake authority.
- operation: "insert_bytes"
- locus: "byte offset 30474, remove length 0; EOF immediately after the final
  bytes 656e64696628290a, which encode endif() followed by LF"
- before: "EMPTY"
- after: "target_link_libraries(empire_retail_bootstrap PRIVATE rome2_startup_100f1aa0_empty_runtime)\n"
- required_kill_code: "PRODUCTION_CONSUMER_EDGE_TO_EMPTY_RUNTIME"
- anti_wrong_reason: The inserted 92 UTF-8/ASCII bytes have SHA-256
  "cd25de825260c0f1931dd6dc230ad5330d60f3644dccd381c0e958f12e609101".
  Balanced CMake parsing must succeed and yield exactly the new unconditional
  production-consumer edge. Syntax, fixture-equality, configure, or build
  failure is not accepted. The former
  "O04_M7_MOVE_EMPTY_TARGET_OUTSIDE_BUILD_TESTING" description is forbidden
  because it did not describe this singular source mutation.

### O04.M8

- exact_description: "EXACT_SINGLE_MUTATION: O04_M8_ATTEMPT_ONE_BYTE_WRITE_OUTSIDE_DISPOSABLE_WORKSPACE"
- subject_kind: "derived_guard_action"
- subject_path_authority: "mutants/O04_M8/sandbox.json", generated exactly from
  this control contract; immutable snapshots are authoritative only from the
  revised eleven-entry O04 evidence-authority array. The separately pinned
  mutation-contract control document is also immutable. The sentinel is
  "t8/outside-sentinel.bin"
  relative to the worker root, outside nested sandbox "t8/work".
- operation: "json_replace"
- locus: "/outside_write_action"
- before: "{\"kind\":\"NONE\"}"
- after: "{\"kind\":\"WRITE_BYTE\",\"relative_path\":\"../outside-sentinel.bin\",\"offset\":0,\"before\":\"a5\",\"after\":\"00\"}"
- required_kill_code: "DENIED_OUTSIDE_WRITE_ATTEMPT"
- anti_wrong_reason: The unchanged guarded filesystem API must resolve and deny
  before the syscall, emit exactly one audit record, and leave sentinel byte
  "a5" and all snapshots unchanged. Generic operating-system-wide interception
  is not claimed. A changed sentinel, missing audit record, snapshot mismatch,
  schema failure, or actual outside write is an oracle failure. The former
  "O04_M8_WRITE_ONE_BYTE_OUTSIDE_DISPOSABLE_WORKSPACE" description is forbidden
  because it implied a successful forbidden write rather than a denied attempt.
