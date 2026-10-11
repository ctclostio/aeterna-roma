#ifndef ROME2_PORTED_100EDD70_FULL_ENTRY_H
#define ROME2_PORTED_100EDD70_FULL_ENTRY_H

#include "ported_100edd70_unified_entry.h"

#define ROME2_PORT_100EDD70_START_PC UINT32_C(0x100edd70)
#define ROME2_PORT_100EDD70_SELECTOR_PC UINT32_C(0x100edecc)
#define ROME2_PORT_100EDD70_RETURN_PC UINT32_C(0x100edfaf)
#define ROME2_PORT_100EDD70_EARLY_RETURN_PC UINT32_C(0x100edec8)
#define ROME2_PORT_100EDD70_PREFIX_STEP_CAPACITY 16U
#define ROME2_100EDD70_PREFIX_STEP_CAPACITY ROME2_PORT_100EDD70_PREFIX_STEP_CAPACITY

/*
 * Step kinds for the pre-selector prefix [0x100edd70, 0x100edecc)
 */
typedef enum rome2_100edd70_prefix_step_kind {
    ROME2_100EDD70_PREFIX_STEP_UNUSED = 0,
    ROME2_100EDD70_PREFIX_STEP_FRAME_SETUP = 1,
    ROME2_100EDD70_PREFIX_STEP_CALL_112F6190 = 2,
    ROME2_100EDD70_PREFIX_STEP_CALL_100E2980 = 3,
    ROME2_100EDD70_PREFIX_STEP_CO_INITIALIZE = 4,
    ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_CMD_SHOW = 5,
    ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_PARAM5 = 6,
    ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_PARAM6 = 7,
    ROME2_100EDD70_PREFIX_STEP_CONFIG_STORE_PARAM7 = 8,
    ROME2_100EDD70_PREFIX_STEP_CONFIG_FREE_PRIOR = 9,
    ROME2_100EDD70_PREFIX_STEP_STUB_100D6900 = 10,
    ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_COCREATE = 11,
    ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_VERIFY_ACCESS = 12,
    ROME2_100EDD70_PREFIX_STEP_GAME_EXPLORER_RELEASE = 13,
    ROME2_100EDD70_PREFIX_STEP_EARLY_EXIT_UNINITIALIZE = 14
} rome2_100edd70_prefix_step_kind;

typedef struct rome2_100edd70_prefix_step {
    rome2_100edd70_prefix_step_kind kind;
    uint32_t instruction_original_pc;
    uint32_t target_original_pc;
    uint32_t width_or_size;
} rome2_100edd70_prefix_step;

typedef void (*rome2_100edd70_prefix_emit_step_fn)(
    void *context,
    rome2_100edd70_prefix_step step);

typedef struct rome2_100edd70_prefix_effects {
    rome2_100edd70_prefix_emit_step_fn emit_step;
    void *context;
    uint64_t context_byte_count;
} rome2_100edd70_prefix_effects;

typedef enum rome2_100edd70_game_explorer_route {
    ROME2_100EDD70_GAME_EXPLORER_BYPASS_CLASSNOTREG = 0,
    ROME2_100EDD70_GAME_EXPLORER_VERIFIED_ACCESS = 1,
    ROME2_100EDD70_GAME_EXPLORER_DENIED_ACCESS = 2
} rome2_100edd70_game_explorer_route;

typedef struct rome2_100edd70_full_entry_result {
    rome2_100edd70_game_explorer_route game_explorer_route;
    uint32_t prior_allocation_freed;
    uint32_t prefix_record_count;
    rome2_100edd70_prefix_step prefix[ROME2_100EDD70_PREFIX_STEP_CAPACITY];
    uint32_t early_exit_taken;
    uint8_t exit_code;
    rome2_100edd70_unified_entry_result unified_result;
} rome2_100edd70_full_entry_result;

/*
 * Execute the complete entry sequence of Total War Rome II (0x100edd70) from byte 0 to ret.
 *
 * Sequence:
 *   1. Pre-selector prefix:
 *      - Stack setup and SEH initialization (0x100edd70)
 *      - Memory diagnostics logging (0x112f6190)
 *      - Working directory / data path resolution (0x100e2980)
 *      - CoInitialize(NULL) (0x1172f92c)
 *      - Config stores into crash record 0x119f3a38 (0x100e8240):
 *          nCmdShow at +0x60, param_5 at +0x64, param_6 at +0x58, param_7 at +0x5c
 *      - If *param_5 != 0: VirtualFree and zero pointer (0x100eddf0)
 *      - Stub call (0x100d6900)
 *      - CoCreateInstance(&CLSID_GameExplorer) (0x100ede22)
 *        - On modern OS (CLASSNOTREG, hr < 0): jumps directly to 0x100edecc
 *        - On verified access: VerifyAccess -> Release -> continues to 0x100edecc
 *        - On denied access: VerifyAccess -> Release -> CoUninitialize -> early ret 0
 *   2. Unified entry sequence at 0x100edecc:
 *      - Scans lpCmdLine for -no_exception_handler -> SKIP vs INSTALL
 *      - On INSTALL: 4 registration records
 *      - Engine loop caller closure (0x100ed3c0 + 0x101136d0 + 0x101150f0)
 *      - On INSTALL: tail store at [ebp-4] = -1
 *      - Epilogue: CoUninitialize, load DAT_119f3144, restore fs:[0], pops, ret
 */
rome2_100f1bb0_owned_status rome2_port_100edd70_run_full_entry_sequence(
    void *hInstance,
    uint32_t param_2,
    rome2_guest_addr32 caller_position3_text,
    int32_t nCmdShow,
    uint32_t param_5,
    uint32_t param_6,
    uint32_t param_7,
    uint32_t param_8,
    int prior_alloc_present,
    rome2_100edd70_game_explorer_route game_explorer_route,
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    const rome2_guest_read_view *text_view,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_guest_write_view *temporary_heap_view,
    const rome2_guest_write_view *persistent_descriptor_view,
    const rome2_guest_write_view *persistent_heap_view,
    const rome2_guest_read_view *dispatch_view,
    rome2_guest_addr32 dispatch_receiver,
    uint32_t max_poll_calls,
    const rome2_100edd70_prefix_effects *prefix_effects,
    const rome2_100ed3c0_nonempty_lifecycle_effects *parent_effects,
    const rome2_100edd70_caller_closure_effects *continuation_effects,
    const rome2_100edd70_registration_effects *registration_effects,
    const rome2_100edd70_terminal_effects *terminal_effects,
    rome2_100f1bb0_owned_owner *temporary_owner,
    rome2_100f1bb0_owned_owner *persistent_owner,
    rome2_100f2750_first_use_lifecycle *lifecycle,
    rome2_100edd70_full_entry_result *result_out);

/*
 * Top-level native x64 entry point export conforming to the 522-export contract.
 */
uint8_t rome2_port_100edd70_entry_point(
    void *hInstance,
    uint32_t param_2,
    const uint16_t *lpCmdLine,
    int32_t nCmdShow,
    uint32_t param_5,
    uint32_t param_6,
    uint32_t param_7,
    uint32_t param_8);

#endif
