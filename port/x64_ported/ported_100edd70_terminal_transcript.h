#ifndef ROME2_PORTED_100EDD70_TERMINAL_TRANSCRIPT_H
#define ROME2_PORTED_100EDD70_TERMINAL_TRANSCRIPT_H

#include <stdint.h>

/* Same numeric policy domain as the existing selector, without a dependency. */
#define ROME2_100EDD70_TERMINAL_POLICY_INSTALL UINT32_C(0)
#define ROME2_100EDD70_TERMINAL_POLICY_SKIP UINT32_C(1)
#define ROME2_100EDD70_TERMINAL_TAIL_CAPACITY 2U
#define ROME2_100EDD70_TERMINAL_EPILOGUE_CAPACITY 10U

typedef enum rome2_100edd70_terminal_status {
    ROME2_100EDD70_TERMINAL_OK = 0,
    ROME2_100EDD70_TERMINAL_BAD_ARGUMENT = 1
} rome2_100edd70_terminal_status;

typedef enum rome2_100edd70_terminal_step_kind {
    ROME2_100EDD70_TERMINAL_UNUSED = 0,
    ROME2_100EDD70_TERMINAL_TAIL_FRAME_STORE = 1,
    ROME2_100EDD70_TERMINAL_BRANCH = 2,
    ROME2_100EDD70_TERMINAL_IMPORTED_CALL_SHAPE = 3,
    ROME2_100EDD70_TERMINAL_GLOBAL_BYTE_LOAD = 4,
    ROME2_100EDD70_TERMINAL_SEH_SLOT_LOAD = 5,
    ROME2_100EDD70_TERMINAL_FS_ZERO_STORE = 6,
    ROME2_100EDD70_TERMINAL_POP_EDI = 7,
    ROME2_100EDD70_TERMINAL_POP_ESI = 8,
    ROME2_100EDD70_TERMINAL_POP_EBX = 9,
    ROME2_100EDD70_TERMINAL_TEARDOWN_MOV_ESP_EBP = 10,
    ROME2_100EDD70_TERMINAL_TEARDOWN_POP_EBP = 11,
    ROME2_100EDD70_TERMINAL_RETURN = 12
} rome2_100edd70_terminal_step_kind;

/* Operand ordinals, NOT addresses or live registers. FS_ZERO is a distinct
 * host-state destination class, not a guest-memory global or host pointer. */
typedef enum rome2_100edd70_terminal_identity {
    ROME2_100EDD70_TERMINAL_ID_NONE = 0,
    ROME2_100EDD70_TERMINAL_ID_AL = 1,
    ROME2_100EDD70_TERMINAL_ID_ECX = 2,
    ROME2_100EDD70_TERMINAL_ID_EDI = 3,
    ROME2_100EDD70_TERMINAL_ID_ESI = 4,
    ROME2_100EDD70_TERMINAL_ID_EBX = 5,
    ROME2_100EDD70_TERMINAL_ID_ESP = 6,
    ROME2_100EDD70_TERMINAL_ID_EBP = 7,
    ROME2_100EDD70_TERMINAL_ID_FRAME_SLOT = 8,
    ROME2_100EDD70_TERMINAL_ID_FS_ZERO = 9,
    ROME2_100EDD70_TERMINAL_ID_STACK_TOP = 10,
    ROME2_100EDD70_TERMINAL_ID_GLOBAL_BYTE = 11,
    ROME2_100EDD70_TERMINAL_ID_IMMEDIATE = 12
} rome2_100edd70_terminal_identity;

/* One record per instruction. All fields are data; unused fields are zero.
 * instruction_size_bytes is the encoding length, NOT the operand width.
 * width_or_cleanup_bytes: store/load/pop/mov operand bytes; branch encoding
 * bytes (2); zero for the zero-argument call shape and terminal ret.
 * target_original_pc: branch destination OR indirect-call IAT CELL identity,
 * never a resolved callable address. source_original_address: global load
 * identity only. FRAME_SLOT means [EBP + frame_displacement]; STACK_TOP means
 * the then-current [ESP], whose contents/address remain unknown.
 * immediate is meaningful ONLY for TAIL_FRAME_STORE. In particular its zero
 * in GLOBAL_BYTE_LOAD is unused storage, NOT evidence that the byte is zero.
 * Pops imply stack advancement structurally; no stack values are simulated.
 * RETURN records a terminal instruction only, not a known caller/ret target.
 */
typedef struct rome2_100edd70_terminal_step {
    rome2_100edd70_terminal_step_kind kind;
    uint32_t instruction_original_pc;
    uint32_t instruction_size_bytes;
    uint32_t target_original_pc;
    uint32_t source_original_address;
    rome2_100edd70_terminal_identity source_identity;
    rome2_100edd70_terminal_identity destination_identity;
    int32_t frame_displacement;
    uint32_t immediate;
    uint32_t width_or_cleanup_bytes;
} rome2_100edd70_terminal_step;

typedef struct rome2_100edd70_terminal_transcript_result {
    uint32_t policy;
    uint32_t tail_record_count;
    uint32_t epilogue_record_count;
    rome2_100edd70_terminal_step tail[ROME2_100EDD70_TERMINAL_TAIL_CAPACITY];
    rome2_100edd70_terminal_step epilogue[
        ROME2_100EDD70_TERMINAL_EPILOGUE_CAPACITY];
    uint32_t return_source_identity; /* 0x119f3144 -> AL; no supplied/read byte */
    uint32_t return_original_pc;     /* 0x100edfaf, not a return destination */
} rome2_100edd70_terminal_transcript_result;

/* Standalone C11 candidate, NOT an entry wrapper or an admitted milestone.
 * Projects only [0x100edf41,0x100edf4a) on INSTALL and the ten instructions
 * in [0x100edf94,0x100edfb0) on both policies. Output order is tail then
 * epilogue. SKIP has zero tail records and a fully zeroed unused tail array.
 * No selector/child execution or proof of child success; caller chooses the
 * already-decided normal-route policy. No callbacks, allocation, guest reads,
 * recovered/native calls, host-state effects, or production integration.
 * Exception gap, prefix, and distinct early return-zero epilogue are excluded.
 * Missing recovered writers do NOT establish a constant return-global byte.
 *
 * Invalid policy, null/misaligned output, or wrapping output address range
 * returns BAD_ARGUMENT without touching output. Otherwise result_out must
 * designate a writable live object of the declared type (C cannot validate
 * mapping/lifetime/extent). Success fully initializes it, once and last.
 */
rome2_100edd70_terminal_status rome2_port_100edd70_project_terminal_transcript(
    uint32_t policy,
    rome2_100edd70_terminal_transcript_result *result_out);

#endif
