#include "ported_100edd70_terminal_transcript.h"

#include <stddef.h>
#include <string.h>

/* Fixed-width, padding-free candidate layout: unused output bytes are zero. */
_Static_assert(sizeof(rome2_100edd70_terminal_step_kind) == 4U,
    "candidate requires four-byte kind ordinals");
_Static_assert(sizeof(rome2_100edd70_terminal_identity) == 4U,
    "candidate requires four-byte operand ordinals");
_Static_assert(sizeof(rome2_100edd70_terminal_step) == 40U,
    "candidate record must contain ten four-byte fields without padding");
_Static_assert(sizeof(rome2_100edd70_terminal_transcript_result) == 500U,
    "candidate result must not contain padding");

/* Authenticated installed_tail bytes: c745fcffffffff eb4a.
 * Columns: kind, instruction PC, encoding size, target, global source,
 * source identity, destination identity, frame displacement, immediate,
 * width_or_cleanup_bytes. See the header for per-kind field validity.
 */
static const rome2_100edd70_terminal_step installed_tail[2] = {
    { ROME2_100EDD70_TERMINAL_TAIL_FRAME_STORE,
      UINT32_C(0x100edf41), 7U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_IMMEDIATE,
      ROME2_100EDD70_TERMINAL_ID_FRAME_SLOT,
      -4, UINT32_C(0xffffffff), 4U },
    { ROME2_100EDD70_TERMINAL_BRANCH,
      UINT32_C(0x100edf48), 2U, UINT32_C(0x100edf94), 0U,
      ROME2_100EDD70_TERMINAL_ID_NONE,
      ROME2_100EDD70_TERMINAL_ID_NONE, 0, 0U, 2U }
};

/* Authenticated common_epilogue bytes, one record per instruction:
 * ff1534f97211 a044319f11 8b4df0 64890d00000000 5f 5e 5b 8be5 5d c3.
 * IAT 0x1172f934 identifies ole32.dll!CoUninitialize in the byte oracle;
 * it is never resolved, dereferenced, or called here.
 */
static const rome2_100edd70_terminal_step common_epilogue[10] = {
    { ROME2_100EDD70_TERMINAL_IMPORTED_CALL_SHAPE,
      UINT32_C(0x100edf94), 6U, UINT32_C(0x1172f934), 0U,
      ROME2_100EDD70_TERMINAL_ID_NONE,
      ROME2_100EDD70_TERMINAL_ID_NONE, 0, 0U, 0U },
    { ROME2_100EDD70_TERMINAL_GLOBAL_BYTE_LOAD,
      UINT32_C(0x100edf9a), 5U, 0U, UINT32_C(0x119f3144),
      ROME2_100EDD70_TERMINAL_ID_GLOBAL_BYTE,
      ROME2_100EDD70_TERMINAL_ID_AL, 0, 0U, 1U },
    { ROME2_100EDD70_TERMINAL_SEH_SLOT_LOAD,
      UINT32_C(0x100edf9f), 3U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_FRAME_SLOT,
      ROME2_100EDD70_TERMINAL_ID_ECX, -16, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_FS_ZERO_STORE,
      UINT32_C(0x100edfa2), 7U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_ECX,
      ROME2_100EDD70_TERMINAL_ID_FS_ZERO, 0, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_POP_EDI,
      UINT32_C(0x100edfa9), 1U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_STACK_TOP,
      ROME2_100EDD70_TERMINAL_ID_EDI, 0, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_POP_ESI,
      UINT32_C(0x100edfaa), 1U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_STACK_TOP,
      ROME2_100EDD70_TERMINAL_ID_ESI, 0, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_POP_EBX,
      UINT32_C(0x100edfab), 1U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_STACK_TOP,
      ROME2_100EDD70_TERMINAL_ID_EBX, 0, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_TEARDOWN_MOV_ESP_EBP,
      UINT32_C(0x100edfac), 2U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_EBP,
      ROME2_100EDD70_TERMINAL_ID_ESP, 0, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_TEARDOWN_POP_EBP,
      UINT32_C(0x100edfae), 1U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_STACK_TOP,
      ROME2_100EDD70_TERMINAL_ID_EBP, 0, 0U, 4U },
    { ROME2_100EDD70_TERMINAL_RETURN,
      UINT32_C(0x100edfaf), 1U, 0U, 0U,
      ROME2_100EDD70_TERMINAL_ID_NONE,
      ROME2_100EDD70_TERMINAL_ID_NONE, 0, 0U, 0U }
};

rome2_100edd70_terminal_status rome2_port_100edd70_project_terminal_transcript(
    uint32_t policy,
    rome2_100edd70_terminal_transcript_result *result_out)
{
    rome2_100edd70_terminal_transcript_result result;
    uintptr_t address;

    if ((policy != ROME2_100EDD70_TERMINAL_POLICY_INSTALL &&
         policy != ROME2_100EDD70_TERMINAL_POLICY_SKIP) ||
        result_out == NULL) {
        return ROME2_100EDD70_TERMINAL_BAD_ARGUMENT;
    }
    address = (uintptr_t)result_out;
    if (address % _Alignof(rome2_100edd70_terminal_transcript_result) != 0U ||
        sizeof(*result_out) - 1U > UINTPTR_MAX - address) {
        return ROME2_100EDD70_TERMINAL_BAD_ARGUMENT;
    }

    memset(&result, 0, sizeof(result));
    result.policy = policy;
    if (policy == ROME2_100EDD70_TERMINAL_POLICY_INSTALL) {
        result.tail_record_count = ROME2_100EDD70_TERMINAL_TAIL_CAPACITY;
        memcpy(result.tail, installed_tail, sizeof(installed_tail));
    }
    result.epilogue_record_count = ROME2_100EDD70_TERMINAL_EPILOGUE_CAPACITY;
    memcpy(result.epilogue, common_epilogue, sizeof(common_epilogue));
    result.return_source_identity = UINT32_C(0x119f3144);
    result.return_original_pc = UINT32_C(0x100edfaf);
    memcpy(result_out, &result, sizeof(result));
    return ROME2_100EDD70_TERMINAL_OK;
}
