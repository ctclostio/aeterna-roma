/* Coordinator fallback: focused install-tail oracle, not admission coverage.
 * Original bytes at 100edf41: c745fcffffffff eb4a.
 * Expected values below are literal byte-derived values, not port table copies.
 */
#include "ported_100edd70_terminal_transcript.h"
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

int main(void)
{
    rome2_100edd70_terminal_transcript_result result;
    rome2_100edd70_terminal_transcript_result saved;
    const rome2_100edd70_terminal_step *step;
    unsigned char empty_tail[sizeof(result.tail)] = {0};

    memset(&result, 0xa5, sizeof(result));
    CHECK(rome2_port_100edd70_project_terminal_transcript(0U, &result) ==
        ROME2_100EDD70_TERMINAL_OK);
    CHECK(result.policy == 0U);
    CHECK(result.tail_record_count == 2U);
    CHECK(result.epilogue_record_count == 10U);
    step = &result.tail[0];
    CHECK(step->kind == ROME2_100EDD70_TERMINAL_TAIL_FRAME_STORE);
    CHECK(step->instruction_original_pc == UINT32_C(0x100edf41));
    CHECK(step->instruction_size_bytes == 7U);
    CHECK(step->target_original_pc == 0U);
    CHECK(step->source_original_address == 0U);
    CHECK(step->source_identity == ROME2_100EDD70_TERMINAL_ID_IMMEDIATE);
    CHECK(step->destination_identity == ROME2_100EDD70_TERMINAL_ID_FRAME_SLOT);
    CHECK(step->frame_displacement == -4);
    CHECK(step->immediate == UINT32_C(0xffffffff));
    CHECK(step->width_or_cleanup_bytes == 4U);
    step = &result.tail[1];
    CHECK(step->kind == ROME2_100EDD70_TERMINAL_BRANCH);
    CHECK(step->instruction_original_pc == UINT32_C(0x100edf48));
    CHECK(step->instruction_size_bytes == 2U);
    CHECK(step->target_original_pc == UINT32_C(0x100edf94));
    CHECK(step->target_original_pc == step->instruction_original_pc + 2U + 0x4aU);
    CHECK(step->source_original_address == 0U);
    CHECK(step->source_identity == ROME2_100EDD70_TERMINAL_ID_NONE);
    CHECK(step->destination_identity == ROME2_100EDD70_TERMINAL_ID_NONE);
    CHECK(step->frame_displacement == 0);
    CHECK(step->immediate == 0U);
    CHECK(step->width_or_cleanup_bytes == 2U);
    CHECK(result.epilogue[0].instruction_original_pc == UINT32_C(0x100edf94));
    CHECK(result.return_source_identity == UINT32_C(0x119f3144));
    CHECK(result.return_original_pc == UINT32_C(0x100edfaf));

    saved = result;
    memset(&result, 0x5a, sizeof(result));
    CHECK(rome2_port_100edd70_project_terminal_transcript(0U, &result) ==
        ROME2_100EDD70_TERMINAL_OK);
    CHECK(memcmp(&result, &saved, sizeof(result)) == 0);
    CHECK(rome2_port_100edd70_project_terminal_transcript(2U, &result) ==
        ROME2_100EDD70_TERMINAL_BAD_ARGUMENT);
    CHECK(memcmp(&result, &saved, sizeof(result)) == 0);
    CHECK(rome2_port_100edd70_project_terminal_transcript(UINT32_MAX, &result) ==
        ROME2_100EDD70_TERMINAL_BAD_ARGUMENT);
    CHECK(memcmp(&result, &saved, sizeof(result)) == 0);
    CHECK(rome2_port_100edd70_project_terminal_transcript(0U, NULL) ==
        ROME2_100EDD70_TERMINAL_BAD_ARGUMENT);
    CHECK(rome2_port_100edd70_project_terminal_transcript(1U, &result) ==
        ROME2_100EDD70_TERMINAL_OK);
    CHECK(result.policy == 1U && result.tail_record_count == 0U);
    CHECK(result.epilogue_record_count == 10U);
    CHECK(memcmp(result.tail, empty_tail, sizeof(empty_tail)) == 0);
    CHECK(memcmp(result.epilogue, saved.epilogue, sizeof(result.epilogue)) == 0);
    puts("terminal transcript focused install-tail oracle: PASS");
    return 0;
}
