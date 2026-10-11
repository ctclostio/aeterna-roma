/* Diagnostic executable: emits inert records, never executes represented calls. */
#include "ported_100edd70_terminal_transcript.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(void *) == 8, "native x64 runner required");

static void print_step(const rome2_100edd70_terminal_step *s)
{
    printf("[%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
           ",%u,%u,%" PRId32 ",%" PRIu32 ",%" PRIu32 "]",
        (unsigned)s->kind, s->instruction_original_pc,
        s->instruction_size_bytes, s->target_original_pc,
        s->source_original_address, (unsigned)s->source_identity,
        (unsigned)s->destination_identity, s->frame_displacement,
        s->immediate, s->width_or_cleanup_bytes);
}

int main(int argc, char **argv)
{
    rome2_100edd70_terminal_transcript_result result;
    uint32_t policy;
    unsigned i;
    if (argc != 2 || (strcmp(argv[1], "install") != 0 &&
                      strcmp(argv[1], "skip") != 0)) {
        fputs("usage: terminal_runner install|skip\n", stderr);
        return 2;
    }
    policy = strcmp(argv[1], "install") == 0 ? 0U : 1U;
    memset(&result, 0xa5, sizeof(result));
    if (rome2_port_100edd70_project_terminal_transcript(policy, &result) !=
        ROME2_100EDD70_TERMINAL_OK) {
        fputs("projection failed\n", stderr);
        return 1;
    }
    printf("{\"mode\":\"inert-transcript\",\"policy\":%" PRIu32
           ",\"tail_count\":%" PRIu32 ",\"epilogue_count\":%" PRIu32
           ",\"tail\":[", result.policy, result.tail_record_count,
           result.epilogue_record_count);
    /* Include unused tail storage so the external oracle checks initialization. */
    for (i = 0; i < ROME2_100EDD70_TERMINAL_TAIL_CAPACITY; ++i) {
        if (i != 0) putchar(',');
        print_step(&result.tail[i]);
    }
    fputs("],\"epilogue\":[", stdout);
    for (i = 0; i < ROME2_100EDD70_TERMINAL_EPILOGUE_CAPACITY; ++i) {
        if (i != 0) putchar(',');
        print_step(&result.epilogue[i]);
    }
    printf("],\"return_source_identity\":%" PRIu32
           ",\"return_original_pc\":%" PRIu32 "}\n",
           result.return_source_identity, result.return_original_pc);
    return ferror(stdout) ? 1 : 0;
}
