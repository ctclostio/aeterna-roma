#include "ported_100e9340_handler_transcript.h"

#include <stddef.h>
#include <stdint.h>

static rome2_guest_status rome2_100e9340_validate_object(
    const void *object,
    size_t size)
{
    uintptr_t start;

    if (object == NULL || size == 0U) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }
    start = (uintptr_t)object;
    if (size - 1U > UINTPTR_MAX - start) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }
    return ROME2_GUEST_OK;
}

static int rome2_100e9340_ranges_overlap(
    const void *left,
    size_t left_size,
    const void *right,
    size_t right_size)
{
    uintptr_t left_start = (uintptr_t)left;
    uintptr_t right_start = (uintptr_t)right;

    if (left_start >= right_start) {
        return left_start - right_start < right_size;
    }
    return right_start - left_start < left_size;
}

static void rome2_100e9340_clear_step(rome2_100e9340_step *step)
{
    step->argument_count = UINT32_C(0);
    step->argument0 = UINT32_C(0);
    step->argument1 = UINT32_C(0);
    step->argument2 = UINT32_C(0);
    step->result_width_bytes = UINT32_C(0);
    step->result_u32 = UINT32_C(0);
}

rome2_guest_status rome2_port_100e9340_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e9340_transcript_effects *effects,
    uint8_t *return_al_out)
{
    rome2_100e9340_transcript_effects effects_snapshot;
    rome2_100e9340_step step;
    rome2_guest_status status;
    uint32_t patched_receiver;

    status = rome2_100e9340_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100e9340_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)effects % _Alignof(rome2_100e9340_transcript_effects) != 0U ||
        rome2_100e9340_ranges_overlap(
            effects, sizeof(*effects),
            return_al_out, sizeof(*return_al_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL ||
        effects_snapshot.selected_byte_49 > UINT32_C(0xff)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    (void)guest_argument;
    patched_receiver =
        (guest_receiver.value & UINT32_C(0xffffff00)) |
        effects_snapshot.selected_byte_49;

    rome2_100e9340_clear_step(&step);
    step.kind = ROME2_100E9340_STEP_LOOKUP_DWORD_12;
    step.argument_count = UINT32_C(1);
    step.argument0 = ROME2_PORT_100E9340_SELECTOR_DWORD;
    step.result_width_bytes = UINT32_C(4);
    step.result_u32 = effects_snapshot.selected_dword_12;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e9340_clear_step(&step);
    step.kind = ROME2_100E9340_STEP_LOOKUP_BYTE_49;
    step.argument_count = UINT32_C(1);
    step.argument0 = ROME2_PORT_100E9340_SELECTOR_BYTE;
    step.result_width_bytes = UINT32_C(1);
    step.result_u32 = effects_snapshot.selected_byte_49;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e9340_clear_step(&step);
    step.kind = ROME2_100E9340_STEP_CALL_112E1830;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e9340_clear_step(&step);
    step.kind = ROME2_100E9340_STEP_CALL_112CBBB0;
    step.argument_count = UINT32_C(3);
    step.argument0 = effects_snapshot.selected_dword_12;
    step.argument1 = patched_receiver;
    step.argument2 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    *return_al_out = ROME2_PORT_100E9340_AL;
    return ROME2_GUEST_OK;
}
