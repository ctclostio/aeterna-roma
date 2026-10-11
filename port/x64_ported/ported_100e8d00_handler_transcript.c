#include "ported_100e8d00_handler_transcript.h"

#include <stddef.h>
#include <stdint.h>

static rome2_guest_status rome2_100e8d00_validate_object(
    const void *object,
    size_t size)
{
    uintptr_t start;

    if (object == NULL || size == 0U) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    start = (uintptr_t)object;
    if (size > UINTPTR_MAX - start) {
        return ROME2_GUEST_RANGE_OVERFLOW;
    }

    return ROME2_GUEST_OK;
}

static int rome2_100e8d00_ranges_overlap(
    const void *left,
    size_t left_size,
    const void *right,
    size_t right_size)
{
    uintptr_t left_start = (uintptr_t)left;
    uintptr_t right_start = (uintptr_t)right;
    uintptr_t left_end = left_start + left_size;
    uintptr_t right_end = right_start + right_size;

    return left_start < right_end && right_start < left_end;
}

rome2_guest_status rome2_port_100e8d00_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e8d00_transcript_effects *effects,
    uint8_t *return_al_out)
{
    rome2_100e8d00_transcript_effects effects_snapshot;
    rome2_100e8d00_step step;
    rome2_guest_status status;

    status = rome2_100e8d00_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100e8d00_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100e8d00_ranges_overlap(
            effects, sizeof(*effects),
            return_al_out, sizeof(*return_al_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    /* The authenticated original handler does not inspect either identity. */
    (void)guest_receiver;
    (void)guest_argument;

    step.kind = ROME2_100E8D00_STEP_CALL_10CB6160;
    step.argument_count = UINT32_C(2);
    step.argument0 = UINT32_C(0);
    step.argument1 = UINT32_C(1);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    step.kind = ROME2_100E8D00_STEP_CALL_10115D40;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(0);
    step.argument1 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    step.kind = ROME2_100E8D00_STEP_CALL_112DC9F0;
    step.argument_count = UINT32_C(2);
    step.argument0 = ROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY;
    step.argument1 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    step.kind = ROME2_100E8D00_STEP_CALL_101150A0;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(1);
    step.argument1 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    step.kind = ROME2_100E8D00_STEP_CALL_101151D0;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(0);
    step.argument1 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    step.kind = ROME2_100E8D00_STEP_CALL_112E2CB0;
    step.argument_count = UINT32_C(0);
    step.argument0 = UINT32_C(0);
    step.argument1 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    *return_al_out = ROME2_PORT_100E8D00_AL;
    return ROME2_GUEST_OK;
}
