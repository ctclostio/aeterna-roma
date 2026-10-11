#include "ported_100e8580_handler_transcript.h"

#include <stddef.h>
#include <stdint.h>

static rome2_guest_status rome2_100e8580_validate_object(
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

static int rome2_100e8580_ranges_overlap(
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

static void rome2_100e8580_clear_step(rome2_100e8580_step *step)
{
    step->argument_count = UINT32_C(0);
    step->argument0 = UINT32_C(0);
    step->argument1 = UINT32_C(0);
    step->argument2 = UINT32_C(0);
    step->has_guest_result = UINT32_C(0);
    step->returned_guest_identity.value = UINT32_C(0);
}

rome2_guest_status rome2_port_100e8580_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e8580_transcript_effects *effects,
    uint8_t *return_al_out)
{
    rome2_100e8580_transcript_effects effects_snapshot;
    rome2_100e8580_step step;
    rome2_guest_addr32 adjusted_identity;
    rome2_guest_status status;

    status = rome2_100e8580_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100e8580_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if (rome2_100e8580_ranges_overlap(
            effects, sizeof(*effects),
            return_al_out, sizeof(*return_al_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    (void)guest_receiver;
    (void)guest_argument;

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_100D6560;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_112D0510;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_112E0950_ONE;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(1);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_100D9810;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_100DDF50;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_112E0950_ZERO;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_100E8240;
    step.argument_count = UINT32_C(1);
    step.argument0 = UINT32_C(0);
    step.has_guest_result = UINT32_C(1);
    step.returned_guest_identity = effects_snapshot.result_100e8240;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    status = rome2_guest_add_checked(
        effects_snapshot.result_100e8240,
        ROME2_PORT_100E8580_RESULT_DISPLACEMENT,
        &adjusted_identity);
    if (status != ROME2_GUEST_OK) {
        return status;
    }

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_112BFEE0;
    step.argument_count = UINT32_C(1);
    step.argument0 = adjusted_identity.value;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e8580_clear_step(&step);
    step.kind = ROME2_100E8580_STEP_CALL_112DCAF0;
    step.argument_count = UINT32_C(3);
    step.argument0 = ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY;
    step.argument1 = UINT32_C(0);
    step.argument2 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    *return_al_out = ROME2_PORT_100E8580_AL;
    return ROME2_GUEST_OK;
}
