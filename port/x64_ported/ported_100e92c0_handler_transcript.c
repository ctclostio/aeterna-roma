#include "ported_100e92c0_handler_transcript.h"

#include <stddef.h>
#include <stdint.h>

static rome2_guest_status rome2_100e92c0_validate_object(
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

static int rome2_100e92c0_ranges_overlap(
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

static void rome2_100e92c0_clear_step(rome2_100e92c0_step *step)
{
    step->argument_count = UINT32_C(0);
    step->argument0 = UINT32_C(0);
    step->argument1 = UINT32_C(0);
    step->argument2 = UINT32_C(0);
    step->argument3 = UINT32_C(0);
    step->result_count = UINT32_C(0);
    step->result0 = UINT32_C(0);
    step->result1 = UINT32_C(0);
    step->local_before0 = UINT32_C(0);
    step->local_before1 = UINT32_C(0);
    step->local_after0 = UINT32_C(0);
    step->local_after1 = UINT32_C(0);
}

static void rome2_100e92c0_emit_final(
    const rome2_100e92c0_transcript_effects *effects,
    rome2_100e92c0_step *step,
    uint32_t argument0,
    uint32_t argument1,
    uint32_t argument2,
    uint32_t argument3)
{
    rome2_100e92c0_clear_step(step);
    step->kind = ROME2_100E92C0_STEP_CALL_100D5150;
    step->argument_count = UINT32_C(4);
    step->argument0 = argument0;
    step->argument1 = argument1;
    step->argument2 = argument2;
    step->argument3 = argument3;
    effects->emit_step(effects->context, *step);
}

rome2_guest_status rome2_port_100e92c0_run_handler_transcript(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    const rome2_100e92c0_transcript_effects *effects,
    uint8_t *return_al_out)
{
    rome2_100e92c0_transcript_effects effects_snapshot;
    rome2_100e92c0_step step;
    rome2_guest_status status;

    status = rome2_100e92c0_validate_object(effects, sizeof(*effects));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    status = rome2_100e92c0_validate_object(
        return_al_out, sizeof(*return_al_out));
    if (status != ROME2_GUEST_OK) {
        return status;
    }
    if ((uintptr_t)effects % _Alignof(rome2_100e92c0_transcript_effects) != 0U ||
        rome2_100e92c0_ranges_overlap(
            effects, sizeof(*effects),
            return_al_out, sizeof(*return_al_out))) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    effects_snapshot = *effects;
    if (effects_snapshot.emit_step == NULL ||
        effects_snapshot.context == NULL ||
        effects_snapshot.predicate_10fde370 > UINT32_C(1) ||
        effects_snapshot.predicate_10fde9d0 > UINT32_C(1)) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    (void)guest_receiver;
    (void)guest_argument;

    rome2_100e92c0_clear_step(&step);
    step.kind = ROME2_100E92C0_STEP_CALL_100D6970;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e92c0_clear_step(&step);
    step.kind = ROME2_100E92C0_STEP_CALL_10FDE370;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.predicate_10fde370;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    if (effects_snapshot.predicate_10fde370 == UINT32_C(0)) {
        rome2_100e92c0_emit_final(
            &effects_snapshot, &step,
            UINT32_C(0), UINT32_C(0), UINT32_C(0), UINT32_C(0));
        *return_al_out = ROME2_PORT_100E92C0_AL;
        return ROME2_GUEST_OK;
    }

    rome2_100e92c0_clear_step(&step);
    step.kind = ROME2_100E92C0_STEP_CALL_10FDE9D0;
    step.result_count = UINT32_C(1);
    step.result0 = effects_snapshot.predicate_10fde9d0;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    if (effects_snapshot.predicate_10fde9d0 == UINT32_C(0)) {
        rome2_100e92c0_emit_final(
            &effects_snapshot, &step,
            UINT32_C(0), UINT32_C(0), UINT32_C(0), UINT32_C(0));
        *return_al_out = ROME2_PORT_100E92C0_AL;
        return ROME2_GUEST_OK;
    }

    rome2_100e92c0_clear_step(&step);
    step.kind = ROME2_100E92C0_STEP_CALL_10FDE270;
    step.result_count = UINT32_C(2);
    step.result0 = effects_snapshot.result_10fde270_low;
    step.result1 = UINT32_C(0);
    step.local_after0 = effects_snapshot.result_10fde270_low;
    step.local_after1 = UINT32_C(0);
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e92c0_clear_step(&step);
    step.kind = ROME2_100E92C0_STEP_CALL_10FDE990;
    step.result_count = UINT32_C(2);
    step.result0 = effects_snapshot.result_10fde990_low;
    step.result1 = effects_snapshot.result_10fde990_high;
    step.local_before0 = effects_snapshot.result_10fde270_low;
    step.local_before1 = UINT32_C(0);
    step.local_after0 = effects_snapshot.result_10fde990_low;
    step.local_after1 = effects_snapshot.result_10fde990_high;
    effects_snapshot.emit_step(effects_snapshot.context, step);

    rome2_100e92c0_emit_final(
        &effects_snapshot, &step,
        effects_snapshot.result_10fde270_low,
        UINT32_C(0),
        effects_snapshot.result_10fde990_low,
        effects_snapshot.result_10fde990_high);

    *return_al_out = ROME2_PORT_100E92C0_AL;
    return ROME2_GUEST_OK;
}
