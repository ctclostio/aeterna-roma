#ifndef ROME2_PORTED_100ED3C0_EMPTY_PRELOOP_H
#define ROME2_PORTED_100ED3C0_EMPTY_PRELOOP_H

#include "ported_100df270_headless.h"
#include "ported_100df270_platform_prefix_transcript.h"
#include "ported_100df270_suffix_transcript.h"
#include "ported_100f1aa0_empty.h"
#include "ported_100f1bb0_bounded.h"
#include "ported_100f1cc0_nonowning.h"

#define ROME2_PORT_100ED3C0_PRELOOP_STEP_COUNT UINT32_C(9)
#define ROME2_PORT_100ED3C0_PRELOOP_START_PC UINT32_C(0x100ed3c0)
#define ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES UINT32_C(0x90c)
#define ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS UINT32_C(1)

#define ROME2_PORT_100ED3C0_PRELOOP_ZERO_OFFSET UINT32_C(0x00)
#define ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET UINT32_C(0x04)
#define ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET UINT32_C(0x10)
#define ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET UINT32_C(0x1c)
#define ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET UINT32_C(0x20)
#define ROME2_PORT_100ED3C0_PRELOOP_ZERO_DWORD_OFFSET UINT32_C(0x24)
#define ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET UINT32_C(0x28)
#define ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET UINT32_C(0x34)
#define ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET UINT32_C(0x3c)
#define ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET UINT32_C(0x48)
#define ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET UINT32_C(0x54)
#define ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET UINT32_C(0x58)
#define ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET UINT32_C(0x5c)
#define ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET UINT32_C(0x60)
#define ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET UINT32_C(0x64)

#define ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C8 UINT32_C(0x119f31c8)
#define ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C5 UINT32_C(0x119f31c5)
#define ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC UINT32_C(0x100ed471)

#define ROME2_PORT_100ED3C0_PRELOOP_TARGET_100F1C10 UINT32_C(0x100f1c10)
#define ROME2_PORT_100ED3C0_PRELOOP_TARGET_100F1AA0 UINT32_C(0x100f1aa0)
#define ROME2_PORT_100ED3C0_PRELOOP_TARGET_100F1BB0 UINT32_C(0x100f1bb0)
#define ROME2_PORT_100ED3C0_PRELOOP_TARGET_100DF270 UINT32_C(0x100df270)
#define ROME2_PORT_100ED3C0_PRELOOP_TARGET_100F1CC0 UINT32_C(0x100f1cc0)

typedef enum rome2_100ed3c0_preloop_step_kind {
    ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C8 = 1,
    ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C5 = 2,
    ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0 = 3,
    ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1 = 4,
    ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY0 = 5,
    ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY1 = 6,
    ROME2_100ED3C0_PRELOOP_STEP_BUILD_EMPTY_DESCRIPTOR = 7,
    ROME2_100ED3C0_PRELOOP_STEP_RUN_100DF270 = 8,
    ROME2_100ED3C0_PRELOOP_STEP_CLEANUP_DESCRIPTOR = 9
} rome2_100ed3c0_preloop_step_kind;

typedef enum rome2_100ed3c0_preloop_value_kind {
    ROME2_100ED3C0_PRELOOP_VALUE_NONE = 0,
    ROME2_100ED3C0_PRELOOP_VALUE_SCALAR = 1,
    ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY = 2,
    ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY = 3,
    ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY = 4,
    ROME2_100ED3C0_PRELOOP_VALUE_OPAQUE32 = 5
} rome2_100ed3c0_preloop_value_kind;

typedef struct rome2_100ed3c0_preloop_value {
    rome2_100ed3c0_preloop_value_kind kind;
    uint32_t value;
} rome2_100ed3c0_preloop_value;

typedef struct rome2_100ed3c0_preloop_step {
    rome2_100ed3c0_preloop_step_kind kind;
    uint32_t argument_count;
    rome2_100ed3c0_preloop_value argument0;
    rome2_100ed3c0_preloop_value argument1;
    rome2_100ed3c0_preloop_value argument2;
    uint32_t result_count;
    rome2_100ed3c0_preloop_value result0;
} rome2_100ed3c0_preloop_step;

typedef void (*rome2_100ed3c0_preloop_emit_step_fn)(
    void *context,
    rome2_100ed3c0_preloop_step step);

typedef struct rome2_100ed3c0_preloop_effects {
    rome2_100ed3c0_preloop_emit_step_fn emit_step;
    void *context;
    rome2_100df270_prefix_effects child_prefix;
    rome2_100df270_suffix_effects child_suffix;
} rome2_100ed3c0_preloop_effects;

typedef struct rome2_100ed3c0_preloop_result {
    rome2_guest_addr32 child_receiver;
    rome2_guest_addr32 child_packet;
    rome2_guest_addr32 child_argument;
    uint32_t next_original_pc;
} rome2_100ed3c0_preloop_result;

/*
 * Compose the straight-line original interval [0x100ed3c0,0x100ed471) for
 * the allocation-free empty UTF-16 route.  frame_view supplies the complete
 * original 0x90c-byte local frame at guest_frame.  argument_position1 and
 * argument_position3_text name only the two caller stack positions proven to
 * be read by raw x86 evidence; no native calling convention is inferred.
 * text_max_units must be exactly one and the first unit must be zero.
 * Nonempty text remains outside this port because original 0x100f1bb0 then
 * enters the allocator-capable 0x100ef330 path.
 *
 * The adapter emits the exact nine parent operations by value.  The two
 * original global byte stores are represented only by their authenticated
 * identities and are never performed.  The deterministic triplets, empty
 * copies, packet fields, and empty descriptor are materialized in frame_view.
 * The admitted 0x100df270 injected prefix, deterministic middle, and injected
 * suffix are then executed in original call position using snapshotted child
 * effects; selector_view contains the suffix's two injected result cells.
 * The final descriptor cleanup is the admitted nonowning sentinel no-op.
 * Execution stops before original 0x100ed471 and returns that identity only as
 * data in result_out.
 *
 * Before the first callback or write, the adapter validates and snapshots all
 * views, controls, effects, derived identities, the empty text unit, predicted
 * packet, and child route requirements.  Mutable/read-only backings and all
 * control objects must be pairwise disjoint.  Callbacks are total,
 * nonreentrant, return normally, retain no borrowed object, and do not modify
 * guest bytes, views, result_out, or another callback descriptor; only their
 * disjoint contexts may change.  Once emission begins, writes and callbacks
 * form an ordered committed prefix.  Validation failure emits nothing and
 * preserves both mutable views and result_out.
 *
 * No original address, guest-derived function pointer, native allocator,
 * process global, platform API, or native/guest pointer cast is used.
 */
rome2_guest_status rome2_port_100ed3c0_run_empty_preloop(
    const rome2_guest_write_view *frame_view,
    rome2_guest_addr32 guest_frame,
    uint32_t argument_position1,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 argument_position3_text,
    uint32_t text_max_units,
    const rome2_guest_write_view *selector_view,
    const rome2_100ed3c0_preloop_effects *effects,
    rome2_100ed3c0_preloop_result *result_out);

#endif
