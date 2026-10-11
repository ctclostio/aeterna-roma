#ifndef ROME2_PORTED_100DF270_PLATFORM_PREFIX_TRANSCRIPT_H
#define ROME2_PORTED_100DF270_PLATFORM_PREFIX_TRANSCRIPT_H

#include "ported_100f1c10_triplet.h"

#define ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT UINT32_C(7)
#define ROME2_PORT_100DF270_PREFIX_DUPLICATE_STEP_COUNT UINT32_C(10)

#define ROME2_PORT_100DF270_PREFIX_RECEIVER_BYTES UINT32_C(0x80c)
#define ROME2_PORT_100DF270_PREFIX_PACKET_BYTES UINT32_C(0x2d)
#define ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET UINT32_C(0x04)
#define ROME2_PORT_100DF270_PREFIX_NAME_OFFSET UINT32_C(0x08)
#define ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET UINT32_C(0x408)
#define ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET UINT32_C(0x808)
#define ROME2_PORT_100DF270_PREFIX_ALLOW_DUPLICATE_OFFSET UINT32_C(0x2c)

#define ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE UINT32_C(0x1173f208)
#define ROME2_PORT_100DF270_PREFIX_MUTEX_FORMAT UINT32_C(0x1173f460)
#define ROME2_PORT_100DF270_PREFIX_DUPLICATE_FORMAT UINT32_C(0x1173f4a0)
#define ROME2_PORT_100DF270_PREFIX_MUTEX_CAPTION UINT32_C(0x1173f440)
#define ROME2_PORT_100DF270_PREFIX_MOUSE_TRAILS_GLOBAL UINT32_C(0x119f3854)

#define ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE UINT32_C(0x6d)
#define ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME UINT32_C(0x67)
#define ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY UINT32_C(0x200)
#define ROME2_PORT_100DF270_PREFIX_ERROR_ALREADY_EXISTS UINT32_C(0xb7)
#define ROME2_PORT_100DF270_PREFIX_SPI_GETMOUSETRAILS UINT32_C(0x5e)
#define ROME2_PORT_100DF270_PREFIX_SPI_SETMOUSETRAILS UINT32_C(0x5d)
#define ROME2_PORT_100DF270_PREFIX_MESSAGEBOX_FLAGS UINT32_C(0x10)
#define ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID UINT32_C(1)

#define ROME2_PORT_100DF270_PREFIX_IAT_LOADSTRINGW UINT32_C(0x1172f66c)
#define ROME2_PORT_100DF270_PREFIX_IAT_CREATEMUTEXW UINT32_C(0x1172f17c)
#define ROME2_PORT_100DF270_PREFIX_IAT_MESSAGEBOXW UINT32_C(0x1172f69c)
#define ROME2_PORT_100DF270_PREFIX_IAT_SYSTEMPARAMETERSINFOW UINT32_C(0x1172f6a8)
#define ROME2_PORT_100DF270_PREFIX_TARGET_100EDFE0 UINT32_C(0x100edfe0)
#define ROME2_PORT_100DF270_PREFIX_TARGET_100F3880 UINT32_C(0x100f3880)
#define ROME2_PORT_100DF270_PREFIX_TARGET_10102850 UINT32_C(0x10102850)

/* Numeric values are transcript ordinals, never native call targets. */
typedef enum rome2_100df270_prefix_step_kind {
    ROME2_100DF270_PREFIX_STEP_LOAD_TITLE = 1,
    ROME2_100DF270_PREFIX_STEP_LOAD_NAME = 2,
    ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME = 3,
    ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX = 4,
    ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR = 5,
    ROME2_100DF270_PREFIX_STEP_FORMAT_DUPLICATE_MESSAGE = 6,
    ROME2_100DF270_PREFIX_STEP_SHOW_DUPLICATE_MESSAGE = 7,
    ROME2_100DF270_PREFIX_STEP_TERMINATE_PROCESS = 8,
    ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS = 9,
    ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS = 10
} rome2_100df270_prefix_step_kind;

/*
 * Each argument/result has an explicit domain.  GUEST_IDENTITY values are
 * coordinates inside the supplied state view.  ORIGINAL_IDENTITY values are
 * authenticated x86 image identities used only as transcript data.
 * LOCAL_BUFFER identifies the single original 0x400-byte stack buffer without
 * inventing a native or guest pointer.  OPAQUE32 carries x86 HINSTANCE/HANDLE
 * bits.  SCALAR carries resource IDs, sizes, flags, actions, and error codes.
 */
typedef enum rome2_100df270_prefix_value_kind {
    ROME2_100DF270_PREFIX_VALUE_NONE = 0,
    ROME2_100DF270_PREFIX_VALUE_SCALAR = 1,
    ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY = 2,
    ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY = 3,
    ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER = 4,
    ROME2_100DF270_PREFIX_VALUE_OPAQUE32 = 5
} rome2_100df270_prefix_value_kind;

typedef struct rome2_100df270_prefix_value {
    rome2_100df270_prefix_value_kind kind;
    uint32_t value;
} rome2_100df270_prefix_value;

typedef struct rome2_100df270_prefix_step {
    rome2_100df270_prefix_step_kind kind;
    uint32_t argument_count;
    rome2_100df270_prefix_value argument0;
    rome2_100df270_prefix_value argument1;
    rome2_100df270_prefix_value argument2;
    rome2_100df270_prefix_value argument3;
    uint32_t result_count;
    rome2_100df270_prefix_value result0;
} rome2_100df270_prefix_step;

typedef void (*rome2_100df270_prefix_emit_step_fn)(
    void *context,
    rome2_100df270_prefix_step step);

typedef struct rome2_100df270_prefix_effects {
    rome2_100df270_prefix_emit_step_fn emit_step;
    void *context;
    uint32_t created_mutex;
    uint32_t last_error;
} rome2_100df270_prefix_effects;

/*
 * Bounded call-shape transcript for original interval
 * [0x100df270, 0x100df343).  The complete receiver and packet spans must be
 * present, nonnull, and logically and physically disjoint in one borrowed
 * guest32 view.  Before the first callback, the adapter snapshots the view,
 * effects, packet instance value, and packet byte +0x2c, then validates all
 * checked receiver-derived identities.
 *
 * The exact deterministic writes are receiver+4 = packet[0], receiver+0 =
 * 0x1173f208 before the first step, followed by receiver+0x808 = the injected
 * CreateMutexW result after the CREATE_MUTEX callback and before GET_LAST_ERROR.
 * A normal route emits seven call shapes.  If last_error is 0xb7 and packet
 * byte +0x2c is zero, the three duplicate-instance call shapes are inserted
 * before the two SystemParametersInfoW shapes, for ten steps total.  The
 * 0x10102850 shape may return, matching the original fallthrough when
 * TerminateProcess does not terminate.  return_receiver_out is committed only
 * after the final callback returns.
 *
 * LoadStringW output bytes, the local formatted buffer, the original global at
 * 0x119f3854, mutex creation, UI, system settings, and process termination are
 * deliberately not fabricated.  Their endpoint identities and call order are
 * represented by values passed by copy.  The callback is total, nonreentrant,
 * returns normally, retains no borrowed object, and modifies neither guest
 * bytes nor return_receiver_out.  It may mutate only disjoint context storage.
 *
 * Validation failure emits nothing and preserves all guest bytes and output.
 * After emission begins, deterministic writes and callbacks form an ordered
 * committed prefix.  This port calls no original address, guest-derived
 * function pointer, native allocator, process global, or platform API and
 * performs no guest/native pointer cast.
 */
rome2_guest_status rome2_port_100df270_run_platform_prefix_transcript(
    const rome2_guest_write_view *state_view,
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_packet,
    const rome2_100df270_prefix_effects *effects,
    rome2_guest_addr32 *return_receiver_out);

#endif
