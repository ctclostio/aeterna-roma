#include "canonical_identity.h"
#include "ported_100df270_headless.h"
#include "ported_100df270_platform_prefix_transcript.h"
#include "ported_100df270_suffix_transcript.h"
#include "ported_100ed3c0_empty_preloop.h"
#include "ported_100ed471_ordinary_lifecycle.h"
#include "ported_100e2460_append_prefix.h"
#include "ported_100e2460_capacity_zero_branch.h"
#include "ported_100e2460_growth_branch.h"
#include "ported_100e2460_preallocated_branch.h"
#include "ported_100e2460_router.h"
#include "ported_100e8d00_handler_transcript.h"
#include "ported_100e85d0_normal_adapter.h"
#include "ported_100e8580_handler_transcript.h"
#include "ported_100e9340_handler_transcript.h"
#include "ported_100e92c0_handler_transcript.h"
#include "ported_100e87a0_handler_transcript.h"
#include "ported_100ea4d0_injected.h"
#include "ported_100edd70_policy.h"
#include "ported_100f1aa0_empty.h"
#include "ported_100f1bb0_bounded.h"
#include "ported_100f1cc0_nonowning.h"
#include "ported_100f2750_nonalloc.h"
#include "ported_100e8240_fastpath.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_HEADLESS_GUEST_BASE UINT32_C(0x1000)
#define ROME2_HEADLESS_SOURCE_OFFSET UINT32_C(0x40)
#define ROME2_HEADLESS_DESTINATION_OFFSET UINT32_C(0x50)
#define ROME2_HEADLESS_MEMORY_SIZE 128
#define ROME2_HEADLESS_SHORT_SOURCE_PAYLOAD_OFFSET UINT32_C(0x60)
#define ROME2_HEADLESS_SHORT_DESTINATION_PAYLOAD_OFFSET UINT32_C(0x70)
#define ROME2_HEADLESS_STARTUP_GUEST_BASE UINT32_C(0x2000)
#define ROME2_HEADLESS_STARTUP_PACKET_OFFSET UINT32_C(0x8c0)
#define ROME2_HEADLESS_STARTUP_MEMORY_SIZE 0x900
#define ROME2_HEADLESS_APPEND_VECTOR_OFFSET UINT32_C(0x854)
#define ROME2_HEADLESS_APPEND_HANDLER_A_OFFSET UINT32_C(0x8a8)
#define ROME2_HEADLESS_APPEND_HANDLER_B_OFFSET UINT32_C(0x8ac)
#define ROME2_HEADLESS_APPEND_BACKING_OFFSET UINT32_C(0x8b0)
#define ROME2_HEADLESS_FASTPATH_GUEST_BASE UINT32_C(0x3000)
#define ROME2_HEADLESS_FASTPATH_MEMORY_SIZE 0x100
#define ROME2_HEADLESS_FASTPATH_INDEX_OFFSET UINT32_C(0x00)
#define ROME2_HEADLESS_FASTPATH_THRESHOLD_OFFSET UINT32_C(0x10)
#define ROME2_HEADLESS_FASTPATH_TLS_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_FASTPATH_TLS_DATA_OFFSET UINT32_C(0x30)
#define ROME2_HEADLESS_FASTPATH_TLS_VALUE_OFFSET \
    (ROME2_HEADLESS_FASTPATH_TLS_DATA_OFFSET + 4)
#define ROME2_HEADLESS_BRANCH_STATE_GUEST_BASE UINT32_C(0x4000)
#define ROME2_HEADLESS_BRANCH_STATE_MEMORY_SIZE 0x100
#define ROME2_HEADLESS_BRANCH_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_BRANCH_HANDLER_OFFSET UINT32_C(0x60)
#define ROME2_HEADLESS_BRANCH_BACKING_OFFSET UINT32_C(0x80)
#define ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE UINT32_C(0x1173f200)
#define ROME2_HEADLESS_BRANCH_VTABLE_MEMORY_SIZE 0x100
#define ROME2_HEADLESS_BRANCH_VTABLE_OFFSET UINT32_C(0x24)
#define ROME2_HEADLESS_BRANCH_METHOD_IDENTITY UINT32_C(0x100e9340)
#define ROME2_HEADLESS_BRANCH_ARGUMENT UINT32_C(0x2824)
#define ROME2_HEADLESS_BRANCH_DISPATCH_EAX UINT32_C(0x123456a5)
#define ROME2_HEADLESS_ZERO_STATE_GUEST_BASE UINT32_C(0x5000)
#define ROME2_HEADLESS_ZERO_STATE_MEMORY_SIZE 0x100
#define ROME2_HEADLESS_ZERO_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_ZERO_HANDLER_OFFSET UINT32_C(0x60)
#define ROME2_HEADLESS_ZERO_ALLOCATION_OFFSET UINT32_C(0x80)
#define ROME2_HEADLESS_ZERO_ARGUMENT UINT32_C(0x2824)
#define ROME2_HEADLESS_ZERO_DISPATCH_EAX UINT32_C(0x89abcde7)
#define ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE UINT32_C(0x6000)
#define ROME2_HEADLESS_GROWTH_STATE_MEMORY_SIZE 0x180
#define ROME2_HEADLESS_GROWTH_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_GROWTH_HANDLER_OFFSET UINT32_C(0x60)
#define ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET UINT32_C(0x80)
#define ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET UINT32_C(0x100)
#define ROME2_HEADLESS_GROWTH_ALLOCATION_BYTES UINT32_C(16)
#define ROME2_HEADLESS_GROWTH_ARGUMENT UINT32_C(0x2824)
#define ROME2_HEADLESS_GROWTH_DISPATCH_EAX UINT32_C(0x765432d9)
#define ROME2_HEADLESS_GROWTH_OLD_CELL_A UINT32_C(0x41414141)
#define ROME2_HEADLESS_GROWTH_OLD_CELL_B UINT32_C(0x42424242)
#define ROME2_HEADLESS_ROUTER_STATE_GUEST_BASE UINT32_C(0x7000)
#define ROME2_HEADLESS_ROUTER_STATE_MEMORY_SIZE 0x400
#define ROME2_HEADLESS_ROUTER_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_ROUTER_HANDLER_OFFSET UINT32_C(0x80)
#define ROME2_HEADLESS_ROUTER_HANDLER_STRIDE UINT32_C(0x10)
#define ROME2_HEADLESS_ROUTER_BUFFER_A_OFFSET UINT32_C(0x200)
#define ROME2_HEADLESS_ROUTER_BUFFER_B_OFFSET UINT32_C(0x220)
#define ROME2_HEADLESS_ROUTER_BUFFER_C_OFFSET UINT32_C(0x240)
#define ROME2_HEADLESS_ROUTER_BUFFER_D_OFFSET UINT32_C(0x280)
#define ROME2_HEADLESS_ROUTER_APPEND_COUNT UINT32_C(6)
#define ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT UINT32_C(4)
#define ROME2_HEADLESS_ROUTER_ARGUMENT UINT32_C(0x2824)
#define ROME2_HEADLESS_ROUTER_SPARE UINT32_C(0xcccccccc)
#define ROME2_HEADLESS_ROUTER_87A0_LISTENER_OFFSET UINT32_C(0x300)
#define ROME2_HEADLESS_OUTER_STATE_GUEST_BASE UINT32_C(0x8000)
#define ROME2_HEADLESS_OUTER_STATE_MEMORY_SIZE 0x1400
#define ROME2_HEADLESS_OUTER_RECEIVER_OFFSET UINT32_C(0x100)
#define ROME2_HEADLESS_OUTER_VECTOR_OFFSET \
    (ROME2_HEADLESS_OUTER_RECEIVER_OFFSET + \
        ROME2_PORT_100EA4D0_VECTOR_OFFSET)
#define ROME2_HEADLESS_OUTER_ARGUMENT \
    (ROME2_HEADLESS_OUTER_STATE_GUEST_BASE + \
        ROME2_HEADLESS_OUTER_RECEIVER_OFFSET + \
        ROME2_PORT_100EA4D0_ARGUMENT_OFFSET)
#define ROME2_HEADLESS_OUTER_HANDLER_OFFSET UINT32_C(0x1000)
#define ROME2_HEADLESS_OUTER_HANDLER_STRIDE UINT32_C(0x10)
#define ROME2_HEADLESS_OUTER_BUFFER_A_OFFSET UINT32_C(0x1100)
#define ROME2_HEADLESS_OUTER_BUFFER_B_OFFSET UINT32_C(0x1120)
#define ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET UINT32_C(0x1140)
#define ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET UINT32_C(0x1180)
#define ROME2_HEADLESS_OUTER_87A0_LISTENER_OFFSET UINT32_C(0x1300)

#define ROME2_HEADLESS_SUFFIX_STATE_GUEST_BASE UINT32_C(0xa000)
#define ROME2_HEADLESS_SUFFIX_STATE_MEMORY_SIZE 0x40
#define ROME2_HEADLESS_SUFFIX_FIRST_RESULT_OFFSET UINT32_C(0x10)
#define ROME2_HEADLESS_SUFFIX_SECOND_RESULT_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_SUFFIX_FIRST_RESULT \
    (ROME2_HEADLESS_SUFFIX_STATE_GUEST_BASE + \
        ROME2_HEADLESS_SUFFIX_FIRST_RESULT_OFFSET)
#define ROME2_HEADLESS_SUFFIX_SECOND_RESULT \
    (ROME2_HEADLESS_SUFFIX_STATE_GUEST_BASE + \
        ROME2_HEADLESS_SUFFIX_SECOND_RESULT_OFFSET)
#define ROME2_HEADLESS_SUFFIX_FIRST_VALUE UINT32_C(0x01020304)
#define ROME2_HEADLESS_SUFFIX_SECOND_SENTINEL UINT32_C(0xcccccccc)
#define ROME2_HEADLESS_SUFFIX_ARGUMENT UINT32_C(0x2824)

#define ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE UINT32_C(0xb000)
#define ROME2_HEADLESS_PRELOOP_TEXT_GUEST_BASE UINT32_C(0xc000)
#define ROME2_HEADLESS_PRELOOP_ARGUMENT1 ROME2_HEADLESS_PREFIX_INSTANCE
#define ROME2_HEADLESS_PRELOOP_INITIAL_BYTE UINT8_C(0xa7)
#define ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL UINT32_C(0x7c7c7c7c)

#define ROME2_HEADLESS_LIFECYCLE_DISPATCH_GUEST_BASE UINT32_C(0x11897800)
#define ROME2_HEADLESS_LIFECYCLE_DISPATCH_MEMORY_SIZE 0x100
#define ROME2_HEADLESS_LIFECYCLE_RECEIVER_OFFSET UINT32_C(0x20)
#define ROME2_HEADLESS_LIFECYCLE_RECEIVER \
    (ROME2_HEADLESS_LIFECYCLE_DISPATCH_GUEST_BASE + \
        ROME2_HEADLESS_LIFECYCLE_RECEIVER_OFFSET)
#define ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW UINT32_C(0x89abcdef)
#define ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH UINT32_C(0x01234567)
#define ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL UINT32_C(0x6b6b6b6b)
#define ROME2_HEADLESS_LIFECYCLE_POLL_COUNT UINT32_C(3)
#define ROME2_HEADLESS_LIFECYCLE_STEP_COUNT UINT32_C(14)

#define ROME2_HEADLESS_PREFIX_INSTANCE UINT32_C(0x00400000)
#define ROME2_HEADLESS_PREFIX_MUTEX UINT32_C(0xdecafbad)

#define ROME2_HEADLESS_92C0_FIRST_LOW UINT32_C(0x11223344)
#define ROME2_HEADLESS_92C0_SECOND_LOW UINT32_C(0x55667788)
#define ROME2_HEADLESS_92C0_SECOND_HIGH UINT32_C(0x99aabbcc)
#define ROME2_HEADLESS_87A0_LISTENER_SENTINEL UINT32_C(0xcccccccc)

static const uint8_t rome2_headless_command_line[] = {
    0x2d, 0x00, 0x6e, 0x00, 0x6f, 0x00, 0x5f, 0x00,
    0x65, 0x00, 0x78, 0x00, 0x63, 0x00, 0x65, 0x00,
    0x70, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00,
    0x6e, 0x00, 0x5f, 0x00, 0x68, 0x00, 0x61, 0x00,
    0x6e, 0x00, 0x64, 0x00, 0x6c, 0x00, 0x65, 0x00,
    0x72, 0x00, 0x00, 0x00
};

static const uint8_t rome2_headless_empty_triplet[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x90, 0x40, 0xaf, 0x11
};

static const uint8_t rome2_headless_short_payload[] = {
    0x52, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x65, 0x00, 0x00, 0x00
};

typedef union rome2_headless_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_MEMORY_SIZE];
} rome2_headless_memory;

typedef union rome2_headless_startup_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_STARTUP_MEMORY_SIZE];
} rome2_headless_startup_memory;

typedef union rome2_headless_fastpath_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_FASTPATH_MEMORY_SIZE];
} rome2_headless_fastpath_memory;

typedef union rome2_headless_branch_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_BRANCH_STATE_MEMORY_SIZE];
} rome2_headless_branch_state_memory;

typedef union rome2_headless_branch_vtable_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_BRANCH_VTABLE_MEMORY_SIZE];
} rome2_headless_branch_vtable_memory;

typedef union rome2_headless_zero_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_ZERO_STATE_MEMORY_SIZE];
} rome2_headless_zero_state_memory;

typedef union rome2_headless_growth_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_GROWTH_STATE_MEMORY_SIZE];
} rome2_headless_growth_state_memory;

typedef union rome2_headless_router_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_ROUTER_STATE_MEMORY_SIZE];
} rome2_headless_router_state_memory;

typedef union rome2_headless_outer_state_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_OUTER_STATE_MEMORY_SIZE];
} rome2_headless_outer_state_memory;

typedef union rome2_headless_preloop_frame_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES];
} rome2_headless_preloop_frame_memory;

typedef union rome2_headless_preloop_text_memory {
    uint64_t alignment;
    uint8_t bytes[2];
} rome2_headless_preloop_text_memory;

typedef union rome2_headless_preloop_selector_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_SUFFIX_STATE_MEMORY_SIZE];
} rome2_headless_preloop_selector_memory;

typedef union rome2_headless_lifecycle_dispatch_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_HEADLESS_LIFECYCLE_DISPATCH_MEMORY_SIZE];
} rome2_headless_lifecycle_dispatch_memory;

typedef struct rome2_headless_branch_effect_context {
    const uint8_t *state_bytes;
    uint32_t expected_receiver;
    uint32_t expected_method;
    uint32_t expected_argument;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t observed_receiver;
    uint32_t observed_method;
    uint32_t observed_argument;
    uint32_t bad_observations;
} rome2_headless_branch_effect_context;

typedef struct rome2_headless_zero_effect_context {
    const uint8_t *state_bytes;
    uint32_t expected_receiver;
    uint32_t expected_method;
    uint32_t expected_argument;
    uint32_t expected_allocation;
    uint32_t allocation_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t effect_order;
    uint32_t allocation_order;
    uint32_t dispatch_order;
    uint32_t first_peek_order;
    uint32_t observed_receiver;
    uint32_t observed_method;
    uint32_t observed_argument;
    uint32_t bad_observations;
} rome2_headless_zero_effect_context;

typedef struct rome2_headless_growth_effect_context {
    const uint8_t *state_bytes;
    uint32_t expected_receiver;
    uint32_t expected_method;
    uint32_t expected_argument;
    uint32_t expected_old_backing;
    uint32_t expected_allocation;
    uint32_t allocation_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t effect_order;
    uint32_t allocation_order;
    uint32_t release_order;
    uint32_t dispatch_order;
    uint32_t first_peek_order;
    uint32_t observed_release;
    uint32_t observed_receiver;
    uint32_t observed_method;
    uint32_t observed_argument;
    uint32_t bad_observations;
} rome2_headless_growth_effect_context;

typedef struct rome2_headless_8d00_effect_context {
    uint32_t observed_steps;
    uint32_t bad_observations;
    const uint8_t *return_al;
} rome2_headless_8d00_effect_context;

typedef struct rome2_headless_8580_effect_context {
    uint32_t observed_steps;
    uint32_t bad_observations;
    const uint8_t *return_al;
} rome2_headless_8580_effect_context;

typedef struct rome2_headless_9340_effect_context {
    uint32_t observed_steps;
    uint32_t expected_receiver;
    uint32_t bad_observations;
    const uint8_t *return_al;
} rome2_headless_9340_effect_context;

typedef struct rome2_headless_92c0_effect_context {
    uint32_t observed_steps;
    uint32_t bad_observations;
    const uint8_t *return_al;
} rome2_headless_92c0_effect_context;

typedef struct rome2_headless_87a0_effect_context {
    const uint8_t *state_bytes;
    uint32_t listener_offset;
    uint32_t listener_guest;
    uint32_t allocation_calls;
    uint32_t publish_calls;
    uint32_t startup_calls;
    uint32_t effect_order;
    uint32_t bad_observations;
    const uint8_t *return_al;
} rome2_headless_87a0_effect_context;

typedef struct rome2_headless_router_effect_context {
    const uint8_t *state_bytes;
    const rome2_guest_write_view *state_view;
    uint32_t handlers[ROME2_HEADLESS_ROUTER_APPEND_COUNT];
    uint32_t allocations[ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT];
    uint32_t current_append;
    uint32_t allocation_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t handler_8d00_calls;
    uint32_t handler_85d0_calls;
    uint32_t handler_8580_calls;
    uint32_t handler_9340_calls;
    uint32_t handler_92c0_calls;
    uint32_t handler_87a0_calls;
    uint32_t bad_observations;
    rome2_100e8d00_transcript_effects handler_8d00_effects;
    rome2_headless_8d00_effect_context handler_8d00_context;
    rome2_100e8580_transcript_effects handler_8580_effects;
    rome2_headless_8580_effect_context handler_8580_context;
    rome2_100e9340_transcript_effects handler_9340_effects;
    rome2_headless_9340_effect_context handler_9340_context;
    rome2_100e92c0_transcript_effects handler_92c0_effects;
    rome2_headless_92c0_effect_context handler_92c0_context;
    rome2_100e87a0_effects handler_87a0_effects;
    rome2_headless_87a0_effect_context handler_87a0_context;
} rome2_headless_router_effect_context;

typedef struct rome2_headless_outer_effect_context {
    const uint8_t *state_bytes;
    const rome2_guest_write_view *state_view;
    uint32_t handlers[ROME2_PORT_100EA4D0_REGISTRATION_COUNT];
    uint32_t allocations[ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT];
    uint32_t current_append;
    uint32_t handler_allocation_calls;
    uint32_t backing_allocation_calls;
    uint32_t release_calls;
    uint32_t dispatch_calls;
    uint32_t peek_calls;
    uint32_t handler_8d00_calls;
    uint32_t handler_85d0_calls;
    uint32_t handler_8580_calls;
    uint32_t handler_9340_calls;
    uint32_t handler_92c0_calls;
    uint32_t handler_87a0_calls;
    uint32_t bad_observations;
    rome2_100e8d00_transcript_effects handler_8d00_effects;
    rome2_headless_8d00_effect_context handler_8d00_context;
    rome2_100e8580_transcript_effects handler_8580_effects;
    rome2_headless_8580_effect_context handler_8580_context;
    rome2_100e9340_transcript_effects handler_9340_effects;
    rome2_headless_9340_effect_context handler_9340_context;
    rome2_100e92c0_transcript_effects handler_92c0_effects;
    rome2_headless_92c0_effect_context handler_92c0_context;
    rome2_100e87a0_effects handler_87a0_effects;
    rome2_headless_87a0_effect_context handler_87a0_context;
} rome2_headless_outer_effect_context;

typedef struct rome2_headless_preloop_trace {
    const uint8_t *frame_bytes;
    const uint8_t *selector_bytes;
    const rome2_100ed3c0_preloop_result *result;
    uint32_t parent_steps;
    uint32_t prefix_steps;
    uint32_t suffix_steps;
    uint32_t bad_observations;
} rome2_headless_preloop_trace;

typedef struct rome2_headless_preloop_parent_context {
    rome2_headless_preloop_trace *trace;
} rome2_headless_preloop_parent_context;

typedef struct rome2_headless_preloop_prefix_context {
    rome2_headless_preloop_trace *trace;
} rome2_headless_preloop_prefix_context;

typedef struct rome2_headless_preloop_suffix_context {
    rome2_headless_preloop_trace *trace;
} rome2_headless_preloop_suffix_context;

typedef struct rome2_headless_lifecycle_trace {
    const uint8_t *frame_bytes;
    const rome2_100ed471_lifecycle_result *result;
    uint32_t timestamp_before_low;
    uint32_t timestamp_before_high;
    uint32_t timestamp_copy_before_low;
    uint32_t timestamp_copy_before_high;
    uint32_t steps;
    uint32_t bad_observations;
} rome2_headless_lifecycle_trace;

static const rome2_100e8d00_step rome2_headless_8d00_steps[
    ROME2_PORT_100E8D00_STEP_COUNT] = {
    {ROME2_100E8D00_STEP_CALL_10CB6160, 2, 0, 1},
    {ROME2_100E8D00_STEP_CALL_10115D40, 1, 0, 0},
    {
        ROME2_100E8D00_STEP_CALL_112DC9F0,
        2,
        ROME2_PORT_100E8D00_PRE_DB_APP_INIT_IDENTITY,
        0
    },
    {ROME2_100E8D00_STEP_CALL_101150A0, 1, 1, 0},
    {ROME2_100E8D00_STEP_CALL_101151D0, 1, 0, 0},
    {ROME2_100E8D00_STEP_CALL_112E2CB0, 0, 0, 0},
};

static const rome2_100e8580_step rome2_headless_8580_steps[
    ROME2_PORT_100E8580_STEP_COUNT] = {
    {ROME2_100E8580_STEP_CALL_100D6560, 0, 0, 0, 0, 0, {0}},
    {ROME2_100E8580_STEP_CALL_112D0510, 0, 0, 0, 0, 0, {0}},
    {ROME2_100E8580_STEP_CALL_112E0950_ONE, 1, 1, 0, 0, 0, {0}},
    {ROME2_100E8580_STEP_CALL_100D9810, 0, 0, 0, 0, 0, {0}},
    {ROME2_100E8580_STEP_CALL_100DDF50, 0, 0, 0, 0, 0, {0}},
    {ROME2_100E8580_STEP_CALL_112E0950_ZERO, 1, 0, 0, 0, 0, {0}},
    {
        ROME2_100E8580_STEP_CALL_100E8240,
        1,
        0,
        0,
        0,
        1,
        {UINT32_C(0x119f3a38)}
    },
    {
        ROME2_100E8580_STEP_CALL_112BFEE0,
        1,
        UINT32_C(0x119f3aa0),
        0,
        0,
        0,
        {0}
    },
    {
        ROME2_100E8580_STEP_CALL_112DCAF0,
        3,
        ROME2_PORT_100E8580_FINISHED_RUN_VARS_IDENTITY,
        0,
        0,
        0,
        {0}
    },
};

static const rome2_100e92c0_step rome2_headless_92c0_steps[
    ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT] = {
    {
        ROME2_100E92C0_STEP_CALL_100D6970,
        0, 0, 0, 0, 0,
        0, 0, 0,
        0, 0, 0, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE370,
        0, 0, 0, 0, 0,
        1, 1, 0,
        0, 0, 0, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE9D0,
        0, 0, 0, 0, 0,
        1, 1, 0,
        0, 0, 0, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE270,
        0, 0, 0, 0, 0,
        2, ROME2_HEADLESS_92C0_FIRST_LOW, 0,
        0, 0, ROME2_HEADLESS_92C0_FIRST_LOW, 0
    },
    {
        ROME2_100E92C0_STEP_CALL_10FDE990,
        0, 0, 0, 0, 0,
        2,
        ROME2_HEADLESS_92C0_SECOND_LOW,
        ROME2_HEADLESS_92C0_SECOND_HIGH,
        ROME2_HEADLESS_92C0_FIRST_LOW,
        0,
        ROME2_HEADLESS_92C0_SECOND_LOW,
        ROME2_HEADLESS_92C0_SECOND_HIGH
    },
    {
        ROME2_100E92C0_STEP_CALL_100D5150,
        4,
        ROME2_HEADLESS_92C0_FIRST_LOW,
        0,
        ROME2_HEADLESS_92C0_SECOND_LOW,
        ROME2_HEADLESS_92C0_SECOND_HIGH,
        0, 0, 0,
        0, 0, 0, 0
    },
};

static const rome2_100df270_suffix_step rome2_headless_suffix_steps[
    ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT] = {
    {
        ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER,
        2,
        ROME2_PORT_100DF270_SUFFIX_GLOBAL_RECEIVER,
        ROME2_HEADLESS_STARTUP_GUEST_BASE,
        0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_100E8240,
        1,
        ROME2_HEADLESS_SUFFIX_ARGUMENT,
        0,
        1,
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD,
        0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_100F2750,
        2,
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD +
            ROME2_PORT_100DF270_SUFFIX_RESULT_OFFSET,
        ROME2_HEADLESS_SUFFIX_ARGUMENT,
        0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0,
        1,
        ROME2_HEADLESS_STARTUP_GUEST_BASE,
        0,
        0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST,
        2,
        ROME2_HEADLESS_STARTUP_GUEST_BASE +
            ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,
        ROME2_PORT_100DF270_SUFFIX_SELECTOR,
        1,
        ROME2_HEADLESS_SUFFIX_FIRST_RESULT,
        ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE,
        ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET,
        ROME2_HEADLESS_SUFFIX_FIRST_VALUE
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        1, UINT32_C(0x2d), 0, 0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        1, UINT32_C(0x12), 0, 0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        1, UINT32_C(0x16), 0, 0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_CALL_101046D0,
        1, UINT32_C(0x21), 0, 0, 0, 0, 0, 0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND,
        2,
        ROME2_HEADLESS_STARTUP_GUEST_BASE +
            ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET,
        ROME2_PORT_100DF270_SUFFIX_SELECTOR,
        1,
        ROME2_HEADLESS_SUFFIX_SECOND_RESULT,
        ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE,
        ROME2_PORT_100DF270_SUFFIX_VIRTUAL_SLOT_OFFSET,
        0
    },
    {
        ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER,
        2,
        ROME2_HEADLESS_SUFFIX_SECOND_RESULT,
        ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER,
        0, 0, 0, 0, 0
    },
};

static const rome2_100df270_prefix_step rome2_headless_prefix_steps[
    ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT] = {
    {
        ROME2_100DF270_PREFIX_STEP_LOAD_TITLE,
        4,
        {ROME2_100DF270_PREFIX_VALUE_OPAQUE32,
            ROME2_HEADLESS_PREFIX_INSTANCE},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_RESOURCE_TITLE},
        {ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
            ROME2_HEADLESS_STARTUP_GUEST_BASE +
                ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY},
        0,
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0}
    },
    {
        ROME2_100DF270_PREFIX_STEP_LOAD_NAME,
        4,
        {ROME2_100DF270_PREFIX_VALUE_OPAQUE32,
            ROME2_HEADLESS_PREFIX_INSTANCE},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_RESOURCE_NAME},
        {ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
            ROME2_HEADLESS_STARTUP_GUEST_BASE +
                ROME2_PORT_100DF270_PREFIX_NAME_OFFSET},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY},
        0,
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0}
    },
    {
        ROME2_100DF270_PREFIX_STEP_FORMAT_MUTEX_NAME,
        4,
        {ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER,
            ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_WCHAR_CAPACITY},
        {ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            ROME2_PORT_100DF270_PREFIX_MUTEX_FORMAT},
        {ROME2_100DF270_PREFIX_VALUE_GUEST_IDENTITY,
            ROME2_HEADLESS_STARTUP_GUEST_BASE +
                ROME2_PORT_100DF270_PREFIX_NAME_OFFSET},
        0,
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0}
    },
    {
        ROME2_100DF270_PREFIX_STEP_CREATE_MUTEX,
        3,
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 1},
        {ROME2_100DF270_PREFIX_VALUE_LOCAL_BUFFER,
            ROME2_PORT_100DF270_PREFIX_LOCAL_BUFFER_ID},
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0},
        1,
        {ROME2_100DF270_PREFIX_VALUE_OPAQUE32,
            ROME2_HEADLESS_PREFIX_MUTEX}
    },
    {
        ROME2_100DF270_PREFIX_STEP_GET_LAST_ERROR,
        0,
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0},
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0},
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0},
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0},
        1,
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0}
    },
    {
        ROME2_100DF270_PREFIX_STEP_GET_MOUSE_TRAILS,
        4,
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_SPI_GETMOUSETRAILS},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0},
        {ROME2_100DF270_PREFIX_VALUE_ORIGINAL_IDENTITY,
            ROME2_PORT_100DF270_PREFIX_MOUSE_TRAILS_GLOBAL},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0},
        0,
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0}
    },
    {
        ROME2_100DF270_PREFIX_STEP_SET_MOUSE_TRAILS,
        4,
        {ROME2_100DF270_PREFIX_VALUE_SCALAR,
            ROME2_PORT_100DF270_PREFIX_SPI_SETMOUSETRAILS},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0},
        {ROME2_100DF270_PREFIX_VALUE_SCALAR, 0},
        0,
        {ROME2_100DF270_PREFIX_VALUE_NONE, 0}
    },
};

static const uint32_t rome2_headless_router_capacities[
    ROME2_HEADLESS_ROUTER_APPEND_COUNT] = {1, 2, 4, 4, 8, 8};

static const uint32_t rome2_headless_router_backing_offsets[
    ROME2_HEADLESS_ROUTER_APPEND_COUNT] = {
        ROME2_HEADLESS_ROUTER_BUFFER_A_OFFSET,
        ROME2_HEADLESS_ROUTER_BUFFER_B_OFFSET,
        ROME2_HEADLESS_ROUTER_BUFFER_C_OFFSET,
        ROME2_HEADLESS_ROUTER_BUFFER_C_OFFSET,
        ROME2_HEADLESS_ROUTER_BUFFER_D_OFFSET,
        ROME2_HEADLESS_ROUTER_BUFFER_D_OFFSET,
    };

static const uint32_t rome2_headless_router_vtables[
    ROME2_HEADLESS_ROUTER_APPEND_COUNT] = {
        UINT32_C(0x1173f20c),
        UINT32_C(0x1173f214),
        UINT32_C(0x1173f21c),
        UINT32_C(0x1173f224),
        UINT32_C(0x1173f2ec),
        UINT32_C(0x1173f2dc),
    };

static const uint32_t rome2_headless_router_methods[
    ROME2_HEADLESS_ROUTER_APPEND_COUNT] = {
        UINT32_C(0x100e8d00),
        UINT32_C(0x100e85d0),
        UINT32_C(0x100e8580),
        UINT32_C(0x100e9340),
        UINT32_C(0x100e92c0),
        UINT32_C(0x100e87a0),
    };

static const uint32_t rome2_headless_outer_backing_offsets[
    ROME2_HEADLESS_ROUTER_APPEND_COUNT] = {
        ROME2_HEADLESS_OUTER_BUFFER_A_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_B_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET,
    };

static void rome2_headless_put_u32(
    uint8_t *bytes,
    size_t offset,
    uint32_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

static uint32_t rome2_headless_get_u32(
    const uint8_t *bytes,
    size_t offset)
{
    return
        (uint32_t)bytes[offset] |
        ((uint32_t)bytes[offset + 1] << 8) |
        ((uint32_t)bytes[offset + 2] << 16) |
        ((uint32_t)bytes[offset + 3] << 24);
}

static int rome2_headless_bytes_are(
    const uint8_t *bytes,
    size_t offset,
    size_t byte_count,
    uint8_t expected)
{
    size_t index;

    for (index = 0; index < byte_count; ++index) {
        if (bytes[offset + index] != expected) {
            return 0;
        }
    }
    return 1;
}

static int rome2_headless_prefix_value_is_exact(
    rome2_100df270_prefix_value actual,
    rome2_100df270_prefix_value expected)
{
    return actual.kind == expected.kind && actual.value == expected.value;
}

static int rome2_headless_prefix_step_is_exact(
    rome2_100df270_prefix_step actual,
    const rome2_100df270_prefix_step *expected)
{
    return
        expected != NULL &&
        actual.kind == expected->kind &&
        actual.argument_count == expected->argument_count &&
        rome2_headless_prefix_value_is_exact(
            actual.argument0, expected->argument0) &&
        rome2_headless_prefix_value_is_exact(
            actual.argument1, expected->argument1) &&
        rome2_headless_prefix_value_is_exact(
            actual.argument2, expected->argument2) &&
        rome2_headless_prefix_value_is_exact(
            actual.argument3, expected->argument3) &&
        actual.result_count == expected->result_count &&
        rome2_headless_prefix_value_is_exact(
            actual.result0, expected->result0);
}

static int rome2_headless_suffix_step_is_exact(
    rome2_100df270_suffix_step actual,
    const rome2_100df270_suffix_step *expected)
{
    return
        expected != NULL &&
        actual.kind == expected->kind &&
        actual.argument_count == expected->argument_count &&
        actual.argument0 == expected->argument0 &&
        actual.argument1 == expected->argument1 &&
        actual.result_count == expected->result_count &&
        actual.result0 == expected->result0 &&
        actual.dispatch_vtable == expected->dispatch_vtable &&
        actual.dispatch_slot_offset == expected->dispatch_slot_offset &&
        actual.observed_value == expected->observed_value;
}

static rome2_100ed3c0_preloop_value rome2_headless_preloop_value(
    rome2_100ed3c0_preloop_value_kind kind,
    uint32_t value)
{
    rome2_100ed3c0_preloop_value result;

    result.kind = kind;
    result.value = value;
    return result;
}

static int rome2_headless_preloop_value_is_exact(
    rome2_100ed3c0_preloop_value actual,
    rome2_100ed3c0_preloop_value expected)
{
    return actual.kind == expected.kind && actual.value == expected.value;
}

static int rome2_headless_preloop_parent_step_is_exact(
    rome2_100ed3c0_preloop_step actual,
    uint32_t index)
{
    rome2_100ed3c0_preloop_step expected;
    uint32_t frame = ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE;

    memset(&expected, 0, sizeof(expected));
    switch (index) {
    case 0:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C8;
        expected.argument_count = UINT32_C(2);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
            ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C8);
        expected.argument1 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
        break;
    case 1:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_WRITE_GLOBAL_119F31C5;
        expected.argument_count = UINT32_C(2);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_ORIGINAL_IDENTITY,
            ROME2_PORT_100ED3C0_PRELOOP_GLOBAL_119F31C5);
        expected.argument1 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_SCALAR, UINT32_C(1));
        break;
    case 2:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET0;
        expected.argument_count = UINT32_C(1);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET);
        break;
    case 3:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_INIT_TRIPLET1;
        expected.argument_count = UINT32_C(1);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET);
        break;
    case 4:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY0;
        expected.argument_count = UINT32_C(2);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET);
        expected.argument1 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET);
        break;
    case 5:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_COPY_EMPTY1;
        expected.argument_count = UINT32_C(2);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET);
        expected.argument1 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET);
        break;
    case 6:
        expected.kind =
            ROME2_100ED3C0_PRELOOP_STEP_BUILD_EMPTY_DESCRIPTOR;
        expected.argument_count = UINT32_C(2);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET);
        expected.argument1 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_GUEST_IDENTITY,
            ROME2_HEADLESS_PRELOOP_TEXT_GUEST_BASE);
        expected.result_count = UINT32_C(1);
        expected.result0 = expected.argument0;
        break;
    case 7:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_RUN_100DF270;
        expected.argument_count = UINT32_C(3);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET);
        expected.argument1 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET);
        expected.argument2 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET);
        break;
    case 8:
        expected.kind = ROME2_100ED3C0_PRELOOP_STEP_CLEANUP_DESCRIPTOR;
        expected.argument_count = UINT32_C(1);
        expected.argument0 = rome2_headless_preloop_value(
            ROME2_100ED3C0_PRELOOP_VALUE_FRAME_IDENTITY,
            frame + ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET);
        break;
    default:
        return 0;
    }

    return
        actual.kind == expected.kind &&
        actual.argument_count == expected.argument_count &&
        rome2_headless_preloop_value_is_exact(
            actual.argument0, expected.argument0) &&
        rome2_headless_preloop_value_is_exact(
            actual.argument1, expected.argument1) &&
        rome2_headless_preloop_value_is_exact(
            actual.argument2, expected.argument2) &&
        actual.result_count == expected.result_count &&
        rome2_headless_preloop_value_is_exact(
            actual.result0, expected.result0);
}

static int rome2_headless_preloop_result_is_uncommitted(
    const rome2_100ed3c0_preloop_result *result)
{
    return
        result != NULL &&
        result->child_receiver.value ==
            ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL &&
        result->child_packet.value ==
            ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL &&
        result->child_argument.value ==
            ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL &&
        result->next_original_pc == ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL;
}

static void rome2_headless_preloop_parent_emit(
    void *opaque_context,
    rome2_100ed3c0_preloop_step step)
{
    rome2_headless_preloop_parent_context *context =
        (rome2_headless_preloop_parent_context *)opaque_context;
    rome2_headless_preloop_trace *trace = context->trace;
    uint32_t index = trace->parent_steps;

    if (!rome2_headless_preloop_result_is_uncommitted(trace->result) ||
        (index < UINT32_C(8) &&
            (trace->prefix_steps != UINT32_C(0) ||
             trace->suffix_steps != UINT32_C(0))) ||
        (index == UINT32_C(8) &&
            (trace->prefix_steps !=
                ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT ||
             trace->suffix_steps !=
                ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT)) ||
        !rome2_headless_preloop_parent_step_is_exact(step, index)) {
        ++trace->bad_observations;
    }
    if (index < ROME2_PORT_100ED3C0_PRELOOP_STEP_COUNT) {
        trace->parent_steps = index + UINT32_C(1);
    }
}

static int rome2_headless_preloop_prefix_step_is_exact(
    rome2_100df270_prefix_step actual,
    uint32_t index)
{
    rome2_100df270_prefix_step expected;
    uint32_t receiver = ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE +
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET;

    if (index >= ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT) {
        return 0;
    }
    expected = rome2_headless_prefix_steps[index];
    if (index == UINT32_C(0)) {
        expected.argument2.value =
            receiver + ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET;
    } else if (index == UINT32_C(1)) {
        expected.argument2.value =
            receiver + ROME2_PORT_100DF270_PREFIX_NAME_OFFSET;
    } else if (index == UINT32_C(2)) {
        expected.argument3.value =
            receiver + ROME2_PORT_100DF270_PREFIX_NAME_OFFSET;
    }
    return rome2_headless_prefix_step_is_exact(actual, &expected);
}

static void rome2_headless_preloop_prefix_emit(
    void *opaque_context,
    rome2_100df270_prefix_step step)
{
    rome2_headless_preloop_prefix_context *context =
        (rome2_headless_preloop_prefix_context *)opaque_context;
    rome2_headless_preloop_trace *trace = context->trace;
    const uint8_t *receiver = trace->frame_bytes +
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET;
    uint32_t index = trace->prefix_steps;
    uint32_t expected_mutex = index >= UINT32_C(4)
        ? ROME2_HEADLESS_PREFIX_MUTEX
        : UINT32_C(0xa7a7a7a7);

    if (!rome2_headless_preloop_result_is_uncommitted(trace->result) ||
        trace->parent_steps != UINT32_C(8) ||
        trace->suffix_steps != UINT32_C(0) ||
        !rome2_headless_preloop_prefix_step_is_exact(step, index) ||
        rome2_headless_get_u32(receiver, 0) !=
            ROME2_PORT_100DF270_PREFIX_INITIAL_VTABLE ||
        rome2_headless_get_u32(
            receiver, ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET) !=
                ROME2_HEADLESS_PRELOOP_ARGUMENT1 ||
        rome2_headless_get_u32(
            receiver, ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET) !=
                expected_mutex ||
        !rome2_headless_bytes_are(
            receiver,
            ROME2_PORT_100DF270_PREFIX_NAME_OFFSET,
            ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET -
                ROME2_PORT_100DF270_PREFIX_NAME_OFFSET,
            ROME2_HEADLESS_PRELOOP_INITIAL_BYTE) ||
        !rome2_headless_bytes_are(
            receiver,
            ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET,
            ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET -
                ROME2_PORT_100DF270_PREFIX_TITLE_OFFSET,
            ROME2_HEADLESS_PRELOOP_INITIAL_BYTE)) {
        ++trace->bad_observations;
    }
    if (index < ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT) {
        trace->prefix_steps = index + UINT32_C(1);
    }
}

static int rome2_headless_preloop_suffix_step_is_exact(
    rome2_100df270_suffix_step actual,
    uint32_t index)
{
    rome2_100df270_suffix_step expected;
    uint32_t receiver = ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE +
        ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET;
    uint32_t argument = ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE +
        ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET;

    if (index >= ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT) {
        return 0;
    }
    expected = rome2_headless_suffix_steps[index];
    switch (expected.kind) {
    case ROME2_100DF270_SUFFIX_STEP_PUBLISH_RECEIVER:
        expected.argument1 = receiver;
        break;
    case ROME2_100DF270_SUFFIX_STEP_CALL_100E8240:
        expected.argument0 = argument;
        break;
    case ROME2_100DF270_SUFFIX_STEP_CALL_100F2750:
        expected.argument1 = argument;
        break;
    case ROME2_100DF270_SUFFIX_STEP_CALL_100EA4D0:
        expected.argument0 = receiver;
        break;
    case ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_FIRST:
    case ROME2_100DF270_SUFFIX_STEP_QUERY_SELECTOR2_SECOND:
        expected.argument0 =
            receiver + ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET;
        break;
    default:
        break;
    }
    return rome2_headless_suffix_step_is_exact(actual, &expected);
}

static void rome2_headless_preloop_suffix_emit(
    void *opaque_context,
    rome2_100df270_suffix_step step)
{
    rome2_headless_preloop_suffix_context *context =
        (rome2_headless_preloop_suffix_context *)opaque_context;
    rome2_headless_preloop_trace *trace = context->trace;
    uint32_t index = trace->suffix_steps;
    uint32_t expected_second =
        step.kind == ROME2_100DF270_SUFFIX_STEP_STORE_FINAL_MARKER
        ? ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER
        : ROME2_HEADLESS_SUFFIX_SECOND_SENTINEL;

    if (!rome2_headless_preloop_result_is_uncommitted(trace->result) ||
        trace->parent_steps != UINT32_C(8) ||
        trace->prefix_steps !=
            ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT ||
        !rome2_headless_preloop_suffix_step_is_exact(step, index) ||
        rome2_headless_get_u32(
            trace->selector_bytes,
            ROME2_HEADLESS_SUFFIX_FIRST_RESULT_OFFSET) !=
                ROME2_HEADLESS_SUFFIX_FIRST_VALUE ||
        rome2_headless_get_u32(
            trace->selector_bytes,
            ROME2_HEADLESS_SUFFIX_SECOND_RESULT_OFFSET) != expected_second) {
        ++trace->bad_observations;
    }
    if (index < ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT) {
        trace->suffix_steps = index + UINT32_C(1);
    }
}

static int rome2_headless_lifecycle_result_is_uncommitted(
    const rome2_100ed471_lifecycle_result *result)
{
    return
        result != NULL &&
        result->dispatch_receiver.value ==
            ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->dispatch_vtable.value ==
            ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->dispatch_target.value ==
            ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->poll_calls == ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->terminal_poll_result ==
            ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->timestamp_low == ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->timestamp_high == ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL &&
        result->return_original_pc ==
            ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL;
}

static int rome2_headless_lifecycle_step_is_exact(
    rome2_100ed471_step actual,
    uint32_t index)
{
    static const uint32_t cleanup_offsets[] = {
        ROME2_PORT_100ED471_CLEANUP0_OFFSET,
        ROME2_PORT_100ED471_CLEANUP1_OFFSET,
        ROME2_PORT_100ED471_CLEANUP2_OFFSET,
        ROME2_PORT_100ED471_CLEANUP3_OFFSET
    };
    rome2_100ed471_step expected;
    uint32_t frame = ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE;

    memset(&expected, 0, sizeof(expected));
    switch (index) {
    case 0:
        expected.kind = ROME2_100ED471_STEP_CALL_100EA060;
        expected.argument_count = UINT32_C(1);
        expected.argument0 =
            frame + ROME2_PORT_100ED471_RECEIVER_OFFSET;
        break;
    case 1:
        expected.kind = ROME2_100ED471_STEP_CALL_112DCAF0;
        expected.argument_count = UINT32_C(3);
        expected.argument0 = ROME2_PORT_100ED471_LOG_MESSAGE;
        break;
    case 2:
        expected.kind = ROME2_100ED471_STEP_CALL_100D6560;
        expected.argument_count = UINT32_C(1);
        break;
    case 3:
        expected.kind = ROME2_100ED471_STEP_CALL_112E3D20;
        expected.result_count = UINT32_C(1);
        expected.result0 = ROME2_HEADLESS_LIFECYCLE_RECEIVER;
        break;
    case 4:
        expected.kind = ROME2_100ED471_STEP_INDIRECT_SLOT_54;
        expected.argument_count = UINT32_C(2);
        expected.argument0 = ROME2_HEADLESS_LIFECYCLE_RECEIVER;
        expected.dispatch_vtable = ROME2_PORT_100ED471_LOCAL_VTABLE;
        expected.dispatch_slot_offset =
            ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET;
        expected.dispatch_target = ROME2_PORT_100ED471_LOCAL_METHOD;
        break;
    case 5:
        expected.kind = ROME2_100ED471_STEP_CALL_112E2BB0;
        expected.argument_count = UINT32_C(1);
        expected.argument0 =
            frame + ROME2_PORT_100ED471_TIMESTAMP_OFFSET;
        expected.result_count = UINT32_C(2);
        expected.result0 = ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW;
        expected.result1 = ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH;
        break;
    case 6:
    case 7:
    case 8:
        expected.kind = ROME2_100ED471_STEP_CALL_100EC5C0;
        expected.argument_count = UINT32_C(1);
        expected.argument0 =
            frame + ROME2_PORT_100ED471_RECEIVER_OFFSET;
        expected.result_count = UINT32_C(1);
        expected.result0 = index == UINT32_C(8)
            ? UINT32_C(2)
            : UINT32_C(0);
        break;
    case 9:
        expected.kind = ROME2_100ED471_STEP_CALL_100E0650;
        expected.argument_count = UINT32_C(1);
        expected.argument0 =
            frame + ROME2_PORT_100ED471_RECEIVER_OFFSET;
        break;
    case 10:
    case 11:
    case 12:
    case 13:
        expected.kind = ROME2_100ED471_STEP_CALL_100F1CC0;
        expected.argument_count = UINT32_C(1);
        expected.argument0 = frame + cleanup_offsets[index - UINT32_C(10)];
        break;
    default:
        return 0;
    }

    return
        actual.kind == expected.kind &&
        actual.argument_count == expected.argument_count &&
        actual.argument0 == expected.argument0 &&
        actual.argument1 == expected.argument1 &&
        actual.argument2 == expected.argument2 &&
        actual.result_count == expected.result_count &&
        actual.result0 == expected.result0 &&
        actual.result1 == expected.result1 &&
        actual.dispatch_vtable == expected.dispatch_vtable &&
        actual.dispatch_slot_offset == expected.dispatch_slot_offset &&
        actual.dispatch_target == expected.dispatch_target;
}

static void rome2_headless_lifecycle_emit(
    void *opaque_context,
    rome2_100ed471_step step)
{
    rome2_headless_lifecycle_trace *trace =
        (rome2_headless_lifecycle_trace *)opaque_context;
    uint32_t index = trace->steps;
    int timestamp_is_exact;

    if (index <= UINT32_C(5)) {
        timestamp_is_exact =
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_OFFSET) ==
                    trace->timestamp_before_low &&
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4)) ==
                    trace->timestamp_before_high &&
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) ==
                    trace->timestamp_copy_before_low &&
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4)) ==
                    trace->timestamp_copy_before_high;
    } else {
        timestamp_is_exact =
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_OFFSET) ==
                    ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW &&
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4)) ==
                    ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH &&
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) ==
                    ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW &&
            rome2_headless_get_u32(
                trace->frame_bytes,
                ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4)) ==
                    ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH;
    }

    if (!rome2_headless_lifecycle_result_is_uncommitted(trace->result) ||
        !rome2_headless_lifecycle_step_is_exact(step, index) ||
        !timestamp_is_exact ||
        memcmp(
            trace->frame_bytes + ROME2_PORT_100ED471_CLEANUP0_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            trace->frame_bytes + ROME2_PORT_100ED471_CLEANUP1_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            trace->frame_bytes + ROME2_PORT_100ED471_CLEANUP2_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            trace->frame_bytes + ROME2_PORT_100ED471_CLEANUP3_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0) {
        ++trace->bad_observations;
    }
    if (index < ROME2_HEADLESS_LIFECYCLE_STEP_COUNT) {
        trace->steps = index + UINT32_C(1);
    }
}

static uint32_t rome2_headless_branch_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_headless_branch_effect_context *context =
        (rome2_headless_branch_effect_context *)opaque_context;
    uint32_t count = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_BRANCH_VECTOR_OFFSET + 8);
    uint32_t slot = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_BRANCH_BACKING_OFFSET + 4);

    ++context->dispatch_calls;
    context->observed_receiver = receiver.value;
    context->observed_method = method.value;
    context->observed_argument = argument.value;
    if (context->dispatch_calls != 1 || count != 2 ||
        slot != context->expected_receiver ||
        receiver.value != context->expected_receiver ||
        method.value != context->expected_method ||
        argument.value != context->expected_argument) {
        ++context->bad_observations;
    }
    return ROME2_HEADLESS_BRANCH_DISPATCH_EAX;
}

static uint32_t rome2_headless_branch_peek(
    void *opaque_context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    rome2_headless_branch_effect_context *context =
        (rome2_headless_branch_effect_context *)opaque_context;

    ++context->peek_calls;
    if (context->dispatch_calls != 1 || context->peek_calls > 2 ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    return context->peek_calls == 1 ? UINT32_C(1) : UINT32_C(0);
}

static rome2_guest_addr32 rome2_headless_zero_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_headless_zero_effect_context *context =
        (rome2_headless_zero_effect_context *)opaque_context;
    rome2_guest_addr32 allocation = {0};
    uint32_t capacity = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 4);
    uint32_t count = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 8);
    uint32_t backing = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 12);

    ++context->allocation_calls;
    context->allocation_order = ++context->effect_order;
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->dispatch_calls != 0 || context->peek_calls != 0 ||
        byte_count != ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_BYTES ||
        allocation_class !=
            ROME2_PORT_100E2460_CAPACITY_ZERO_ALLOCATION_CLASS ||
        capacity != 1 || count != 0 || backing != 0) {
        ++context->bad_observations;
    }
    allocation.value = context->expected_allocation;
    return allocation;
}

static uint32_t rome2_headless_zero_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_headless_zero_effect_context *context =
        (rome2_headless_zero_effect_context *)opaque_context;
    uint32_t capacity = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 4);
    uint32_t count = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 8);
    uint32_t backing = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 12);
    uint32_t slot = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_ZERO_ALLOCATION_OFFSET);

    ++context->dispatch_calls;
    context->dispatch_order = ++context->effect_order;
    context->observed_receiver = receiver.value;
    context->observed_method = method.value;
    context->observed_argument = argument.value;
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->dispatch_calls != 1 || context->dispatch_order != 2 ||
        context->peek_calls != 0 || capacity != 1 || count != 1 ||
        backing != context->expected_allocation ||
        slot != context->expected_receiver ||
        receiver.value != context->expected_receiver ||
        method.value != context->expected_method ||
        argument.value != context->expected_argument) {
        ++context->bad_observations;
    }
    return ROME2_HEADLESS_ZERO_DISPATCH_EAX;
}

static uint32_t rome2_headless_zero_peek(
    void *opaque_context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    rome2_headless_zero_effect_context *context =
        (rome2_headless_zero_effect_context *)opaque_context;

    ++context->peek_calls;
    ++context->effect_order;
    if (context->peek_calls == 1) {
        context->first_peek_order = context->effect_order;
    }
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->dispatch_calls != 1 || context->dispatch_order != 2 ||
        context->peek_calls > 2 || context->first_peek_order != 3 ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    return context->peek_calls == 1 ? UINT32_C(1) : UINT32_C(0);
}

static rome2_guest_addr32 rome2_headless_growth_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_headless_growth_effect_context *context =
        (rome2_headless_growth_effect_context *)opaque_context;
    rome2_guest_addr32 allocation = {0};
    uint32_t capacity = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 4);
    uint32_t count = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8);
    uint32_t backing = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 12);

    ++context->allocation_calls;
    context->allocation_order = ++context->effect_order;
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->release_calls != 0 || context->dispatch_calls != 0 ||
        context->peek_calls != 0 ||
        byte_count != ROME2_HEADLESS_GROWTH_ALLOCATION_BYTES ||
        allocation_class != ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        capacity != 4 || count != 2 ||
        backing != context->expected_old_backing ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_A ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET + 4) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_B ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET) !=
            UINT32_C(0xcccccccc) ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 12) !=
            UINT32_C(0xcccccccc)) {
        ++context->bad_observations;
    }
    allocation.value = context->expected_allocation;
    return allocation;
}

static void rome2_headless_growth_release(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    rome2_headless_growth_effect_context *context =
        (rome2_headless_growth_effect_context *)opaque_context;
    uint32_t capacity = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 4);
    uint32_t count = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8);
    uint32_t backing = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 12);

    ++context->release_calls;
    context->release_order = ++context->effect_order;
    context->observed_release = allocation.value;
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->release_calls != 1 || context->release_order != 2 ||
        context->dispatch_calls != 0 || context->peek_calls != 0 ||
        allocation.value != context->expected_old_backing ||
        capacity != 4 || count != 2 ||
        backing != context->expected_allocation ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_A ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET + 4) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_B ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_A ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 4) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_B ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 8) !=
            context->expected_receiver ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 12) !=
            UINT32_C(0xcccccccc)) {
        ++context->bad_observations;
    }
}

static uint32_t rome2_headless_growth_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_headless_growth_effect_context *context =
        (rome2_headless_growth_effect_context *)opaque_context;
    uint32_t capacity = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 4);
    uint32_t count = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8);
    uint32_t backing = rome2_headless_get_u32(
        context->state_bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 12);

    ++context->dispatch_calls;
    context->dispatch_order = ++context->effect_order;
    context->observed_receiver = receiver.value;
    context->observed_method = method.value;
    context->observed_argument = argument.value;
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->release_calls != 1 || context->release_order != 2 ||
        context->dispatch_calls != 1 || context->dispatch_order != 3 ||
        context->peek_calls != 0 || capacity != 4 || count != 3 ||
        backing != context->expected_allocation ||
        receiver.value != context->expected_receiver ||
        method.value != context->expected_method ||
        argument.value != context->expected_argument ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_A ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 4) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_B ||
        rome2_headless_get_u32(
            context->state_bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 8) !=
            context->expected_receiver) {
        ++context->bad_observations;
    }
    return ROME2_HEADLESS_GROWTH_DISPATCH_EAX;
}

static uint32_t rome2_headless_growth_peek(
    void *opaque_context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    rome2_headless_growth_effect_context *context =
        (rome2_headless_growth_effect_context *)opaque_context;

    ++context->peek_calls;
    ++context->effect_order;
    if (context->peek_calls == 1) {
        context->first_peek_order = context->effect_order;
    }
    if (context->allocation_calls != 1 || context->allocation_order != 1 ||
        context->release_calls != 1 || context->release_order != 2 ||
        context->dispatch_calls != 1 || context->dispatch_order != 3 ||
        context->peek_calls > 2 || context->first_peek_order != 4 ||
        context->effect_order != UINT32_C(3) + context->peek_calls ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    return context->peek_calls == 1 ? UINT32_C(1) : UINT32_C(0);
}

static uint32_t rome2_headless_router_guest(uint32_t offset)
{
    return ROME2_HEADLESS_ROUTER_STATE_GUEST_BASE + offset;
}

static uint32_t rome2_headless_router_vector_cell(
    const rome2_headless_router_effect_context *context,
    uint32_t cell_offset)
{
    return rome2_headless_get_u32(
        context->state_bytes,
        ROME2_HEADLESS_ROUTER_VECTOR_OFFSET + cell_offset);
}

static int rome2_headless_router_buffer_shape(
    uint32_t backing,
    uint32_t *offset_out,
    uint32_t *capacity_out)
{
    uint32_t offset;

    if (backing < ROME2_HEADLESS_ROUTER_STATE_GUEST_BASE) {
        return 0;
    }
    offset = backing - ROME2_HEADLESS_ROUTER_STATE_GUEST_BASE;
    switch (offset) {
    case ROME2_HEADLESS_ROUTER_BUFFER_A_OFFSET:
        *offset_out = offset;
        *capacity_out = 1;
        return 1;
    case ROME2_HEADLESS_ROUTER_BUFFER_B_OFFSET:
        *offset_out = offset;
        *capacity_out = 2;
        return 1;
    case ROME2_HEADLESS_ROUTER_BUFFER_C_OFFSET:
        *offset_out = offset;
        *capacity_out = 4;
        return 1;
    case ROME2_HEADLESS_ROUTER_BUFFER_D_OFFSET:
        *offset_out = offset;
        *capacity_out = 8;
        return 1;
    default:
        return 0;
    }
}

static int rome2_headless_router_buffer_is_ordered(
    const rome2_headless_router_effect_context *context,
    uint32_t backing,
    uint32_t populated_count)
{
    uint32_t offset;
    uint32_t capacity;
    uint32_t index;

    if (!rome2_headless_router_buffer_shape(
            backing, &offset, &capacity) ||
        populated_count > capacity) {
        return 0;
    }
    for (index = 0; index < populated_count; ++index) {
        if (rome2_headless_get_u32(
                context->state_bytes,
                (size_t)offset + (size_t)index * 4) !=
            context->handlers[index]) {
            return 0;
        }
    }
    for (index = populated_count; index < capacity; ++index) {
        if (rome2_headless_get_u32(
                context->state_bytes,
                (size_t)offset + (size_t)index * 4) !=
            ROME2_HEADLESS_ROUTER_SPARE) {
            return 0;
        }
    }
    return 1;
}

static rome2_guest_addr32 rome2_headless_router_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    static const uint32_t allocation_appends[
        ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT] = {0, 1, 2, 4};
    rome2_headless_router_effect_context *context =
        (rome2_headless_router_effect_context *)opaque_context;
    rome2_guest_addr32 result = {0};
    uint32_t allocation_index = context->allocation_calls;
    uint32_t expected_backing;

    if (allocation_index >= ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT) {
        ++context->bad_observations;
        return result;
    }
    result.value = context->allocations[allocation_index];
    expected_backing = allocation_index == 0
        ? 0
        : context->allocations[allocation_index - 1];
    ++context->allocation_calls;
    if (context->current_append != allocation_appends[allocation_index] ||
        byte_count != UINT32_C(4) << allocation_index ||
        allocation_class != ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        rome2_headless_router_vector_cell(context, 4) !=
            (UINT32_C(1) << allocation_index) ||
        rome2_headless_router_vector_cell(context, 8) !=
            context->current_append ||
        rome2_headless_router_vector_cell(context, 12) != expected_backing ||
        !rome2_headless_router_buffer_is_ordered(context, result.value, 0)) {
        ++context->bad_observations;
    }
    return result;
}

static void rome2_headless_router_release(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    static const uint32_t release_appends[3] = {1, 2, 4};
    rome2_headless_router_effect_context *context =
        (rome2_headless_router_effect_context *)opaque_context;
    uint32_t release_index = context->release_calls;
    uint32_t current_backing =
        rome2_headless_router_vector_cell(context, 12);

    if (release_index >= 3) {
        ++context->bad_observations;
        return;
    }
    ++context->release_calls;
    if (context->current_append != release_appends[release_index] ||
        allocation.value != context->allocations[release_index] ||
        current_backing != context->allocations[release_index + 1] ||
        rome2_headless_router_vector_cell(context, 4) !=
            rome2_headless_router_capacities[context->current_append] ||
        rome2_headless_router_vector_cell(context, 8) !=
            context->current_append ||
        !rome2_headless_router_buffer_is_ordered(
            context, current_backing, context->current_append + 1)) {
        ++context->bad_observations;
    }
}

static void rome2_headless_8d00_emit(
    void *opaque_context,
    rome2_100e8d00_step step)
{
    rome2_headless_8d00_effect_context *context =
        (rome2_headless_8d00_effect_context *)opaque_context;
    uint32_t index = context->observed_steps;

    if (index >= ROME2_PORT_100E8D00_STEP_COUNT ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc)) {
        ++context->bad_observations;
        return;
    }
    if (step.kind != rome2_headless_8d00_steps[index].kind ||
        step.argument_count !=
            rome2_headless_8d00_steps[index].argument_count ||
        step.argument0 != rome2_headless_8d00_steps[index].argument0 ||
        step.argument1 != rome2_headless_8d00_steps[index].argument1) {
        ++context->bad_observations;
    }
    ++context->observed_steps;
}

static void rome2_headless_8580_emit(
    void *opaque_context,
    rome2_100e8580_step step)
{
    rome2_headless_8580_effect_context *context =
        (rome2_headless_8580_effect_context *)opaque_context;
    uint32_t index = context->observed_steps;

    if (index >= ROME2_PORT_100E8580_STEP_COUNT ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc)) {
        ++context->bad_observations;
        return;
    }
    if (step.kind != rome2_headless_8580_steps[index].kind ||
        step.argument_count !=
            rome2_headless_8580_steps[index].argument_count ||
        step.argument0 != rome2_headless_8580_steps[index].argument0 ||
        step.argument1 != rome2_headless_8580_steps[index].argument1 ||
        step.argument2 != rome2_headless_8580_steps[index].argument2 ||
        step.has_guest_result !=
            rome2_headless_8580_steps[index].has_guest_result ||
        step.returned_guest_identity.value !=
            rome2_headless_8580_steps[index].returned_guest_identity.value) {
        ++context->bad_observations;
    }
    ++context->observed_steps;
}

static void rome2_headless_9340_emit(
    void *opaque_context,
    rome2_100e9340_step step)
{
    rome2_headless_9340_effect_context *context =
        (rome2_headless_9340_effect_context *)opaque_context;
    uint32_t index = context->observed_steps;
    int matches = 0;

    if (index >= ROME2_PORT_100E9340_STEP_COUNT ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc)) {
        ++context->bad_observations;
        return;
    }

    if (index == UINT32_C(0)) {
        matches =
            step.kind == ROME2_100E9340_STEP_LOOKUP_DWORD_12 &&
            step.argument_count == UINT32_C(1) &&
            step.argument0 == UINT32_C(0x12) &&
            step.argument1 == UINT32_C(0) &&
            step.argument2 == UINT32_C(0) &&
            step.result_width_bytes == UINT32_C(4) &&
            step.result_u32 == UINT32_C(0x89abcdef);
    } else if (index == UINT32_C(1)) {
        matches =
            step.kind == ROME2_100E9340_STEP_LOOKUP_BYTE_49 &&
            step.argument_count == UINT32_C(1) &&
            step.argument0 == UINT32_C(0x49) &&
            step.argument1 == UINT32_C(0) &&
            step.argument2 == UINT32_C(0) &&
            step.result_width_bytes == UINT32_C(1) &&
            step.result_u32 == UINT32_C(0xa5);
    } else if (index == UINT32_C(2)) {
        matches =
            step.kind == ROME2_100E9340_STEP_CALL_112E1830 &&
            step.argument_count == UINT32_C(0) &&
            step.argument0 == UINT32_C(0) &&
            step.argument1 == UINT32_C(0) &&
            step.argument2 == UINT32_C(0) &&
            step.result_width_bytes == UINT32_C(0) &&
            step.result_u32 == UINT32_C(0);
    } else {
        matches =
            step.kind == ROME2_100E9340_STEP_CALL_112CBBB0 &&
            step.argument_count == UINT32_C(3) &&
            step.argument0 == UINT32_C(0x89abcdef) &&
            step.argument1 ==
                ((context->expected_receiver & UINT32_C(0xffffff00)) |
                    UINT32_C(0xa5)) &&
            step.argument2 == UINT32_C(0) &&
            step.result_width_bytes == UINT32_C(0) &&
            step.result_u32 == UINT32_C(0);
    }
    if (!matches) {
        ++context->bad_observations;
    }
    ++context->observed_steps;
}

static void rome2_headless_92c0_emit(
    void *opaque_context,
    rome2_100e92c0_step step)
{
    rome2_headless_92c0_effect_context *context =
        (rome2_headless_92c0_effect_context *)opaque_context;
    uint32_t index = context->observed_steps;
    const rome2_100e92c0_step *expected;

    if (index >= ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc)) {
        ++context->bad_observations;
        return;
    }
    expected = &rome2_headless_92c0_steps[index];
    if (step.kind != expected->kind ||
        step.argument_count != expected->argument_count ||
        step.argument0 != expected->argument0 ||
        step.argument1 != expected->argument1 ||
        step.argument2 != expected->argument2 ||
        step.argument3 != expected->argument3 ||
        step.result_count != expected->result_count ||
        step.result0 != expected->result0 ||
        step.result1 != expected->result1 ||
        step.local_before0 != expected->local_before0 ||
        step.local_before1 != expected->local_before1 ||
        step.local_after0 != expected->local_after0 ||
        step.local_after1 != expected->local_after1) {
        ++context->bad_observations;
    }
    ++context->observed_steps;
}

static rome2_guest_addr32 rome2_headless_87a0_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_headless_87a0_effect_context *context =
        (rome2_headless_87a0_effect_context *)opaque_context;
    rome2_guest_addr32 result = {0};

    ++context->allocation_calls;
    ++context->effect_order;
    if (context->allocation_calls != UINT32_C(1) ||
        context->effect_order != UINT32_C(1) ||
        context->state_bytes == NULL ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc) ||
        byte_count != ROME2_PORT_100E87A0_LISTENER_BYTES ||
        allocation_class != ROME2_PORT_100E87A0_ALLOCATION_CLASS ||
        rome2_headless_get_u32(
            context->state_bytes, context->listener_offset) !=
            ROME2_HEADLESS_87A0_LISTENER_SENTINEL) {
        ++context->bad_observations;
    }
    result.value = context->listener_guest;
    return result;
}

static void rome2_headless_87a0_publish(
    void *opaque_context,
    rome2_guest_addr32 listener)
{
    rome2_headless_87a0_effect_context *context =
        (rome2_headless_87a0_effect_context *)opaque_context;

    ++context->publish_calls;
    ++context->effect_order;
    if (context->publish_calls != UINT32_C(1) ||
        context->allocation_calls != UINT32_C(1) ||
        context->effect_order != UINT32_C(2) ||
        context->state_bytes == NULL ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc) ||
        listener.value != context->listener_guest ||
        rome2_headless_get_u32(
            context->state_bytes, context->listener_offset) !=
            ROME2_PORT_100E87A0_LISTENER_VTABLE) {
        ++context->bad_observations;
    }
}

static void rome2_headless_87a0_startup(
    void *opaque_context,
    rome2_100e87a0_memory_policy policy,
    rome2_guest_addr32 listener,
    uint32_t log_level)
{
    rome2_headless_87a0_effect_context *context =
        (rome2_headless_87a0_effect_context *)opaque_context;

    ++context->startup_calls;
    ++context->effect_order;
    if (context->startup_calls != UINT32_C(1) ||
        context->publish_calls != UINT32_C(1) ||
        context->effect_order != UINT32_C(3) ||
        context->state_bytes == NULL ||
        context->return_al == NULL ||
        *context->return_al != UINT8_C(0xcc) ||
        listener.value != context->listener_guest ||
        log_level != ROME2_PORT_100E87A0_LOG_LEVEL ||
        policy.allocation_type != ROME2_PORT_100E87A0_POLICY_TYPE ||
        policy.track_allocations !=
            ROME2_PORT_100E87A0_POLICY_TRACK_ALLOCATIONS ||
        policy.allocate_identity !=
            ROME2_PORT_100E87A0_POLICY_ALLOCATE_IDENTITY ||
        policy.allocate_debug_identity !=
            ROME2_PORT_100E87A0_POLICY_ALLOCATE_DEBUG_IDENTITY ||
        policy.free_identity != ROME2_PORT_100E87A0_POLICY_FREE_IDENTITY ||
        rome2_headless_get_u32(
            context->state_bytes, context->listener_offset) !=
            ROME2_PORT_100E87A0_LISTENER_VTABLE) {
        ++context->bad_observations;
    }
}

static uint32_t rome2_headless_router_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_headless_router_effect_context *context =
        (rome2_headless_router_effect_context *)opaque_context;
    uint32_t append = context->current_append;
    uint32_t expected_backing = rome2_headless_router_guest(
        rome2_headless_router_backing_offsets[append]);
    rome2_guest_status handler_status;
    uint8_t handler_al = UINT8_C(0xcc);

    ++context->dispatch_calls;
    if (context->dispatch_calls != append + 1 ||
        rome2_headless_router_vector_cell(context, 4) !=
            rome2_headless_router_capacities[append] ||
        rome2_headless_router_vector_cell(context, 8) != append + 1 ||
        rome2_headless_router_vector_cell(context, 12) != expected_backing ||
        !rome2_headless_router_buffer_is_ordered(
            context, expected_backing, append + 1) ||
        receiver.value != context->handlers[append] ||
        method.value != rome2_headless_router_methods[append] ||
        argument.value != ROME2_HEADLESS_ROUTER_ARGUMENT) {
        ++context->bad_observations;
    }

    if (method.value == UINT32_C(0x100e8d00)) {
        ++context->handler_8d00_calls;
        context->handler_8d00_context.return_al = &handler_al;
        handler_status = rome2_port_100e8d00_run_handler_transcript(
            receiver,
            argument,
            &context->handler_8d00_effects,
            &handler_al);
        context->handler_8d00_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E8D00_AL ||
            context->handler_8d00_calls != 1) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e85d0)) {
        ++context->handler_85d0_calls;
        handler_status = rome2_port_100e85d0_normal_adapter(
            receiver, argument, &handler_al);
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E85D0_NORMAL_AL ||
            context->handler_85d0_calls != 1) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e8580)) {
        ++context->handler_8580_calls;
        context->handler_8580_context.return_al = &handler_al;
        handler_status = rome2_port_100e8580_run_handler_transcript(
            receiver,
            argument,
            &context->handler_8580_effects,
            &handler_al);
        context->handler_8580_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E8580_AL ||
            context->handler_8580_calls != 1) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e9340)) {
        ++context->handler_9340_calls;
        context->handler_9340_context.return_al = &handler_al;
        context->handler_9340_context.expected_receiver = receiver.value;
        handler_status = rome2_port_100e9340_run_handler_transcript(
            receiver,
            argument,
            &context->handler_9340_effects,
            &handler_al);
        context->handler_9340_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E9340_AL ||
            context->handler_9340_calls != 1 ||
            context->handler_9340_context.bad_observations != UINT32_C(0)) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e92c0)) {
        ++context->handler_92c0_calls;
        context->handler_92c0_context.return_al = &handler_al;
        handler_status = rome2_port_100e92c0_run_handler_transcript(
            receiver,
            argument,
            &context->handler_92c0_effects,
            &handler_al);
        context->handler_92c0_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E92C0_AL ||
            context->handler_92c0_calls != UINT32_C(1) ||
            context->handler_92c0_context.bad_observations != UINT32_C(0)) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e87a0)) {
        rome2_100e87a0_status handler_87a0_status;

        ++context->handler_87a0_calls;
        context->handler_87a0_context.return_al = &handler_al;
        handler_87a0_status = rome2_port_100e87a0_run_handler_transcript(
            context->state_view,
            receiver,
            argument,
            &context->handler_87a0_effects,
            &handler_al);
        context->handler_87a0_context.return_al = NULL;
        if (handler_87a0_status != ROME2_100E87A0_OK ||
            handler_al != ROME2_PORT_100E87A0_AL ||
            context->handler_87a0_calls != UINT32_C(1) ||
            context->handler_87a0_context.bad_observations != UINT32_C(0)) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    ++context->bad_observations;
    return UINT32_C(0);
}

static uint32_t rome2_headless_router_peek(
    void *opaque_context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    rome2_headless_router_effect_context *context =
        (rome2_headless_router_effect_context *)opaque_context;

    ++context->peek_calls;
    if (context->peek_calls != context->current_append + 1 ||
        context->dispatch_calls != context->peek_calls ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    return 0;
}

static void rome2_headless_router_initialize_buffer(
    uint8_t *state_bytes,
    uint32_t offset,
    uint32_t capacity)
{
    uint32_t index;

    for (index = 0; index < capacity; ++index) {
        rome2_headless_put_u32(
            state_bytes,
            (size_t)offset + (size_t)index * 4,
            ROME2_HEADLESS_ROUTER_SPARE);
    }
}

static uint32_t rome2_headless_outer_guest(uint32_t offset)
{
    return ROME2_HEADLESS_OUTER_STATE_GUEST_BASE + offset;
}

static uint32_t rome2_headless_outer_vector_cell(
    const rome2_headless_outer_effect_context *context,
    uint32_t cell_offset)
{
    return rome2_headless_get_u32(
        context->state_bytes,
        ROME2_HEADLESS_OUTER_VECTOR_OFFSET + cell_offset);
}

static int rome2_headless_outer_buffer_shape(
    uint32_t backing,
    uint32_t *offset_out,
    uint32_t *capacity_out)
{
    uint32_t offset;

    if (backing < ROME2_HEADLESS_OUTER_STATE_GUEST_BASE) {
        return 0;
    }
    offset = backing - ROME2_HEADLESS_OUTER_STATE_GUEST_BASE;
    switch (offset) {
    case ROME2_HEADLESS_OUTER_BUFFER_A_OFFSET:
        *offset_out = offset;
        *capacity_out = 1;
        return 1;
    case ROME2_HEADLESS_OUTER_BUFFER_B_OFFSET:
        *offset_out = offset;
        *capacity_out = 2;
        return 1;
    case ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET:
        *offset_out = offset;
        *capacity_out = 4;
        return 1;
    case ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET:
        *offset_out = offset;
        *capacity_out = 8;
        return 1;
    default:
        return 0;
    }
}

static int rome2_headless_outer_buffer_is_ordered(
    const rome2_headless_outer_effect_context *context,
    uint32_t backing,
    uint32_t populated_count)
{
    uint32_t offset;
    uint32_t capacity;
    uint32_t index;

    if (!rome2_headless_outer_buffer_shape(
            backing, &offset, &capacity) ||
        populated_count > capacity) {
        return 0;
    }
    for (index = 0; index < populated_count; ++index) {
        if (rome2_headless_get_u32(
                context->state_bytes,
                (size_t)offset + (size_t)index * 4) !=
            context->handlers[index]) {
            return 0;
        }
    }
    for (index = populated_count; index < capacity; ++index) {
        if (rome2_headless_get_u32(
                context->state_bytes,
                (size_t)offset + (size_t)index * 4) !=
            ROME2_HEADLESS_ROUTER_SPARE) {
            return 0;
        }
    }
    return 1;
}

static int rome2_headless_outer_prefix_is_exact(
    const rome2_headless_outer_effect_context *context,
    uint32_t completed)
{
    static const uint32_t capacities[
        ROME2_PORT_100EA4D0_REGISTRATION_COUNT + 1] = {
        0, 1, 2, 4, 4, 8, 8,
    };
    static const uint32_t backing_offsets[
        ROME2_PORT_100EA4D0_REGISTRATION_COUNT + 1] = {
        0,
        ROME2_HEADLESS_OUTER_BUFFER_A_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_B_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET,
        ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET,
    };
    uint32_t index;
    uint32_t backing;

    if (completed > ROME2_PORT_100EA4D0_REGISTRATION_COUNT ||
        rome2_headless_outer_vector_cell(context, 4) !=
            capacities[completed] ||
        rome2_headless_outer_vector_cell(context, 8) != completed) {
        return 0;
    }
    backing = rome2_headless_outer_vector_cell(context, 12);
    if (completed == 0) {
        if (backing != 0) {
            return 0;
        }
    } else if (
        backing != rome2_headless_outer_guest(backing_offsets[completed]) ||
        !rome2_headless_outer_buffer_is_ordered(
            context, backing, completed)) {
        return 0;
    }
    for (index = 0; index < completed; ++index) {
        uint32_t handler_offset =
            context->handlers[index] -
            ROME2_HEADLESS_OUTER_STATE_GUEST_BASE;

        if (rome2_headless_get_u32(
                context->state_bytes, handler_offset) !=
            rome2_headless_router_vtables[index]) {
            return 0;
        }
    }
    return 1;
}

static rome2_guest_addr32 rome2_headless_outer_allocate_handler(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    rome2_headless_outer_effect_context *context =
        (rome2_headless_outer_effect_context *)opaque_context;
    rome2_guest_addr32 result = {0};
    uint32_t index = context->handler_allocation_calls;

    if (index >= ROME2_PORT_100EA4D0_REGISTRATION_COUNT) {
        ++context->bad_observations;
        return result;
    }
    context->current_append = index;
    ++context->handler_allocation_calls;
    if (byte_count != ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_BYTES ||
        allocation_class != ROME2_PORT_100EA4D0_HANDLER_ALLOCATION_CLASS ||
        !rome2_headless_outer_prefix_is_exact(context, index)) {
        ++context->bad_observations;
    }
    result.value = context->handlers[index];
    return result;
}

static rome2_guest_addr32 rome2_headless_outer_allocate_backing(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    static const uint32_t allocation_appends[
        ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT] = {0, 1, 2, 4};
    rome2_headless_outer_effect_context *context =
        (rome2_headless_outer_effect_context *)opaque_context;
    rome2_guest_addr32 result = {0};
    uint32_t index = context->backing_allocation_calls;
    uint32_t expected_backing;

    if (index >= ROME2_HEADLESS_ROUTER_ALLOCATION_COUNT) {
        ++context->bad_observations;
        return result;
    }
    result.value = context->allocations[index];
    expected_backing = index == 0 ? 0 : context->allocations[index - 1];
    ++context->backing_allocation_calls;
    if (context->current_append != allocation_appends[index] ||
        byte_count != (UINT32_C(4) << index) ||
        allocation_class != ROME2_PORT_100E2460_GROWTH_ALLOCATION_CLASS ||
        rome2_headless_outer_vector_cell(context, 4) !=
            (UINT32_C(1) << index) ||
        rome2_headless_outer_vector_cell(context, 8) !=
            context->current_append ||
        rome2_headless_outer_vector_cell(context, 12) != expected_backing ||
        !rome2_headless_outer_buffer_is_ordered(
            context, result.value, 0)) {
        ++context->bad_observations;
    }
    return result;
}

static void rome2_headless_outer_release_backing(
    void *opaque_context,
    rome2_guest_addr32 allocation)
{
    static const uint32_t release_appends[3] = {1, 2, 4};
    rome2_headless_outer_effect_context *context =
        (rome2_headless_outer_effect_context *)opaque_context;
    uint32_t index = context->release_calls;
    uint32_t current_backing =
        rome2_headless_outer_vector_cell(context, 12);

    if (index >= 3) {
        ++context->bad_observations;
        return;
    }
    ++context->release_calls;
    if (context->current_append != release_appends[index] ||
        allocation.value != context->allocations[index] ||
        current_backing != context->allocations[index + 1] ||
        rome2_headless_outer_vector_cell(context, 4) !=
            rome2_headless_router_capacities[context->current_append] ||
        rome2_headless_outer_vector_cell(context, 8) !=
            context->current_append ||
        !rome2_headless_outer_buffer_is_ordered(
            context, current_backing, context->current_append + 1)) {
        ++context->bad_observations;
    }
}

static uint32_t rome2_headless_outer_dispatch(
    void *opaque_context,
    rome2_guest_addr32 receiver,
    rome2_guest_addr32 method,
    rome2_guest_addr32 argument)
{
    rome2_headless_outer_effect_context *context =
        (rome2_headless_outer_effect_context *)opaque_context;
    uint32_t append = context->current_append;
    uint32_t expected_backing = rome2_headless_outer_guest(
        rome2_headless_outer_backing_offsets[append]);
    rome2_guest_status handler_status;
    uint8_t handler_al = UINT8_C(0xcc);

    ++context->dispatch_calls;
    if (append >= ROME2_PORT_100EA4D0_REGISTRATION_COUNT ||
        context->dispatch_calls != append + 1 ||
        rome2_headless_outer_vector_cell(context, 4) !=
            rome2_headless_router_capacities[append] ||
        rome2_headless_outer_vector_cell(context, 8) != append + 1 ||
        rome2_headless_outer_vector_cell(context, 12) != expected_backing ||
        !rome2_headless_outer_buffer_is_ordered(
            context, expected_backing, append + 1) ||
        receiver.value != context->handlers[append] ||
        method.value != rome2_headless_router_methods[append] ||
        argument.value != ROME2_HEADLESS_OUTER_ARGUMENT) {
        ++context->bad_observations;
    }

    if (method.value == UINT32_C(0x100e8d00)) {
        ++context->handler_8d00_calls;
        context->handler_8d00_context.return_al = &handler_al;
        handler_status = rome2_port_100e8d00_run_handler_transcript(
            receiver,
            argument,
            &context->handler_8d00_effects,
            &handler_al);
        context->handler_8d00_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E8D00_AL ||
            context->handler_8d00_calls != 1) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e85d0)) {
        ++context->handler_85d0_calls;
        handler_status = rome2_port_100e85d0_normal_adapter(
            receiver, argument, &handler_al);
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E85D0_NORMAL_AL ||
            context->handler_85d0_calls != 1) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e8580)) {
        ++context->handler_8580_calls;
        context->handler_8580_context.return_al = &handler_al;
        handler_status = rome2_port_100e8580_run_handler_transcript(
            receiver,
            argument,
            &context->handler_8580_effects,
            &handler_al);
        context->handler_8580_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E8580_AL ||
            context->handler_8580_calls != 1) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e9340)) {
        ++context->handler_9340_calls;
        context->handler_9340_context.return_al = &handler_al;
        context->handler_9340_context.expected_receiver = receiver.value;
        handler_status = rome2_port_100e9340_run_handler_transcript(
            receiver,
            argument,
            &context->handler_9340_effects,
            &handler_al);
        context->handler_9340_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E9340_AL ||
            context->handler_9340_calls != 1 ||
            context->handler_9340_context.bad_observations != UINT32_C(0)) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e92c0)) {
        ++context->handler_92c0_calls;
        context->handler_92c0_context.return_al = &handler_al;
        handler_status = rome2_port_100e92c0_run_handler_transcript(
            receiver,
            argument,
            &context->handler_92c0_effects,
            &handler_al);
        context->handler_92c0_context.return_al = NULL;
        if (handler_status != ROME2_GUEST_OK ||
            handler_al != ROME2_PORT_100E92C0_AL ||
            context->handler_92c0_calls != UINT32_C(1) ||
            context->handler_92c0_context.bad_observations != UINT32_C(0)) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    if (method.value == UINT32_C(0x100e87a0)) {
        rome2_100e87a0_status handler_87a0_status;

        ++context->handler_87a0_calls;
        context->handler_87a0_context.return_al = &handler_al;
        handler_87a0_status = rome2_port_100e87a0_run_handler_transcript(
            context->state_view,
            receiver,
            argument,
            &context->handler_87a0_effects,
            &handler_al);
        context->handler_87a0_context.return_al = NULL;
        if (handler_87a0_status != ROME2_100E87A0_OK ||
            handler_al != ROME2_PORT_100E87A0_AL ||
            context->handler_87a0_calls != UINT32_C(1) ||
            context->handler_87a0_context.bad_observations != UINT32_C(0)) {
            ++context->bad_observations;
        }
        return handler_al;
    }
    ++context->bad_observations;
    return UINT32_C(0);
}

static uint32_t rome2_headless_outer_peek(
    void *opaque_context,
    rome2_guest_addr32 message,
    rome2_guest_addr32 window,
    uint32_t filter_min,
    uint32_t filter_max,
    uint32_t remove_flags)
{
    rome2_headless_outer_effect_context *context =
        (rome2_headless_outer_effect_context *)opaque_context;

    ++context->peek_calls;
    if (context->peek_calls != context->current_append + 1 ||
        context->dispatch_calls != context->peek_calls ||
        message.value != 0 || window.value != 0 || filter_min != 0 ||
        filter_max != 0 ||
        remove_flags != ROME2_PORT_100E2460_PM_REMOVE) {
        ++context->bad_observations;
    }
    return 0;
}

int main(void)
{
    rome2_guest_addr32 append_count_cell;
    rome2_guest_addr32 append_count_value;
    rome2_guest_addr32 append_element;
    rome2_guest_addr32 append_slot_cell;
    rome2_guest_addr32 append_slot_value;
    rome2_guest_addr32 append_vector;
    rome2_guest_addr32 command_line;
    rome2_guest_addr32 destination;
    rome2_guest_addr32 payload_cell;
    rome2_guest_addr32 payload_value;
    rome2_guest_addr32 fastpath_index_cell;
    rome2_guest_addr32 fastpath_record;
    rome2_guest_addr32 fastpath_tls_vector;
    rome2_guest_addr32 fastpath_threshold_cell;
    rome2_guest_read_view fastpath_view;
    rome2_guest_write_view branch_state_view;
    rome2_guest_read_view branch_vtable_view;
    rome2_100e2460_effects branch_effects;
    rome2_100e2460_branch_status branch_status;
    rome2_guest_write_view zero_state_view;
    rome2_100e2460_capacity_zero_effects zero_effects;
    rome2_100e2460_branch_status zero_status;
    rome2_guest_write_view growth_state_view;
    rome2_100e2460_growth_effects growth_effects;
    rome2_100e2460_branch_status growth_status;
    rome2_guest_write_view router_state_view;
    rome2_100e2460_growth_effects router_effects;
    rome2_100e2460_branch_status router_status;
    rome2_guest_write_view outer_state_view;
    rome2_100ea4d0_effects outer_effects;
    rome2_100ea4d0_status outer_status;
    rome2_guest_write_view preloop_frame_view;
    rome2_guest_read_view preloop_text_view;
    rome2_guest_write_view preloop_selector_view;
    rome2_100ed3c0_preloop_effects preloop_effects;
    rome2_100ed3c0_preloop_result preloop_result;
    rome2_guest_read_view lifecycle_dispatch_view;
    rome2_100ed471_lifecycle_effects lifecycle_effects;
    rome2_100ed471_lifecycle_result lifecycle_result;
    rome2_guest_addr32 returned_destination;
    rome2_guest_addr32 short_copy_count;
    rome2_guest_addr32 short_copy_return;
    rome2_guest_addr32 source;
    rome2_guest_read_view read_view;
    rome2_guest_status status;
    rome2_guest_write_view write_view;
    rome2_headless_fastpath_memory fastpath_memory;
    rome2_headless_branch_state_memory branch_state_memory;
    rome2_headless_branch_vtable_memory branch_vtable_memory;
    rome2_headless_branch_effect_context branch_effect_context;
    rome2_headless_zero_state_memory zero_state_memory;
    rome2_headless_zero_effect_context zero_effect_context;
    rome2_headless_growth_state_memory growth_state_memory;
    rome2_headless_growth_effect_context growth_effect_context;
    rome2_headless_router_state_memory router_state_memory;
    rome2_headless_router_effect_context router_effect_context;
    rome2_headless_outer_state_memory outer_state_memory;
    rome2_headless_outer_effect_context outer_effect_context;
    rome2_headless_preloop_frame_memory preloop_frame_memory;
    rome2_headless_preloop_text_memory preloop_text_memory;
    rome2_headless_preloop_selector_memory preloop_selector_memory;
    rome2_headless_preloop_trace preloop_trace;
    rome2_headless_preloop_parent_context preloop_parent_context;
    rome2_headless_preloop_prefix_context preloop_prefix_context;
    rome2_headless_preloop_suffix_context preloop_suffix_context;
    rome2_headless_lifecycle_dispatch_memory lifecycle_dispatch_memory;
    rome2_headless_lifecycle_trace lifecycle_trace;
    rome2_headless_memory memory;
    rome2_headless_startup_memory startup_memory;
    rome2_invalid_parameter_policy policy = UINT32_C(0xffffffff);
    uint32_t utf16_length = UINT32_MAX;
    uint32_t router_append;
    uint8_t branch_return_al = UINT8_C(0xcc);
    uint8_t zero_return_al = UINT8_C(0xcc);
    uint8_t growth_return_al = UINT8_C(0xcc);
    uint8_t router_return_al = UINT8_C(0xcc);

    memset(memory.bytes, 0xa5, sizeof(memory.bytes));
    memcpy(memory.bytes, rome2_headless_command_line,
        sizeof(rome2_headless_command_line));

    /* The admitted 0x100f1aa0 route requires a zero count in the first
     * source cell.  The remaining eight source bytes are deliberately opaque. */
    memset(memory.bytes + ROME2_HEADLESS_SOURCE_OFFSET, 0, 4);

    command_line.value = ROME2_HEADLESS_GUEST_BASE;
    source.value = ROME2_HEADLESS_GUEST_BASE + ROME2_HEADLESS_SOURCE_OFFSET;
    destination.value =
        ROME2_HEADLESS_GUEST_BASE + ROME2_HEADLESS_DESTINATION_OFFSET;
    returned_destination.value = UINT32_C(0xcccccccc);
    payload_value.value = UINT32_C(0xcccccccc);

    read_view.host_base = memory.bytes;
    read_view.guest_base = ROME2_HEADLESS_GUEST_BASE;
    read_view.byte_count = sizeof(rome2_headless_command_line);
    status = rome2_port_100edd70_select_invalid_parameter_policy(
        &read_view, command_line, &policy);
    if (status != ROME2_GUEST_OK ||
        policy != ROME2_INVALID_PARAMETER_SKIP_HANDLER) {
        fprintf(stderr,
            "rome2_headless64: entry-policy stage failed: status=%d policy=%lu\n",
            (int)status, (unsigned long)policy);
        return 10;
    }

    status = rome2_port_100f1bb0_measure_utf16(
        &read_view, command_line, 22, &utf16_length);
    if (status != ROME2_GUEST_OK || utf16_length != 21) {
        fprintf(stderr,
            "rome2_headless64: bounded UTF-16 stage failed: status=%d length=%lu\n",
            (int)status, (unsigned long)utf16_length);
        return 15;
    }

    write_view.host_base = memory.bytes;
    write_view.guest_base = ROME2_HEADLESS_GUEST_BASE;
    write_view.byte_count = sizeof(memory.bytes);
    status = rome2_port_100f1aa0_copy_empty_source(
        &write_view, destination, source, &returned_destination);
    if (status != ROME2_GUEST_OK ||
        returned_destination.value != destination.value ||
        memcmp(memory.bytes + ROME2_HEADLESS_DESTINATION_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0) {
        fprintf(stderr,
            "rome2_headless64: bounded startup stage failed: status=%d return=0x%08lx\n",
            (int)status, (unsigned long)returned_destination.value);
        return 20;
    }

    read_view.host_base = memory.bytes;
    read_view.guest_base = ROME2_HEADLESS_GUEST_BASE;
    read_view.byte_count = sizeof(memory.bytes);
    status = rome2_guest_add_checked(destination, UINT32_C(8), &payload_cell);
    if (status == ROME2_GUEST_OK) {
        status = rome2_guest_read_addr32_le(
            &read_view, payload_cell, &payload_value);
    }
    if (status == ROME2_GUEST_OK) {
        status = rome2_port_100f1cc0_accept_nonowning_noop(payload_value);
    }
    if (status != ROME2_GUEST_OK ||
        payload_value.value != ROME2_PORT_100F1CC0_SENTINEL) {
        fprintf(stderr,
            "rome2_headless64: nonowning cleanup stage failed: status=%d value=0x%08lx\n",
            (int)status, (unsigned long)payload_value.value);
        return 25;
    }

    rome2_headless_put_u32(
        memory.bytes, ROME2_HEADLESS_DESTINATION_OFFSET,
        UINT32_C(0xdddddddd));
    rome2_headless_put_u32(
        memory.bytes, ROME2_HEADLESS_DESTINATION_OFFSET + 4, UINT32_C(4));
    rome2_headless_put_u32(
        memory.bytes, ROME2_HEADLESS_DESTINATION_OFFSET + 8,
        ROME2_HEADLESS_GUEST_BASE +
            ROME2_HEADLESS_SHORT_DESTINATION_PAYLOAD_OFFSET);
    rome2_headless_put_u32(
        memory.bytes, ROME2_HEADLESS_SOURCE_OFFSET, UINT32_C(4));
    rome2_headless_put_u32(
        memory.bytes, ROME2_HEADLESS_SOURCE_OFFSET + 4,
        UINT32_C(0xeeeeeeee));
    rome2_headless_put_u32(
        memory.bytes, ROME2_HEADLESS_SOURCE_OFFSET + 8,
        ROME2_HEADLESS_GUEST_BASE + ROME2_HEADLESS_SHORT_SOURCE_PAYLOAD_OFFSET);
    memcpy(
        memory.bytes + ROME2_HEADLESS_SHORT_SOURCE_PAYLOAD_OFFSET,
        rome2_headless_short_payload,
        sizeof(rome2_headless_short_payload));
    memset(
        memory.bytes + ROME2_HEADLESS_SHORT_DESTINATION_PAYLOAD_OFFSET,
        0xa5,
        sizeof(rome2_headless_short_payload));
    short_copy_return.value = UINT32_C(0xcccccccc);
    status = rome2_port_100f2750_copy_nonallocating_short(
        &write_view, destination, source, 5, &short_copy_return);
    read_view.host_base = memory.bytes;
    read_view.guest_base = ROME2_HEADLESS_GUEST_BASE;
    read_view.byte_count = sizeof(memory.bytes);
    short_copy_count.value = UINT32_C(0xcccccccc);
    if (status == ROME2_GUEST_OK) {
        status = rome2_guest_read_addr32_le(
            &read_view, destination, &short_copy_count);
    }
    if (status != ROME2_GUEST_OK ||
        short_copy_return.value != destination.value ||
        short_copy_count.value != 4 ||
        memcmp(
            memory.bytes + ROME2_HEADLESS_SHORT_DESTINATION_PAYLOAD_OFFSET,
            rome2_headless_short_payload,
            sizeof(rome2_headless_short_payload)) != 0) {
        fprintf(stderr,
            "rome2_headless64: short nonallocating copy failed: status=%d return=0x%08lx\n",
            (int)status, (unsigned long)short_copy_return.value);
        return 28;
    }

    /* Compose the authenticated empty-input interval [0x100ed3c0,
     * 0x100ed471) over one exact local frame.  All platform/global/indirect
     * effects remain typed observations; the nested child executes its
     * admitted seven-step prefix, deterministic middle, and eleven-step
     * mismatch suffix exactly once inside the parent adapter. */
    memset(
        preloop_frame_memory.bytes,
        ROME2_HEADLESS_PRELOOP_INITIAL_BYTE,
        sizeof(preloop_frame_memory.bytes));
    memset(preloop_text_memory.bytes, 0, sizeof(preloop_text_memory.bytes));
    memset(preloop_selector_memory.bytes, 0xc9,
        sizeof(preloop_selector_memory.bytes));
    rome2_headless_put_u32(
        preloop_selector_memory.bytes,
        ROME2_HEADLESS_SUFFIX_FIRST_RESULT_OFFSET,
        ROME2_HEADLESS_SUFFIX_FIRST_VALUE);
    rome2_headless_put_u32(
        preloop_selector_memory.bytes,
        ROME2_HEADLESS_SUFFIX_SECOND_RESULT_OFFSET,
        ROME2_HEADLESS_SUFFIX_SECOND_SENTINEL);

    preloop_frame_view.host_base = preloop_frame_memory.bytes;
    preloop_frame_view.guest_base =
        ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE;
    preloop_frame_view.byte_count =
        ROME2_PORT_100ED3C0_PRELOOP_FRAME_BYTES;
    preloop_text_view.host_base = preloop_text_memory.bytes;
    preloop_text_view.guest_base = ROME2_HEADLESS_PRELOOP_TEXT_GUEST_BASE;
    preloop_text_view.byte_count = sizeof(preloop_text_memory.bytes);
    preloop_selector_view.host_base = preloop_selector_memory.bytes;
    preloop_selector_view.guest_base =
        ROME2_HEADLESS_SUFFIX_STATE_GUEST_BASE;
    preloop_selector_view.byte_count = sizeof(preloop_selector_memory.bytes);

    memset(&preloop_trace, 0, sizeof(preloop_trace));
    memset(&preloop_effects, 0, sizeof(preloop_effects));
    preloop_trace.frame_bytes = preloop_frame_memory.bytes;
    preloop_trace.selector_bytes = preloop_selector_memory.bytes;
    preloop_trace.result = &preloop_result;
    preloop_parent_context.trace = &preloop_trace;
    preloop_prefix_context.trace = &preloop_trace;
    preloop_suffix_context.trace = &preloop_trace;
    preloop_effects.emit_step = rome2_headless_preloop_parent_emit;
    preloop_effects.context = &preloop_parent_context;
    preloop_effects.child_prefix.emit_step =
        rome2_headless_preloop_prefix_emit;
    preloop_effects.child_prefix.context = &preloop_prefix_context;
    preloop_effects.child_prefix.created_mutex = ROME2_HEADLESS_PREFIX_MUTEX;
    preloop_effects.child_prefix.last_error = UINT32_C(0);
    preloop_effects.child_suffix.emit_step =
        rome2_headless_preloop_suffix_emit;
    preloop_effects.child_suffix.context = &preloop_suffix_context;
    preloop_effects.child_suffix.result_100e8240.value =
        ROME2_PORT_100DF270_SUFFIX_CRASH_RECORD;
    preloop_effects.child_suffix.first_selector_result.value =
        ROME2_HEADLESS_SUFFIX_FIRST_RESULT;
    preloop_effects.child_suffix.second_selector_result.value =
        ROME2_HEADLESS_SUFFIX_SECOND_RESULT;
    preloop_result.child_receiver.value =
        ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL;
    preloop_result.child_packet.value =
        ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL;
    preloop_result.child_argument.value =
        ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL;
    preloop_result.next_original_pc =
        ROME2_HEADLESS_PRELOOP_RESULT_SENTINEL;

    status = rome2_port_100ed3c0_run_empty_preloop(
        &preloop_frame_view,
        (rome2_guest_addr32){ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE},
        ROME2_HEADLESS_PRELOOP_ARGUMENT1,
        &preloop_text_view,
        (rome2_guest_addr32){ROME2_HEADLESS_PRELOOP_TEXT_GUEST_BASE},
        ROME2_PORT_100ED3C0_PRELOOP_TEXT_UNITS,
        &preloop_selector_view,
        &preloop_effects,
        &preloop_result);
    if (status != ROME2_GUEST_OK ||
        preloop_trace.parent_steps !=
            ROME2_PORT_100ED3C0_PRELOOP_STEP_COUNT ||
        preloop_trace.prefix_steps !=
            ROME2_PORT_100DF270_PREFIX_NORMAL_STEP_COUNT ||
        preloop_trace.suffix_steps !=
            ROME2_PORT_100DF270_SUFFIX_MISMATCH_STEP_COUNT ||
        preloop_trace.bad_observations != UINT32_C(0) ||
        preloop_result.child_receiver.value !=
            ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE +
                ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET ||
        preloop_result.child_packet.value !=
            ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE +
                ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET ||
        preloop_result.child_argument.value !=
            ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE +
                ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET ||
        preloop_result.next_original_pc !=
            ROME2_PORT_100ED3C0_PRELOOP_NEXT_PC ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_ZERO_OFFSET) != UINT32_C(0) ||
        memcmp(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_TRIPLET0_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_TRIPLET1_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_DESCRIPTOR_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_COPY0_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        memcmp(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_COPY1_OFFSET,
            rome2_headless_empty_triplet,
            sizeof(rome2_headless_empty_triplet)) != 0 ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_ARGUMENT_COPY_OFFSET) !=
                ROME2_HEADLESS_PRELOOP_ARGUMENT1 ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET) !=
                ROME2_HEADLESS_PRELOOP_ARGUMENT1 ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_OFFSET + UINT32_C(4)) !=
                UINT32_C(0) ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_ARGUMENT_OFFSET) !=
                ROME2_HEADLESS_PRELOOP_ARGUMENT1 ||
        preloop_frame_memory.bytes[
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET] != UINT8_C(0) ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_DWORD_OFFSET) != UINT32_C(0) ||
        preloop_frame_memory.bytes[
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET] != UINT8_C(0) ||
        !rome2_headless_bytes_are(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_ZERO_BYTE_OFFSET + UINT32_C(1),
            UINT32_C(3), ROME2_HEADLESS_PRELOOP_INITIAL_BYTE) ||
        !rome2_headless_bytes_are(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_BYTE_OFFSET + UINT32_C(1),
            UINT32_C(3), ROME2_HEADLESS_PRELOOP_INITIAL_BYTE) ||
        !rome2_headless_bytes_are(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED3C0_PRELOOP_PACKET_FLAG_OFFSET + UINT32_C(1),
            UINT32_C(3), ROME2_HEADLESS_PRELOOP_INITIAL_BYTE) ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
            UINT32_C(0)) != UINT32_C(0x1173f2f4) ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
            ROME2_PORT_100DF270_PREFIX_INSTANCE_OFFSET) !=
                ROME2_HEADLESS_PRELOOP_ARGUMENT1 ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
            ROME2_PORT_100DF270_PREFIX_MUTEX_OFFSET) !=
                ROME2_HEADLESS_PREFIX_MUTEX ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
            UINT32_C(0x854)) != preloop_result.child_receiver.value ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes +
                ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
            ROME2_PORT_100DF270_SUFFIX_OWNER_OFFSET) !=
                ROME2_PORT_100DF270_SUFFIX_OWNER_VTABLE ||
        rome2_headless_get_u32(
            preloop_selector_memory.bytes,
            ROME2_HEADLESS_SUFFIX_FIRST_RESULT_OFFSET) !=
                ROME2_HEADLESS_SUFFIX_FIRST_VALUE ||
        rome2_headless_get_u32(
            preloop_selector_memory.bytes,
            ROME2_HEADLESS_SUFFIX_SECOND_RESULT_OFFSET) !=
                ROME2_PORT_100DF270_SUFFIX_FINAL_MARKER ||
        preloop_text_memory.bytes[0] != UINT8_C(0) ||
        preloop_text_memory.bytes[1] != UINT8_C(0)) {
        fprintf(stderr,
            "rome2_headless64: 100ed3c0 empty preloop failed: status=%d parent=%lu prefix=%lu suffix=%lu observations=%lu next=0x%08lx\n",
            (int)status,
            (unsigned long)preloop_trace.parent_steps,
            (unsigned long)preloop_trace.prefix_steps,
            (unsigned long)preloop_trace.suffix_steps,
            (unsigned long)preloop_trace.bad_observations,
            (unsigned long)preloop_result.next_original_pc);
        return 50;
    }

    /* Continue the authenticated ordinary-domain tail [0x100ed471,
     * 0x100ed550) over the exact frame produced above.  The finite poll
     * transcript is prevalidated as 0,0,2; every original direct/indirect
     * effect remains a typed by-value observation. */
    memset(
        lifecycle_dispatch_memory.bytes,
        0xa5,
        sizeof(lifecycle_dispatch_memory.bytes));
    rome2_headless_put_u32(
        lifecycle_dispatch_memory.bytes,
        ROME2_HEADLESS_LIFECYCLE_RECEIVER_OFFSET,
        ROME2_PORT_100ED471_LOCAL_VTABLE);
    rome2_headless_put_u32(
        lifecycle_dispatch_memory.bytes,
        ROME2_PORT_100ED471_LOCAL_VTABLE -
            ROME2_HEADLESS_LIFECYCLE_DISPATCH_GUEST_BASE +
            ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET,
        ROME2_PORT_100ED471_LOCAL_METHOD);
    lifecycle_dispatch_view.host_base = lifecycle_dispatch_memory.bytes;
    lifecycle_dispatch_view.guest_base =
        ROME2_HEADLESS_LIFECYCLE_DISPATCH_GUEST_BASE;
    lifecycle_dispatch_view.byte_count =
        sizeof(lifecycle_dispatch_memory.bytes);

    memset(&lifecycle_trace, 0, sizeof(lifecycle_trace));
    memset(&lifecycle_effects, 0, sizeof(lifecycle_effects));
    memset(
        &lifecycle_result,
        (int)(ROME2_HEADLESS_LIFECYCLE_RESULT_SENTINEL & UINT32_C(0xff)),
        sizeof(lifecycle_result));
    lifecycle_trace.frame_bytes = preloop_frame_memory.bytes;
    lifecycle_trace.result = &lifecycle_result;
    lifecycle_trace.timestamp_before_low = rome2_headless_get_u32(
        preloop_frame_memory.bytes,
        ROME2_PORT_100ED471_TIMESTAMP_OFFSET);
    lifecycle_trace.timestamp_before_high = rome2_headless_get_u32(
        preloop_frame_memory.bytes,
        ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4));
    lifecycle_trace.timestamp_copy_before_low = rome2_headless_get_u32(
        preloop_frame_memory.bytes,
        ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET);
    lifecycle_trace.timestamp_copy_before_high = rome2_headless_get_u32(
        preloop_frame_memory.bytes,
        ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4));
    lifecycle_effects.emit_step = rome2_headless_lifecycle_emit;
    lifecycle_effects.context = &lifecycle_trace;
    lifecycle_effects.timestamp_low =
        ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW;
    lifecycle_effects.timestamp_high =
        ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH;
    lifecycle_effects.poll_result_count =
        ROME2_HEADLESS_LIFECYCLE_POLL_COUNT;
    lifecycle_effects.poll_results[0] = UINT32_C(0);
    lifecycle_effects.poll_results[1] = UINT32_C(0);
    lifecycle_effects.poll_results[2] = UINT32_C(2);

    status = rome2_port_100ed471_run_ordinary_lifecycle(
        &preloop_frame_view,
        (rome2_guest_addr32){ROME2_HEADLESS_PRELOOP_FRAME_GUEST_BASE},
        &lifecycle_dispatch_view,
        (rome2_guest_addr32){ROME2_HEADLESS_LIFECYCLE_RECEIVER},
        ROME2_HEADLESS_LIFECYCLE_POLL_COUNT,
        &lifecycle_effects,
        &lifecycle_result);
    if (status != ROME2_GUEST_OK ||
        lifecycle_trace.steps != ROME2_HEADLESS_LIFECYCLE_STEP_COUNT ||
        lifecycle_trace.bad_observations != UINT32_C(0) ||
        lifecycle_result.dispatch_receiver.value !=
            ROME2_HEADLESS_LIFECYCLE_RECEIVER ||
        lifecycle_result.dispatch_vtable.value !=
            ROME2_PORT_100ED471_LOCAL_VTABLE ||
        lifecycle_result.dispatch_target.value !=
            ROME2_PORT_100ED471_LOCAL_METHOD ||
        lifecycle_result.poll_calls !=
            ROME2_HEADLESS_LIFECYCLE_POLL_COUNT ||
        lifecycle_result.terminal_poll_result != UINT32_C(2) ||
        lifecycle_result.timestamp_low !=
            ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW ||
        lifecycle_result.timestamp_high !=
            ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH ||
        lifecycle_result.return_original_pc !=
            ROME2_PORT_100ED471_RETURN_PC ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED471_TIMESTAMP_OFFSET) !=
                ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED471_TIMESTAMP_OFFSET + UINT32_C(4)) !=
                ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET) !=
                ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_LOW ||
        rome2_headless_get_u32(
            preloop_frame_memory.bytes,
            ROME2_PORT_100ED471_TIMESTAMP_COPY_OFFSET + UINT32_C(4)) !=
                ROME2_HEADLESS_LIFECYCLE_TIMESTAMP_HIGH ||
        rome2_headless_get_u32(
            lifecycle_dispatch_memory.bytes,
            ROME2_HEADLESS_LIFECYCLE_RECEIVER_OFFSET) !=
                ROME2_PORT_100ED471_LOCAL_VTABLE ||
        rome2_headless_get_u32(
            lifecycle_dispatch_memory.bytes,
            ROME2_PORT_100ED471_LOCAL_VTABLE -
                ROME2_HEADLESS_LIFECYCLE_DISPATCH_GUEST_BASE +
                ROME2_PORT_100ED471_DISPATCH_SLOT_OFFSET) !=
                    ROME2_PORT_100ED471_LOCAL_METHOD) {
        fprintf(stderr,
            "rome2_headless64: 100ed471 ordinary lifecycle failed: status=%d steps=%lu observations=%lu polls=%lu return=0x%08lx\n",
            (int)status,
            (unsigned long)lifecycle_trace.steps,
            (unsigned long)lifecycle_trace.bad_observations,
            (unsigned long)lifecycle_result.poll_calls,
            (unsigned long)lifecycle_result.return_original_pc);
        return 52;
    }

    /* Continue exercising the older registry slices over an independent
     * legacy-base copy of the now-composed child receiver. */
    memset(startup_memory.bytes, 0xa5, sizeof(startup_memory.bytes));
    memcpy(
        startup_memory.bytes,
        preloop_frame_memory.bytes +
            ROME2_PORT_100ED3C0_PRELOOP_RECEIVER_OFFSET,
        ROME2_PORT_100DF270_OBJECT_BYTES);
    write_view.host_base = startup_memory.bytes;
    write_view.guest_base = ROME2_HEADLESS_STARTUP_GUEST_BASE;
    write_view.byte_count = sizeof(startup_memory.bytes);
    read_view.host_base = startup_memory.bytes;
    read_view.guest_base = ROME2_HEADLESS_STARTUP_GUEST_BASE;
    read_view.byte_count = sizeof(startup_memory.bytes);

    /* Bounded no-crash fast path of original 0x100e8240.  The TLS index is
     * zero, and the injected FS:[0x2c] TLS-vector base selects a slot that
     * points at a TLS data cell whose +4 value (1) is not below the zero
     * threshold.  The admitted read-only branch therefore returns the
     * crash-record identity 0x119f3a38 without any write. */
    memset(fastpath_memory.bytes, 0xa5, sizeof(fastpath_memory.bytes));
    rome2_headless_put_u32(
        fastpath_memory.bytes, ROME2_HEADLESS_FASTPATH_INDEX_OFFSET, 0);
    rome2_headless_put_u32(
        fastpath_memory.bytes, ROME2_HEADLESS_FASTPATH_THRESHOLD_OFFSET, 0);
    rome2_headless_put_u32(
        fastpath_memory.bytes, ROME2_HEADLESS_FASTPATH_TLS_VECTOR_OFFSET,
        ROME2_HEADLESS_FASTPATH_GUEST_BASE +
            ROME2_HEADLESS_FASTPATH_TLS_DATA_OFFSET);
    rome2_headless_put_u32(
        fastpath_memory.bytes, ROME2_HEADLESS_FASTPATH_TLS_VALUE_OFFSET, 1);

    fastpath_view.host_base = fastpath_memory.bytes;
    fastpath_view.guest_base = ROME2_HEADLESS_FASTPATH_GUEST_BASE;
    fastpath_view.byte_count = sizeof(fastpath_memory.bytes);
    fastpath_tls_vector.value = ROME2_HEADLESS_FASTPATH_GUEST_BASE +
        ROME2_HEADLESS_FASTPATH_TLS_VECTOR_OFFSET;
    fastpath_index_cell.value = ROME2_HEADLESS_FASTPATH_GUEST_BASE +
        ROME2_HEADLESS_FASTPATH_INDEX_OFFSET;
    fastpath_threshold_cell.value = ROME2_HEADLESS_FASTPATH_GUEST_BASE +
        ROME2_HEADLESS_FASTPATH_THRESHOLD_OFFSET;
    fastpath_record.value = UINT32_C(0xcccccccc);
    status = rome2_port_100e8240_crash_record_fastpath(
        &fastpath_view,
        fastpath_tls_vector,
        fastpath_index_cell,
        fastpath_threshold_cell,
        &fastpath_record);
    if (status != ROME2_GUEST_OK ||
        fastpath_record.value != UINT32_C(0x119f3a38)) {
        fprintf(stderr,
            "rome2_headless64: crash-record fast path failed: status=%d record=0x%08lx\n",
            (int)status, (unsigned long)fastpath_record.value);
        return 32;
    }

    /* Seed a synthetic already-preallocated registry state adjacent to the
     * authenticated 0x100df270 projection.  The appended opaque value is
     * handler B's guest address.  This admits only the fourth/sixth
     * style no-growth append prefix; it does not model the earlier allocator
     * calls, invoke the handler vtable, or drain the Windows message queue. */
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_VECTOR_OFFSET + 4, 2);
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_VECTOR_OFFSET + 8, 1);
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_VECTOR_OFFSET + 12,
        ROME2_HEADLESS_STARTUP_GUEST_BASE +
            ROME2_HEADLESS_APPEND_BACKING_OFFSET);
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_HANDLER_A_OFFSET,
        UINT32_C(0x1173f20c));
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_HANDLER_B_OFFSET,
        UINT32_C(0x1173f224));
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_BACKING_OFFSET,
        ROME2_HEADLESS_STARTUP_GUEST_BASE +
            ROME2_HEADLESS_APPEND_HANDLER_A_OFFSET);
    rome2_headless_put_u32(
        startup_memory.bytes, ROME2_HEADLESS_APPEND_BACKING_OFFSET + 4,
        UINT32_C(0xcccccccc));

    append_vector.value = ROME2_HEADLESS_STARTUP_GUEST_BASE +
        ROME2_HEADLESS_APPEND_VECTOR_OFFSET;
    append_element.value = ROME2_HEADLESS_STARTUP_GUEST_BASE +
        ROME2_HEADLESS_APPEND_HANDLER_B_OFFSET;
    status = rome2_port_100e2460_append_preallocated_prefix(
        &write_view, append_vector, append_element);
    append_count_value.value = UINT32_C(0xcccccccc);
    append_slot_value.value = UINT32_C(0xcccccccc);
    append_count_cell.value = append_vector.value + UINT32_C(8);
    append_slot_cell.value = ROME2_HEADLESS_STARTUP_GUEST_BASE +
        ROME2_HEADLESS_APPEND_BACKING_OFFSET + UINT32_C(4);
    if (status == ROME2_GUEST_OK) {
        status = rome2_guest_read_addr32_le(
            &read_view, append_count_cell, &append_count_value);
    }
    if (status == ROME2_GUEST_OK) {
        status = rome2_guest_read_addr32_le(
            &read_view, append_slot_cell, &append_slot_value);
    }
    if (status != ROME2_GUEST_OK || append_count_value.value != 2 ||
        append_slot_value.value != append_element.value) {
        fprintf(stderr,
            "rome2_headless64: append prefix failed: status=%d count=%lu slot=0x%08lx\n",
            (int)status,
            (unsigned long)append_count_value.value,
            (unsigned long)append_slot_value.value);
        return 34;
    }

    /* Execute the complete preallocated branch in a distinct synthetic guest
     * state.  The total adapters model, but do not perform, the original
     * indirect guest dispatch and native PeekMessageW effects.  Dispatch must
     * observe the committed count/slot, and the bounded queue returns true
     * once before the terminating false probe publishes the saved low AL. */
    memset(branch_state_memory.bytes, 0xa5,
        sizeof(branch_state_memory.bytes));
    memset(branch_vtable_memory.bytes, 0xa5,
        sizeof(branch_vtable_memory.bytes));
    memset(&branch_effect_context, 0, sizeof(branch_effect_context));
    rome2_headless_put_u32(
        branch_state_memory.bytes,
        ROME2_HEADLESS_BRANCH_VECTOR_OFFSET + 4,
        UINT32_C(2));
    rome2_headless_put_u32(
        branch_state_memory.bytes,
        ROME2_HEADLESS_BRANCH_VECTOR_OFFSET + 8,
        UINT32_C(1));
    rome2_headless_put_u32(
        branch_state_memory.bytes,
        ROME2_HEADLESS_BRANCH_VECTOR_OFFSET + 12,
        ROME2_HEADLESS_BRANCH_STATE_GUEST_BASE +
            ROME2_HEADLESS_BRANCH_BACKING_OFFSET);
    rome2_headless_put_u32(
        branch_state_memory.bytes,
        ROME2_HEADLESS_BRANCH_HANDLER_OFFSET,
        ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE +
            ROME2_HEADLESS_BRANCH_VTABLE_OFFSET);
    rome2_headless_put_u32(
        branch_state_memory.bytes,
        ROME2_HEADLESS_BRANCH_BACKING_OFFSET,
        UINT32_C(0x41414141));
    rome2_headless_put_u32(
        branch_state_memory.bytes,
        ROME2_HEADLESS_BRANCH_BACKING_OFFSET + 4,
        UINT32_C(0xcccccccc));
    rome2_headless_put_u32(
        branch_vtable_memory.bytes,
        ROME2_HEADLESS_BRANCH_VTABLE_OFFSET + 4,
        ROME2_HEADLESS_BRANCH_METHOD_IDENTITY);

    branch_state_view.host_base = branch_state_memory.bytes;
    branch_state_view.guest_base = ROME2_HEADLESS_BRANCH_STATE_GUEST_BASE;
    branch_state_view.byte_count = sizeof(branch_state_memory.bytes);
    branch_vtable_view.host_base = branch_vtable_memory.bytes;
    branch_vtable_view.guest_base = ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE;
    branch_vtable_view.byte_count = sizeof(branch_vtable_memory.bytes);
    branch_effect_context.state_bytes = branch_state_memory.bytes;
    branch_effect_context.expected_receiver =
        ROME2_HEADLESS_BRANCH_STATE_GUEST_BASE +
        ROME2_HEADLESS_BRANCH_HANDLER_OFFSET;
    branch_effect_context.expected_method =
        ROME2_HEADLESS_BRANCH_METHOD_IDENTITY;
    branch_effect_context.expected_argument = ROME2_HEADLESS_BRANCH_ARGUMENT;
    branch_effects.context = &branch_effect_context;
    branch_effects.dispatch = rome2_headless_branch_dispatch;
    branch_effects.peek = rome2_headless_branch_peek;

    branch_status = rome2_port_100e2460_run_preallocated_branch(
        &branch_state_view,
        &branch_vtable_view,
        (rome2_guest_addr32){
            ROME2_HEADLESS_BRANCH_STATE_GUEST_BASE +
                ROME2_HEADLESS_BRANCH_VECTOR_OFFSET},
        (rome2_guest_addr32){
            ROME2_HEADLESS_BRANCH_STATE_GUEST_BASE +
                ROME2_HEADLESS_BRANCH_HANDLER_OFFSET},
        (rome2_guest_addr32){ROME2_HEADLESS_BRANCH_ARGUMENT},
        &branch_effects,
        UINT32_C(2),
        &branch_return_al);
    if (branch_status != ROME2_100E2460_BRANCH_OK ||
        branch_return_al != UINT8_C(0xa5) ||
        branch_effect_context.dispatch_calls != 1 ||
        branch_effect_context.peek_calls != 2 ||
        branch_effect_context.bad_observations != 0 ||
        branch_effect_context.observed_receiver !=
            branch_effect_context.expected_receiver ||
        branch_effect_context.observed_method !=
            branch_effect_context.expected_method ||
        branch_effect_context.observed_argument !=
            branch_effect_context.expected_argument ||
        rome2_headless_get_u32(
            branch_state_memory.bytes,
            ROME2_HEADLESS_BRANCH_VECTOR_OFFSET + 8) != 2 ||
        rome2_headless_get_u32(
            branch_state_memory.bytes,
            ROME2_HEADLESS_BRANCH_BACKING_OFFSET + 4) !=
            branch_effect_context.expected_receiver) {
        fprintf(stderr,
            "rome2_headless64: preallocated branch failed: status=%d AL=0x%02x dispatch=%lu peek=%lu observations=%lu\n",
            (int)branch_status,
            (unsigned int)branch_return_al,
            (unsigned long)branch_effect_context.dispatch_calls,
            (unsigned long)branch_effect_context.peek_calls,
            (unsigned long)branch_effect_context.bad_observations);
        return 36;
    }

    /* Execute the complete capacity-zero branch in a separate synthetic
     * guest state.  The allocation adapter returns a pre-provisioned guest
     * cell and performs no host or platform allocation.  Its observations
     * pin capacity publication before allocation, followed by backing/slot/
     * count publication before dispatch and the two Peek-shaped probes. */
    memset(zero_state_memory.bytes, 0xa5, sizeof(zero_state_memory.bytes));
    memset(&zero_effect_context, 0, sizeof(zero_effect_context));
    memset(&zero_effects, 0, sizeof(zero_effects));
    rome2_headless_put_u32(
        zero_state_memory.bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 4,
        UINT32_C(0));
    rome2_headless_put_u32(
        zero_state_memory.bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 8,
        UINT32_C(0));
    rome2_headless_put_u32(
        zero_state_memory.bytes, ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 12,
        UINT32_C(0));
    rome2_headless_put_u32(
        zero_state_memory.bytes, ROME2_HEADLESS_ZERO_HANDLER_OFFSET,
        ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE +
            ROME2_HEADLESS_BRANCH_VTABLE_OFFSET);
    rome2_headless_put_u32(
        zero_state_memory.bytes, ROME2_HEADLESS_ZERO_ALLOCATION_OFFSET,
        UINT32_C(0xcccccccc));

    zero_state_view.host_base = zero_state_memory.bytes;
    zero_state_view.guest_base = ROME2_HEADLESS_ZERO_STATE_GUEST_BASE;
    zero_state_view.byte_count = sizeof(zero_state_memory.bytes);
    zero_effect_context.state_bytes = zero_state_memory.bytes;
    zero_effect_context.expected_receiver =
        ROME2_HEADLESS_ZERO_STATE_GUEST_BASE +
        ROME2_HEADLESS_ZERO_HANDLER_OFFSET;
    zero_effect_context.expected_method = ROME2_HEADLESS_BRANCH_METHOD_IDENTITY;
    zero_effect_context.expected_argument = ROME2_HEADLESS_ZERO_ARGUMENT;
    zero_effect_context.expected_allocation =
        ROME2_HEADLESS_ZERO_STATE_GUEST_BASE +
        ROME2_HEADLESS_ZERO_ALLOCATION_OFFSET;
    zero_effects.tail_effects.context = &zero_effect_context;
    zero_effects.tail_effects.dispatch = rome2_headless_zero_dispatch;
    zero_effects.tail_effects.peek = rome2_headless_zero_peek;
    zero_effects.allocate = rome2_headless_zero_allocate;

    zero_status = rome2_port_100e2460_run_capacity_zero_branch(
        &zero_state_view,
        &branch_vtable_view,
        (rome2_guest_addr32){
            ROME2_HEADLESS_ZERO_STATE_GUEST_BASE +
                ROME2_HEADLESS_ZERO_VECTOR_OFFSET},
        (rome2_guest_addr32){
            ROME2_HEADLESS_ZERO_STATE_GUEST_BASE +
                ROME2_HEADLESS_ZERO_HANDLER_OFFSET},
        (rome2_guest_addr32){ROME2_HEADLESS_ZERO_ARGUMENT},
        &zero_effects,
        UINT32_C(2),
        &zero_return_al);
    if (zero_status != ROME2_100E2460_BRANCH_OK ||
        zero_return_al != UINT8_C(0xe7) ||
        zero_effect_context.allocation_calls != 1 ||
        zero_effect_context.dispatch_calls != 1 ||
        zero_effect_context.peek_calls != 2 ||
        zero_effect_context.effect_order != 4 ||
        zero_effect_context.allocation_order != 1 ||
        zero_effect_context.dispatch_order != 2 ||
        zero_effect_context.first_peek_order != 3 ||
        zero_effect_context.bad_observations != 0 ||
        zero_effect_context.observed_receiver !=
            zero_effect_context.expected_receiver ||
        zero_effect_context.observed_method !=
            zero_effect_context.expected_method ||
        zero_effect_context.observed_argument !=
            zero_effect_context.expected_argument ||
        rome2_headless_get_u32(
            zero_state_memory.bytes,
            ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 4) != 1 ||
        rome2_headless_get_u32(
            zero_state_memory.bytes,
            ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 8) != 1 ||
        rome2_headless_get_u32(
            zero_state_memory.bytes,
            ROME2_HEADLESS_ZERO_VECTOR_OFFSET + 12) !=
            zero_effect_context.expected_allocation ||
        rome2_headless_get_u32(
            zero_state_memory.bytes,
            ROME2_HEADLESS_ZERO_ALLOCATION_OFFSET) !=
            zero_effect_context.expected_receiver) {
        fprintf(stderr,
            "rome2_headless64: capacity-zero branch failed: status=%d AL=0x%02x allocate=%lu dispatch=%lu peek=%lu order=%lu observations=%lu\n",
            (int)zero_status,
            (unsigned int)zero_return_al,
            (unsigned long)zero_effect_context.allocation_calls,
            (unsigned long)zero_effect_context.dispatch_calls,
            (unsigned long)zero_effect_context.peek_calls,
            (unsigned long)zero_effect_context.effect_order,
            (unsigned long)zero_effect_context.bad_observations);
        return 38;
    }

    /* Execute the complete admitted nonzero-capacity growth route in a third
     * synthetic registry.  The allocator selects a pre-provisioned four-cell
     * span and the release adapter records the superseded guest identity; no
     * native allocation or release occurs.  Callback observations pin the
     * original capacity -> allocate -> copy/append -> release -> count ->
     * dispatch -> Peek ordering and the exact copied guest32 cells. */
    memset(growth_state_memory.bytes, 0xa5,
        sizeof(growth_state_memory.bytes));
    memset(&growth_effect_context, 0, sizeof(growth_effect_context));
    memset(&growth_effects, 0, sizeof(growth_effects));
    rome2_headless_put_u32(
        growth_state_memory.bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 4,
        UINT32_C(2));
    rome2_headless_put_u32(
        growth_state_memory.bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8,
        UINT32_C(2));
    rome2_headless_put_u32(
        growth_state_memory.bytes, ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 12,
        ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE +
            ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET);
    rome2_headless_put_u32(
        growth_state_memory.bytes, ROME2_HEADLESS_GROWTH_HANDLER_OFFSET,
        ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE +
            ROME2_HEADLESS_BRANCH_VTABLE_OFFSET);
    rome2_headless_put_u32(
        growth_state_memory.bytes, ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET,
        ROME2_HEADLESS_GROWTH_OLD_CELL_A);
    rome2_headless_put_u32(
        growth_state_memory.bytes,
        ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET + 4,
        ROME2_HEADLESS_GROWTH_OLD_CELL_B);
    rome2_headless_put_u32(
        growth_state_memory.bytes, ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET,
        UINT32_C(0xcccccccc));
    rome2_headless_put_u32(
        growth_state_memory.bytes,
        ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 4,
        UINT32_C(0xcccccccc));
    rome2_headless_put_u32(
        growth_state_memory.bytes,
        ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 8,
        UINT32_C(0xcccccccc));
    rome2_headless_put_u32(
        growth_state_memory.bytes,
        ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 12,
        UINT32_C(0xcccccccc));

    growth_state_view.host_base = growth_state_memory.bytes;
    growth_state_view.guest_base = ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE;
    growth_state_view.byte_count = sizeof(growth_state_memory.bytes);
    growth_effect_context.state_bytes = growth_state_memory.bytes;
    growth_effect_context.expected_receiver =
        ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE +
        ROME2_HEADLESS_GROWTH_HANDLER_OFFSET;
    growth_effect_context.expected_method =
        ROME2_HEADLESS_BRANCH_METHOD_IDENTITY;
    growth_effect_context.expected_argument = ROME2_HEADLESS_GROWTH_ARGUMENT;
    growth_effect_context.expected_old_backing =
        ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE +
        ROME2_HEADLESS_GROWTH_OLD_BACKING_OFFSET;
    growth_effect_context.expected_allocation =
        ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE +
        ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET;
    growth_effects.tail_effects.context = &growth_effect_context;
    growth_effects.tail_effects.dispatch = rome2_headless_growth_dispatch;
    growth_effects.tail_effects.peek = rome2_headless_growth_peek;
    growth_effects.allocate = rome2_headless_growth_allocate;
    growth_effects.release = rome2_headless_growth_release;

    growth_status = rome2_port_100e2460_run_growth_branch(
        &growth_state_view,
        &branch_vtable_view,
        (rome2_guest_addr32){
            ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE +
                ROME2_HEADLESS_GROWTH_VECTOR_OFFSET},
        (rome2_guest_addr32){
            ROME2_HEADLESS_GROWTH_STATE_GUEST_BASE +
                ROME2_HEADLESS_GROWTH_HANDLER_OFFSET},
        (rome2_guest_addr32){ROME2_HEADLESS_GROWTH_ARGUMENT},
        &growth_effects,
        UINT32_C(2),
        &growth_return_al);
    if (growth_status != ROME2_100E2460_BRANCH_OK ||
        growth_return_al != UINT8_C(0xd9) ||
        growth_effect_context.allocation_calls != 1 ||
        growth_effect_context.release_calls != 1 ||
        growth_effect_context.dispatch_calls != 1 ||
        growth_effect_context.peek_calls != 2 ||
        growth_effect_context.effect_order != 5 ||
        growth_effect_context.allocation_order != 1 ||
        growth_effect_context.release_order != 2 ||
        growth_effect_context.dispatch_order != 3 ||
        growth_effect_context.first_peek_order != 4 ||
        growth_effect_context.bad_observations != 0 ||
        growth_effect_context.observed_release !=
            growth_effect_context.expected_old_backing ||
        growth_effect_context.observed_receiver !=
            growth_effect_context.expected_receiver ||
        growth_effect_context.observed_method !=
            growth_effect_context.expected_method ||
        growth_effect_context.observed_argument !=
            growth_effect_context.expected_argument ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 4) != 4 ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 8) != 3 ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_VECTOR_OFFSET + 12) !=
            growth_effect_context.expected_allocation ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_A ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 4) !=
            ROME2_HEADLESS_GROWTH_OLD_CELL_B ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 8) !=
            growth_effect_context.expected_receiver ||
        rome2_headless_get_u32(
            growth_state_memory.bytes,
            ROME2_HEADLESS_GROWTH_ALLOCATION_OFFSET + 12) !=
            UINT32_C(0xcccccccc)) {
        fprintf(stderr,
            "rome2_headless64: growth branch failed: status=%d AL=0x%02x allocate=%lu release=%lu dispatch=%lu peek=%lu order=%lu observations=%lu\n",
            (int)growth_status,
            (unsigned int)growth_return_al,
            (unsigned long)growth_effect_context.allocation_calls,
            (unsigned long)growth_effect_context.release_calls,
            (unsigned long)growth_effect_context.dispatch_calls,
            (unsigned long)growth_effect_context.peek_calls,
            (unsigned long)growth_effect_context.effect_order,
            (unsigned long)growth_effect_context.bad_observations);
        return 40;
    }

    /* Exercise the exact unsigned selector over the six original registry
     * insertions as one persistent vector.  Four pre-provisioned guest spans
     * model 4/8/16/32-byte allocator results; the injected release adapter
     * observes each superseded identity.  The six real vtable/method
     * identities preserve original order while dispatch remains data-only. */
    memset(router_state_memory.bytes, 0x5a,
        sizeof(router_state_memory.bytes));
    memset(&router_effect_context, 0, sizeof(router_effect_context));
    memset(&router_effects, 0, sizeof(router_effects));
    rome2_headless_put_u32(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_VECTOR_OFFSET,
        UINT32_C(0xfeedface));
    rome2_headless_put_u32(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_VECTOR_OFFSET + 4,
        UINT32_C(0));
    rome2_headless_put_u32(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_VECTOR_OFFSET + 8,
        UINT32_C(0));
    rome2_headless_put_u32(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_VECTOR_OFFSET + 12,
        UINT32_C(0));
    rome2_headless_router_initialize_buffer(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_BUFFER_A_OFFSET,
        UINT32_C(1));
    rome2_headless_router_initialize_buffer(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_BUFFER_B_OFFSET,
        UINT32_C(2));
    rome2_headless_router_initialize_buffer(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_BUFFER_C_OFFSET,
        UINT32_C(4));
    rome2_headless_router_initialize_buffer(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_BUFFER_D_OFFSET,
        UINT32_C(8));
    rome2_headless_put_u32(
        router_state_memory.bytes,
        ROME2_HEADLESS_ROUTER_87A0_LISTENER_OFFSET,
        ROME2_HEADLESS_87A0_LISTENER_SENTINEL);

    router_state_view.host_base = router_state_memory.bytes;
    router_state_view.guest_base = ROME2_HEADLESS_ROUTER_STATE_GUEST_BASE;
    router_state_view.byte_count = sizeof(router_state_memory.bytes);
    router_effect_context.state_bytes = router_state_memory.bytes;
    router_effect_context.state_view = &router_state_view;
    router_effect_context.allocations[0] = rome2_headless_router_guest(
        ROME2_HEADLESS_ROUTER_BUFFER_A_OFFSET);
    router_effect_context.allocations[1] = rome2_headless_router_guest(
        ROME2_HEADLESS_ROUTER_BUFFER_B_OFFSET);
    router_effect_context.allocations[2] = rome2_headless_router_guest(
        ROME2_HEADLESS_ROUTER_BUFFER_C_OFFSET);
    router_effect_context.allocations[3] = rome2_headless_router_guest(
        ROME2_HEADLESS_ROUTER_BUFFER_D_OFFSET);
    router_effects.tail_effects.context = &router_effect_context;
    router_effects.tail_effects.dispatch = rome2_headless_router_dispatch;
    router_effects.tail_effects.peek = rome2_headless_router_peek;
    router_effects.allocate = rome2_headless_router_allocate;
    router_effects.release = rome2_headless_router_release;
    router_effect_context.handler_8d00_effects.emit_step =
        rome2_headless_8d00_emit;
    router_effect_context.handler_8d00_effects.context =
        &router_effect_context.handler_8d00_context;
    router_effect_context.handler_8580_effects.emit_step =
        rome2_headless_8580_emit;
    router_effect_context.handler_8580_effects.context =
        &router_effect_context.handler_8580_context;
    router_effect_context.handler_8580_effects.result_100e8240.value =
        UINT32_C(0x119f3a38);
    router_effect_context.handler_9340_effects.emit_step =
        rome2_headless_9340_emit;
    router_effect_context.handler_9340_effects.context =
        &router_effect_context.handler_9340_context;
    router_effect_context.handler_9340_effects.selected_dword_12 =
        UINT32_C(0x89abcdef);
    router_effect_context.handler_9340_effects.selected_byte_49 =
        UINT32_C(0xa5);
    router_effect_context.handler_92c0_effects.emit_step =
        rome2_headless_92c0_emit;
    router_effect_context.handler_92c0_effects.context =
        &router_effect_context.handler_92c0_context;
    router_effect_context.handler_92c0_effects.predicate_10fde370 =
        UINT32_C(1);
    router_effect_context.handler_92c0_effects.predicate_10fde9d0 =
        UINT32_C(1);
    router_effect_context.handler_92c0_effects.result_10fde270_low =
        ROME2_HEADLESS_92C0_FIRST_LOW;
    router_effect_context.handler_92c0_effects.result_10fde990_low =
        ROME2_HEADLESS_92C0_SECOND_LOW;
    router_effect_context.handler_92c0_effects.result_10fde990_high =
        ROME2_HEADLESS_92C0_SECOND_HIGH;
    router_effect_context.handler_87a0_effects.allocate_listener =
        rome2_headless_87a0_allocate;
    router_effect_context.handler_87a0_effects.publish_listener =
        rome2_headless_87a0_publish;
    router_effect_context.handler_87a0_effects.startup_facefx =
        rome2_headless_87a0_startup;
    router_effect_context.handler_87a0_effects.context =
        &router_effect_context.handler_87a0_context;
    router_effect_context.handler_87a0_context.state_bytes =
        router_state_memory.bytes;
    router_effect_context.handler_87a0_context.listener_offset =
        ROME2_HEADLESS_ROUTER_87A0_LISTENER_OFFSET;
    router_effect_context.handler_87a0_context.listener_guest =
        rome2_headless_router_guest(
            ROME2_HEADLESS_ROUTER_87A0_LISTENER_OFFSET);

    for (router_append = 0;
         router_append < ROME2_HEADLESS_ROUTER_APPEND_COUNT;
         ++router_append) {
        uint32_t handler_offset =
            ROME2_HEADLESS_ROUTER_HANDLER_OFFSET +
            router_append * ROME2_HEADLESS_ROUTER_HANDLER_STRIDE;
        uint32_t method_offset =
            rome2_headless_router_vtables[router_append] -
            ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE + UINT32_C(4);

        router_effect_context.handlers[router_append] =
            rome2_headless_router_guest(handler_offset);
        rome2_headless_put_u32(
            router_state_memory.bytes,
            handler_offset,
            rome2_headless_router_vtables[router_append]);
        rome2_headless_put_u32(
            branch_vtable_memory.bytes,
            method_offset,
            rome2_headless_router_methods[router_append]);
    }

    for (router_append = 0;
         router_append < ROME2_HEADLESS_ROUTER_APPEND_COUNT;
         ++router_append) {
        uint32_t expected_backing = rome2_headless_router_guest(
            rome2_headless_router_backing_offsets[router_append]);
        uint8_t expected_al = UINT8_C(1);

        router_effect_context.current_append = router_append;
        router_return_al = UINT8_C(0xcc);
        router_status = rome2_port_100e2460_run_router(
            &router_state_view,
            &branch_vtable_view,
            (rome2_guest_addr32){
                ROME2_HEADLESS_ROUTER_STATE_GUEST_BASE +
                    ROME2_HEADLESS_ROUTER_VECTOR_OFFSET},
            (rome2_guest_addr32){
                router_effect_context.handlers[router_append]},
            (rome2_guest_addr32){ROME2_HEADLESS_ROUTER_ARGUMENT},
            &router_effects,
            UINT32_C(1),
            &router_return_al);
        if (router_status != ROME2_100E2460_BRANCH_OK ||
            router_return_al != expected_al ||
            rome2_headless_router_vector_cell(
                &router_effect_context, 4) !=
                rome2_headless_router_capacities[router_append] ||
            rome2_headless_router_vector_cell(
                &router_effect_context, 8) != router_append + 1 ||
            rome2_headless_router_vector_cell(
                &router_effect_context, 12) != expected_backing ||
            router_effect_context.bad_observations != 0) {
            fprintf(stderr,
                "rome2_headless64: router sequence failed: append=%lu status=%d AL=0x%02x observations=%lu\n",
                (unsigned long)(router_append + 1),
                (int)router_status,
                (unsigned int)router_return_al,
                (unsigned long)router_effect_context.bad_observations);
            return 42;
        }
    }
    if (router_effect_context.allocation_calls != 4 ||
        router_effect_context.release_calls != 3 ||
        router_effect_context.dispatch_calls != 6 ||
        router_effect_context.peek_calls != 6 ||
        router_effect_context.handler_8d00_calls != 1 ||
        router_effect_context.handler_85d0_calls != 1 ||
        router_effect_context.handler_8580_calls != 1 ||
        router_effect_context.handler_9340_calls != 1 ||
        router_effect_context.handler_92c0_calls != 1 ||
        router_effect_context.handler_87a0_calls != 1 ||
        router_effect_context.handler_8d00_context.observed_steps !=
            ROME2_PORT_100E8D00_STEP_COUNT ||
        router_effect_context.handler_8d00_context.bad_observations != 0 ||
        router_effect_context.handler_8580_context.observed_steps !=
            ROME2_PORT_100E8580_STEP_COUNT ||
        router_effect_context.handler_8580_context.bad_observations != 0 ||
        router_effect_context.handler_9340_context.observed_steps !=
            ROME2_PORT_100E9340_STEP_COUNT ||
        router_effect_context.handler_9340_context.bad_observations != 0 ||
        router_effect_context.handler_92c0_context.observed_steps !=
            ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT ||
        router_effect_context.handler_92c0_context.bad_observations != 0 ||
        router_effect_context.handler_87a0_context.allocation_calls != 1 ||
        router_effect_context.handler_87a0_context.publish_calls != 1 ||
        router_effect_context.handler_87a0_context.startup_calls != 1 ||
        router_effect_context.handler_87a0_context.effect_order != 3 ||
        router_effect_context.handler_87a0_context.bad_observations != 0 ||
        rome2_headless_get_u32(
            router_state_memory.bytes,
            ROME2_HEADLESS_ROUTER_87A0_LISTENER_OFFSET) !=
            ROME2_PORT_100E87A0_LISTENER_VTABLE ||
        !rome2_headless_router_buffer_is_ordered(
            &router_effect_context,
            router_effect_context.allocations[0],
            UINT32_C(1)) ||
        !rome2_headless_router_buffer_is_ordered(
            &router_effect_context,
            router_effect_context.allocations[1],
            UINT32_C(2)) ||
        !rome2_headless_router_buffer_is_ordered(
            &router_effect_context,
            router_effect_context.allocations[2],
            UINT32_C(4)) ||
        !rome2_headless_router_buffer_is_ordered(
            &router_effect_context,
            router_effect_context.allocations[3],
            UINT32_C(6))) {
        fprintf(stderr,
            "rome2_headless64: router final state failed: allocate=%lu release=%lu dispatch=%lu peek=%lu observations=%lu\n",
            (unsigned long)router_effect_context.allocation_calls,
            (unsigned long)router_effect_context.release_calls,
            (unsigned long)router_effect_context.dispatch_calls,
            (unsigned long)router_effect_context.peek_calls,
            (unsigned long)router_effect_context.bad_observations);
        return 44;
    }

    /* Compose the original outer six-registration loop over a fresh guest32
     * arena.  The outer allocator supplies six four-byte handler objects;
     * its nested router adapters supply the same bounded 4/8/16/32-byte
     * backing progression.  Dispatch executes all six admitted handler
     * ports through bounded, injected-effect adapters. */
    memset(outer_state_memory.bytes, 0x5a,
        sizeof(outer_state_memory.bytes));
    memset(&outer_effect_context, 0, sizeof(outer_effect_context));
    memset(&outer_effects, 0, sizeof(outer_effects));
    rome2_headless_put_u32(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_VECTOR_OFFSET,
        UINT32_C(0xfeedface));
    rome2_headless_put_u32(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_VECTOR_OFFSET + 4,
        UINT32_C(0));
    rome2_headless_put_u32(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_VECTOR_OFFSET + 8,
        UINT32_C(0));
    rome2_headless_put_u32(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_VECTOR_OFFSET + 12,
        UINT32_C(0));
    rome2_headless_router_initialize_buffer(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_BUFFER_A_OFFSET,
        UINT32_C(1));
    rome2_headless_router_initialize_buffer(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_BUFFER_B_OFFSET,
        UINT32_C(2));
    rome2_headless_router_initialize_buffer(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET,
        UINT32_C(4));
    rome2_headless_router_initialize_buffer(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET,
        UINT32_C(8));
    rome2_headless_put_u32(
        outer_state_memory.bytes,
        ROME2_HEADLESS_OUTER_87A0_LISTENER_OFFSET,
        ROME2_HEADLESS_87A0_LISTENER_SENTINEL);

    outer_state_view.host_base = outer_state_memory.bytes;
    outer_state_view.guest_base = ROME2_HEADLESS_OUTER_STATE_GUEST_BASE;
    outer_state_view.byte_count = sizeof(outer_state_memory.bytes);
    outer_effect_context.state_bytes = outer_state_memory.bytes;
    outer_effect_context.state_view = &outer_state_view;
    outer_effect_context.allocations[0] = rome2_headless_outer_guest(
        ROME2_HEADLESS_OUTER_BUFFER_A_OFFSET);
    outer_effect_context.allocations[1] = rome2_headless_outer_guest(
        ROME2_HEADLESS_OUTER_BUFFER_B_OFFSET);
    outer_effect_context.allocations[2] = rome2_headless_outer_guest(
        ROME2_HEADLESS_OUTER_BUFFER_C_OFFSET);
    outer_effect_context.allocations[3] = rome2_headless_outer_guest(
        ROME2_HEADLESS_OUTER_BUFFER_D_OFFSET);
    outer_effects.allocation_context = &outer_effect_context;
    outer_effects.allocate_handler = rome2_headless_outer_allocate_handler;
    outer_effects.router_effects.tail_effects.context =
        &outer_effect_context;
    outer_effects.router_effects.tail_effects.dispatch =
        rome2_headless_outer_dispatch;
    outer_effects.router_effects.tail_effects.peek =
        rome2_headless_outer_peek;
    outer_effects.router_effects.allocate =
        rome2_headless_outer_allocate_backing;
    outer_effects.router_effects.release =
        rome2_headless_outer_release_backing;
    outer_effect_context.handler_8d00_effects.emit_step =
        rome2_headless_8d00_emit;
    outer_effect_context.handler_8d00_effects.context =
        &outer_effect_context.handler_8d00_context;
    outer_effect_context.handler_8580_effects.emit_step =
        rome2_headless_8580_emit;
    outer_effect_context.handler_8580_effects.context =
        &outer_effect_context.handler_8580_context;
    outer_effect_context.handler_8580_effects.result_100e8240.value =
        UINT32_C(0x119f3a38);
    outer_effect_context.handler_9340_effects.emit_step =
        rome2_headless_9340_emit;
    outer_effect_context.handler_9340_effects.context =
        &outer_effect_context.handler_9340_context;
    outer_effect_context.handler_9340_effects.selected_dword_12 =
        UINT32_C(0x89abcdef);
    outer_effect_context.handler_9340_effects.selected_byte_49 =
        UINT32_C(0xa5);
    outer_effect_context.handler_92c0_effects.emit_step =
        rome2_headless_92c0_emit;
    outer_effect_context.handler_92c0_effects.context =
        &outer_effect_context.handler_92c0_context;
    outer_effect_context.handler_92c0_effects.predicate_10fde370 =
        UINT32_C(1);
    outer_effect_context.handler_92c0_effects.predicate_10fde9d0 =
        UINT32_C(1);
    outer_effect_context.handler_92c0_effects.result_10fde270_low =
        ROME2_HEADLESS_92C0_FIRST_LOW;
    outer_effect_context.handler_92c0_effects.result_10fde990_low =
        ROME2_HEADLESS_92C0_SECOND_LOW;
    outer_effect_context.handler_92c0_effects.result_10fde990_high =
        ROME2_HEADLESS_92C0_SECOND_HIGH;
    outer_effect_context.handler_87a0_effects.allocate_listener =
        rome2_headless_87a0_allocate;
    outer_effect_context.handler_87a0_effects.publish_listener =
        rome2_headless_87a0_publish;
    outer_effect_context.handler_87a0_effects.startup_facefx =
        rome2_headless_87a0_startup;
    outer_effect_context.handler_87a0_effects.context =
        &outer_effect_context.handler_87a0_context;
    outer_effect_context.handler_87a0_context.state_bytes =
        outer_state_memory.bytes;
    outer_effect_context.handler_87a0_context.listener_offset =
        ROME2_HEADLESS_OUTER_87A0_LISTENER_OFFSET;
    outer_effect_context.handler_87a0_context.listener_guest =
        rome2_headless_outer_guest(
            ROME2_HEADLESS_OUTER_87A0_LISTENER_OFFSET);

    for (router_append = 0;
         router_append < ROME2_PORT_100EA4D0_REGISTRATION_COUNT;
         ++router_append) {
        uint32_t handler_offset =
            ROME2_HEADLESS_OUTER_HANDLER_OFFSET +
            router_append * ROME2_HEADLESS_OUTER_HANDLER_STRIDE;
        uint32_t method_offset =
            rome2_headless_router_vtables[router_append] -
            ROME2_HEADLESS_BRANCH_VTABLE_GUEST_BASE + UINT32_C(4);

        outer_effect_context.handlers[router_append] =
            rome2_headless_outer_guest(handler_offset);
        rome2_headless_put_u32(
            branch_vtable_memory.bytes,
            method_offset,
            rome2_headless_router_methods[router_append]);
    }

    outer_status = rome2_port_100ea4d0_run_injected(
        &outer_state_view,
        &branch_vtable_view,
        (rome2_guest_addr32){
            ROME2_HEADLESS_OUTER_STATE_GUEST_BASE +
                ROME2_HEADLESS_OUTER_RECEIVER_OFFSET},
        &outer_effects,
        UINT32_C(1));
    if (outer_status != ROME2_100EA4D0_OK ||
        outer_effect_context.handler_allocation_calls != 6 ||
        outer_effect_context.backing_allocation_calls != 4 ||
        outer_effect_context.release_calls != 3 ||
        outer_effect_context.dispatch_calls != 6 ||
        outer_effect_context.peek_calls != 6 ||
        outer_effect_context.handler_8d00_calls != 1 ||
        outer_effect_context.handler_85d0_calls != 1 ||
        outer_effect_context.handler_8580_calls != 1 ||
        outer_effect_context.handler_9340_calls != 1 ||
        outer_effect_context.handler_92c0_calls != 1 ||
        outer_effect_context.handler_87a0_calls != 1 ||
        outer_effect_context.handler_8d00_context.observed_steps !=
            ROME2_PORT_100E8D00_STEP_COUNT ||
        outer_effect_context.handler_8d00_context.bad_observations != 0 ||
        outer_effect_context.handler_8580_context.observed_steps !=
            ROME2_PORT_100E8580_STEP_COUNT ||
        outer_effect_context.handler_8580_context.bad_observations != 0 ||
        outer_effect_context.handler_9340_context.observed_steps !=
            ROME2_PORT_100E9340_STEP_COUNT ||
        outer_effect_context.handler_9340_context.bad_observations != 0 ||
        outer_effect_context.handler_92c0_context.observed_steps !=
            ROME2_PORT_100E92C0_BOTH_TRUE_STEP_COUNT ||
        outer_effect_context.handler_92c0_context.bad_observations != 0 ||
        outer_effect_context.handler_87a0_context.allocation_calls != 1 ||
        outer_effect_context.handler_87a0_context.publish_calls != 1 ||
        outer_effect_context.handler_87a0_context.startup_calls != 1 ||
        outer_effect_context.handler_87a0_context.effect_order != 3 ||
        outer_effect_context.handler_87a0_context.bad_observations != 0 ||
        rome2_headless_get_u32(
            outer_state_memory.bytes,
            ROME2_HEADLESS_OUTER_87A0_LISTENER_OFFSET) !=
            ROME2_PORT_100E87A0_LISTENER_VTABLE ||
        outer_effect_context.bad_observations != 0 ||
        !rome2_headless_outer_prefix_is_exact(
            &outer_effect_context,
            ROME2_PORT_100EA4D0_REGISTRATION_COUNT)) {
        fprintf(stderr,
            "rome2_headless64: outer initializer failed: status=%d handlers=%lu backing=%lu release=%lu dispatch=%lu peek=%lu observations=%lu\n",
            (int)outer_status,
            (unsigned long)outer_effect_context.handler_allocation_calls,
            (unsigned long)outer_effect_context.backing_allocation_calls,
            (unsigned long)outer_effect_context.release_calls,
            (unsigned long)outer_effect_context.dispatch_calls,
            (unsigned long)outer_effect_context.peek_calls,
            (unsigned long)outer_effect_context.bad_observations);
        return 46;
    }

    printf(
        "rome2_headless64: canonical=%s;functions=%s;data=%s;"
        "entry-policy=skip;utf16-length=%lu;startup=bounded-empty;"
        "cleanup=nonowning-noop;short-copy=nonallocating-10-byte;"
        "crash-record=fast-path-no-crash;"
        "initializer-append=preallocated-prefix;"
        "initializer-branch=preallocated-complete;"
        "initializer-capacity-zero=injected-complete;"
        "initializer-growth=injected-complete;"
        "initializer-router=injected-complete;"
        "initializer-handler-100e8d00=injected-transcript-complete;"
        "initializer-handler-100e85d0=effect-free-complete;"
        "initializer-handler-100e8580=injected-transcript-complete;"
        "initializer-100ea4d0=injected-complete;"
        "initializer-handler-100e9340=injected-transcript-complete;"
        "initializer-handler-100e92c0=injected-transcript-complete;"
        "initializer-handler-100e87a0=injected-transcript-complete;"
        "startup-100df270-suffix=injected-transcript-complete;"
        "startup-100df270-platform-prefix=injected-call-shape-complete;"
        "startup-100ed3c0-empty-preloop=injected-composition-complete;"
        "startup-100ed471-ordinary-lifecycle=injected-bounded-complete;"
        "platform-effects=not-run;"
        "post-platform-state=bounded-empty-projection;"
        "allocator=injected-4-byte;native-allocator=not-run;"
        "growth-allocator=injected-16-byte;"
        "growth-release=injected-old-backing;native-release=not-run;"
        "initializer-dispatch=injected-complete;"
        "queue-drain=injected-bounded-complete;gameplay=not-linked\n",
        ROME2_CANONICAL_FINGERPRINT,
        ROME2_CANONICAL_FUNCTION_COUNT,
        ROME2_CANONICAL_DATA_SYMBOL_COUNT,
        (unsigned long)utf16_length);
    return 0;
}
