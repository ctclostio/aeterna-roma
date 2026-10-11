#include "ported_100f1bb0_owned_utf16.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TEST_DESCRIPTOR_STORAGE_BYTES UINT32_C(128)
#define TEST_TEXT_STORAGE_BYTES UINT32_C(65584)
#define TEST_HEAP_STORAGE_BYTES UINT32_C(65632)
#define TEST_DESCRIPTOR_BASE UINT32_C(0x21000001)
#define TEST_TEXT_BASE UINT32_C(0x31000001)
#define TEST_HEAP_BASE UINT32_C(0x41000001)
#define TEST_DESCRIPTOR_OFFSET UINT32_C(5)
#define TEST_TEXT_OFFSET UINT32_C(6)
#define TEST_RAW_OFFSET_BASE UINT32_C(32)
#define TEST_MAX_LENGTH \
    (ROME2_PORT_100F1BB0_OWNED_MAX_UNITS - UINT32_C(1))
#define TEST_TOKEN UINT64_C(0x1122334455667788)
#define TEST_RETURN_SENTINEL UINT32_C(0xdeadbeef)
#define TEST_DESCRIPTOR_FILL UINT8_C(0xd3)
#define TEST_TEXT_FILL UINT8_C(0xc7)
#define TEST_HEAP_FILL UINT8_C(0xa5)
#define TEST_MAX_EVENTS UINT32_C(8)

#define TEST_EVENT_ALLOCATE UINT32_C(1)
#define TEST_EVENT_RELEASE UINT32_C(2)
#define TEST_EVENT_HOOK UINT32_C(3)

#define TEST_RELEASE_NONE UINT32_C(0)
#define TEST_RELEASE_COMPENSATION UINT32_C(1)
#define TEST_RELEASE_CLEANUP UINT32_C(2)

_Static_assert(
    ROME2_PORT_100F1BB0_OWNED_MAX_UNITS == UINT32_C(32768),
    "the finite UTF-16 ceiling changed");
_Static_assert(
    ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS == UINT32_C(0),
    "the authenticated allocation class changed");
_Static_assert(
    sizeof(rome2_100f1bb0_owned_grant) == 16U &&
        sizeof(rome2_100f1bb0_owned_owner) == 32U,
    "the ownership ABI changed");
_Static_assert(
    _Alignof(rome2_guest_write_view) > 1U &&
        _Alignof(rome2_guest_read_view) > 1U &&
        _Alignof(rome2_100f1bb0_owned_effects) > 1U &&
        _Alignof(rome2_100f1bb0_owned_owner) > 1U,
    "the alignment adversaries require naturally aligned controls");

typedef union test_descriptor_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_DESCRIPTOR_STORAGE_BYTES];
} test_descriptor_memory;

typedef union test_text_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_TEXT_STORAGE_BYTES];
} test_text_memory;

typedef union test_heap_memory {
    uint64_t alignment;
    uint8_t bytes[TEST_HEAP_STORAGE_BYTES];
} test_heap_memory;

typedef union test_write_view_storage {
    rome2_guest_write_view alignment;
    uint8_t bytes[
        sizeof(rome2_guest_write_view) + _Alignof(rome2_guest_write_view)];
} test_write_view_storage;

typedef union test_read_view_storage {
    rome2_guest_read_view alignment;
    uint8_t bytes[
        sizeof(rome2_guest_read_view) + _Alignof(rome2_guest_read_view)];
} test_read_view_storage;

typedef union test_effects_storage {
    rome2_100f1bb0_owned_effects alignment;
    uint8_t bytes[
        sizeof(rome2_100f1bb0_owned_effects) +
        _Alignof(rome2_100f1bb0_owned_effects)];
} test_effects_storage;

typedef union test_owner_storage {
    rome2_100f1bb0_owned_owner alignment;
    uint8_t bytes[
        sizeof(rome2_100f1bb0_owned_owner) +
        _Alignof(rome2_100f1bb0_owned_owner)];
} test_owner_storage;

typedef union test_return_storage {
    rome2_guest_addr32 alignment;
    uint8_t bytes[
        sizeof(rome2_guest_addr32) + _Alignof(rome2_guest_addr32)];
} test_return_storage;

typedef struct test_effect_context {
    rome2_100f1bb0_owned_grant_result allocation_result;
    rome2_100f1bb0_owned_grant grant;
    uint32_t expected_allocation_bytes;
    uint32_t expected_allocation_class;
    uint32_t expected_release_mode;
    uint32_t expected_owner_phase;
    uint64_t expected_release_token;
    rome2_guest_addr32 expected_release_raw;
    rome2_100f1bb0_owned_owner *observed_owner;
    rome2_guest_addr32 *observed_return;
    uint8_t *observed_descriptor;
    uint8_t descriptor_before[12];
    rome2_100f1bb0_owned_owner owner_before;
    rome2_guest_addr32 return_before;
    uint32_t events[TEST_MAX_EVENTS];
    uint32_t event_count;
    uint32_t allocate_calls;
    uint32_t release_calls;
    uint32_t hook_calls;
    uint32_t observed_allocate_bytes;
    uint32_t observed_allocate_class;
    uint64_t observed_release_token;
    rome2_guest_addr32 observed_release_raw;
    uint32_t observed_release_bytes;
    uint32_t observed_release_class;
    rome2_guest_addr32 observed_hook_raw;
    uint32_t observed_hook_zero;
    uint32_t bad_observations;
} test_effect_context;

typedef struct test_fixture {
    test_descriptor_memory descriptor;
    test_text_memory text;
    test_heap_memory heap;
    rome2_guest_write_view descriptor_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner owner;
    rome2_guest_addr32 guest_return;
    rome2_guest_addr32 guest_descriptor;
    rome2_guest_addr32 guest_text;
    uint32_t max_units;
    uint32_t length_units;
    test_effect_context context;
} test_fixture;

typedef struct test_snapshot {
    test_descriptor_memory descriptor;
    test_text_memory text;
    test_heap_memory heap;
    rome2_guest_write_view descriptor_view;
    rome2_guest_read_view text_view;
    rome2_guest_write_view heap_view;
    rome2_100f1bb0_owned_effects effects;
    rome2_100f1bb0_owned_owner owner;
    rome2_guest_addr32 guest_return;
    test_effect_context context;
} test_snapshot;

static test_fixture test_fixture_storage;
static test_snapshot test_snapshot_storage;
static uint32_t test_case_count;

static uint32_t test_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static uint16_t test_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static void test_write_u32_le(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void test_write_u16_le(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
}

static int test_expect(int condition, const char *case_name, const char *detail)
{
    if (condition) {
        return 0;
    }
    (void)fprintf(
        stderr, "100f1bb0 owned UTF-16 runtime: %s: %s\n",
        case_name, detail);
    return 1;
}

static void test_begin_case(void)
{
    test_case_count += UINT32_C(1);
}

static void test_trace(test_effect_context *context, uint32_t event)
{
    if (context->event_count >= TEST_MAX_EVENTS) {
        ++context->bad_observations;
        return;
    }
    context->events[context->event_count] = event;
    ++context->event_count;
}

static rome2_100f1bb0_owned_grant_result test_allocate(
    void *opaque_context,
    uint32_t byte_count,
    uint32_t allocation_class,
    rome2_100f1bb0_owned_grant *grant_out)
{
    test_effect_context *context = (test_effect_context *)opaque_context;

    test_trace(context, TEST_EVENT_ALLOCATE);
    ++context->allocate_calls;
    context->observed_allocate_bytes = byte_count;
    context->observed_allocate_class = allocation_class;
    if (context->event_count != UINT32_C(1) ||
        context->release_calls != UINT32_C(0) ||
        context->hook_calls != UINT32_C(0) || grant_out == NULL ||
        grant_out->token != UINT64_C(0) ||
        grant_out->raw_base.value != UINT32_C(0) ||
        grant_out->reserved != UINT32_C(0) ||
        byte_count != context->expected_allocation_bytes ||
        allocation_class != context->expected_allocation_class ||
        memcmp(
            context->observed_descriptor,
            context->descriptor_before,
            sizeof(context->descriptor_before)) != 0 ||
        memcmp(
            context->observed_owner,
            &context->owner_before,
            sizeof(context->owner_before)) != 0 ||
        context->observed_return->value != context->return_before.value) {
        ++context->bad_observations;
    }
    if (grant_out != NULL) {
        *grant_out = context->grant;
    }
    return context->allocation_result;
}

static void test_release(
    void *opaque_context,
    uint64_t token,
    rome2_guest_addr32 raw_base,
    uint32_t byte_count,
    uint32_t allocation_class)
{
    test_effect_context *context = (test_effect_context *)opaque_context;

    test_trace(context, TEST_EVENT_RELEASE);
    ++context->release_calls;
    context->observed_release_token = token;
    context->observed_release_raw = raw_base;
    context->observed_release_bytes = byte_count;
    context->observed_release_class = allocation_class;
    if (context->hook_calls != UINT32_C(0) ||
        token != context->expected_release_token ||
        raw_base.value != context->expected_release_raw.value ||
        byte_count != context->expected_allocation_bytes ||
        allocation_class != context->expected_allocation_class) {
        ++context->bad_observations;
    }
    if (context->expected_release_mode == TEST_RELEASE_COMPENSATION) {
        if (context->event_count != UINT32_C(2) ||
            context->events[0] != TEST_EVENT_ALLOCATE ||
            context->events[1] != TEST_EVENT_RELEASE ||
            context->allocate_calls != UINT32_C(1) ||
            memcmp(
                context->observed_owner,
                &context->owner_before,
                sizeof(context->owner_before)) != 0) {
            ++context->bad_observations;
        }
    } else if (context->expected_release_mode == TEST_RELEASE_CLEANUP) {
        if (context->event_count != UINT32_C(1) ||
            context->events[0] != TEST_EVENT_RELEASE ||
            context->allocate_calls != UINT32_C(0) ||
            context->observed_owner->phase != context->expected_owner_phase) {
            ++context->bad_observations;
        }
    } else {
        ++context->bad_observations;
    }
}

static void test_release_hook(
    void *opaque_context,
    rome2_guest_addr32 raw_base,
    uint32_t zero_argument)
{
    test_effect_context *context = (test_effect_context *)opaque_context;

    test_trace(context, TEST_EVENT_HOOK);
    ++context->hook_calls;
    context->observed_hook_raw = raw_base;
    context->observed_hook_zero = zero_argument;
    if (context->expected_release_mode != TEST_RELEASE_CLEANUP ||
        context->event_count != UINT32_C(2) ||
        context->events[0] != TEST_EVENT_RELEASE ||
        context->events[1] != TEST_EVENT_HOOK ||
        context->allocate_calls != UINT32_C(0) ||
        context->release_calls != UINT32_C(1) ||
        raw_base.value != context->expected_release_raw.value ||
        zero_argument != UINT32_C(0) ||
        context->observed_owner->phase != context->expected_owner_phase) {
        ++context->bad_observations;
    }
}

static uint32_t test_raw_offset_for_residue(
    const rome2_guest_write_view *heap_view,
    uint32_t residue)
{
    uint32_t raw = heap_view->guest_base + TEST_RAW_OFFSET_BASE;
    return TEST_RAW_OFFSET_BASE + ((residue - (raw & UINT32_C(3))) &
        UINT32_C(3));
}

static void test_refresh_callback_observations(test_fixture *fixture)
{
    test_effect_context *context = &fixture->context;
    uint32_t descriptor_offset =
        fixture->guest_descriptor.value - fixture->descriptor_view.guest_base;

    context->observed_owner = &fixture->owner;
    context->observed_return = &fixture->guest_return;
    context->observed_descriptor =
        fixture->descriptor_view.host_base + descriptor_offset;
    memcpy(
        context->descriptor_before,
        context->observed_descriptor,
        sizeof(context->descriptor_before));
    context->owner_before = fixture->owner;
    context->return_before = fixture->guest_return;
}

static void test_reset_trace(test_fixture *fixture)
{
    test_effect_context *context = &fixture->context;

    memset(context->events, 0, sizeof(context->events));
    context->event_count = UINT32_C(0);
    context->allocate_calls = UINT32_C(0);
    context->release_calls = UINT32_C(0);
    context->hook_calls = UINT32_C(0);
    context->observed_allocate_bytes = UINT32_C(0);
    context->observed_allocate_class = UINT32_C(0);
    context->observed_release_token = UINT64_C(0);
    context->observed_release_raw.value = UINT32_C(0);
    context->observed_release_bytes = UINT32_C(0);
    context->observed_release_class = UINT32_C(0);
    context->observed_hook_raw.value = UINT32_C(0);
    context->observed_hook_zero = UINT32_C(0);
    context->bad_observations = UINT32_C(0);
}

static void test_init_fixture(
    test_fixture *fixture,
    uint32_t length_units,
    uint32_t raw_residue,
    int enable_hook)
{
    uint32_t index;
    uint32_t text_offset;
    uint32_t raw_offset;

    memset(fixture, 0, sizeof(*fixture));
    memset(fixture->descriptor.bytes, TEST_DESCRIPTOR_FILL,
        sizeof(fixture->descriptor.bytes));
    memset(fixture->text.bytes, TEST_TEXT_FILL, sizeof(fixture->text.bytes));
    memset(fixture->heap.bytes, TEST_HEAP_FILL, sizeof(fixture->heap.bytes));

    fixture->descriptor_view.host_base = fixture->descriptor.bytes + 1U;
    fixture->descriptor_view.guest_base = TEST_DESCRIPTOR_BASE;
    fixture->descriptor_view.byte_count =
        TEST_DESCRIPTOR_STORAGE_BYTES - UINT32_C(2);
    fixture->text_view.host_base = fixture->text.bytes + 1U;
    fixture->text_view.guest_base = TEST_TEXT_BASE;
    fixture->text_view.byte_count = TEST_TEXT_STORAGE_BYTES - UINT32_C(2);
    fixture->heap_view.host_base = fixture->heap.bytes + 1U;
    fixture->heap_view.guest_base = TEST_HEAP_BASE;
    fixture->heap_view.byte_count = TEST_HEAP_STORAGE_BYTES - UINT32_C(2);

    fixture->guest_descriptor.value =
        fixture->descriptor_view.guest_base + TEST_DESCRIPTOR_OFFSET;
    fixture->guest_text.value =
        fixture->text_view.guest_base + TEST_TEXT_OFFSET;
    fixture->max_units = length_units + UINT32_C(1);
    fixture->length_units = length_units;

    text_offset = fixture->guest_text.value - fixture->text_view.guest_base;
    for (index = UINT32_C(0); index < length_units; ++index) {
        uint16_t unit = (uint16_t)(UINT16_C(0x0101) +
            (uint16_t)(index % UINT32_C(0x7e00)));
        test_write_u16_le(
            fixture->text.bytes + 1U + text_offset + index * 2U,
            unit);
    }
    test_write_u16_le(
        fixture->text.bytes + 1U + text_offset + length_units * 2U,
        UINT16_C(0));

    raw_offset = test_raw_offset_for_residue(
        &fixture->heap_view, raw_residue);
    fixture->context.allocation_result =
        ROME2_100F1BB0_OWNED_GRANT_GRANTED;
    fixture->context.grant.token = TEST_TOKEN;
    fixture->context.grant.raw_base.value =
        fixture->heap_view.guest_base + raw_offset;
    fixture->context.grant.reserved = UINT32_C(0);
    fixture->context.expected_allocation_bytes =
        length_units * UINT32_C(2) + UINT32_C(10);
    fixture->context.expected_allocation_class =
        ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS;
    fixture->context.expected_release_mode = TEST_RELEASE_NONE;
    fixture->context.expected_owner_phase = UINT32_C(0);
    fixture->context.expected_release_token = TEST_TOKEN;
    fixture->context.expected_release_raw =
        fixture->context.grant.raw_base;

    fixture->guest_return.value = TEST_RETURN_SENTINEL;
    fixture->effects.allocate = test_allocate;
    fixture->effects.release = test_release;
    fixture->effects.release_hook = enable_hook ? test_release_hook : NULL;
    fixture->effects.context = &fixture->context;
    fixture->effects.context_byte_count = sizeof(fixture->context);
    test_refresh_callback_observations(fixture);
    test_reset_trace(fixture);
}

static void test_take_snapshot(const test_fixture *fixture)
{
    test_snapshot_storage.descriptor = fixture->descriptor;
    test_snapshot_storage.text = fixture->text;
    test_snapshot_storage.heap = fixture->heap;
    test_snapshot_storage.descriptor_view = fixture->descriptor_view;
    test_snapshot_storage.text_view = fixture->text_view;
    test_snapshot_storage.heap_view = fixture->heap_view;
    test_snapshot_storage.effects = fixture->effects;
    test_snapshot_storage.owner = fixture->owner;
    test_snapshot_storage.guest_return = fixture->guest_return;
    test_snapshot_storage.context = fixture->context;
}

static int test_expect_preserved(
    const char *case_name,
    const test_fixture *fixture,
    int expect_context_unchanged)
{
    int failed = 0;

    failed |= test_expect(
        memcmp(
            &fixture->descriptor,
            &test_snapshot_storage.descriptor,
            sizeof(fixture->descriptor)) == 0,
        case_name, "descriptor backing changed on failure");
    failed |= test_expect(
        memcmp(
            &fixture->text,
            &test_snapshot_storage.text,
            sizeof(fixture->text)) == 0,
        case_name, "text backing changed on failure");
    failed |= test_expect(
        memcmp(
            &fixture->heap,
            &test_snapshot_storage.heap,
            sizeof(fixture->heap)) == 0,
        case_name, "heap backing changed on failure");
    failed |= test_expect(
        memcmp(
            &fixture->descriptor_view,
            &test_snapshot_storage.descriptor_view,
            sizeof(fixture->descriptor_view)) == 0 &&
        memcmp(
            &fixture->text_view,
            &test_snapshot_storage.text_view,
            sizeof(fixture->text_view)) == 0 &&
        memcmp(
            &fixture->heap_view,
            &test_snapshot_storage.heap_view,
            sizeof(fixture->heap_view)) == 0,
        case_name, "a view descriptor changed on failure");
    failed |= test_expect(
        memcmp(
            &fixture->effects,
            &test_snapshot_storage.effects,
            sizeof(fixture->effects)) == 0,
        case_name, "effects table changed on failure");
    failed |= test_expect(
        memcmp(
            &fixture->owner,
            &test_snapshot_storage.owner,
            sizeof(fixture->owner)) == 0,
        case_name, "owner changed on failure");
    failed |= test_expect(
        fixture->guest_return.value ==
            test_snapshot_storage.guest_return.value,
        case_name, "return output changed on failure");
    if (expect_context_unchanged) {
        failed |= test_expect(
            memcmp(
                &fixture->context,
                &test_snapshot_storage.context,
                sizeof(fixture->context)) == 0,
            case_name, "preflight failure changed callback context");
    }
    return failed;
}

static rome2_100f1bb0_owned_status test_call_build(
    test_fixture *fixture)
{
    return rome2_port_100f1bb0_build_owned_utf16(
        &fixture->descriptor_view,
        fixture->guest_descriptor,
        &fixture->text_view,
        fixture->guest_text,
        fixture->max_units,
        &fixture->heap_view,
        &fixture->effects,
        &fixture->owner,
        &fixture->guest_return);
}

static int test_verify_build_success(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status status)
{
    const test_snapshot *before = &test_snapshot_storage;
    uint32_t raw = fixture->context.grant.raw_base.value;
    uint32_t payload = (raw + UINT32_C(8)) & UINT32_C(0xfffffffc);
    uint32_t descriptor_offset =
        fixture->guest_descriptor.value - fixture->descriptor_view.guest_base;
    uint32_t text_offset =
        fixture->guest_text.value - fixture->text_view.guest_base;
    uint32_t metadata_offset = payload - UINT32_C(4) -
        fixture->heap_view.guest_base;
    uint32_t payload_offset = payload - fixture->heap_view.guest_base;
    size_t heap_host_offset = (size_t)(
        fixture->heap_view.host_base - fixture->heap.bytes);
    size_t heap_host_end =
        heap_host_offset + (size_t)fixture->heap_view.byte_count;
    uint32_t index;
    size_t host_index;
    int failed = 0;

    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        case_name, "success status changed");
    failed |= test_expect(
        fixture->context.event_count == UINT32_C(1) &&
            fixture->context.events[0] == TEST_EVENT_ALLOCATE &&
            fixture->context.allocate_calls == UINT32_C(1) &&
            fixture->context.release_calls == UINT32_C(0) &&
            fixture->context.hook_calls == UINT32_C(0) &&
            fixture->context.bad_observations == UINT32_C(0),
        case_name, "allocation callback order or observations changed");
    failed |= test_expect(
        fixture->context.observed_allocate_bytes ==
                fixture->context.expected_allocation_bytes &&
            fixture->context.observed_allocate_class ==
                ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,
        case_name, "allocation arguments changed");
    failed |= test_expect(
        test_read_u32_le(
            fixture->descriptor_view.host_base + descriptor_offset) ==
                fixture->length_units &&
        test_read_u32_le(
            fixture->descriptor_view.host_base + descriptor_offset + 4U) ==
                fixture->length_units &&
        test_read_u32_le(
            fixture->descriptor_view.host_base + descriptor_offset + 8U) ==
                payload,
        case_name, "descriptor triplet is not exact");
    failed |= test_expect(
        test_read_u32_le(
            fixture->heap_view.host_base + metadata_offset) == raw,
        case_name, "hidden raw-allocation header is not exact");
    for (index = UINT32_C(0); index < fixture->length_units; ++index) {
        failed |= test_expect(
            test_read_u16_le(
                fixture->heap_view.host_base + payload_offset + index * 2U) ==
            test_read_u16_le(
                fixture->text_view.host_base + text_offset + index * 2U),
            case_name, "copied UTF-16 payload differs from source");
    }
    failed |= test_expect(
        test_read_u16_le(
            fixture->heap_view.host_base + payload_offset +
                fixture->length_units * 2U) == UINT16_C(0),
        case_name, "literal zero terminator was not written");
    for (index = UINT32_C(0);
         index < (uint32_t)fixture->heap_view.byte_count;
         ++index) {
        int is_header = index >= metadata_offset &&
            index < metadata_offset + UINT32_C(4);
        int is_payload = index >= payload_offset &&
            index < payload_offset + fixture->length_units * UINT32_C(2);
        int is_terminator = index >=
                payload_offset + fixture->length_units * UINT32_C(2) &&
            index < payload_offset + fixture->length_units * UINT32_C(2) +
                UINT32_C(2);
        if (!is_header && !is_payload && !is_terminator) {
            failed |= test_expect(
                fixture->heap_view.host_base[index] ==
                    before->heap.bytes[heap_host_offset + index],
                case_name, "heap padding or unrelated arena byte changed");
        }
    }
    for (host_index = 0U; host_index < sizeof(fixture->heap.bytes);
         ++host_index) {
        if (host_index < heap_host_offset || host_index >= heap_host_end) {
            failed |= test_expect(
                fixture->heap.bytes[host_index] ==
                    before->heap.bytes[host_index],
                case_name, "byte outside the heap view changed");
        }
    }
    for (index = UINT32_C(0);
         index < TEST_DESCRIPTOR_STORAGE_BYTES;
         ++index) {
        uint32_t absolute_start = UINT32_C(1) + descriptor_offset;
        if (index < absolute_start || index >= absolute_start + UINT32_C(12)) {
            failed |= test_expect(
                fixture->descriptor.bytes[index] ==
                    before->descriptor.bytes[index],
                case_name, "unrelated descriptor-arena byte changed");
        }
    }
    failed |= test_expect(
        memcmp(&fixture->text, &before->text, sizeof(fixture->text)) == 0,
        case_name, "source text changed");
    failed |= test_expect(
        fixture->owner.token == TEST_TOKEN &&
            fixture->owner.raw_base.value == raw &&
            fixture->owner.payload.value == payload &&
            fixture->owner.allocation_bytes ==
                fixture->context.expected_allocation_bytes &&
            fixture->owner.length_units == fixture->length_units &&
            fixture->owner.phase ==
                ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE &&
            fixture->owner.reserved == UINT32_C(0),
        case_name, "LIVE owner record is not exact");
    failed |= test_expect(
        fixture->guest_return.value == fixture->guest_descriptor.value,
        case_name, "descriptor return identity changed");
    failed |= test_expect(
        memcmp(
            &fixture->descriptor_view,
            &before->descriptor_view,
            sizeof(fixture->descriptor_view)) == 0 &&
        memcmp(
            &fixture->text_view,
            &before->text_view,
            sizeof(fixture->text_view)) == 0 &&
        memcmp(
            &fixture->heap_view,
            &before->heap_view,
            sizeof(fixture->heap_view)) == 0 &&
        memcmp(
            &fixture->effects,
            &before->effects,
            sizeof(fixture->effects)) == 0,
        case_name, "a control descriptor changed on success");
    return failed;
}

static void test_prepare_cleanup(test_fixture *fixture)
{
    test_reset_trace(fixture);
    fixture->context.expected_release_mode = TEST_RELEASE_CLEANUP;
    fixture->context.expected_owner_phase =
        ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;
    fixture->context.expected_release_token = fixture->owner.token;
    fixture->context.expected_release_raw = fixture->owner.raw_base;
    fixture->context.expected_allocation_bytes = fixture->owner.allocation_bytes;
    test_refresh_callback_observations(fixture);
}

static int test_verify_cleanup_success(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status status,
    int expect_hook)
{
    rome2_100f1bb0_owned_owner expected_owner =
        test_snapshot_storage.owner;
    int failed = 0;

    expected_owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;
    failed |= test_expect(
        status == ROME2_100F1BB0_OWNED_OK,
        case_name, "cleanup status changed");
    failed |= test_expect(
        fixture->context.event_count == (expect_hook ? UINT32_C(2) :
            UINT32_C(1)) &&
            fixture->context.events[0] == TEST_EVENT_RELEASE &&
            (!expect_hook || fixture->context.events[1] == TEST_EVENT_HOOK) &&
            fixture->context.allocate_calls == UINT32_C(0) &&
            fixture->context.release_calls == UINT32_C(1) &&
            fixture->context.hook_calls ==
                (expect_hook ? UINT32_C(1) : UINT32_C(0)) &&
            fixture->context.bad_observations == UINT32_C(0),
        case_name, "cleanup callback order or phase observation changed");
    failed |= test_expect(
        fixture->context.observed_release_token ==
                test_snapshot_storage.owner.token &&
            fixture->context.observed_release_raw.value ==
                test_snapshot_storage.owner.raw_base.value &&
            fixture->context.observed_release_bytes ==
                test_snapshot_storage.owner.allocation_bytes &&
            fixture->context.observed_release_class ==
                ROME2_PORT_100F1BB0_OWNED_ALLOCATION_CLASS,
        case_name, "release arguments changed");
    if (expect_hook) {
        failed |= test_expect(
            fixture->context.observed_hook_raw.value ==
                    test_snapshot_storage.owner.raw_base.value &&
                fixture->context.observed_hook_zero == UINT32_C(0),
            case_name, "release-hook arguments changed");
    }
    failed |= test_expect(
        memcmp(
            &fixture->owner, &expected_owner, sizeof(expected_owner)) == 0,
        case_name, "cleanup changed more than owner phase");
    failed |= test_expect(
        memcmp(
            &fixture->descriptor,
            &test_snapshot_storage.descriptor,
            sizeof(fixture->descriptor)) == 0 &&
        memcmp(
            &fixture->text,
            &test_snapshot_storage.text,
            sizeof(fixture->text)) == 0 &&
        memcmp(
            &fixture->heap,
            &test_snapshot_storage.heap,
            sizeof(fixture->heap)) == 0,
        case_name, "cleanup mutated guest bytes");
    return failed;
}

static int test_success_alignment_residues_and_cleanup(void)
{
    test_fixture *fixture = &test_fixture_storage;
    uint32_t residue;
    int failed = 0;

    for (residue = UINT32_C(0); residue < UINT32_C(4); ++residue) {
        char case_name[80];
        rome2_100f1bb0_owned_status status;

        (void)sprintf_s(
            case_name, sizeof(case_name),
            "length-one raw alignment residue %u", (unsigned int)residue);
        test_begin_case();
        test_init_fixture(fixture, UINT32_C(1), residue, 1);
        test_take_snapshot(fixture);
        status = test_call_build(fixture);
        failed |= test_verify_build_success(case_name, fixture, status);

        test_prepare_cleanup(fixture);
        test_take_snapshot(fixture);
        status = rome2_port_100f1cc0_cleanup_owned_utf16(
            &fixture->descriptor_view,
            fixture->guest_descriptor,
            &fixture->heap_view,
            &fixture->effects,
            &fixture->owner);
        failed |= test_verify_cleanup_success(
            case_name, fixture, status, 1);

        test_reset_trace(fixture);
        test_refresh_callback_observations(fixture);
        test_take_snapshot(fixture);
        status = rome2_port_100f1cc0_cleanup_owned_utf16(
            &fixture->descriptor_view,
            fixture->guest_descriptor,
            &fixture->heap_view,
            &fixture->effects,
            &fixture->owner);
        failed |= test_expect(
            status == ROME2_100F1BB0_OWNED_ALREADY_CONSUMED,
            case_name, "a consumed owner was not rejected");
        failed |= test_expect_preserved(case_name, fixture, 1);
    }
    return failed;
}

static int test_success_maximum_length_and_guest_endpoint(void)
{
    test_fixture *fixture = &test_fixture_storage;
    const uint32_t allocation_bytes =
        TEST_MAX_LENGTH * UINT32_C(2) + UINT32_C(10);
    const uint32_t raw = UINT32_MAX - allocation_bytes + UINT32_C(1);
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, TEST_MAX_LENGTH, raw & UINT32_C(3), 1);
    fixture->heap_view.guest_base = raw;
    fixture->heap_view.byte_count = allocation_bytes;
    fixture->context.grant.raw_base.value = raw;
    fixture->context.expected_release_raw.value = raw;
    test_refresh_callback_observations(fixture);
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    failed |= test_verify_build_success(
        "maximum length ending exactly at 2^32", fixture, status);
    failed |= test_expect(
        (uint64_t)raw + (uint64_t)allocation_bytes ==
            (UINT64_C(1) << 32),
        "maximum length ending exactly at 2^32",
        "test fixture no longer reaches the guest32 endpoint");

    test_prepare_cleanup(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->descriptor_view,
        fixture->guest_descriptor,
        &fixture->heap_view,
        &fixture->effects,
        &fixture->owner);
    failed |= test_verify_cleanup_success(
        "maximum length ending exactly at 2^32", fixture, status, 1);
    return failed;
}

static int test_first_terminator_and_optional_hook(void)
{
    test_fixture *fixture = &test_fixture_storage;
    uint32_t text_offset;
    uint32_t payload_offset;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(2), 0);
    fixture->max_units = UINT32_C(8);
    text_offset = fixture->guest_text.value - fixture->text_view.guest_base;
    test_write_u16_le(
        fixture->text.bytes + 1U + text_offset + UINT32_C(8),
        UINT16_C(0x7a7a));
    test_write_u16_le(
        fixture->text.bytes + 1U + text_offset + UINT32_C(10),
        UINT16_C(0x6b6b));
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    failed |= test_verify_build_success(
        "first terminator wins with trailing source units", fixture, status);

    payload_offset = fixture->owner.payload.value -
        fixture->heap_view.guest_base;
    test_write_u16_le(
        fixture->heap_view.host_base + payload_offset,
        UINT16_C(0xf00d));
    test_prepare_cleanup(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->descriptor_view,
        fixture->guest_descriptor,
        &fixture->heap_view,
        &fixture->effects,
        &fixture->owner);
    failed |= test_verify_cleanup_success(
        "cleanup permits mutable payload and absent optional hook",
        fixture, status, 0);
    return failed;
}

static int test_expect_failed_build(
    const char *case_name,
    test_fixture *fixture,
    rome2_100f1bb0_owned_status expected_status,
    uint32_t expected_release_calls)
{
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_refresh_callback_observations(fixture);
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    failed |= test_expect(
        status == expected_status,
        case_name, "post-allocation failure status changed");
    failed |= test_expect(
        fixture->context.allocate_calls == UINT32_C(1) &&
            fixture->context.release_calls == expected_release_calls &&
            fixture->context.hook_calls == UINT32_C(0) &&
            fixture->context.event_count ==
                UINT32_C(1) + expected_release_calls &&
            fixture->context.events[0] == TEST_EVENT_ALLOCATE &&
            (expected_release_calls == UINT32_C(0) ||
                fixture->context.events[1] == TEST_EVENT_RELEASE) &&
            fixture->context.bad_observations == UINT32_C(0),
        case_name, "allocation failure callback transcript changed");
    failed |= test_expect_preserved(case_name, fixture, 0);
    return failed;
}

static int test_allocation_denial_and_protocol_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    int failed = 0;

    test_init_fixture(fixture, UINT32_C(4), UINT32_C(0), 1);
    fixture->context.allocation_result =
        ROME2_100F1BB0_OWNED_GRANT_DENIED;
    memset(&fixture->context.grant, 0, sizeof(fixture->context.grant));
    failed |= test_expect_failed_build(
        "explicit allocation denial", fixture,
        ROME2_100F1BB0_OWNED_ALLOCATION_DENIED, UINT32_C(0));

    test_init_fixture(fixture, UINT32_C(4), UINT32_C(0), 1);
    fixture->context.allocation_result =
        (rome2_100f1bb0_owned_grant_result)2;
    memset(&fixture->context.grant, 0, sizeof(fixture->context.grant));
    failed |= test_expect_failed_build(
        "invalid allocation-result discriminator", fixture,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(0));

    test_init_fixture(fixture, UINT32_C(4), UINT32_C(0), 1);
    fixture->context.allocation_result =
        ROME2_100F1BB0_OWNED_GRANT_DENIED;
    fixture->context.expected_release_mode = TEST_RELEASE_COMPENSATION;
    failed |= test_expect_failed_build(
        "denial carrying a nonzero-token grant", fixture,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(1));

    test_init_fixture(fixture, UINT32_C(4), UINT32_C(0), 1);
    fixture->context.grant.token = UINT64_C(0);
    failed |= test_expect_failed_build(
        "granted result without authority token", fixture,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(0));

    test_init_fixture(fixture, UINT32_C(4), UINT32_C(0), 1);
    fixture->context.grant.reserved = UINT32_C(1);
    fixture->context.expected_release_mode = TEST_RELEASE_COMPENSATION;
    failed |= test_expect_failed_build(
        "granted result with nonzero reserved field", fixture,
        ROME2_100F1BB0_OWNED_EFFECT_PROTOCOL_INVALID, UINT32_C(1));
    return failed;
}

static int test_invalid_allocation_results_are_compensated(void)
{
    static const uint32_t invalid_raws[] = {
        UINT32_C(0),
        TEST_HEAP_BASE - UINT32_C(1),
        TEST_HEAP_BASE + TEST_HEAP_STORAGE_BYTES - UINT32_C(8),
        UINT32_C(0xfffffff8),
        UINT32_MAX
    };
    static const char *const labels[] = {
        "null raw allocation",
        "raw allocation below heap arena",
        "raw allocation truncated by heap arena",
        "raw-plus-eight reaches guest endpoint",
        "raw allocation at final guest byte"
    };
    test_fixture *fixture = &test_fixture_storage;
    size_t index;
    int failed = 0;

    for (index = 0U; index < sizeof(invalid_raws) / sizeof(invalid_raws[0]);
         ++index) {
        test_init_fixture(fixture, UINT32_C(4), UINT32_C(0), 1);
        fixture->context.grant.raw_base.value = invalid_raws[index];
        fixture->context.expected_release_raw =
            fixture->context.grant.raw_base;
        fixture->context.expected_release_mode = TEST_RELEASE_COMPENSATION;
        failed |= test_expect_failed_build(
            labels[index], fixture,
            ROME2_100F1BB0_OWNED_ALLOCATION_RESULT_INVALID,
            UINT32_C(1));
    }
    return failed;
}

static int test_expect_build_preflight_failure(
    const char *case_name,
    test_fixture *fixture,
    const rome2_guest_write_view *descriptor_view,
    rome2_guest_addr32 guest_descriptor,
    const rome2_guest_read_view *text_view,
    rome2_guest_addr32 guest_text,
    uint32_t max_units,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner_out,
    rome2_guest_addr32 *guest_return_out,
    rome2_100f1bb0_owned_status expected_status)
{
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_take_snapshot(fixture);
    status = rome2_port_100f1bb0_build_owned_utf16(
        descriptor_view,
        guest_descriptor,
        text_view,
        guest_text,
        max_units,
        heap_view,
        effects,
        owner_out,
        guest_return_out);
    failed |= test_expect(
        status == expected_status,
        case_name, "preflight status changed");
    failed |= test_expect(
        fixture->context.event_count == UINT32_C(0) &&
            fixture->context.allocate_calls == UINT32_C(0) &&
            fixture->context.release_calls == UINT32_C(0) &&
            fixture->context.hook_calls == UINT32_C(0),
        case_name, "preflight failure invoked an effect");
    failed |= test_expect_preserved(case_name, fixture, 1);
    return failed;
}

static int test_basic_build_preflight_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    int failed = 0;

#define TEST_BUILD_PREFLIGHT(label_, descriptor_, guest_descriptor_, text_, \
        guest_text_, max_, heap_, effects_, owner_, return_, status_) \
    do { \
        test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1); \
        failed |= test_expect_build_preflight_failure( \
            (label_), fixture, (descriptor_), (guest_descriptor_), (text_), \
            (guest_text_), (max_), (heap_), (effects_), (owner_), (return_), \
            (status_)); \
    } while (0)

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    failed |= test_expect_build_preflight_failure(
        "null descriptor view", fixture, NULL,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_BUILD_PREFLIGHT(
        "null text view", &fixture->descriptor_view,
        fixture->guest_descriptor, NULL, fixture->guest_text,
        fixture->max_units, &fixture->heap_view, &fixture->effects,
        &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_BUILD_PREFLIGHT(
        "null heap view", &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view, fixture->guest_text,
        fixture->max_units, NULL, &fixture->effects,
        &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_BUILD_PREFLIGHT(
        "null effects", &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view, fixture->guest_text,
        fixture->max_units, &fixture->heap_view, NULL,
        &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_BUILD_PREFLIGHT(
        "null owner output", &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view, fixture->guest_text,
        fixture->max_units, &fixture->heap_view, &fixture->effects,
        NULL, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_BUILD_PREFLIGHT(
        "null descriptor return output", &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view, fixture->guest_text,
        fixture->max_units, &fixture->heap_view, &fixture->effects,
        &fixture->owner, NULL,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->descriptor_view.host_base = NULL;
    failed |= test_expect_build_preflight_failure(
        "null descriptor host backing", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->text_view.host_base = NULL;
    failed |= test_expect_build_preflight_failure(
        "null text host backing", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->heap_view.host_base = NULL;
    failed |= test_expect_build_preflight_failure(
        "null heap host backing", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->effects.allocate = NULL;
    failed |= test_expect_build_preflight_failure(
        "null allocation effect", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->effects.release = NULL;
    failed |= test_expect_build_preflight_failure(
        "null compensation release effect", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->effects.context = NULL;
    failed |= test_expect_build_preflight_failure(
        "null bounded effect context", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->effects.context_byte_count = UINT64_C(0);
    failed |= test_expect_build_preflight_failure(
        "empty bounded effect context", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    TEST_BUILD_PREFLIGHT(
        "null guest descriptor", &fixture->descriptor_view,
        ((rome2_guest_addr32){UINT32_C(0)}), &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_NULL_ADDRESS);
    TEST_BUILD_PREFLIGHT(
        "null guest text", &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view,
        ((rome2_guest_addr32){UINT32_C(0)}), fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_NULL_ADDRESS);
    TEST_BUILD_PREFLIGHT(
        "zero-unit budget cannot contain nonempty text and terminator",
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, UINT32_C(0),
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_BUILD_PREFLIGHT(
        "one-unit budget cannot contain nonempty text and terminator",
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, UINT32_C(1),
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    TEST_BUILD_PREFLIGHT(
        "budget above finite ceiling", &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view, fixture->guest_text,
        ROME2_PORT_100F1BB0_OWNED_MAX_UNITS + UINT32_C(1),
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

#undef TEST_BUILD_PREFLIGHT
    return failed;
}

static int test_owner_and_text_preflight_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    uint32_t descriptor_offset;
    uint32_t text_offset;
    uint32_t short_count;
    int failed = 0;

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.token = UINT64_C(1);
    failed |= test_expect_build_preflight_failure(
        "owner token must begin zero", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.raw_base.value = UINT32_C(1);
    failed |= test_expect_build_preflight_failure(
        "owner raw identity must begin zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.payload.value = UINT32_C(1);
    failed |= test_expect_build_preflight_failure(
        "owner payload must begin zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.allocation_bytes = UINT32_C(1);
    failed |= test_expect_build_preflight_failure(
        "owner allocation size must begin zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.length_units = UINT32_C(1);
    failed |= test_expect_build_preflight_failure(
        "owner length must begin zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_LIVE;
    failed |= test_expect_build_preflight_failure(
        "owner phase must begin zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->owner.reserved = UINT32_C(1);
    failed |= test_expect_build_preflight_failure(
        "owner reserved field must begin zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    for (short_count = UINT32_C(0); short_count < UINT32_C(12);
         ++short_count) {
        char case_name[72];

        test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
        descriptor_offset = fixture->guest_descriptor.value -
            fixture->descriptor_view.guest_base;
        fixture->descriptor_view.byte_count =
            descriptor_offset + short_count;
        (void)sprintf_s(
            case_name, sizeof(case_name),
            "descriptor truncated to %u of 12 bytes",
            (unsigned int)short_count);
        failed |= test_expect_build_preflight_failure(
            case_name, fixture, &fixture->descriptor_view,
            fixture->guest_descriptor, &fixture->text_view,
            fixture->guest_text, fixture->max_units, &fixture->heap_view,
            &fixture->effects, &fixture->owner, &fixture->guest_return,
            ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    }

    for (short_count = UINT32_C(0); short_count < UINT32_C(8);
         ++short_count) {
        char case_name[72];

        test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
        text_offset = fixture->guest_text.value -
            fixture->text_view.guest_base;
        fixture->text_view.byte_count = text_offset + short_count;
        (void)sprintf_s(
            case_name, sizeof(case_name),
            "text truncated to %u of 8 required bytes",
            (unsigned int)short_count);
        failed |= test_expect_build_preflight_failure(
            case_name, fixture, &fixture->descriptor_view,
            fixture->guest_descriptor, &fixture->text_view,
            fixture->guest_text, fixture->max_units, &fixture->heap_view,
            &fixture->effects, &fixture->owner, &fixture->guest_return,
            ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    }

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    text_offset = fixture->guest_text.value - fixture->text_view.guest_base;
    test_write_u16_le(
        fixture->text.bytes + 1U + text_offset, UINT16_C(0));
    failed |= test_expect_build_preflight_failure(
        "empty source belongs to the nonowning seam", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    text_offset = fixture->guest_text.value - fixture->text_view.guest_base;
    test_write_u16_le(
        fixture->text.bytes + 1U + text_offset + UINT32_C(6),
        UINT16_C(0x7777));
    failed |= test_expect_build_preflight_failure(
        "terminator absent from declared budget", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    return failed;
}

static int test_build_range_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_guest_write_view bad_write;
    rome2_guest_read_view bad_read;
    rome2_100f1bb0_owned_effects bad_effects;
    uint32_t text_offset;
    int failed = 0;

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    bad_write = fixture->descriptor_view;
    bad_write.byte_count = UINT64_C(0x100000001);
    failed |= test_expect_build_preflight_failure(
        "descriptor view exceeds guest32 address space", fixture,
        &bad_write, fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    bad_read = fixture->text_view;
    bad_read.guest_base = UINT32_C(0xfffffff0);
    bad_read.byte_count = UINT64_C(32);
    failed |= test_expect_build_preflight_failure(
        "text view guest interval overflows", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &bad_read,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    bad_write = fixture->heap_view;
    bad_write.host_base = (uint8_t *)(uintptr_t)(UINTPTR_MAX - UINT32_C(7));
    bad_write.byte_count = UINT64_C(16);
    failed |= test_expect_build_preflight_failure(
        "heap host interval overflows", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &bad_write, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    bad_effects = fixture->effects;
    bad_effects.context =
        (void *)(uintptr_t)(UINTPTR_MAX - UINT32_C(7));
    bad_effects.context_byte_count = UINT64_C(16);
    failed |= test_expect_build_preflight_failure(
        "callback context host interval overflows", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &bad_effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    bad_write = fixture->descriptor_view;
    bad_write.guest_base = UINT32_C(0xfffffff8);
    bad_write.byte_count = UINT64_C(8);
    failed |= test_expect_build_preflight_failure(
        "descriptor span crosses guest endpoint", fixture,
        &bad_write, ((rome2_guest_addr32){UINT32_C(0xfffffff8)}),
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    test_init_fixture(fixture, UINT32_C(1), UINT32_C(0), 1);
    bad_read = fixture->text_view;
    bad_read.guest_base = UINT32_C(0xfffffffd);
    bad_read.byte_count = UINT64_C(3);
    bad_read.host_base = fixture->text.bytes + 1U;
    test_write_u16_le(fixture->text.bytes + 1U, UINT16_C(0x1234));
    failed |= test_expect_build_preflight_failure(
        "UTF-16 cursor crosses guest endpoint", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &bad_read,
        ((rome2_guest_addr32){UINT32_C(0xfffffffd)}), UINT32_C(2),
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    failed |= test_expect_build_preflight_failure(
        "descriptor identity below its view", fixture,
        &fixture->descriptor_view,
        ((rome2_guest_addr32){TEST_DESCRIPTOR_BASE - UINT32_C(1)}),
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OUT_OF_RANGE);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    text_offset = fixture->guest_text.value - fixture->text_view.guest_base;
    (void)text_offset;
    failed |= test_expect_build_preflight_failure(
        "text identity below its view", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view,
        ((rome2_guest_addr32){TEST_TEXT_BASE - UINT32_C(1)}),
        fixture->max_units, &fixture->heap_view, &fixture->effects,
        &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    return failed;
}

static int test_build_alignment_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    test_write_view_storage write_storage;
    test_read_view_storage read_storage;
    test_effects_storage effects_storage;
    test_owner_storage owner_storage;
    test_return_storage return_storage;
    rome2_guest_write_view *misaligned_write;
    rome2_guest_read_view *misaligned_read;
    rome2_100f1bb0_owned_effects *misaligned_effects;
    rome2_100f1bb0_owned_owner *misaligned_owner;
    rome2_guest_addr32 *misaligned_return;
    int failed = 0;

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    misaligned_write = (rome2_guest_write_view *)(void *)(
        write_storage.bytes + 1U);
    memcpy(misaligned_write, &fixture->descriptor_view,
        sizeof(*misaligned_write));
    failed |= test_expect_build_preflight_failure(
        "misaligned descriptor-view control", fixture, misaligned_write,
        fixture->guest_descriptor, &fixture->text_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    misaligned_read = (rome2_guest_read_view *)(void *)(
        read_storage.bytes + 1U);
    memcpy(misaligned_read, &fixture->text_view, sizeof(*misaligned_read));
    failed |= test_expect_build_preflight_failure(
        "misaligned text-view control", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        misaligned_read, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    misaligned_write = (rome2_guest_write_view *)(void *)(
        write_storage.bytes + 1U);
    memcpy(misaligned_write, &fixture->heap_view, sizeof(*misaligned_write));
    failed |= test_expect_build_preflight_failure(
        "misaligned heap-view control", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        misaligned_write, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    misaligned_effects = (rome2_100f1bb0_owned_effects *)(void *)(
        effects_storage.bytes + 1U);
    memcpy(misaligned_effects, &fixture->effects, sizeof(*misaligned_effects));
    failed |= test_expect_build_preflight_failure(
        "misaligned effects control", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, misaligned_effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    misaligned_owner = (rome2_100f1bb0_owned_owner *)(void *)(
        owner_storage.bytes + 1U);
    memset(misaligned_owner, 0, sizeof(*misaligned_owner));
    failed |= test_expect_build_preflight_failure(
        "misaligned owner output", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, misaligned_owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    misaligned_return = (rome2_guest_addr32 *)(void *)(
        return_storage.bytes + 1U);
    memcpy(misaligned_return, &fixture->guest_return,
        sizeof(*misaligned_return));
    failed |= test_expect_build_preflight_failure(
        "misaligned descriptor return output", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        misaligned_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    return failed;
}

static int test_build_alias_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_guest_read_view aliased_text;
    rome2_guest_write_view aliased_heap;
    rome2_100f1bb0_owned_effects embedded_effects;
    rome2_100f1bb0_owned_owner *embedded_owner;
    int failed = 0;

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    failed |= test_expect_build_preflight_failure(
        "descriptor and text view controls alias", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        (const rome2_guest_read_view *)(const void *)&fixture->descriptor_view,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    failed |= test_expect_build_preflight_failure(
        "effects and owner controls alias", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects,
        (rome2_100f1bb0_owned_owner *)(void *)&fixture->effects,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    failed |= test_expect_build_preflight_failure(
        "owner and return outputs alias", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        (rome2_guest_addr32 *)(void *)&fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    aliased_text = fixture->text_view;
    aliased_text.host_base = fixture->descriptor_view.host_base;
    failed |= test_expect_build_preflight_failure(
        "descriptor and text host backings overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &aliased_text,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    aliased_heap = fixture->heap_view;
    aliased_heap.host_base = fixture->text.bytes + 1U;
    failed |= test_expect_build_preflight_failure(
        "text and heap host backings overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &aliased_heap, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    aliased_heap = fixture->heap_view;
    aliased_heap.host_base = fixture->descriptor_view.host_base;
    failed |= test_expect_build_preflight_failure(
        "descriptor and heap host backings overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &aliased_heap, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    aliased_text = fixture->text_view;
    aliased_text.guest_base = fixture->descriptor_view.guest_base;
    failed |= test_expect_build_preflight_failure(
        "descriptor and text guest intervals overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &aliased_text,
        fixture->guest_text, fixture->max_units, &fixture->heap_view,
        &fixture->effects, &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    aliased_heap = fixture->heap_view;
    aliased_heap.guest_base = fixture->text_view.guest_base;
    failed |= test_expect_build_preflight_failure(
        "text and heap guest intervals overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &aliased_heap, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    aliased_heap = fixture->heap_view;
    aliased_heap.guest_base = fixture->descriptor_view.guest_base;
    failed |= test_expect_build_preflight_failure(
        "descriptor and heap guest intervals overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &aliased_heap, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    embedded_effects = fixture->effects;
    memcpy(
        fixture->descriptor_view.host_base + UINT32_C(63),
        &embedded_effects, sizeof(embedded_effects));
    failed |= test_expect_build_preflight_failure(
        "effects control aliases descriptor backing", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view,
        (const rome2_100f1bb0_owned_effects *)(const void *)(
            fixture->descriptor_view.host_base + UINT32_C(63)),
        &fixture->owner, &fixture->guest_return,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    embedded_owner = (rome2_100f1bb0_owned_owner *)(void *)(
        fixture->heap_view.host_base + UINT32_C(63));
    memset(embedded_owner, 0, sizeof(*embedded_owner));
    failed |= test_expect_build_preflight_failure(
        "owner control aliases heap backing", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, embedded_owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->effects.context = fixture->heap_view.host_base + UINT32_C(96);
    fixture->effects.context_byte_count = UINT64_C(32);
    failed |= test_expect_build_preflight_failure(
        "bounded context aliases heap backing", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    fixture->effects.context = &fixture->owner;
    fixture->effects.context_byte_count = sizeof(fixture->owner);
    failed |= test_expect_build_preflight_failure(
        "bounded context aliases owner control", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    test_init_fixture(fixture, UINT32_C(3), UINT32_C(0), 1);
    failed |= test_expect_build_preflight_failure(
        "return output aliases text backing", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        (rome2_guest_addr32 *)(void *)(fixture->text.bytes + UINT32_C(64)),
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    return failed;
}

static int test_touching_guest_view_boundaries(void)
{
    test_fixture *fixture = &test_fixture_storage;
    uint32_t raw_offset;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_init_fixture(fixture, UINT32_C(5), UINT32_C(3), 1);
    fixture->descriptor_view.guest_base = UINT32_C(0x00100000);
    fixture->text_view.guest_base = fixture->descriptor_view.guest_base +
        (uint32_t)fixture->descriptor_view.byte_count;
    fixture->heap_view.guest_base = fixture->text_view.guest_base +
        (uint32_t)fixture->text_view.byte_count;
    fixture->guest_descriptor.value = fixture->descriptor_view.guest_base +
        TEST_DESCRIPTOR_OFFSET;
    fixture->guest_text.value = fixture->text_view.guest_base +
        TEST_TEXT_OFFSET;
    raw_offset = test_raw_offset_for_residue(
        &fixture->heap_view, UINT32_C(3));
    fixture->context.grant.raw_base.value =
        fixture->heap_view.guest_base + raw_offset;
    fixture->context.expected_release_raw = fixture->context.grant.raw_base;
    test_refresh_callback_observations(fixture);
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    failed |= test_verify_build_success(
        "half-open guest views may touch at both boundaries",
        fixture, status);

    test_prepare_cleanup(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner);
    failed |= test_verify_cleanup_success(
        "half-open guest views may touch at both boundaries",
        fixture, status, 1);
    return failed;
}

static int test_heap_feasibility_preflight(void)
{
    test_fixture *fixture = &test_fixture_storage;
    const uint32_t length_units = UINT32_C(3);
    const uint32_t allocation_bytes =
        length_units * UINT32_C(2) + UINT32_C(10);
    uint32_t byte_count;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    for (byte_count = UINT32_C(0); byte_count < allocation_bytes;
         ++byte_count) {
        char case_name[72];

        test_init_fixture(fixture, length_units, UINT32_C(0), 1);
        fixture->heap_view.byte_count = byte_count;
        (void)sprintf_s(
            case_name, sizeof(case_name),
            "nonnull-base heap arena has %u of %u required bytes",
            (unsigned int)byte_count, (unsigned int)allocation_bytes);
        failed |= test_expect_build_preflight_failure(
            case_name, fixture, &fixture->descriptor_view,
            fixture->guest_descriptor, &fixture->text_view,
            fixture->guest_text, fixture->max_units, &fixture->heap_view,
            &fixture->effects, &fixture->owner, &fixture->guest_return,
            ROME2_100F1BB0_OWNED_OUT_OF_RANGE);
    }

    test_init_fixture(fixture, length_units, UINT32_C(0), 1);
    fixture->heap_view.guest_base = UINT32_C(0);
    fixture->heap_view.byte_count = allocation_bytes;
    failed |= test_expect_build_preflight_failure(
        "base-zero heap loses one byte to the null identity", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->text_view, fixture->guest_text, fixture->max_units,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        &fixture->guest_return, ROME2_100F1BB0_OWNED_OUT_OF_RANGE);

    test_begin_case();
    test_init_fixture(fixture, length_units, UINT32_C(0), 1);
    fixture->heap_view.byte_count = allocation_bytes;
    fixture->context.grant.raw_base.value = fixture->heap_view.guest_base;
    fixture->context.expected_release_raw = fixture->context.grant.raw_base;
    test_refresh_callback_observations(fixture);
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    failed |= test_verify_build_success(
        "nonnull-base exact-size heap arena", fixture, status);

    test_begin_case();
    test_init_fixture(fixture, length_units, UINT32_C(1), 1);
    fixture->heap_view.guest_base = UINT32_C(0);
    fixture->heap_view.byte_count = allocation_bytes + UINT32_C(1);
    fixture->context.grant.raw_base.value = UINT32_C(1);
    fixture->context.expected_release_raw = fixture->context.grant.raw_base;
    test_refresh_callback_observations(fixture);
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    failed |= test_verify_build_success(
        "base-zero heap with one extra byte admits raw identity one",
        fixture, status);
    return failed;
}

static int test_make_live_fixture(
    test_fixture *fixture,
    const char *case_name)
{
    rome2_100f1bb0_owned_status status;

    test_init_fixture(fixture, UINT32_C(4), UINT32_C(1), 1);
    test_take_snapshot(fixture);
    status = test_call_build(fixture);
    return test_verify_build_success(case_name, fixture, status);
}

static int test_expect_cleanup_failure(
    const char *case_name,
    test_fixture *fixture,
    const rome2_guest_write_view *descriptor_view,
    rome2_guest_addr32 guest_descriptor,
    const rome2_guest_write_view *heap_view,
    const rome2_100f1bb0_owned_effects *effects,
    rome2_100f1bb0_owned_owner *owner,
    rome2_100f1bb0_owned_status expected_status)
{
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    test_reset_trace(fixture);
    fixture->context.expected_release_mode = TEST_RELEASE_CLEANUP;
    fixture->context.expected_owner_phase =
        ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;
    test_refresh_callback_observations(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        descriptor_view, guest_descriptor, heap_view, effects, owner);
    failed |= test_expect(
        status == expected_status,
        case_name, "cleanup preflight status changed");
    failed |= test_expect(
        fixture->context.event_count == UINT32_C(0) &&
            fixture->context.allocate_calls == UINT32_C(0) &&
            fixture->context.release_calls == UINT32_C(0) &&
            fixture->context.hook_calls == UINT32_C(0),
        case_name, "invalid cleanup invoked an effect");
    failed |= test_expect_preserved(case_name, fixture, 1);
    return failed;
}

static int test_cleanup_owner_identity_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    uint32_t descriptor_offset;
    uint32_t header_offset;
    uint32_t terminator_offset;
    int failed = 0;

#define TEST_MUTATED_OWNER(label_, statement_) \
    do { \
        failed |= test_make_live_fixture(fixture, (label_)); \
        statement_; \
        failed |= test_expect_cleanup_failure( \
            (label_), fixture, &fixture->descriptor_view, \
            fixture->guest_descriptor, &fixture->heap_view, \
            &fixture->effects, &fixture->owner, \
            ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID); \
    } while (0)

    TEST_MUTATED_OWNER(
        "zero owner token", fixture->owner.token = UINT64_C(0));
    TEST_MUTATED_OWNER(
        "zero owner raw identity",
        fixture->owner.raw_base.value = UINT32_C(0));
    TEST_MUTATED_OWNER(
        "zero owner payload identity",
        fixture->owner.payload.value = UINT32_C(0));
    TEST_MUTATED_OWNER(
        "zero owner length", fixture->owner.length_units = UINT32_C(0));
    TEST_MUTATED_OWNER(
        "owner length reaches finite ceiling",
        fixture->owner.length_units =
            ROME2_PORT_100F1BB0_OWNED_MAX_UNITS);
    TEST_MUTATED_OWNER(
        "unknown owner phase", fixture->owner.phase = UINT32_C(3));
    TEST_MUTATED_OWNER(
        "nonzero owner reserved field",
        fixture->owner.reserved = UINT32_C(1));
    TEST_MUTATED_OWNER(
        "owner allocation size differs from formula",
        fixture->owner.allocation_bytes += UINT32_C(1));
    TEST_MUTATED_OWNER(
        "owner payload differs from alignment formula",
        fixture->owner.payload.value += UINT32_C(4));

#undef TEST_MUTATED_OWNER

    failed |= test_make_live_fixture(fixture, "consumed-owner setup");
    fixture->owner.phase = ROME2_PORT_100F1BB0_OWNED_OWNER_CONSUMED;
    failed |= test_expect_cleanup_failure(
        "consumed owner is one-shot", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_ALREADY_CONSUMED);

    failed |= test_make_live_fixture(fixture, "descriptor-length setup");
    descriptor_offset = fixture->guest_descriptor.value -
        fixture->descriptor_view.guest_base;
    test_write_u32_le(
        fixture->descriptor_view.host_base + descriptor_offset,
        fixture->owner.length_units + UINT32_C(1));
    failed |= test_expect_cleanup_failure(
        "descriptor first length differs from owner", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    failed |= test_make_live_fixture(fixture, "descriptor-capacity setup");
    descriptor_offset = fixture->guest_descriptor.value -
        fixture->descriptor_view.guest_base;
    test_write_u32_le(
        fixture->descriptor_view.host_base + descriptor_offset + 4U,
        fixture->owner.length_units + UINT32_C(1));
    failed |= test_expect_cleanup_failure(
        "descriptor second length differs from owner", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    failed |= test_make_live_fixture(fixture, "descriptor-payload setup");
    descriptor_offset = fixture->guest_descriptor.value -
        fixture->descriptor_view.guest_base;
    test_write_u32_le(
        fixture->descriptor_view.host_base + descriptor_offset + 8U,
        fixture->owner.payload.value + UINT32_C(4));
    failed |= test_expect_cleanup_failure(
        "descriptor payload differs from owner", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    failed |= test_make_live_fixture(fixture, "raw-header setup");
    header_offset = fixture->owner.payload.value - UINT32_C(4) -
        fixture->heap_view.guest_base;
    test_write_u32_le(
        fixture->heap_view.host_base + header_offset,
        fixture->owner.raw_base.value + UINT32_C(1));
    failed |= test_expect_cleanup_failure(
        "hidden raw header differs from owner", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    failed |= test_make_live_fixture(fixture, "terminator setup");
    terminator_offset = fixture->owner.payload.value -
        fixture->heap_view.guest_base +
        fixture->owner.length_units * UINT32_C(2);
    fixture->heap_view.host_base[terminator_offset] = UINT8_C(1);
    failed |= test_expect_cleanup_failure(
        "owned terminator is not literal zero", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);

    failed |= test_make_live_fixture(fixture, "truncated-allocation setup");
    fixture->heap_view.byte_count =
        (uint64_t)(fixture->owner.raw_base.value -
            fixture->heap_view.guest_base) +
        fixture->owner.allocation_bytes - UINT32_C(1);
    failed |= test_expect_cleanup_failure(
        "heap arena truncates owned allocation", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_OWNERSHIP_INVALID);
    return failed;
}

static int test_cleanup_basic_range_and_alias_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_guest_write_view bad_view;
    rome2_100f1bb0_owned_effects bad_effects;
    rome2_100f1bb0_owned_owner *embedded_owner;
    int failed = 0;

    failed |= test_make_live_fixture(fixture, "null cleanup descriptor setup");
    failed |= test_expect_cleanup_failure(
        "null cleanup descriptor view", fixture, NULL,
        fixture->guest_descriptor, &fixture->heap_view, &fixture->effects,
        &fixture->owner, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "null cleanup heap setup");
    failed |= test_expect_cleanup_failure(
        "null cleanup heap view", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, NULL, &fixture->effects,
        &fixture->owner, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "null cleanup effects setup");
    failed |= test_expect_cleanup_failure(
        "null cleanup effects", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->heap_view, NULL,
        &fixture->owner, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "null cleanup owner setup");
    failed |= test_expect_cleanup_failure(
        "null cleanup owner", fixture, &fixture->descriptor_view,
        fixture->guest_descriptor, &fixture->heap_view, &fixture->effects,
        NULL, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "null release setup");
    bad_effects = fixture->effects;
    bad_effects.release = NULL;
    failed |= test_expect_cleanup_failure(
        "cleanup requires release effect", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &bad_effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "null cleanup context setup");
    bad_effects = fixture->effects;
    bad_effects.context = NULL;
    failed |= test_expect_cleanup_failure(
        "cleanup requires bounded context", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &bad_effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "empty cleanup context setup");
    bad_effects = fixture->effects;
    bad_effects.context_byte_count = UINT64_C(0);
    failed |= test_expect_cleanup_failure(
        "cleanup rejects empty context span", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &bad_effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "overflow cleanup context setup");
    bad_effects = fixture->effects;
    bad_effects.context =
        (void *)(uintptr_t)(UINTPTR_MAX - UINT32_C(7));
    bad_effects.context_byte_count = UINT64_C(16);
    failed |= test_expect_cleanup_failure(
        "cleanup context host interval overflows", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &bad_effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    failed |= test_make_live_fixture(fixture, "null descriptor identity setup");
    failed |= test_expect_cleanup_failure(
        "cleanup rejects null descriptor identity", fixture,
        &fixture->descriptor_view,
        ((rome2_guest_addr32){UINT32_C(0)}), &fixture->heap_view,
        &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_NULL_ADDRESS);

    failed |= test_make_live_fixture(fixture, "short cleanup descriptor setup");
    bad_view = fixture->descriptor_view;
    bad_view.byte_count =
        (uint64_t)(fixture->guest_descriptor.value - bad_view.guest_base) +
        UINT64_C(11);
    failed |= test_expect_cleanup_failure(
        "cleanup descriptor is truncated", fixture, &bad_view,
        fixture->guest_descriptor, &fixture->heap_view, &fixture->effects,
        &fixture->owner, ROME2_100F1BB0_OWNED_OUT_OF_RANGE);

    failed |= test_make_live_fixture(fixture, "overflow cleanup view setup");
    bad_view = fixture->heap_view;
    bad_view.guest_base = UINT32_C(0xfffffff0);
    bad_view.byte_count = UINT64_C(32);
    failed |= test_expect_cleanup_failure(
        "cleanup heap guest interval overflows", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &bad_view,
        &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    failed |= test_make_live_fixture(fixture, "host-overflow cleanup view setup");
    bad_view = fixture->heap_view;
    bad_view.host_base =
        (uint8_t *)(uintptr_t)(UINTPTR_MAX - UINT32_C(7));
    bad_view.byte_count = UINT64_C(16);
    failed |= test_expect_cleanup_failure(
        "cleanup heap host interval overflows", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &bad_view,
        &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_RANGE_OVERFLOW);

    failed |= test_make_live_fixture(fixture, "cleanup control alias setup");
    failed |= test_expect_cleanup_failure(
        "cleanup effects and owner controls alias", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects,
        (rome2_100f1bb0_owned_owner *)(void *)&fixture->effects,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "cleanup backing alias setup");
    bad_view = fixture->heap_view;
    bad_view.host_base = fixture->descriptor_view.host_base;
    failed |= test_expect_cleanup_failure(
        "cleanup descriptor and heap host backings overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &bad_view,
        &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "cleanup logical alias setup");
    bad_view = fixture->heap_view;
    bad_view.guest_base = fixture->descriptor_view.guest_base;
    failed |= test_expect_cleanup_failure(
        "cleanup descriptor and heap guest intervals overlap", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor, &bad_view,
        &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "cleanup embedded owner setup");
    embedded_owner = (rome2_100f1bb0_owned_owner *)(void *)(
        fixture->heap_view.host_base + UINT32_C(63));
    memcpy(embedded_owner, &fixture->owner, sizeof(*embedded_owner));
    failed |= test_expect_cleanup_failure(
        "cleanup owner aliases heap backing", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, embedded_owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(fixture, "cleanup context alias setup");
    bad_effects = fixture->effects;
    bad_effects.context = &fixture->owner;
    bad_effects.context_byte_count = sizeof(fixture->owner);
    failed |= test_expect_cleanup_failure(
        "cleanup context aliases owner control", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &bad_effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    return failed;
}

static int test_cleanup_alignment_failures(void)
{
    test_fixture *fixture = &test_fixture_storage;
    test_write_view_storage write_storage;
    test_effects_storage effects_storage;
    test_owner_storage owner_storage;
    rome2_guest_write_view *misaligned_view;
    rome2_100f1bb0_owned_effects *misaligned_effects;
    rome2_100f1bb0_owned_owner *misaligned_owner;
    int failed = 0;

    failed |= test_make_live_fixture(
        fixture, "misaligned cleanup descriptor setup");
    misaligned_view = (rome2_guest_write_view *)(void *)(
        write_storage.bytes + 1U);
    memcpy(misaligned_view, &fixture->descriptor_view,
        sizeof(*misaligned_view));
    failed |= test_expect_cleanup_failure(
        "misaligned cleanup descriptor view", fixture, misaligned_view,
        fixture->guest_descriptor, &fixture->heap_view, &fixture->effects,
        &fixture->owner, ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(
        fixture, "misaligned cleanup heap setup");
    misaligned_view = (rome2_guest_write_view *)(void *)(
        write_storage.bytes + 1U);
    memcpy(misaligned_view, &fixture->heap_view, sizeof(*misaligned_view));
    failed |= test_expect_cleanup_failure(
        "misaligned cleanup heap view", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        misaligned_view, &fixture->effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(
        fixture, "misaligned cleanup effects setup");
    misaligned_effects = (rome2_100f1bb0_owned_effects *)(void *)(
        effects_storage.bytes + 1U);
    memcpy(misaligned_effects, &fixture->effects, sizeof(*misaligned_effects));
    failed |= test_expect_cleanup_failure(
        "misaligned cleanup effects", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, misaligned_effects, &fixture->owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);

    failed |= test_make_live_fixture(
        fixture, "misaligned cleanup owner setup");
    misaligned_owner = (rome2_100f1bb0_owned_owner *)(void *)(
        owner_storage.bytes + 1U);
    memcpy(misaligned_owner, &fixture->owner, sizeof(*misaligned_owner));
    failed |= test_expect_cleanup_failure(
        "misaligned cleanup owner", fixture,
        &fixture->descriptor_view, fixture->guest_descriptor,
        &fixture->heap_view, &fixture->effects, misaligned_owner,
        ROME2_100F1BB0_OWNED_BAD_ARGUMENT);
    return failed;
}

static int test_cleanup_does_not_require_allocator(void)
{
    test_fixture *fixture = &test_fixture_storage;
    rome2_100f1bb0_owned_status status;
    int failed = 0;

    test_begin_case();
    failed |= test_make_live_fixture(
        fixture, "release-only cleanup effects setup");
    fixture->effects.allocate = NULL;
    test_prepare_cleanup(fixture);
    test_take_snapshot(fixture);
    status = rome2_port_100f1cc0_cleanup_owned_utf16(
        &fixture->descriptor_view,
        fixture->guest_descriptor,
        &fixture->heap_view,
        &fixture->effects,
        &fixture->owner);
    failed |= test_verify_cleanup_success(
        "cleanup uses only release-side effects", fixture, status, 1);
    return failed;
}

int main(void)
{
    int failures = 0;

    failures += test_success_alignment_residues_and_cleanup();
    failures += test_success_maximum_length_and_guest_endpoint();
    failures += test_first_terminator_and_optional_hook();
    failures += test_allocation_denial_and_protocol_failures();
    failures += test_invalid_allocation_results_are_compensated();
    failures += test_basic_build_preflight_failures();
    failures += test_owner_and_text_preflight_failures();
    failures += test_build_range_failures();
    failures += test_build_alignment_failures();
    failures += test_build_alias_failures();
    failures += test_touching_guest_view_boundaries();
    failures += test_heap_feasibility_preflight();
    failures += test_cleanup_owner_identity_failures();
    failures += test_cleanup_basic_range_and_alias_failures();
    failures += test_cleanup_alignment_failures();
    failures += test_cleanup_does_not_require_allocator();

    if (failures != 0) {
        (void)fprintf(
            stderr,
            "100f1bb0 owned UTF-16 runtime: %d failure(s) across %u cases\n",
            failures, (unsigned int)test_case_count);
        return 1;
    }
    (void)printf(
        "100f1bb0 owned UTF-16 runtime: %u cases passed\n",
        (unsigned int)test_case_count);
    return 0;
}
