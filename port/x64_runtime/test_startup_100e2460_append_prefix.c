#include "ported_100e2460_append_prefix.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_GUEST_BASE UINT32_C(0x1000)
#define ROME2_TEST_MEMORY_BYTES 256
#define ROME2_TEST_VECTOR_OFFSET UINT32_C(0x20)
#define ROME2_TEST_BACKING_OFFSET UINT32_C(0x80)

typedef union rome2_test_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_MEMORY_BYTES];
} rome2_test_memory;

#define ROME2_TEST_ALIAS_VIEW_OFFSET 0x40

typedef struct rome2_test_alias_memory {
    uint8_t prefix[ROME2_TEST_ALIAS_VIEW_OFFSET];
    rome2_guest_write_view view;
    uint8_t suffix[
        ROME2_TEST_MEMORY_BYTES - ROME2_TEST_ALIAS_VIEW_OFFSET -
        sizeof(rome2_guest_write_view)];
} rome2_test_alias_memory;

_Static_assert(
    offsetof(rome2_test_alias_memory, view) == ROME2_TEST_ALIAS_VIEW_OFFSET,
    "embedded write view must start at the intended guest-byte offset");
_Static_assert(sizeof(rome2_test_alias_memory) == ROME2_TEST_MEMORY_BYTES,
    "embedded-view fixture must preserve the standard byte-view size");

static rome2_guest_addr32 rome2_test_address(uint32_t value)
{
    rome2_guest_addr32 address;
    address.value = value;
    return address;
}

static void rome2_test_put_u32(
    uint8_t *bytes,
    size_t offset,
    uint32_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

static uint32_t rome2_test_get_u32(const uint8_t *bytes, size_t offset)
{
    return
        (uint32_t)bytes[offset] |
        ((uint32_t)bytes[offset + 1] << 8) |
        ((uint32_t)bytes[offset + 2] << 16) |
        ((uint32_t)bytes[offset + 3] << 24);
}

static void rome2_test_setup_bytes(
    uint8_t *bytes,
    size_t byte_count,
    rome2_guest_write_view *view,
    uint32_t capacity,
    uint32_t count,
    uint32_t backing)
{
    memset(bytes, 0xa5, byte_count);
    rome2_test_put_u32(
        bytes, ROME2_TEST_VECTOR_OFFSET, UINT32_C(0xfeedface));
    rome2_test_put_u32(
        bytes, ROME2_TEST_VECTOR_OFFSET + 4, capacity);
    rome2_test_put_u32(
        bytes, ROME2_TEST_VECTOR_OFFSET + 8, count);
    rome2_test_put_u32(
        bytes, ROME2_TEST_VECTOR_OFFSET + 12, backing);
    view->host_base = bytes;
    view->guest_base = ROME2_TEST_GUEST_BASE;
    view->byte_count = byte_count;
}

static void rome2_test_setup(
    rome2_test_memory *memory,
    rome2_guest_write_view *view,
    uint32_t capacity,
    uint32_t count,
    uint32_t backing)
{
    rome2_test_setup_bytes(
        memory->bytes,
        sizeof(memory->bytes),
        view,
        capacity,
        count,
        backing);
}

static int rome2_test_views_equal(
    const rome2_guest_write_view *first,
    const rome2_guest_write_view *second)
{
    return
        first->host_base == second->host_base &&
        first->guest_base == second->guest_base &&
        first->byte_count == second->byte_count;
}

static int rome2_test_expect_status(
    const char *label,
    rome2_guest_status actual,
    rome2_guest_status expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: status=%d expected=%d\n",
        label, (int)actual, (int)expected);
    return 1;
}

static int rome2_test_success(
    const char *label,
    uint32_t guest_base,
    uint64_t byte_count,
    uint32_t capacity,
    uint32_t count,
    uint32_t backing,
    uint32_t element)
{
    rome2_test_memory actual;
    rome2_test_memory expected;
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 vector;
    uint64_t append_offset;
    int failures = 0;

    rome2_test_setup(&actual, &view, capacity, count, backing);
    view.guest_base = guest_base;
    view.byte_count = byte_count;
    memcpy(expected.bytes, actual.bytes, sizeof(expected.bytes));
    append_offset =
        (uint64_t)backing + (uint64_t)count * UINT64_C(4) - guest_base;
    rome2_test_put_u32(expected.bytes, (size_t)append_offset, element);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_VECTOR_OFFSET + 8, count + UINT32_C(1));
    view_snapshot = view;
    vector = rome2_test_address(guest_base + ROME2_TEST_VECTOR_OFFSET);

    failures += rome2_test_expect_status(label,
        rome2_port_100e2460_append_preallocated_prefix(
            &view, vector, rome2_test_address(element)),
        ROME2_GUEST_OK);
    if (memcmp(actual.bytes, expected.bytes, sizeof(actual.bytes)) != 0) {
        fprintf(stderr, "FAIL %s: exact two-cell byte oracle differs\n", label);
        ++failures;
    }
    if (!rome2_test_views_equal(&view, &view_snapshot)) {
        fprintf(stderr, "FAIL %s: view descriptor changed\n", label);
        ++failures;
    }
    if (rome2_test_get_u32(
            actual.bytes, ROME2_TEST_VECTOR_OFFSET + 4) != capacity ||
        rome2_test_get_u32(
            actual.bytes, ROME2_TEST_VECTOR_OFFSET + 8) != count + 1) {
        fprintf(stderr, "FAIL %s: capacity/count postcondition differs\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_preserved_failure(
    const char *label,
    rome2_guest_write_view *view,
    rome2_guest_addr32 vector,
    rome2_guest_addr32 element,
    rome2_guest_status expected_status,
    rome2_test_memory *memory)
{
    rome2_test_memory snapshot;
    rome2_guest_write_view view_snapshot = *view;
    int failures = 0;

    memcpy(snapshot.bytes, memory->bytes, sizeof(snapshot.bytes));
    failures += rome2_test_expect_status(label,
        rome2_port_100e2460_append_preallocated_prefix(
            view, vector, element),
        expected_status);
    if (memcmp(memory->bytes, snapshot.bytes, sizeof(memory->bytes)) != 0) {
        fprintf(stderr, "FAIL %s: guest bytes changed on failure\n", label);
        ++failures;
    }
    if (!rome2_test_views_equal(view, &view_snapshot)) {
        fprintf(stderr, "FAIL %s: view descriptor changed on failure\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_success_matrix(void)
{
    int failures = 0;

    failures += rome2_test_success(
        "ordinary preallocated append",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, 4, 2,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET,
        UINT32_C(0x12345678));
    failures += rome2_test_success(
        "append fills final capacity slot",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, 4, 3,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET,
        UINT32_C(0xffffffff));
    failures += rome2_test_success(
        "zero-count append stores null element bits",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, 1, 0,
        ROME2_TEST_GUEST_BASE,
        0);
    failures += rome2_test_success(
        "append slot immediately precedes vector",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, 1, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET - 4,
        UINT32_C(0x0badf00d));
    failures += rome2_test_success(
        "append slot immediately follows vector",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, 1, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET +
            ROME2_PORT_100E2460_VECTOR_BYTES,
        UINT32_C(0xc001d00d));
    failures += rome2_test_success(
        "vector ends exactly at view end",
        ROME2_TEST_GUEST_BASE,
        ROME2_TEST_VECTOR_OFFSET + ROME2_PORT_100E2460_VECTOR_BYTES,
        1,
        0,
        ROME2_TEST_GUEST_BASE,
        UINT32_C(0x13579bdf));
    failures += rome2_test_success(
        "slot ends exactly at view end",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, 1, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_MEMORY_BYTES - 4,
        UINT32_C(0x89abcdef));
    failures += rome2_test_success(
        "slot ends at guest address-space end",
        UINT32_MAX - UINT32_C(255), ROME2_TEST_MEMORY_BYTES, 1, 0,
        UINT32_MAX - UINT32_C(3),
        UINT32_C(0x76543210));
    failures += rome2_test_success(
        "maximum capacity remains unchanged",
        ROME2_TEST_GUEST_BASE, ROME2_TEST_MEMORY_BYTES, UINT32_MAX, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET,
        UINT32_C(0x01020304));
    return failures;
}

static int rome2_test_failure_matrix(void)
{
    rome2_test_memory memory;
    rome2_guest_write_view view;
    rome2_guest_addr32 element = rome2_test_address(UINT32_C(0x12345678));
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET);
    int failures = 0;

#define ROME2_RESET(capacity, count, backing) \
    rome2_test_setup(&memory, &view, (capacity), (count), (backing))
#define ROME2_FAIL(label, expected) \
    (failures += rome2_test_preserved_failure( \
        (label), &view, vector, element, (expected), &memory))

    ROME2_RESET(2, 2, ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    ROME2_FAIL("count equals capacity rejects growth route",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(2, 3, ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    ROME2_FAIL("count above capacity rejects malformed growth route",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(0, 0, 0);
    ROME2_FAIL("zero capacity rejects allocator route",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(1, 1, 0);
    ROME2_FAIL("branch rejection precedes null backing",
        ROME2_GUEST_BAD_ARGUMENT);

    ROME2_RESET(1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    vector.value = 0;
    ROME2_FAIL("null vector", ROME2_GUEST_NULL_ADDRESS);
    vector.value = UINT32_MAX - UINT32_C(7);
    ROME2_FAIL("vector header guest overflow", ROME2_GUEST_RANGE_OVERFLOW);
    vector.value = ROME2_TEST_GUEST_BASE - 1;
    ROME2_FAIL("vector below view", ROME2_GUEST_OUT_OF_RANGE);
    vector.value = ROME2_TEST_GUEST_BASE + ROME2_TEST_MEMORY_BYTES - 15;
    ROME2_FAIL("truncated vector header", ROME2_GUEST_OUT_OF_RANGE);
    vector.value = ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET;

    ROME2_RESET(1, 0, 0);
    ROME2_FAIL("null backing", ROME2_GUEST_NULL_ADDRESS);
    ROME2_RESET(1, 0, ROME2_TEST_GUEST_BASE - 1);
    ROME2_FAIL("backing below view", ROME2_GUEST_OUT_OF_RANGE);
    ROME2_RESET(
        UINT32_C(0x40000001), UINT32_C(0x40000000),
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    ROME2_FAIL("scaled index guest overflow", ROME2_GUEST_RANGE_OVERFLOW);
    ROME2_RESET(2, 1, UINT32_MAX - UINT32_C(3));
    ROME2_FAIL("backing plus scaled index guest overflow",
        ROME2_GUEST_RANGE_OVERFLOW);
    ROME2_RESET(
        1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_MEMORY_BYTES - 3);
    ROME2_FAIL("truncated append slot", ROME2_GUEST_OUT_OF_RANGE);
    ROME2_RESET(
        1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_MEMORY_BYTES);
    ROME2_FAIL("append starts exactly at view end", ROME2_GUEST_OUT_OF_RANGE);

    ROME2_RESET(1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET);
    ROME2_FAIL("append slot aliases vector self cell",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(
        1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET + 4);
    ROME2_FAIL("append slot aliases capacity cell",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(
        1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET + 8);
    ROME2_FAIL("append slot aliases count cell",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(
        1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET + 12);
    ROME2_FAIL("append slot aliases backing cell",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET(
        1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET + 1);
    ROME2_FAIL("unaligned append slot overlaps vector",
        ROME2_GUEST_BAD_ARGUMENT);

    ROME2_RESET(1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    view.guest_base = UINT32_MAX - UINT32_C(7);
    view.byte_count = 9;
    ROME2_FAIL("guest view end overflow", ROME2_GUEST_RANGE_OVERFLOW);

    ROME2_RESET(1, 0, ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    view.byte_count = 0;
    vector.value = ROME2_TEST_GUEST_BASE;
    ROME2_FAIL("empty view", ROME2_GUEST_OUT_OF_RANGE);

#undef ROME2_FAIL
#undef ROME2_RESET
    return failures;
}

static int rome2_test_view_alias_and_host_failures(void)
{
    rome2_test_alias_memory alias_memory;
    rome2_test_memory memory;
    rome2_test_memory snapshot;
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_write_view *view_in_memory;
    uint8_t *alias_bytes = (uint8_t *)(void *)&alias_memory;
    rome2_guest_addr32 element = rome2_test_address(UINT32_C(0x12345678));
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET);
    rome2_guest_status status;
    int failures = 0;

    view_in_memory = &alias_memory.view;
    rome2_test_setup_bytes(
        alias_bytes, sizeof(alias_memory), view_in_memory, 1, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    memcpy(snapshot.bytes, alias_bytes, sizeof(snapshot.bytes));
    status = rome2_port_100e2460_append_preallocated_prefix(
        view_in_memory, vector, element);
    failures += rome2_test_expect_status(
        "view descriptor aliases guest bytes", status,
        ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(alias_bytes, snapshot.bytes, sizeof(snapshot.bytes)) != 0) {
        fprintf(stderr,
            "FAIL view descriptor aliases guest bytes: state changed\n");
        ++failures;
    }

    rome2_test_setup(
        &memory, &view, 1, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    view.host_base = (uint8_t *)(UINTPTR_MAX - 1);
    view.byte_count = 4;
    view_snapshot = view;
    status = rome2_port_100e2460_append_preallocated_prefix(
        &view, vector, element);
    failures += rome2_test_expect_status(
        "host numeric range overflow", status,
        ROME2_GUEST_RANGE_OVERFLOW);
    if (!rome2_test_views_equal(&view, &view_snapshot)) {
        fprintf(stderr, "FAIL host numeric range overflow: view changed\n");
        ++failures;
    }
    return failures;
}

static int rome2_test_bad_arguments(void)
{
    rome2_test_memory memory;
    rome2_guest_write_view view;
    rome2_guest_addr32 element = rome2_test_address(0);
    rome2_guest_addr32 vector = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_VECTOR_OFFSET);
    int failures = 0;

    rome2_test_setup(
        &memory, &view, 1, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_BACKING_OFFSET);
    failures += rome2_test_expect_status(
        "null view",
        rome2_port_100e2460_append_preallocated_prefix(
            NULL, vector, element),
        ROME2_GUEST_BAD_ARGUMENT);
    view.host_base = NULL;
    failures += rome2_test_expect_status(
        "null host base",
        rome2_port_100e2460_append_preallocated_prefix(
            &view, vector, element),
        ROME2_GUEST_BAD_ARGUMENT);
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_matrix();
    failures += rome2_test_failure_matrix();
    failures += rome2_test_view_alias_and_host_failures();
    failures += rome2_test_bad_arguments();

    if (failures != 0) {
        fprintf(stderr,
            "startup 100e2460 append-prefix tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100e2460 append-prefix tests: pass");
    return 0;
}
