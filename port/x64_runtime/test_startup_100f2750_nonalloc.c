#include "ported_100f2750_nonalloc.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_GUEST_BASE UINT32_C(0x3000)
#define ROME2_TEST_MEMORY_BYTES 256
#define ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET UINT32_C(0x10)
#define ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET UINT32_C(0x20)
#define ROME2_TEST_DESTINATION_PAYLOAD_OFFSET UINT32_C(0x80)
#define ROME2_TEST_SOURCE_PAYLOAD_OFFSET UINT32_C(0xc0)
#define ROME2_TEST_OUTPUT_SENTINEL UINT32_C(0xc35aa53c)

typedef union rome2_test_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_MEMORY_BYTES];
} rome2_test_memory;

static rome2_guest_addr32 rome2_test_address(uint32_t value)
{
    rome2_guest_addr32 result;

    result.value = value;
    return result;
}

static void rome2_test_put_u32(uint8_t *bytes, size_t offset, uint32_t value)
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

static void rome2_test_setup(
    rome2_test_memory *memory,
    rome2_guest_write_view *view,
    uint32_t source_count,
    uint32_t destination_capacity)
{
    size_t copy_bytes = ((size_t)source_count + 1) * 2;
    size_t index;

    memset(memory->bytes, 0xa5, sizeof(memory->bytes));
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET,
        UINT32_C(0xdddddddd));
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 4,
        destination_capacity);
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_PAYLOAD_OFFSET);
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET, source_count);
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 4,
        UINT32_C(0xeeeeeeee));
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_PAYLOAD_OFFSET);
    for (index = 0; index < copy_bytes &&
         ROME2_TEST_SOURCE_PAYLOAD_OFFSET + index < sizeof(memory->bytes);
         ++index) {
        memory->bytes[ROME2_TEST_SOURCE_PAYLOAD_OFFSET + index] =
            (uint8_t)(UINT8_C(0x31) + (uint8_t)index);
    }
    if (copy_bytes >= 2 &&
        ROME2_TEST_SOURCE_PAYLOAD_OFFSET + copy_bytes <= sizeof(memory->bytes)) {
        /* The original copies this final unit without interpreting it. */
        memory->bytes[ROME2_TEST_SOURCE_PAYLOAD_OFFSET + copy_bytes - 2] = 0xef;
        memory->bytes[ROME2_TEST_SOURCE_PAYLOAD_OFFSET + copy_bytes - 1] = 0xbe;
    }

    view->host_base = memory->bytes;
    view->guest_base = ROME2_TEST_GUEST_BASE;
    view->byte_count = sizeof(memory->bytes);
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

static int rome2_test_success_count(
    const char *label,
    uint32_t source_count,
    uint32_t max_units)
{
    rome2_test_memory actual;
    rome2_test_memory expected;
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 destination;
    rome2_guest_addr32 output;
    rome2_guest_addr32 source;
    size_t copy_bytes = ((size_t)source_count + 1) * 2;
    int failures = 0;

    rome2_test_setup(&actual, &view, source_count, source_count);
    memcpy(expected.bytes, actual.bytes, sizeof(expected.bytes));
    memcpy(
        expected.bytes + ROME2_TEST_DESTINATION_PAYLOAD_OFFSET,
        expected.bytes + ROME2_TEST_SOURCE_PAYLOAD_OFFSET,
        copy_bytes);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET,
        source_count);
    view_snapshot = view;
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);

    failures += rome2_test_expect_status(label,
        rome2_port_100f2750_copy_nonallocating_short(
            &view, destination, source, max_units, &output),
        ROME2_GUEST_OK);
    if (memcmp(actual.bytes, expected.bytes, sizeof(actual.bytes)) != 0) {
        fprintf(stderr, "FAIL %s: exact byte oracle differs\n", label);
        ++failures;
    }
    if (memcmp(&view, &view_snapshot, sizeof(view)) != 0) {
        fprintf(stderr, "FAIL %s: view changed\n", label);
        ++failures;
    }
    if (output.value != destination.value) {
        fprintf(stderr, "FAIL %s: return identity differs\n", label);
        ++failures;
    }
    if (rome2_test_get_u32(
            actual.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 4) !=
            source_count ||
        rome2_test_get_u32(
            actual.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8) !=
            ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_PAYLOAD_OFFSET) {
        fprintf(stderr, "FAIL %s: capacity or payload identity changed\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_preserved_failure(
    const char *label,
    rome2_guest_write_view *view,
    rome2_guest_addr32 destination,
    rome2_guest_addr32 source,
    uint32_t max_units,
    rome2_guest_status expected_status,
    rome2_test_memory *memory)
{
    rome2_test_memory snapshot;
    rome2_guest_write_view view_snapshot = *view;
    rome2_guest_addr32 output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    int failures = 0;

    memcpy(snapshot.bytes, memory->bytes, sizeof(snapshot.bytes));
    failures += rome2_test_expect_status(label,
        rome2_port_100f2750_copy_nonallocating_short(
            view, destination, source, max_units, &output),
        expected_status);
    if (memcmp(memory->bytes, snapshot.bytes, sizeof(memory->bytes)) != 0) {
        fprintf(stderr, "FAIL %s: memory changed on failure\n", label);
        ++failures;
    }
    if (memcmp(view, &view_snapshot, sizeof(*view)) != 0) {
        fprintf(stderr, "FAIL %s: view changed on failure\n", label);
        ++failures;
    }
    if (output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL %s: output changed on failure\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_identical_descriptor_noop(void)
{
    rome2_test_memory memory;
    rome2_test_memory snapshot;
    rome2_guest_write_view view;
    rome2_guest_addr32 descriptor;
    rome2_guest_addr32 output;
    int failures = 0;

    rome2_test_setup(&memory, &view, 4, 4);
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8, 0);
    memcpy(snapshot.bytes, memory.bytes, sizeof(snapshot.bytes));
    descriptor = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("identical descriptor no-op",
        rome2_port_100f2750_copy_nonallocating_short(
            &view, descriptor, descriptor, 5, &output),
        ROME2_GUEST_OK);
    if (memcmp(memory.bytes, snapshot.bytes, sizeof(memory.bytes)) != 0 ||
        output.value != descriptor.value) {
        fprintf(stderr, "FAIL identical descriptor no-op: state differs\n");
        ++failures;
    }
    return failures;
}

static int rome2_test_payload_adjacency_success(void)
{
    rome2_test_memory actual;
    rome2_test_memory expected;
    rome2_guest_write_view view;
    rome2_guest_addr32 destination;
    rome2_guest_addr32 output;
    rome2_guest_addr32 source;
    const size_t copy_bytes = 10;
    const size_t adjacent_offset =
        ROME2_TEST_SOURCE_PAYLOAD_OFFSET + copy_bytes;
    int failures = 0;

    rome2_test_setup(&actual, &view, 4, 4);
    rome2_test_put_u32(
        actual.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE + (uint32_t)adjacent_offset);
    memcpy(expected.bytes, actual.bytes, sizeof(expected.bytes));
    memcpy(
        expected.bytes + adjacent_offset,
        expected.bytes + ROME2_TEST_SOURCE_PAYLOAD_OFFSET,
        copy_bytes);
    rome2_test_put_u32(
        expected.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET, 4);
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("payload adjacency accepted",
        rome2_port_100f2750_copy_nonallocating_short(
            &view, destination, source, 5, &output),
        ROME2_GUEST_OK);
    if (memcmp(actual.bytes, expected.bytes, sizeof(actual.bytes)) != 0 ||
        output.value != destination.value) {
        fprintf(stderr, "FAIL payload adjacency accepted: state differs\n");
        ++failures;
    }
    return failures;
}

static int rome2_test_failure_matrix(void)
{
    rome2_test_memory memory;
    rome2_guest_write_view view;
    rome2_guest_addr32 destination;
    rome2_guest_addr32 source;
    int failures = 0;

    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);

#define ROME2_RESET() rome2_test_setup(&memory, &view, 4, 4)
#define ROME2_FAIL(label, expected) \
    (failures += rome2_test_preserved_failure( \
        (label), &view, destination, source, 5, (expected), &memory))

    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "zero external bound", &view, destination, source, 0,
        ROME2_GUEST_BAD_ARGUMENT, &memory);
    ROME2_RESET();
    failures += rome2_test_preserved_failure(
        "helper threshold exceeded", &view, destination, source, 16,
        ROME2_GUEST_BAD_ARGUMENT, &memory);
    ROME2_RESET();
    rome2_test_put_u32(memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET, 5);
    ROME2_FAIL("count equals external bound", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 4, 3);
    ROME2_FAIL("allocation branch rejected", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 4, 3);
    destination = source;
    ROME2_FAIL("identical descriptor allocation branch rejected",
        ROME2_GUEST_BAD_ARGUMENT);
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);

    ROME2_RESET();
    destination.value = 0;
    ROME2_FAIL("null destination descriptor", ROME2_GUEST_NULL_ADDRESS);
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);
    ROME2_RESET();
    source.value = 0;
    ROME2_FAIL("null source descriptor", ROME2_GUEST_NULL_ADDRESS);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);
    ROME2_RESET();
    destination.value = ROME2_TEST_GUEST_BASE - 1;
    ROME2_FAIL("descriptor below view", ROME2_GUEST_OUT_OF_RANGE);
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);

    ROME2_RESET();
    view.byte_count = ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 11;
    ROME2_FAIL("truncated destination descriptor", ROME2_GUEST_OUT_OF_RANGE);
    ROME2_RESET();
    view.byte_count = ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 11;
    ROME2_FAIL("truncated source descriptor", ROME2_GUEST_OUT_OF_RANGE);
    ROME2_RESET();
    source.value = destination.value + 4;
    ROME2_FAIL("overlapping descriptors", ROME2_GUEST_BAD_ARGUMENT);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);

    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8, 0);
    ROME2_FAIL("null destination payload", ROME2_GUEST_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8, 0);
    ROME2_FAIL("null source payload", ROME2_GUEST_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE - 1);
    ROME2_FAIL("payload below view", ROME2_GUEST_OUT_OF_RANGE);

    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_MEMORY_BYTES - 9);
    ROME2_FAIL("truncated destination payload", ROME2_GUEST_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_MEMORY_BYTES - 9);
    ROME2_FAIL("truncated source payload", ROME2_GUEST_OUT_OF_RANGE);

    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_PAYLOAD_OFFSET + 2);
    ROME2_FAIL("overlapping payloads", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8,
        destination.value);
    ROME2_FAIL("payload overlaps destination descriptor",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8,
        source.value);
    ROME2_FAIL("payload overlaps source descriptor", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET + 8,
        source.value);
    ROME2_FAIL("destination payload overlaps source descriptor",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET + 8,
        destination.value);
    ROME2_FAIL("source payload overlaps destination descriptor",
        ROME2_GUEST_BAD_ARGUMENT);

    ROME2_RESET();
    view.guest_base = UINT32_MAX - UINT32_C(7);
    view.byte_count = 9;
    ROME2_FAIL("guest view end overflow", ROME2_GUEST_RANGE_OVERFLOW);

#undef ROME2_FAIL
#undef ROME2_RESET
    return failures;
}

static int rome2_test_alias_and_host_range_failures(void)
{
    rome2_test_memory memory;
    rome2_test_memory snapshot;
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 destination;
    rome2_guest_addr32 source;
    rome2_guest_addr32 output;
    rome2_guest_status status;
    rome2_guest_write_view *view_in_memory;
    int failures = 0;

    rome2_test_setup(&memory, &view, 4, 4);
    memcpy(snapshot.bytes, memory.bytes, sizeof(snapshot.bytes));
    view_snapshot = view;
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);
    status = rome2_port_100f2750_copy_nonallocating_short(
        &view, destination, source, 5,
        (rome2_guest_addr32 *)(void *)(memory.bytes + 4));
    failures += rome2_test_expect_status(
        "output aliases guest view", status, ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(memory.bytes, snapshot.bytes, sizeof(memory.bytes)) != 0 ||
        memcmp(&view, &view_snapshot, sizeof(view)) != 0) {
        fprintf(stderr, "FAIL output aliases guest view: state changed\n");
        ++failures;
    }

    rome2_test_setup(&memory, &view, 4, 4);
    view_snapshot = view;
    status = rome2_port_100f2750_copy_nonallocating_short(
        &view, destination, source, 5,
        (rome2_guest_addr32 *)(void *)&view.guest_base);
    failures += rome2_test_expect_status(
        "output aliases view descriptor", status, ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(&view, &view_snapshot, sizeof(view)) != 0) {
        fprintf(stderr, "FAIL output aliases view descriptor: view changed\n");
        ++failures;
    }

    rome2_test_setup(&memory, &view, 4, 4);
    view_in_memory = (rome2_guest_write_view *)(void *)(memory.bytes + 0x40);
    *view_in_memory = view;
    memcpy(snapshot.bytes, memory.bytes, sizeof(snapshot.bytes));
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    status = rome2_port_100f2750_copy_nonallocating_short(
        view_in_memory, destination, source, 5, &output);
    failures += rome2_test_expect_status(
        "view descriptor aliases guest bytes", status,
        ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(memory.bytes, snapshot.bytes, sizeof(memory.bytes)) != 0 ||
        output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL view descriptor aliases guest bytes: state changed\n");
        ++failures;
    }

    rome2_test_setup(&memory, &view, 4, 4);
    view.host_base = (uint8_t *)(UINTPTR_MAX - 1);
    view.byte_count = 4;
    view_snapshot = view;
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    status = rome2_port_100f2750_copy_nonallocating_short(
        &view, destination, source, 5, &output);
    failures += rome2_test_expect_status(
        "host numeric range overflow", status, ROME2_GUEST_RANGE_OVERFLOW);
    if (memcmp(&view, &view_snapshot, sizeof(view)) != 0 ||
        output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL host numeric range overflow: state changed\n");
        ++failures;
    }

    return failures;
}

static int rome2_test_bad_arguments(void)
{
    rome2_test_memory memory;
    rome2_guest_write_view view;
    rome2_guest_addr32 destination;
    rome2_guest_addr32 source;
    rome2_guest_addr32 output;
    int failures = 0;

    rome2_test_setup(&memory, &view, 0, 0);
    destination = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_DESTINATION_DESCRIPTOR_OFFSET);
    source = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_SOURCE_DESCRIPTOR_OFFSET);
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("null view",
        rome2_port_100f2750_copy_nonallocating_short(
            NULL, destination, source, 1, &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_test_expect_status("null output",
        rome2_port_100f2750_copy_nonallocating_short(
            &view, destination, source, 1, NULL),
        ROME2_GUEST_BAD_ARGUMENT);
    view.host_base = NULL;
    failures += rome2_test_expect_status("null host base",
        rome2_port_100f2750_copy_nonallocating_short(
            &view, destination, source, 1, &output),
        ROME2_GUEST_BAD_ARGUMENT);
    if (output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL bad arguments: output changed\n");
        ++failures;
    }
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success_count("zero-count two-byte copy", 0, 1);
    failures += rome2_test_success_count(
        "ordinary unterminated final-unit copy", 4, 5);
    failures += rome2_test_success_count(
        "thirty-byte helper-boundary copy", 14,
        ROME2_PORT_100F2750_MAX_UNITS);
    failures += rome2_test_identical_descriptor_noop();
    failures += rome2_test_payload_adjacency_success();
    failures += rome2_test_failure_matrix();
    failures += rome2_test_alias_and_host_range_failures();
    failures += rome2_test_bad_arguments();

    if (failures != 0) {
        fprintf(stderr, "startup 100f2750 nonalloc tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100f2750 nonalloc tests: pass");
    return 0;
}
