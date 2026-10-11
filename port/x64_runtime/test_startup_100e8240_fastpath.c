#include "ported_100e8240_fastpath.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_GUEST_BASE UINT32_C(0x3000)
#define ROME2_TEST_MEMORY_BYTES 256
#define ROME2_TEST_TLS_VALUE_OFFSET UINT32_C(0x04)
#define ROME2_TEST_TLS_INDEX_OFFSET UINT32_C(0x08)
#define ROME2_TEST_TLS_SLOT_OFFSET UINT32_C(0x0c)
#define ROME2_TEST_THRESHOLD_OFFSET UINT32_C(0x10)
#define ROME2_TEST_DEFAULT_TLS_VECTOR UINT32_C(0x300c)
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

static int rome2_test_views_equal(
    const rome2_guest_read_view *first,
    const rome2_guest_read_view *second)
{
    return
        first->host_base == second->host_base &&
        first->guest_base == second->guest_base &&
        first->byte_count == second->byte_count;
}

static void rome2_test_put_u32(uint8_t *bytes, size_t offset, uint32_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

static void rome2_test_setup(
    rome2_test_memory *memory,
    rome2_guest_read_view *view,
    uint32_t tls_index,
    uint32_t slot_value,
    uint32_t tls_value,
    uint32_t threshold)
{
    memset(memory->bytes, 0xa5, sizeof(memory->bytes));
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_TLS_VALUE_OFFSET, tls_value);
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_TLS_INDEX_OFFSET, tls_index);
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_TLS_SLOT_OFFSET, slot_value);
    rome2_test_put_u32(
        memory->bytes, ROME2_TEST_THRESHOLD_OFFSET, threshold);
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

static int rome2_test_success(
    const char *label,
    uint32_t tls_index,
    uint32_t slot_value,
    uint32_t tls_value,
    uint32_t threshold,
    uint32_t guest_tls_vector)
{
    rome2_test_memory actual;
    rome2_test_memory snapshot;
    rome2_guest_read_view view;
    rome2_guest_read_view view_snapshot;
    rome2_guest_addr32 index_cell;
    rome2_guest_addr32 output;
    rome2_guest_addr32 threshold_cell;
    int failures = 0;

    rome2_test_setup(
        &actual, &view, tls_index, slot_value, tls_value, threshold);
    memcpy(snapshot.bytes, actual.bytes, sizeof(actual.bytes));
    view_snapshot = view;
    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);

    failures += rome2_test_expect_status(label,
        rome2_port_100e8240_crash_record_fastpath(
            &view,
            rome2_test_address(guest_tls_vector),
            index_cell,
            threshold_cell,
            &output),
        ROME2_GUEST_OK);
    if (memcmp(actual.bytes, snapshot.bytes, sizeof(actual.bytes)) != 0) {
        fprintf(stderr, "FAIL %s: memory changed\n", label);
        ++failures;
    }
    if (!rome2_test_views_equal(&view, &view_snapshot)) {
        fprintf(stderr, "FAIL %s: view changed\n", label);
        ++failures;
    }
    if (output.value != ROME2_PORT_100E8240_CRASH_RECORD) {
        fprintf(stderr, "FAIL %s: crash record identity differs\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_successes(void)
{
    int failures = 0;

    failures += rome2_test_success(
        "tls value above threshold", 0, ROME2_TEST_GUEST_BASE, 1, 0,
        ROME2_TEST_DEFAULT_TLS_VECTOR);
    failures += rome2_test_success(
        "tls value equal to threshold", 0, ROME2_TEST_GUEST_BASE, 7, 7,
        ROME2_TEST_DEFAULT_TLS_VECTOR);
    failures += rome2_test_success(
        "negative tls value above negative threshold", 0,
        ROME2_TEST_GUEST_BASE, UINT32_C(0xfffffffb),
        UINT32_C(0xfffffff6), ROME2_TEST_DEFAULT_TLS_VECTOR);
    failures += rome2_test_success(
        "nonzero tls index slot", 1, ROME2_TEST_GUEST_BASE, 2, 0,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    failures += rome2_test_success(
        "cross-sign signed accept", 0, ROME2_TEST_GUEST_BASE, 0,
        UINT32_C(0xffffffff), ROME2_TEST_DEFAULT_TLS_VECTOR);
    return failures;
}

static int rome2_test_preserved_failure(
    const char *label,
    rome2_test_memory *memory,
    rome2_guest_read_view *view,
    rome2_guest_addr32 guest_tls_vector,
    rome2_guest_addr32 index_cell,
    rome2_guest_addr32 threshold_cell,
    rome2_guest_status expected_status)
{
    rome2_test_memory snapshot;
    rome2_guest_read_view view_snapshot = *view;
    rome2_guest_addr32 output = rome2_test_address(
        ROME2_TEST_OUTPUT_SENTINEL);
    int failures = 0;

    memcpy(snapshot.bytes, memory->bytes, sizeof(snapshot.bytes));
    failures += rome2_test_expect_status(label,
        rome2_port_100e8240_crash_record_fastpath(
            view, guest_tls_vector, index_cell, threshold_cell, &output),
        expected_status);
    if (memcmp(memory->bytes, snapshot.bytes, sizeof(memory->bytes)) != 0) {
        fprintf(stderr, "FAIL %s: memory changed on failure\n", label);
        ++failures;
    }
    if (!rome2_test_views_equal(view, &view_snapshot)) {
        fprintf(stderr, "FAIL %s: view changed on failure\n", label);
        ++failures;
    }
    if (output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL %s: output changed on failure\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_failure_matrix(void)
{
    rome2_test_memory memory;
    rome2_guest_read_view view;
    rome2_guest_addr32 guest_tls_vector;
    rome2_guest_addr32 index_cell;
    rome2_guest_addr32 threshold_cell;
    int failures = 0;

    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);

#define ROME2_RESET() \
    rome2_test_setup(&memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0)
#define ROME2_FAIL(label, expected) \
    (failures += rome2_test_preserved_failure( \
        (label), &memory, &view, guest_tls_vector, index_cell, threshold_cell, \
        (expected)))

    ROME2_RESET();
    rome2_test_put_u32(memory.bytes, ROME2_TEST_TLS_VALUE_OFFSET, 0);
    rome2_test_put_u32(memory.bytes, ROME2_TEST_THRESHOLD_OFFSET, 1);
    ROME2_FAIL("excluded crash route rejected", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_VALUE_OFFSET, UINT32_C(0xfffffff6));
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_THRESHOLD_OFFSET, UINT32_C(0xfffffffb));
    ROME2_FAIL(
        "negative tls value below negative threshold rejected",
        ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_VALUE_OFFSET, UINT32_C(0xffffffff));
    ROME2_FAIL("cross-sign signed reject", ROME2_GUEST_BAD_ARGUMENT);

    ROME2_RESET();
    guest_tls_vector.value = 0;
    ROME2_FAIL("null tls vector", ROME2_GUEST_NULL_ADDRESS);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);
    ROME2_RESET();
    index_cell.value = 0;
    ROME2_FAIL("null tls index cell", ROME2_GUEST_NULL_ADDRESS);
    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    ROME2_RESET();
    threshold_cell.value = 0;
    ROME2_FAIL("null threshold cell", ROME2_GUEST_NULL_ADDRESS);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);

    ROME2_RESET();
    index_cell.value = ROME2_TEST_GUEST_BASE - 1;
    ROME2_FAIL("tls index cell below view", ROME2_GUEST_OUT_OF_RANGE);
    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    ROME2_RESET();
    threshold_cell.value = ROME2_TEST_GUEST_BASE - 1;
    ROME2_FAIL("threshold cell below view", ROME2_GUEST_OUT_OF_RANGE);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);

    ROME2_RESET();
    index_cell.value = ROME2_TEST_GUEST_BASE + sizeof(memory.bytes) - 2;
    ROME2_FAIL("truncated tls index cell", ROME2_GUEST_OUT_OF_RANGE);
    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    ROME2_RESET();
    threshold_cell.value = ROME2_TEST_GUEST_BASE + sizeof(memory.bytes) - 2;
    ROME2_FAIL("truncated threshold cell", ROME2_GUEST_OUT_OF_RANGE);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);

    ROME2_RESET();
    threshold_cell.value = index_cell.value;
    ROME2_FAIL("overlapping index and threshold cells",
        ROME2_GUEST_BAD_ARGUMENT);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);

    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_INDEX_OFFSET, UINT32_C(0x40000000));
    ROME2_FAIL("tls index overflow rejected", ROME2_GUEST_RANGE_OVERFLOW);
    ROME2_RESET();
    guest_tls_vector.value = UINT32_C(0xfffffffc);
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_INDEX_OFFSET, 1);
    ROME2_FAIL("tls vector slot overflow rejected", ROME2_GUEST_RANGE_OVERFLOW);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);
    ROME2_RESET();
    guest_tls_vector.value = ROME2_TEST_GUEST_BASE - 8;
    ROME2_FAIL("tls slot below view", ROME2_GUEST_OUT_OF_RANGE);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);
    ROME2_RESET();
    guest_tls_vector.value = ROME2_TEST_GUEST_BASE + sizeof(memory.bytes) - 2;
    ROME2_FAIL("truncated tls slot cell", ROME2_GUEST_OUT_OF_RANGE);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);

    ROME2_RESET();
    guest_tls_vector.value = index_cell.value;
    ROME2_FAIL("tls slot aliases index cell", ROME2_GUEST_BAD_ARGUMENT);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);
    ROME2_RESET();
    guest_tls_vector.value = threshold_cell.value;
    ROME2_FAIL("tls slot aliases threshold cell", ROME2_GUEST_BAD_ARGUMENT);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);

    ROME2_RESET();
    rome2_test_put_u32(memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET, 0);
    ROME2_FAIL("null tls data", ROME2_GUEST_NULL_ADDRESS);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET, ROME2_TEST_GUEST_BASE - 1);
    ROME2_FAIL("tls data below view", ROME2_GUEST_OUT_OF_RANGE);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET, UINT32_C(0xfffffffd));
    ROME2_FAIL("tls data overflow rejected", ROME2_GUEST_RANGE_OVERFLOW);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET,
        ROME2_TEST_GUEST_BASE + (uint32_t)sizeof(memory.bytes) - 5);
    ROME2_FAIL("truncated tls value cell", ROME2_GUEST_OUT_OF_RANGE);

    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET - 4);
    ROME2_FAIL("tls value aliases index cell", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_SLOT_OFFSET - 4);
    ROME2_FAIL("tls value aliases slot cell", ROME2_GUEST_BAD_ARGUMENT);
    ROME2_RESET();
    rome2_test_put_u32(
        memory.bytes, ROME2_TEST_TLS_SLOT_OFFSET,
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET - 4);
    ROME2_FAIL("tls value aliases threshold cell",
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
    rome2_guest_read_view view;
    rome2_guest_read_view view_snapshot;
    rome2_guest_addr32 guest_tls_vector;
    rome2_guest_addr32 index_cell;
    rome2_guest_addr32 output;
    rome2_guest_addr32 threshold_cell;
    rome2_guest_status status;
    rome2_guest_read_view *view_in_memory;
    int failures = 0;

    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);

    rome2_test_setup(
        &memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0);
    memcpy(snapshot.bytes, memory.bytes, sizeof(snapshot.bytes));
    view_snapshot = view;
    status = rome2_port_100e8240_crash_record_fastpath(
        &view, guest_tls_vector, index_cell, threshold_cell,
        (rome2_guest_addr32 *)(void *)(memory.bytes + 4));
    failures += rome2_test_expect_status(
        "output aliases guest view", status, ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(memory.bytes, snapshot.bytes, sizeof(memory.bytes)) != 0 ||
        !rome2_test_views_equal(&view, &view_snapshot)) {
        fprintf(stderr, "FAIL output aliases guest view: state changed\n");
        ++failures;
    }

    rome2_test_setup(
        &memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0);
    view_snapshot = view;
    status = rome2_port_100e8240_crash_record_fastpath(
        &view, guest_tls_vector, index_cell, threshold_cell,
        (rome2_guest_addr32 *)(void *)&view.guest_base);
    failures += rome2_test_expect_status(
        "output aliases view descriptor", status,
        ROME2_GUEST_BAD_ARGUMENT);
    if (!rome2_test_views_equal(&view, &view_snapshot)) {
        fprintf(stderr, "FAIL output aliases view descriptor: view changed\n");
        ++failures;
    }

    rome2_test_setup(
        &memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0);
    view_in_memory = (rome2_guest_read_view *)(void *)(memory.bytes + 0x40);
    *view_in_memory = view;
    memcpy(snapshot.bytes, memory.bytes, sizeof(snapshot.bytes));
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    status = rome2_port_100e8240_crash_record_fastpath(
        view_in_memory, guest_tls_vector, index_cell, threshold_cell, &output);
    failures += rome2_test_expect_status(
        "view descriptor aliases guest bytes", status,
        ROME2_GUEST_BAD_ARGUMENT);
    if (memcmp(memory.bytes, snapshot.bytes, sizeof(memory.bytes)) != 0 ||
        output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr,
            "FAIL view descriptor aliases guest bytes: state changed\n");
        ++failures;
    }

    rome2_test_setup(
        &memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0);
    view.host_base = (const uint8_t *)(const void *)(&view) + 1;
    view.byte_count = 1;
    view_snapshot = view;
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    status = rome2_port_100e8240_crash_record_fastpath(
        &view, guest_tls_vector, index_cell, threshold_cell, &output);
    failures += rome2_test_expect_status(
        "guest bytes begin inside view descriptor", status,
        ROME2_GUEST_BAD_ARGUMENT);
    if (!rome2_test_views_equal(&view, &view_snapshot) ||
        output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr,
            "FAIL guest bytes begin inside view descriptor: state changed\n");
        ++failures;
    }

    rome2_test_setup(
        &memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0);
    view.host_base = (uint8_t *)(UINTPTR_MAX - 1);
    view.byte_count = 4;
    view_snapshot = view;
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    status = rome2_port_100e8240_crash_record_fastpath(
        &view, guest_tls_vector, index_cell, threshold_cell, &output);
    failures += rome2_test_expect_status(
        "host numeric range overflow", status, ROME2_GUEST_RANGE_OVERFLOW);
    if (!rome2_test_views_equal(&view, &view_snapshot) ||
        output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr,
            "FAIL host numeric range overflow: state changed\n");
        ++failures;
    }

    return failures;
}

static int rome2_test_bad_arguments(void)
{
    rome2_test_memory memory;
    rome2_guest_read_view view;
    rome2_guest_addr32 guest_tls_vector;
    rome2_guest_addr32 index_cell;
    rome2_guest_addr32 output;
    rome2_guest_addr32 threshold_cell;
    int failures = 0;

    rome2_test_setup(
        &memory, &view, 0, ROME2_TEST_GUEST_BASE, 1, 0);
    guest_tls_vector = rome2_test_address(ROME2_TEST_DEFAULT_TLS_VECTOR);
    index_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_TLS_INDEX_OFFSET);
    threshold_cell = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_THRESHOLD_OFFSET);
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("null view",
        rome2_port_100e8240_crash_record_fastpath(
            NULL, guest_tls_vector, index_cell, threshold_cell, &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_test_expect_status("null output",
        rome2_port_100e8240_crash_record_fastpath(
            &view, guest_tls_vector, index_cell, threshold_cell, NULL),
        ROME2_GUEST_BAD_ARGUMENT);
    view.host_base = NULL;
    failures += rome2_test_expect_status("null host base",
        rome2_port_100e8240_crash_record_fastpath(
            &view, guest_tls_vector, index_cell, threshold_cell, &output),
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

    failures += rome2_test_successes();
    failures += rome2_test_failure_matrix();
    failures += rome2_test_alias_and_host_range_failures();
    failures += rome2_test_bad_arguments();

    if (failures != 0) {
        fprintf(stderr, "startup 100e8240 fastpath tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100e8240 fastpath tests: pass");
    return 0;
}
