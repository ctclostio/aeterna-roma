#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "ported_100f1c10_triplet.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define ROME2_OUTPUT_SENTINEL UINT32_C(0xa5a55a5a)

static const uint8_t rome2_expected_triplet[12] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x90, 0x40, 0xaf, 0x11
};

static rome2_guest_addr32 rome2_guest_address(uint32_t value)
{
    rome2_guest_addr32 result;

    result.value = value;
    return result;
}

static int rome2_expect_status(
    const char *label,
    rome2_guest_status actual,
    rome2_guest_status expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: status=%d expected=%d\n", label,
        (int)actual, (int)expected);
    return 1;
}

static int rome2_expect_output(
    const char *label,
    rome2_guest_addr32 actual,
    uint32_t expected)
{
    if (actual.value == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: output=0x%08x expected=0x%08x\n", label,
        (unsigned int)actual.value, (unsigned int)expected);
    return 1;
}

static int rome2_expect_bytes(
    const char *label,
    const uint8_t *actual,
    const uint8_t *expected,
    size_t byte_count)
{
    if (memcmp(actual, expected, byte_count) == 0) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: bytes changed unexpectedly\n", label);
    return 1;
}

static int rome2_test_exact_aligned(void)
{
    uint8_t bytes[40];
    uint8_t expected[40];
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(bytes, 0xa5, sizeof(bytes));
    memcpy(expected, bytes, sizeof(expected));
    memcpy(expected + 8, rome2_expected_triplet, sizeof(rome2_expected_triplet));
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x1000);
    view.byte_count = (uint64_t)sizeof(bytes);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);

    failures += rome2_expect_status("aligned exact",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x1008)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("aligned exact", output,
        UINT32_C(0x1008));
    failures += rome2_expect_bytes("aligned exact", bytes, expected,
        sizeof(bytes));
    return failures;
}

static int rome2_test_exact_and_unaligned_views(void)
{
    uint8_t exact[12];
    uint8_t unaligned[15];
    uint8_t expected_unaligned[15];
    uint8_t offset_end[20];
    uint8_t expected_offset_end[20];
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(exact, 0xa5, sizeof(exact));
    view.host_base = exact;
    view.guest_base = UINT32_C(0x2000);
    view.byte_count = (uint64_t)sizeof(exact);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("exact 12-byte view",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x2000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("exact 12-byte view", output,
        UINT32_C(0x2000));
    failures += rome2_expect_bytes("exact 12-byte view", exact,
        rome2_expected_triplet, sizeof(exact));

    memset(unaligned, 0x5a, sizeof(unaligned));
    memcpy(expected_unaligned, unaligned, sizeof(expected_unaligned));
    memcpy(expected_unaligned + 1, rome2_expected_triplet,
        sizeof(rome2_expected_triplet));
    view.host_base = unaligned + 1;
    view.guest_base = UINT32_C(0x2001);
    view.byte_count = UINT64_C(12);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("unaligned host and guest",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x2001)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("unaligned host and guest", output,
        UINT32_C(0x2001));
    failures += rome2_expect_bytes("unaligned host and guest", unaligned,
        expected_unaligned, sizeof(unaligned));

    memset(offset_end, 0x5a, sizeof(offset_end));
    memcpy(expected_offset_end, offset_end, sizeof(expected_offset_end));
    memcpy(expected_offset_end + 8, rome2_expected_triplet,
        sizeof(rome2_expected_triplet));
    view.host_base = offset_end;
    view.guest_base = UINT32_C(0x2800);
    view.byte_count = (uint64_t)sizeof(offset_end);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("offset span ends exactly at view end",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x2808)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("offset span ends exactly at view end",
        output, UINT32_C(0x2808));
    failures += rome2_expect_bytes("offset span ends exactly at view end",
        offset_end, expected_offset_end, sizeof(offset_end));
    return failures;
}

static int rome2_test_adjacent_and_guest_top(void)
{
    uint8_t adjacent[24];
    uint8_t expected[24];
    uint8_t top[12];
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(adjacent, 0xa5, sizeof(adjacent));
    memcpy(expected, rome2_expected_triplet, sizeof(rome2_expected_triplet));
    memcpy(expected + 12, rome2_expected_triplet,
        sizeof(rome2_expected_triplet));
    view.host_base = adjacent;
    view.guest_base = UINT32_C(0x3000);
    view.byte_count = (uint64_t)sizeof(adjacent);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("first adjacent destination",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x3000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_status("second adjacent destination",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x300c)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("second adjacent destination", output,
        UINT32_C(0x300c));
    failures += rome2_expect_bytes("adjacent destinations", adjacent,
        expected, sizeof(adjacent));

    memset(top, 0xa5, sizeof(top));
    view.host_base = top;
    view.guest_base = UINT32_C(0xfffffff4);
    view.byte_count = UINT64_C(12);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("view ending at 2^32",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0xfffffff4)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("view ending at 2^32", output,
        UINT32_C(0xfffffff4));
    failures += rome2_expect_bytes("view ending at 2^32", top,
        rome2_expected_triplet, sizeof(top));
    return failures;
}

static int rome2_expect_preserved_failure(
    const char *label,
    rome2_guest_write_view *view,
    rome2_guest_addr32 destination,
    rome2_guest_status expected_status,
    uint8_t *bytes,
    size_t byte_count)
{
    uint8_t snapshot[32];
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 output;
    int failures = 0;

    if (byte_count > sizeof(snapshot)) {
        fprintf(stderr, "FAIL %s: internal snapshot is too small\n", label);
        return 1;
    }
    memcpy(snapshot, bytes, byte_count);
    memcpy(&view_snapshot, view, sizeof(view_snapshot));
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status(label,
        rome2_port_100f1c10_initialize_triplet(view, destination, &output),
        expected_status);
    failures += rome2_expect_output(label, output, ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_bytes(label, bytes, snapshot, byte_count);
    failures += rome2_expect_bytes(label, (const uint8_t *)view,
        (const uint8_t *)&view_snapshot, sizeof(view_snapshot));
    return failures;
}

static int rome2_test_failure_preservation(void)
{
    uint8_t bytes[32];
    uint8_t snapshot[32];
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 output;
    unsigned int short_size;
    int failures = 0;

    memset(bytes, 0xa5, sizeof(bytes));
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x4000);
    view.byte_count = (uint64_t)sizeof(bytes);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);

    failures += rome2_expect_status("null view",
        rome2_port_100f1c10_initialize_triplet(
            NULL, rome2_guest_address(UINT32_C(0x4000)), &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_output("null view", output,
        ROME2_OUTPUT_SENTINEL);
    memcpy(snapshot, bytes, sizeof(snapshot));
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status("null output",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x4000)), NULL),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("null output", bytes, snapshot,
        sizeof(bytes));
    failures += rome2_expect_bytes("null output", (const uint8_t *)&view,
        (const uint8_t *)&view_snapshot, sizeof(view));

    view.host_base = NULL;
    failures += rome2_expect_preserved_failure("null host", &view,
        rome2_guest_address(UINT32_C(0x4000)), ROME2_GUEST_BAD_ARGUMENT,
        bytes, sizeof(bytes));
    view.host_base = bytes;

    failures += rome2_expect_preserved_failure("null guest destination", &view,
        rome2_guest_address(0), ROME2_GUEST_NULL_ADDRESS, bytes,
        sizeof(bytes));
    failures += rome2_expect_preserved_failure("destination below base", &view,
        rome2_guest_address(UINT32_C(0x3fff)), ROME2_GUEST_OUT_OF_RANGE,
        bytes, sizeof(bytes));

    for (short_size = 0; short_size < 12; ++short_size) {
        char label[48];

        (void)sprintf_s(label, sizeof(label), "short span %u", short_size);
        view.byte_count = (uint64_t)short_size;
        failures += rome2_expect_preserved_failure(label, &view,
            rome2_guest_address(UINT32_C(0x4000)),
            ROME2_GUEST_OUT_OF_RANGE, bytes, sizeof(bytes));
    }

    view.guest_base = UINT32_C(0xfffffff5);
    view.byte_count = UINT64_C(12);
    failures += rome2_expect_preserved_failure("guest view end overflow", &view,
        rome2_guest_address(UINT32_C(0xfffffff5)),
        ROME2_GUEST_RANGE_OVERFLOW, bytes, sizeof(bytes));
    view.guest_base = 0;
    view.byte_count = UINT64_C(0x100000001);
    failures += rome2_expect_preserved_failure("view wider than guest space",
        &view, rome2_guest_address(UINT32_C(1)),
        ROME2_GUEST_RANGE_OVERFLOW, bytes, sizeof(bytes));

    view.guest_base = UINT32_C(0xfffffff0);
    view.byte_count = UINT64_C(16);
    failures += rome2_expect_preserved_failure("high guest leaves 11 bytes",
        &view, rome2_guest_address(UINT32_C(0xfffffff5)),
        ROME2_GUEST_OUT_OF_RANGE, bytes, sizeof(bytes));

    view.host_base = (uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)5);
    view.guest_base = UINT32_C(0x4000);
    view.byte_count = UINT64_C(12);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("numeric host interval overflow",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x4000)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_expect_output("numeric host interval overflow", output,
        ROME2_OUTPUT_SENTINEL);

    view.host_base = bytes;
    view.guest_base = UINT32_C(0x4000);
    view.byte_count = UINT64_C(12);
    memcpy(snapshot, bytes, sizeof(snapshot));
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status("numeric output interval overflow",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x4000)),
            (rome2_guest_addr32 *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1)),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_expect_bytes("numeric output interval overflow", bytes,
        snapshot, sizeof(bytes));
    failures += rome2_expect_bytes("numeric output interval overflow",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));

    view.host_base = (uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)11);
    view.guest_base = UINT32_C(0x6000);
    view.byte_count = UINT64_C(12);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("host interval ending at UINTPTR_MAX",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x5fff)), &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += rome2_expect_output("host interval ending at UINTPTR_MAX",
        output, ROME2_OUTPUT_SENTINEL);

    view.host_base = bytes;
    view.guest_base = UINT32_C(0x4000);
    view.byte_count = UINT64_C(12);
    memcpy(snapshot, bytes, sizeof(snapshot));
    failures += rome2_expect_status("output cell ending at UINTPTR_MAX",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(0),
            (rome2_guest_addr32 *)(uintptr_t)(
                UINTPTR_MAX - (uintptr_t)3)),
        ROME2_GUEST_NULL_ADDRESS);
    failures += rome2_expect_bytes("output cell ending at UINTPTR_MAX", bytes,
        snapshot, sizeof(bytes));
    return failures;
}

static int rome2_test_output_overlap(void)
{
    union rome2_overlap_storage {
        rome2_guest_addr32 aligned[8];
        uint8_t bytes[32];
    } storage;
    uint8_t snapshot[sizeof(storage.bytes)];
    uint8_t expected[sizeof(storage.bytes)];
    rome2_guest_write_view view;
    int failures = 0;

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    memcpy(snapshot, storage.bytes, sizeof(snapshot));
    view.host_base = storage.bytes + 8;
    view.guest_base = UINT32_C(0x5000);
    view.byte_count = UINT64_C(12);
    failures += rome2_expect_status("output starts at write view",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x5000)),
            &storage.aligned[2]),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("output starts at write view", storage.bytes,
        snapshot, sizeof(snapshot));

    view.host_base = storage.bytes + 10;
    failures += rome2_expect_status("output overlaps view from left",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x5000)),
            &storage.aligned[2]),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("output overlaps view from left",
        storage.bytes, snapshot, sizeof(snapshot));

    view.host_base = storage.bytes + 2;
    failures += rome2_expect_status("output overlaps view from right",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x5000)),
            &storage.aligned[3]),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("output overlaps view from right",
        storage.bytes, snapshot, sizeof(snapshot));

    view.host_base = storage.bytes + 12;
    memcpy(expected, snapshot, sizeof(expected));
    expected[8] = 0x00;
    expected[9] = 0x50;
    expected[10] = 0x00;
    expected[11] = 0x00;
    memcpy(expected + 12, rome2_expected_triplet,
        sizeof(rome2_expected_triplet));
    failures += rome2_expect_status("output adjacent before view",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x5000)),
            &storage.aligned[2]),
        ROME2_GUEST_OK);
    failures += rome2_expect_bytes("output adjacent before view", storage.bytes,
        expected, sizeof(expected));

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    memcpy(expected, storage.bytes, sizeof(expected));
    view.host_base = storage.bytes + 4;
    expected[16] = 0x00;
    expected[17] = 0x50;
    expected[18] = 0x00;
    expected[19] = 0x00;
    memcpy(expected + 4, rome2_expected_triplet,
        sizeof(rome2_expected_triplet));
    failures += rome2_expect_status("output adjacent after view",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x5000)),
            &storage.aligned[4]),
        ROME2_GUEST_OK);
    failures += rome2_expect_bytes("output adjacent after view", storage.bytes,
        expected, sizeof(expected));
    return failures;
}

static int rome2_test_status_precedence(void)
{
    union rome2_precedence_storage {
        rome2_guest_addr32 aligned[4];
        uint8_t bytes[16];
    } storage;
    uint8_t snapshot[sizeof(storage.bytes)];
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    memcpy(snapshot, storage.bytes, sizeof(snapshot));

    view.host_base = NULL;
    view.guest_base = UINT32_C(0xffffffff);
    view.byte_count = UINT64_C(0x100000001);
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("null host precedes malformed ranges",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(0), &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_output("null host precedes malformed ranges",
        output, ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_bytes("null host precedes malformed ranges",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));

    view.host_base = storage.bytes;
    view.guest_base = UINT32_C(0xfffffff5);
    view.byte_count = UINT64_C(12);
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status("range overflow precedes output overlap",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(0), &storage.aligned[0]),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_expect_bytes("range overflow precedes output overlap",
        storage.bytes, snapshot, sizeof(snapshot));
    failures += rome2_expect_bytes("range overflow precedes output overlap",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));

    view.guest_base = UINT32_C(0x9000);
    view.byte_count = UINT64_C(12);
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status("output overlap precedes null destination",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(0), &storage.aligned[0]),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("output overlap precedes null destination",
        storage.bytes, snapshot, sizeof(snapshot));
    failures += rome2_expect_bytes("output overlap precedes null destination",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));

    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status(
        "output interval overflow precedes null destination",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(0),
            (rome2_guest_addr32 *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1)),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_expect_bytes(
        "output interval overflow precedes null destination", storage.bytes,
        snapshot, sizeof(snapshot));
    failures += rome2_expect_bytes(
        "output interval overflow precedes null destination",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));
    return failures;
}

static int rome2_test_guard_page(void)
{
    SYSTEM_INFO system_info;
    uint8_t *allocation;
    uint8_t *destination;
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    DWORD old_protect = 0;
    SIZE_T allocation_size;
    int failures = 0;

    GetSystemInfo(&system_info);
    if (system_info.dwPageSize < 12) {
        return 1;
    }
    allocation_size = (SIZE_T)system_info.dwPageSize * 2;
    allocation = (uint8_t *)VirtualAlloc(NULL, allocation_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation == NULL) {
        return 1;
    }
    if (VirtualProtect(allocation + system_info.dwPageSize,
            system_info.dwPageSize, PAGE_NOACCESS, &old_protect) == 0) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        return 1;
    }

    destination = allocation + system_info.dwPageSize - 12;
    memset(destination, 0xa5, 12);
    view.host_base = destination;
    view.guest_base = UINT32_C(0x6000);
    view.byte_count = UINT64_C(12);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("guard-page exact end",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x6000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("guard-page exact end", output,
        UINT32_C(0x6000));
    failures += rome2_expect_bytes("guard-page exact end", destination,
        rome2_expected_triplet, 12);

    destination = allocation + system_info.dwPageSize - 11;
    memset(destination, 0xa5, 11);
    view.host_base = destination;
    view.guest_base = UINT32_C(0x6100);
    view.byte_count = UINT64_C(11);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("guard-page short span",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x6100)), &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += rome2_expect_output("guard-page short span", output,
        ROME2_OUTPUT_SENTINEL);
    {
        uint8_t preserved[11];

        memset(preserved, 0xa5, sizeof(preserved));
        failures += rome2_expect_bytes("guard-page short span", destination,
            preserved, sizeof(preserved));
    }
    VirtualFree(allocation, 0, MEM_RELEASE);
    return failures;
}

static int rome2_test_high_native(void)
{
    static const SIZE_T allocation_size = (SIZE_T)0x100000;
    static const uintptr_t hints[] = {
        (uintptr_t)UINT64_C(0x0000010000000000),
        (uintptr_t)UINT64_C(0x0000020000000000),
        (uintptr_t)UINT64_C(0x0000040000000000)
    };
    uint8_t *allocation = NULL;
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    size_t index;
    int failures = 0;

    for (index = 0; index < ROME2_ARRAY_COUNT(hints); ++index) {
        allocation = (uint8_t *)VirtualAlloc((LPVOID)hints[index],
            allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (allocation != NULL &&
            (uintptr_t)allocation > (uintptr_t)UINT32_MAX) {
            break;
        }
        if (allocation != NULL) {
            VirtualFree(allocation, 0, MEM_RELEASE);
            allocation = NULL;
        }
    }
    if (allocation == NULL) {
        allocation = (uint8_t *)VirtualAlloc(NULL, allocation_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (allocation == NULL ||
        (uintptr_t)allocation <= (uintptr_t)UINT32_MAX) {
        if (allocation != NULL) {
            VirtualFree(allocation, 0, MEM_RELEASE);
        }
        fprintf(stderr, "FAIL high-native: allocation above 4 GiB unavailable\n");
        return 1;
    }

    memset(allocation, 0xa5, 12);
    view.host_base = allocation;
    view.guest_base = UINT32_C(0x7000);
    view.byte_count = UINT64_C(12);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("high-native allocation",
        rome2_port_100f1c10_initialize_triplet(
            &view, rome2_guest_address(UINT32_C(0x7000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("high-native allocation", output,
        UINT32_C(0x7000));
    failures += rome2_expect_bytes("high-native allocation", allocation,
        rome2_expected_triplet, 12);
    VirtualFree(allocation, 0, MEM_RELEASE);
    return failures;
}

typedef struct rome2_triplet_thread_context {
    unsigned int index;
    unsigned int failures;
} rome2_triplet_thread_context;

static DWORD WINAPI rome2_triplet_thread(LPVOID parameter)
{
    rome2_triplet_thread_context *context =
        (rome2_triplet_thread_context *)parameter;
    uint8_t bytes[12];
    rome2_guest_write_view view;
    unsigned int iteration;

    view.host_base = bytes;
    view.guest_base = UINT32_C(0x8000) + context->index * UINT32_C(0x100);
    view.byte_count = UINT64_C(12);
    for (iteration = 0; iteration < 2000; ++iteration) {
        rome2_guest_addr32 output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);

        memset(bytes, 0xa5, sizeof(bytes));
        if (rome2_port_100f1c10_initialize_triplet(
                &view, rome2_guest_address(view.guest_base), &output) !=
                ROME2_GUEST_OK ||
            output.value != view.guest_base ||
            memcmp(bytes, rome2_expected_triplet, sizeof(bytes)) != 0) {
            ++context->failures;
            break;
        }
    }
    return (DWORD)context->failures;
}

static int rome2_test_concurrency(void)
{
    enum { thread_count = 8 };
    HANDLE threads[thread_count];
    rome2_triplet_thread_context contexts[thread_count];
    unsigned int created = 0;
    unsigned int index;
    int failures = 0;

    memset(threads, 0, sizeof(threads));
    memset(contexts, 0, sizeof(contexts));
    for (index = 0; index < thread_count; ++index) {
        contexts[index].index = index;
        threads[index] = CreateThread(NULL, 0, rome2_triplet_thread,
            &contexts[index], 0, NULL);
        if (threads[index] == NULL) {
            fprintf(stderr, "FAIL concurrency: CreateThread failed\n");
            ++failures;
            break;
        }
        ++created;
    }
    if (created != 0 &&
        WaitForMultipleObjects(created, threads, TRUE, INFINITE) !=
            WAIT_OBJECT_0) {
        fprintf(stderr, "FAIL concurrency: worker wait failed\n");
        ++failures;
        for (index = 0; index < created; ++index) {
            (void)WaitForSingleObject(threads[index], INFINITE);
        }
    }
    for (index = 0; index < created; ++index) {
        DWORD thread_exit = 0;

        if (GetExitCodeThread(threads[index], &thread_exit) == 0 ||
            thread_exit != 0 || contexts[index].failures != 0) {
            fprintf(stderr, "FAIL concurrency: worker mismatch\n");
            ++failures;
        }
        CloseHandle(threads[index]);
    }
    return created == 0 ? failures + 1 : failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_exact_aligned();
    failures += rome2_test_exact_and_unaligned_views();
    failures += rome2_test_adjacent_and_guest_top();
    failures += rome2_test_failure_preservation();
    failures += rome2_test_output_overlap();
    failures += rome2_test_status_precedence();
    failures += rome2_test_guard_page();
    failures += rome2_test_high_native();
    failures += rome2_test_concurrency();
    if (failures != 0) {
        fprintf(stderr, "startup 100f1c10 tests failed: %d\n", failures);
        return 1;
    }
    printf("startup 100f1c10 tests passed\n");
    return 0;
}
