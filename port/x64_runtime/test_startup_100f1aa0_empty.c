#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include "ported_100f1aa0_empty.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define ROME2_OUTPUT_SENTINEL UINT32_C(0x5aa5c33c)

static const uint8_t rome2_triplet_oracle[12] = {
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

static void rome2_set_source(uint8_t *source, uint32_t count)
{
    source[0] = (uint8_t)count;
    source[1] = (uint8_t)(count >> 8);
    source[2] = (uint8_t)(count >> 16);
    source[3] = (uint8_t)(count >> 24);
    source[4] = 0x34;
    source[5] = 0x12;
    source[6] = 0xcd;
    source[7] = 0xab;
    source[8] = 0xef;
    source[9] = 0xbe;
    source[10] = 0xad;
    source[11] = 0xde;
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

static int rome2_expect_preserved_failure(
    const char *label,
    rome2_guest_write_view *view,
    rome2_guest_addr32 destination,
    rome2_guest_addr32 source,
    rome2_guest_status expected_status,
    uint8_t *bytes,
    size_t byte_count)
{
    uint8_t snapshot[128];
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
        rome2_port_100f1aa0_copy_empty_source(
            view, destination, source, &output),
        expected_status);
    failures += rome2_expect_output(label, output, ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_bytes(label, bytes, snapshot, byte_count);
    failures += rome2_expect_bytes(label, (const uint8_t *)view,
        (const uint8_t *)&view_snapshot, sizeof(view_snapshot));
    return failures;
}

static int rome2_test_success_geometry(void)
{
    uint8_t exact[24];
    uint8_t reverse[24];
    uint8_t unaligned_storage[31];
    uint8_t unaligned_expected[31];
    uint8_t top[24];
    uint8_t expected[24];
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(exact, 0xa5, sizeof(exact));
    rome2_set_source(exact, 0);
    memcpy(expected, exact, sizeof(expected));
    memcpy(expected + 12, rome2_triplet_oracle, sizeof(rome2_triplet_oracle));
    view.host_base = exact;
    view.guest_base = UINT32_C(0x1000);
    view.byte_count = (uint64_t)sizeof(exact);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("exact adjacent source then destination",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x100c)),
            rome2_guest_address(UINT32_C(0x1000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("exact adjacent source then destination",
        output, UINT32_C(0x100c));
    failures += rome2_expect_bytes("exact adjacent source then destination",
        exact, expected, sizeof(exact));

    memset(reverse, 0x5a, sizeof(reverse));
    rome2_set_source(reverse + 12, 0);
    memcpy(expected, reverse, sizeof(expected));
    memcpy(expected, rome2_triplet_oracle, sizeof(rome2_triplet_oracle));
    view.host_base = reverse;
    view.guest_base = UINT32_C(0x2000);
    view.byte_count = (uint64_t)sizeof(reverse);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("exact adjacent destination then source",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x2000)),
            rome2_guest_address(UINT32_C(0x200c)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("exact adjacent destination then source",
        output, UINT32_C(0x2000));
    failures += rome2_expect_bytes("exact adjacent destination then source",
        reverse, expected, sizeof(reverse));

    memset(unaligned_storage, 0xcc, sizeof(unaligned_storage));
    rome2_set_source(unaligned_storage + 2, 0);
    memcpy(unaligned_expected, unaligned_storage, sizeof(unaligned_expected));
    memcpy(unaligned_expected + 15, rome2_triplet_oracle,
        sizeof(rome2_triplet_oracle));
    view.host_base = unaligned_storage + 1;
    view.guest_base = UINT32_C(0x3001);
    view.byte_count = UINT64_C(27);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("unaligned separated spans",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x300f)),
            rome2_guest_address(UINT32_C(0x3002)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("unaligned separated spans", output,
        UINT32_C(0x300f));
    failures += rome2_expect_bytes("unaligned separated spans",
        unaligned_storage, unaligned_expected, sizeof(unaligned_storage));

    memset(top, 0x77, sizeof(top));
    rome2_set_source(top, 0);
    memcpy(expected, top, sizeof(expected));
    memcpy(expected + 12, rome2_triplet_oracle, sizeof(rome2_triplet_oracle));
    view.host_base = top;
    view.guest_base = UINT32_C(0xffffffe8);
    view.byte_count = UINT64_C(24);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("guest view ending at 2^32",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0xfffffff4)),
            rome2_guest_address(UINT32_C(0xffffffe8)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("guest view ending at 2^32", output,
        UINT32_C(0xfffffff4));
    failures += rome2_expect_bytes("guest view ending at 2^32", top,
        expected, sizeof(top));
    return failures;
}

static int rome2_test_failure_preservation(void)
{
    uint8_t bytes[64];
    uint8_t snapshot[64];
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 output;
    unsigned int shortage;
    int failures = 0;

    memset(bytes, 0xa5, sizeof(bytes));
    rome2_set_source(bytes + 8, 0);
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x4000);
    view.byte_count = (uint64_t)sizeof(bytes);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("null view",
        rome2_port_100f1aa0_copy_empty_source(NULL,
            rome2_guest_address(UINT32_C(0x4020)),
            rome2_guest_address(UINT32_C(0x4008)), &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_output("null view", output,
        ROME2_OUTPUT_SENTINEL);

    memcpy(snapshot, bytes, sizeof(snapshot));
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status("null output",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x4020)),
            rome2_guest_address(UINT32_C(0x4008)), NULL),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("null output bytes", bytes, snapshot,
        sizeof(bytes));
    failures += rome2_expect_bytes("null output view", (const uint8_t *)&view,
        (const uint8_t *)&view_snapshot, sizeof(view));

    view.host_base = NULL;
    failures += rome2_expect_preserved_failure("null host", &view,
        rome2_guest_address(UINT32_C(0x4020)),
        rome2_guest_address(UINT32_C(0x4008)), ROME2_GUEST_BAD_ARGUMENT,
        bytes, sizeof(bytes));
    view.host_base = bytes;

    failures += rome2_expect_preserved_failure("null destination", &view,
        rome2_guest_address(0), rome2_guest_address(UINT32_C(0x4008)),
        ROME2_GUEST_NULL_ADDRESS, bytes, sizeof(bytes));
    failures += rome2_expect_preserved_failure("null source", &view,
        rome2_guest_address(UINT32_C(0x4020)), rome2_guest_address(0),
        ROME2_GUEST_NULL_ADDRESS, bytes, sizeof(bytes));
    failures += rome2_expect_preserved_failure("destination below base", &view,
        rome2_guest_address(UINT32_C(0x3fff)),
        rome2_guest_address(UINT32_C(0x4008)), ROME2_GUEST_OUT_OF_RANGE,
        bytes, sizeof(bytes));
    failures += rome2_expect_preserved_failure("source below base", &view,
        rome2_guest_address(UINT32_C(0x4020)),
        rome2_guest_address(UINT32_C(0x3fff)), ROME2_GUEST_OUT_OF_RANGE,
        bytes, sizeof(bytes));

    for (shortage = 0; shortage < 12; ++shortage) {
        char label[64];

        view.byte_count = UINT64_C(32) + (uint64_t)shortage;
        (void)sprintf_s(label, sizeof(label),
            "destination has only %u bytes", shortage);
        failures += rome2_expect_preserved_failure(label, &view,
            rome2_guest_address(UINT32_C(0x4020)),
            rome2_guest_address(UINT32_C(0x4008)), ROME2_GUEST_OUT_OF_RANGE,
            bytes, sizeof(bytes));
    }
    view.byte_count = UINT64_C(64);
    for (shortage = 0; shortage < 12; ++shortage) {
        char label[64];

        (void)sprintf_s(label, sizeof(label), "source has only %u bytes",
            shortage);
        failures += rome2_expect_preserved_failure(label, &view,
            rome2_guest_address(UINT32_C(0x4000)),
            rome2_guest_address(UINT32_C(0x4040) - shortage),
            ROME2_GUEST_OUT_OF_RANGE, bytes, sizeof(bytes));
    }

    view.guest_base = UINT32_C(0xfffffff5);
    view.byte_count = UINT64_C(12);
    failures += rome2_expect_preserved_failure("guest view end overflow", &view,
        rome2_guest_address(UINT32_C(0xfffffff5)),
        rome2_guest_address(UINT32_C(0xfffffff5)),
        ROME2_GUEST_RANGE_OVERFLOW, bytes, sizeof(bytes));
    view.guest_base = 0;
    view.byte_count = UINT64_C(0x100000001);
    failures += rome2_expect_preserved_failure("view wider than guest space",
        &view, rome2_guest_address(UINT32_C(1)),
        rome2_guest_address(UINT32_C(16)), ROME2_GUEST_RANGE_OVERFLOW,
        bytes, sizeof(bytes));
    return failures;
}

static int rome2_test_overlap_and_nonempty_rejection(void)
{
    uint8_t bytes[64];
    rome2_guest_write_view view;
    static const uint32_t counts[] = {
        UINT32_C(1), UINT32_C(0x100), UINT32_C(0x00010000),
        UINT32_C(0x01000000), UINT32_MAX
    };
    size_t index;
    int failures = 0;

    memset(bytes, 0xa5, sizeof(bytes));
    rome2_set_source(bytes + 8, 0);
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x5000);
    view.byte_count = (uint64_t)sizeof(bytes);

    failures += rome2_expect_preserved_failure("identical source/destination",
        &view, rome2_guest_address(UINT32_C(0x5008)),
        rome2_guest_address(UINT32_C(0x5008)), ROME2_GUEST_BAD_ARGUMENT,
        bytes, sizeof(bytes));
    failures += rome2_expect_preserved_failure("destination overlaps right",
        &view, rome2_guest_address(UINT32_C(0x5009)),
        rome2_guest_address(UINT32_C(0x5008)), ROME2_GUEST_BAD_ARGUMENT,
        bytes, sizeof(bytes));
    failures += rome2_expect_preserved_failure("destination overlaps left",
        &view, rome2_guest_address(UINT32_C(0x5007)),
        rome2_guest_address(UINT32_C(0x5008)), ROME2_GUEST_BAD_ARGUMENT,
        bytes, sizeof(bytes));
    failures += rome2_expect_preserved_failure("overlap at final byte",
        &view, rome2_guest_address(UINT32_C(0x5013)),
        rome2_guest_address(UINT32_C(0x5008)), ROME2_GUEST_BAD_ARGUMENT,
        bytes, sizeof(bytes));

    for (index = 0; index < ROME2_ARRAY_COUNT(counts); ++index) {
        char label[64];

        rome2_set_source(bytes + 8, counts[index]);
        (void)sprintf_s(label, sizeof(label), "nonempty count 0x%08x",
            (unsigned int)counts[index]);
        failures += rome2_expect_preserved_failure(label, &view,
            rome2_guest_address(UINT32_C(0x5020)),
            rome2_guest_address(UINT32_C(0x5008)),
            ROME2_GUEST_BAD_ARGUMENT, bytes, sizeof(bytes));
    }
    return failures;
}

static int rome2_test_status_precedence(void)
{
    typedef struct rome2_precedence_case {
        const char *label;
        uint32_t guest_base;
        uint64_t byte_count;
        uint32_t destination;
        uint32_t source;
        uint32_t source_count;
        int null_host;
        rome2_guest_status expected_status;
    } rome2_precedence_case;
    static const rome2_precedence_case cases[] = {
        {
            "null host precedes guest extent overflow",
            UINT32_MAX,
            UINT64_C(0x100000001),
            0,
            0,
            0,
            1,
            ROME2_GUEST_BAD_ARGUMENT
        },
        {
            "guest extent overflow precedes null addresses",
            UINT32_C(0xfffffff5),
            UINT64_C(12),
            0,
            0,
            0,
            0,
            ROME2_GUEST_RANGE_OVERFLOW
        },
        {
            "null destination precedes source below base",
            UINT32_C(0x9000),
            UINT64_C(64),
            0,
            UINT32_C(0x8fff),
            0,
            0,
            ROME2_GUEST_NULL_ADDRESS
        },
        {
            "below-base addresses precede guest overlap",
            UINT32_C(0x9000),
            UINT64_C(64),
            UINT32_C(0x8fff),
            UINT32_C(0x8fff),
            0,
            0,
            ROME2_GUEST_OUT_OF_RANGE
        },
        {
            "short destination precedes nonempty source",
            UINT32_C(0x9000),
            UINT64_C(64),
            UINT32_C(0x903c),
            UINT32_C(0x9008),
            UINT32_C(1),
            0,
            ROME2_GUEST_OUT_OF_RANGE
        },
        {
            "guest overlap precedes nonempty source",
            UINT32_C(0x9000),
            UINT64_C(64),
            UINT32_C(0x9010),
            UINT32_C(0x9008),
            UINT32_C(1),
            0,
            ROME2_GUEST_BAD_ARGUMENT
        }
    };
    union rome2_precedence_storage {
        rome2_guest_addr32 aligned[16];
        uint8_t bytes[64];
    } storage;
    uint8_t snapshot[sizeof(storage.bytes)];
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    size_t index;
    int failures = 0;

    for (index = 0; index < ROME2_ARRAY_COUNT(cases); ++index) {
        memset(storage.bytes, 0xa5, sizeof(storage.bytes));
        rome2_set_source(storage.bytes + 8, cases[index].source_count);
        view.host_base = cases[index].null_host ? NULL : storage.bytes;
        view.guest_base = cases[index].guest_base;
        view.byte_count = cases[index].byte_count;
        failures += rome2_expect_preserved_failure(cases[index].label, &view,
            rome2_guest_address(cases[index].destination),
            rome2_guest_address(cases[index].source),
            cases[index].expected_status, storage.bytes,
            sizeof(storage.bytes));
    }

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    rome2_set_source(storage.bytes + 8, 0);
    memcpy(snapshot, storage.bytes, sizeof(snapshot));
    view.host_base = storage.bytes;
    view.guest_base = UINT32_C(0x9000);
    view.byte_count = UINT64_C(64);
    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status(
        "output/view alias precedes null addresses",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(0), rome2_guest_address(0),
            &storage.aligned[4]),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes(
        "output/view alias precedes null addresses bytes", storage.bytes,
        snapshot, sizeof(snapshot));
    failures += rome2_expect_bytes(
        "output/view alias precedes null addresses view",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));
    return failures;
}

static int rome2_test_native_alias_and_overflow_rejection(void)
{
    union rome2_aligned_storage {
        rome2_guest_addr32 cells[16];
        uint8_t bytes[64];
    } storage;
    union rome2_self_alias_storage {
        rome2_guest_write_view view;
        uint8_t bytes[64];
    } self_alias;
    uint8_t snapshot[sizeof(storage.bytes)];
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(storage.bytes, 0xa5, sizeof(storage.bytes));
    rome2_set_source(storage.bytes + 8, 0);
    memcpy(snapshot, storage.bytes, sizeof(snapshot));
    view.host_base = storage.bytes;
    view.guest_base = UINT32_C(0x6000);
    view.byte_count = (uint64_t)sizeof(storage.bytes);
    failures += rome2_expect_status("output aliases guest view",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x6020)),
            rome2_guest_address(UINT32_C(0x6008)), &storage.cells[4]),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("output aliases guest view", storage.bytes,
        snapshot, sizeof(snapshot));

    memcpy(&view_snapshot, &view, sizeof(view_snapshot));
    failures += rome2_expect_status("output aliases descriptor",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x6020)),
            rome2_guest_address(UINT32_C(0x6008)),
            (rome2_guest_addr32 *)(void *)&view.guest_base),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_bytes("output aliases descriptor bytes",
        storage.bytes, snapshot, sizeof(snapshot));
    failures += rome2_expect_bytes("output aliases descriptor object",
        (const uint8_t *)&view, (const uint8_t *)&view_snapshot, sizeof(view));

    memset(self_alias.bytes, 0xa5, sizeof(self_alias.bytes));
    self_alias.view.host_base = self_alias.bytes;
    self_alias.view.guest_base = UINT32_C(0x6800);
    self_alias.view.byte_count = UINT64_C(64);
    memcpy(snapshot, self_alias.bytes, sizeof(snapshot));
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("descriptor aliases guest view",
        rome2_port_100f1aa0_copy_empty_source(&self_alias.view,
            rome2_guest_address(UINT32_C(0x6820)),
            rome2_guest_address(UINT32_C(0x6808)), &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_expect_output("descriptor aliases guest view", output,
        ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_bytes("descriptor aliases guest view bytes",
        self_alias.bytes, snapshot, sizeof(snapshot));

    view.host_base = (uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)10);
    view.guest_base = UINT32_C(0x7000);
    view.byte_count = UINT64_C(24);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("numeric host interval overflow",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x700c)),
            rome2_guest_address(UINT32_C(0x7000)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_expect_output("numeric host interval overflow", output,
        ROME2_OUTPUT_SENTINEL);

    view.host_base = storage.bytes;
    view.guest_base = UINT32_C(0x7000);
    view.byte_count = UINT64_C(64);
    memcpy(snapshot, storage.bytes, sizeof(snapshot));
    failures += rome2_expect_status("numeric output interval overflow",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x7020)),
            rome2_guest_address(UINT32_C(0x7008)),
            (rome2_guest_addr32 *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)1)),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += rome2_expect_bytes("numeric output interval overflow",
        storage.bytes, snapshot, sizeof(snapshot));
    return failures;
}

static int rome2_test_guard_page(void)
{
    SYSTEM_INFO system_info;
    uint8_t *allocation;
    uint8_t *view_bytes;
    uint8_t expected[24];
    rome2_guest_write_view view;
    rome2_guest_addr32 output;
    DWORD old_protect = 0;
    SIZE_T allocation_size;
    int failures = 0;

    GetSystemInfo(&system_info);
    if (system_info.dwPageSize < 24) {
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

    view_bytes = allocation + system_info.dwPageSize - 24;
    memset(view_bytes, 0xa5, 24);
    rome2_set_source(view_bytes, 0);
    memcpy(expected, view_bytes, sizeof(expected));
    memcpy(expected + 12, rome2_triplet_oracle, sizeof(rome2_triplet_oracle));
    view.host_base = view_bytes;
    view.guest_base = UINT32_C(0x8000);
    view.byte_count = UINT64_C(24);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("guard-page exact end",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x800c)),
            rome2_guest_address(UINT32_C(0x8000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("guard-page exact end", output,
        UINT32_C(0x800c));
    failures += rome2_expect_bytes("guard-page exact end", view_bytes,
        expected, sizeof(expected));

    view_bytes = allocation + system_info.dwPageSize - 23;
    memset(view_bytes, 0xa5, 23);
    rome2_set_source(view_bytes, 0);
    view.host_base = view_bytes;
    view.guest_base = UINT32_C(0x8100);
    view.byte_count = UINT64_C(23);
    failures += rome2_expect_preserved_failure("guard-page short view", &view,
        rome2_guest_address(UINT32_C(0x810c)),
        rome2_guest_address(UINT32_C(0x8100)), ROME2_GUEST_OUT_OF_RANGE,
        view_bytes, 23);
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
    uint8_t expected[24];
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
        fprintf(stderr, "FAIL high-native allocation above 4 GiB unavailable\n");
        return 1;
    }

    memset(allocation, 0xa5, 24);
    rome2_set_source(allocation, 0);
    memcpy(expected, allocation, sizeof(expected));
    memcpy(expected + 12, rome2_triplet_oracle, sizeof(rome2_triplet_oracle));
    view.host_base = allocation;
    view.guest_base = UINT32_C(0x9000);
    view.byte_count = UINT64_C(24);
    output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);
    failures += rome2_expect_status("high-native allocation",
        rome2_port_100f1aa0_copy_empty_source(&view,
            rome2_guest_address(UINT32_C(0x900c)),
            rome2_guest_address(UINT32_C(0x9000)), &output),
        ROME2_GUEST_OK);
    failures += rome2_expect_output("high-native allocation", output,
        UINT32_C(0x900c));
    failures += rome2_expect_bytes("high-native allocation", allocation,
        expected, sizeof(expected));
    VirtualFree(allocation, 0, MEM_RELEASE);
    return failures;
}

typedef struct rome2_empty_thread_context {
    unsigned int index;
    unsigned int failures;
} rome2_empty_thread_context;

static DWORD WINAPI rome2_empty_thread(LPVOID parameter)
{
    rome2_empty_thread_context *context =
        (rome2_empty_thread_context *)parameter;
    uint8_t bytes[24];
    rome2_guest_write_view view;
    unsigned int iteration;

    view.host_base = bytes;
    view.guest_base = UINT32_C(0xa000) + context->index * UINT32_C(0x100);
    view.byte_count = UINT64_C(24);
    for (iteration = 0; iteration < 2000; ++iteration) {
        rome2_guest_addr32 output = rome2_guest_address(ROME2_OUTPUT_SENTINEL);

        memset(bytes, 0xa5, sizeof(bytes));
        rome2_set_source(bytes, 0);
        if (rome2_port_100f1aa0_copy_empty_source(&view,
                rome2_guest_address(view.guest_base + UINT32_C(12)),
                rome2_guest_address(view.guest_base), &output) !=
                ROME2_GUEST_OK ||
            output.value != view.guest_base + UINT32_C(12) ||
            memcmp(bytes + 12, rome2_triplet_oracle,
                sizeof(rome2_triplet_oracle)) != 0 ||
            bytes[0] != 0 || bytes[4] != 0x34 || bytes[8] != 0xef) {
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
    rome2_empty_thread_context contexts[thread_count];
    unsigned int created = 0;
    unsigned int index;
    int failures = 0;

    memset(threads, 0, sizeof(threads));
    memset(contexts, 0, sizeof(contexts));
    for (index = 0; index < thread_count; ++index) {
        contexts[index].index = index;
        threads[index] = CreateThread(NULL, 0, rome2_empty_thread,
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

    failures += rome2_test_success_geometry();
    failures += rome2_test_failure_preservation();
    failures += rome2_test_overlap_and_nonempty_rejection();
    failures += rome2_test_status_precedence();
    failures += rome2_test_native_alias_and_overflow_rejection();
    failures += rome2_test_guard_page();
    failures += rome2_test_high_native();
    failures += rome2_test_concurrency();
    if (failures != 0) {
        fprintf(stderr, "startup 100f1aa0 empty tests failed: %d\n", failures);
        return 1;
    }
    printf("startup 100f1aa0 empty tests passed\n");
    return 0;
}
