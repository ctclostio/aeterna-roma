#include "guest32.h"
#include "ported_100edd70_policy.h"

#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#define LITERAL_UNIT_COUNT ((size_t)22)
#define LITERAL_BYTE_COUNT ((size_t)44)
#define POLICY_SENTINEL UINT32_C(0xdeadbeef)

static const uint16_t expected_units[LITERAL_UNIT_COUNT] = {
    UINT16_C(0x002d), UINT16_C(0x006e), UINT16_C(0x006f), UINT16_C(0x005f),
    UINT16_C(0x0065), UINT16_C(0x0078), UINT16_C(0x0063), UINT16_C(0x0065),
    UINT16_C(0x0070), UINT16_C(0x0074), UINT16_C(0x0069), UINT16_C(0x006f),
    UINT16_C(0x006e), UINT16_C(0x005f), UINT16_C(0x0068), UINT16_C(0x0061),
    UINT16_C(0x006e), UINT16_C(0x0064), UINT16_C(0x006c), UINT16_C(0x0065),
    UINT16_C(0x0072), UINT16_C(0x0000)
};

static rome2_guest_addr32 guest_address(uint32_t value)
{
    rome2_guest_addr32 address;

    address.value = value;
    return address;
}

static void store_u16_le(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)(value & UINT16_C(0xff));
    destination[1] = (uint8_t)((value >> 8) & UINT16_C(0xff));
}

static void store_literal(uint8_t *destination)
{
    size_t index;

    for (index = 0; index < LITERAL_UNIT_COUNT; ++index) {
        store_u16_le(destination + 2 * index, expected_units[index]);
    }
}

static void make_view(
    rome2_guest_read_view *view,
    const uint8_t *host_base,
    uint32_t guest_base,
    uint64_t byte_count)
{
    view->host_base = host_base;
    view->guest_base = guest_base;
    view->byte_count = byte_count;
}

static int expect_status(
    const char *test_name,
    rome2_guest_status actual,
    rome2_guest_status expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "%s: status %d, expected %d\n", test_name,
        (int)actual, (int)expected);
    return 1;
}

static int expect_policy(
    const char *test_name,
    rome2_invalid_parameter_policy actual,
    rome2_invalid_parameter_policy expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "%s: policy %lu, expected %lu\n", test_name,
        (unsigned long)actual, (unsigned long)expected);
    return 1;
}

static int run_selector_expect(
    const char *test_name,
    const rome2_guest_read_view *view,
    uint32_t command_value,
    rome2_invalid_parameter_policy *policy,
    rome2_guest_status expected_status,
    rome2_invalid_parameter_policy expected_policy)
{
    rome2_guest_status status;
    int failures = 0;

    *policy = POLICY_SENTINEL;
    status = rome2_port_100edd70_select_invalid_parameter_policy(
        view, guest_address(command_value), policy);
    failures += expect_status(test_name, status, expected_status);
    failures += expect_policy(test_name, *policy, expected_policy);
    return failures;
}

static int test_exact_match(void)
{
    /* The exact pinned literal including its terminator selects skip. */
    uint8_t bytes[LITERAL_BYTE_COUNT];
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;
    int failures;

    store_literal(bytes);
    make_view(&view, bytes, UINT32_C(0x2000), LITERAL_BYTE_COUNT);
    failures = run_selector_expect("exact literal selects skip", &view,
        UINT32_C(0x2000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_SKIP_HANDLER);

    /* Unaligned guest address succeeds and still selects skip. */
    {
        uint8_t shifted[LITERAL_BYTE_COUNT + 2];

        memset(shifted, 0xcc, sizeof(shifted));
        store_literal(shifted + 1);
        make_view(&view, shifted, UINT32_C(0x3000),
            LITERAL_BYTE_COUNT + 1);
        failures += run_selector_expect("unaligned literal selects skip",
            &view, UINT32_C(0x3001), &policy, ROME2_GUEST_OK,
            ROME2_INVALID_PARAMETER_SKIP_HANDLER);
    }
    return failures;
}

static int test_mismatches_install(void)
{
    uint8_t bytes[LITERAL_BYTE_COUNT + 4];
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;
    size_t index;
    int failures = 0;

    memset(bytes, 0, sizeof(bytes));
    make_view(&view, bytes, UINT32_C(0x4000), UINT64_C(2));
    failures += run_selector_expect("empty string installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    store_literal(bytes);
    store_u16_le(bytes + 2, UINT16_C(0x004e));
    make_view(&view, bytes, UINT32_C(0x4000), LITERAL_BYTE_COUNT);
    failures += run_selector_expect("ASCII case change installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    store_literal(bytes);
    store_u16_le(bytes + 6, UINT16_C(0x0000));
    make_view(&view, bytes, UINT32_C(0x4000), UINT64_C(8));
    failures += run_selector_expect("proper prefix installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    store_literal(bytes);
    store_u16_le(bytes + 42, UINT16_C(0x0078));
    store_u16_le(bytes + 44, UINT16_C(0x0000));
    make_view(&view, bytes, UINT32_C(0x4000), UINT64_C(46));
    failures += run_selector_expect("appended suffix installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    store_u16_le(bytes, UINT16_C(0x0020));
    store_literal(bytes + 2);
    make_view(&view, bytes, UINT32_C(0x4000), UINT64_C(46));
    failures += run_selector_expect("leading space installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    store_literal(bytes);
    store_u16_le(bytes + 42, UINT16_C(0x0020));
    store_u16_le(bytes + 44, UINT16_C(0x0000));
    make_view(&view, bytes, UINT32_C(0x4000), UINT64_C(46));
    failures += run_selector_expect("trailing space installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    store_u16_le(bytes, UINT16_C(0x0022));
    for (index = 0; index < LITERAL_UNIT_COUNT - 1; ++index) {
        store_u16_le(bytes + 2 * (index + 1), expected_units[index]);
    }
    store_u16_le(bytes + 44, UINT16_C(0x0022));
    store_u16_le(bytes + 46, UINT16_C(0x0000));
    make_view(&view, bytes, UINT32_C(0x4000), UINT64_C(48));
    failures += run_selector_expect("quoted literal installs", &view,
        UINT32_C(0x4000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);
    return failures;
}

static int test_bounded_reads(void)
{
    uint8_t bytes[LITERAL_BYTE_COUNT];
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;
    int failures = 0;

    /* First-unit mismatch succeeds when the view holds exactly two bytes. */
    bytes[0] = 0x21;
    bytes[1] = 0x00;
    make_view(&view, bytes, UINT32_C(0x5000), UINT64_C(2));
    failures += run_selector_expect("first-unit mismatch on two-byte view",
        &view, UINT32_C(0x5000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    /*
     * Units 0..9 match, unit 10 mismatches, and the view ends there: the
     * selector stops on the first mismatch without reading the missing
     * suffix, so this succeeds even though the full literal cannot fit.
     */
    store_literal(bytes);
    store_u16_le(bytes + 20, UINT16_C(0x005a));
    make_view(&view, bytes, UINT32_C(0x6000), UINT64_C(22));
    failures += run_selector_expect("later mismatch needs no unread suffix",
        &view, UINT32_C(0x6000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);
    return failures;
}

static int test_missing_units_fail(void)
{
    uint8_t bytes[LITERAL_BYTE_COUNT];
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;
    int failures = 0;

    /* Matching units 0..20 but no terminator unit: fail closed. */
    store_literal(bytes);
    make_view(&view, bytes, UINT32_C(0x7000), UINT64_C(42));
    failures += run_selector_expect("missing terminator fails", &view,
        UINT32_C(0x7000), &policy, ROME2_GUEST_OUT_OF_RANGE, POLICY_SENTINEL);

    /* One-byte final unit at offset 42: fail closed. */
    make_view(&view, bytes, UINT32_C(0x7000), UINT64_C(43));
    failures += run_selector_expect("one-byte final unit fails", &view,
        UINT32_C(0x7000), &policy, ROME2_GUEST_OUT_OF_RANGE, POLICY_SENTINEL);

    /* Truncated interior unit after a matching prefix: fail closed. */
    make_view(&view, bytes, UINT32_C(0x7000), UINT64_C(15));
    failures += run_selector_expect("truncated interior unit fails", &view,
        UINT32_C(0x7000), &policy, ROME2_GUEST_OUT_OF_RANGE, POLICY_SENTINEL);
    return failures;
}

static int test_argument_and_range_failures(void)
{
    uint8_t bytes[LITERAL_BYTE_COUNT];
    uint8_t high_bytes[64];
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;
    rome2_guest_status status;
    int failures = 0;

    store_literal(bytes);
    make_view(&view, bytes, UINT32_C(0x8000), LITERAL_BYTE_COUNT);

    policy = POLICY_SENTINEL;
    failures += expect_status("null view",
        rome2_port_100edd70_select_invalid_parameter_policy(NULL,
            guest_address(UINT32_C(0x8000)), &policy),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_policy("null view preserves output", policy,
        POLICY_SENTINEL);

    failures += expect_status("null policy output",
        rome2_port_100edd70_select_invalid_parameter_policy(&view,
            guest_address(UINT32_C(0x8000)), NULL),
        ROME2_GUEST_BAD_ARGUMENT);

    view.host_base = NULL;
    failures += run_selector_expect("null host base", &view,
        UINT32_C(0x8000), &policy, ROME2_GUEST_BAD_ARGUMENT,
        POLICY_SENTINEL);
    make_view(&view, bytes, UINT32_C(0x8000), LITERAL_BYTE_COUNT);

    /* Null command address fails and preserves the output sentinel. */
    failures += run_selector_expect("null command address", &view,
        0, &policy, ROME2_GUEST_NULL_ADDRESS, POLICY_SENTINEL);

    /* Guest extent wider than the address space is malformed. */
    view.byte_count = UINT64_C(0x100000001);
    failures += run_selector_expect("malformed guest extent", &view,
        UINT32_C(0x8000), &policy, ROME2_GUEST_RANGE_OVERFLOW,
        POLICY_SENTINEL);
    view.byte_count = LITERAL_BYTE_COUNT;

    /* Host buffer whose numeric range overflows uintptr is rejected before
     * any byte is touched. */
    view.host_base = (const uint8_t *)(uintptr_t)(UINTPTR_MAX - 2);
    failures += run_selector_expect("numeric host-range overflow", &view,
        UINT32_C(0x8000), &policy, ROME2_GUEST_RANGE_OVERFLOW,
        POLICY_SENTINEL);
    view.host_base = bytes;

    /*
     * Required checked-address overflow: the final '-' sits at guest
     * 0xfffffffe so the checked +2 advance to the next unit would exceed
     * UINT32_MAX.  The read succeeds, then add_checked fails closed and both
     * outputs stay untouched.
     */
    store_literal(high_bytes);
    make_view(&view, high_bytes, UINT32_C(0xffffffc0), UINT64_C(64));
    high_bytes[0x3e] = 0x2d;
    high_bytes[0x3f] = 0x00;
    failures += run_selector_expect("checked-address overflow fails", &view,
        UINT32_C(0xfffffffe), &policy, ROME2_GUEST_RANGE_OVERFLOW,
        POLICY_SENTINEL);
    /* Every failure above preserved the policy sentinel; assert explicitly
     * once more that a failed unit read leaves its own output unchanged. */
    {
        uint16_t unit = UINT16_C(0xa5a5);

        make_view(&view, bytes, UINT32_C(0x8000), UINT64_C(1));
        status = rome2_guest_read_u16_le(&view,
            guest_address(UINT32_C(0x8000)), &unit);
        failures += expect_status("one-byte unit read", status,
            ROME2_GUEST_OUT_OF_RANGE);
        failures += expect_policy("unit output preserved on failure",
            (rome2_invalid_parameter_policy)unit,
            (rome2_invalid_parameter_policy)UINT16_C(0xa5a5));
    }
    return failures;
}

static int test_view_ending_at_address_space_end(void)
{
    uint8_t bytes[64];
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;
    int failures;

    store_literal(bytes);
    /* [0xffffffc0, 2^32) is a valid extent whose end is exactly 2^32. */
    make_view(&view, bytes, UINT32_C(0xffffffc0), UINT64_C(64));
    failures = run_selector_expect("view ending exactly at 2^32", &view,
        UINT32_C(0xffffffc0), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_SKIP_HANDLER);
    return failures;
}

static int test_high_host_buffer(void)
{
    int failures = 0;
#if defined(_WIN32)
    static const SIZE_T allocation_size = 0x100000;
    static const uintptr_t hints[] = {
        UINT64_C(0x0000010000000000),
        UINT64_C(0x0000020000000000),
        UINT64_C(0x0000000200000000),
        UINT64_C(0x0000000100010000)
    };
    size_t index;
    uint8_t *buffer = NULL;
    rome2_guest_read_view view;
    rome2_invalid_parameter_policy policy;

    /* Reserve a genuine host buffer above 4 GiB so any internal truncation
     * of host_base would be observable as corruption or failure. */
    for (index = 0; index < sizeof(hints) / sizeof(hints[0]); ++index) {
        buffer = (uint8_t *)VirtualAlloc((LPVOID)hints[index],
            allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (buffer != NULL && (uintptr_t)buffer > (uintptr_t)UINT32_MAX) {
            break;
        }
        if (buffer != NULL) {
            VirtualFree(buffer, 0, MEM_RELEASE);
            buffer = NULL;
        }
    }
    if (buffer == NULL) {
        buffer = (uint8_t *)VirtualAlloc(NULL, allocation_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (buffer == NULL) {
        fprintf(stderr, "genuine host buffer above 4 GiB unavailable\n");
        return 1;
    }
    if ((uintptr_t)buffer <= (uintptr_t)UINT32_MAX) {
        fprintf(stderr, "allocated host buffer is not above 4 GiB\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return 1;
    }

    store_literal(buffer + 0x40);
    make_view(&view, buffer + 0x40, UINT32_C(0x40000000),
        LITERAL_BYTE_COUNT);
    failures += run_selector_expect("high host buffer exact match", &view,
        UINT32_C(0x40000000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_SKIP_HANDLER);

    buffer[0x40] = 0x58; /* '-' -> 'X' */
    failures += run_selector_expect("high host buffer mismatch", &view,
        UINT32_C(0x40000000), &policy, ROME2_GUEST_OK,
        ROME2_INVALID_PARAMETER_INSTALL_HANDLER);

    if (VirtualFree(buffer, 0, MEM_RELEASE) == 0) {
        fprintf(stderr, "failed to release high host buffer\n");
        failures += 1;
    }
#else
    fprintf(stderr,
        "high-host-buffer probe requires a Windows x64 runner; skipped on "
        "this platform by design, not by omission of the assertion\n");
#endif
    return failures;
}

static int test_read_u16_le(void)
{
    uint8_t bytes[16];
    rome2_guest_read_view view;
    uint16_t unit;
    rome2_guest_status status;
    int failures = 0;

    memset(bytes, 0, sizeof(bytes));
    make_view(&view, bytes, UINT32_C(0x1000), (uint64_t)sizeof(bytes));

    /* Little-endian assembly at an odd offset. */
    bytes[1] = 0xef;
    bytes[2] = 0xbe;
    unit = UINT16_C(0xffff);
    status = rome2_guest_read_u16_le(&view,
        guest_address(UINT32_C(0x1001)), &unit);
    failures += expect_status("unaligned u16 read", status, ROME2_GUEST_OK);
    failures += expect_policy("unaligned u16 value", unit, UINT16_C(0xbeef));

    /* Partial final cell (one byte) fails and preserves the output. */
    bytes[sizeof(bytes) - 1] = 0x11;
    unit = UINT16_C(0xffff);
    status = rome2_guest_read_u16_le(&view,
        guest_address(UINT32_C(0x1000) + (uint32_t)sizeof(bytes) - 1), &unit);
    failures += expect_status("partial final u16 cell", status,
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_policy("partial u16 leaves output", unit,
        UINT16_C(0xffff));

    /* View shorter than one unit fails. */
    view.byte_count = UINT64_C(1);
    unit = UINT16_C(0xffff);
    status = rome2_guest_read_u16_le(&view,
        guest_address(UINT32_C(0x1000)), &unit);
    failures += expect_status("short view u16", status, ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_policy("short view u16 leaves output", unit,
        UINT16_C(0xffff));
    view.byte_count = (uint64_t)sizeof(bytes);

    unit = UINT16_C(0xa5a5);
    failures += expect_status("below-base u16",
        rome2_guest_read_u16_le(&view, guest_address(UINT32_C(0x0fff)), &unit),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_policy("below-base u16 preserves output", unit,
        UINT16_C(0xa5a5));
    unit = UINT16_C(0xa5a5);
    failures += expect_status("null unit",
        rome2_guest_read_u16_le(&view, guest_address(0), &unit),
        ROME2_GUEST_NULL_ADDRESS);
    failures += expect_policy("null unit preserves output", unit,
        UINT16_C(0xa5a5));
    unit = UINT16_C(0xa5a5);
    failures += expect_status("null u16 view",
        rome2_guest_read_u16_le(NULL, guest_address(UINT32_C(0x1000)), &unit),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_policy("null u16 view preserves output", unit,
        UINT16_C(0xa5a5));
    failures += expect_status("null u16 output",
        rome2_guest_read_u16_le(&view, guest_address(UINT32_C(0x1000)), NULL),
        ROME2_GUEST_BAD_ARGUMENT);

    view.host_base = NULL;
    unit = UINT16_C(0xa5a5);
    failures += expect_status("null u16 host base",
        rome2_guest_read_u16_le(&view, guest_address(UINT32_C(0x1000)), &unit),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_policy("null u16 host base preserves output", unit,
        UINT16_C(0xa5a5));
    view.host_base = bytes;

    /* Extent ending exactly at 2^32 accepts the last complete unit. */
    make_view(&view, bytes, UINT32_C(0xfffffff0), UINT64_C(16));
    bytes[14] = 0xcd;
    bytes[15] = 0xab;
    status = rome2_guest_read_u16_le(&view,
        guest_address(UINT32_C(0xfffffffe)), &unit);
    failures += expect_status("u16 view ending at 2^32", status,
        ROME2_GUEST_OK);
    failures += expect_policy("u16 value ending at 2^32", unit,
        UINT16_C(0xabcd));

    /* Host interval overflowing uintptr is rejected. */
    view.host_base = (const uint8_t *)(uintptr_t)(UINTPTR_MAX - 1);
    unit = UINT16_C(0xa5a5);
    failures += expect_status("u16 host overflow",
        rome2_guest_read_u16_le(&view, guest_address(UINT32_C(0xfffffff0)),
            &unit),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_policy("u16 host overflow preserves output", unit,
        UINT16_C(0xa5a5));

    /* Malformed guest extent outranks the null-address check. */
    view.host_base = bytes;
    view.byte_count = UINT64_C(17);
    unit = UINT16_C(0xa5a5);
    failures += expect_status("u16 extent overflow precedes null",
        rome2_guest_read_u16_le(&view, guest_address(0), &unit),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_policy("u16 extent overflow preserves output", unit,
        UINT16_C(0xa5a5));
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += test_exact_match();
    failures += test_mismatches_install();
    failures += test_bounded_reads();
    failures += test_missing_units_fail();
    failures += test_argument_and_range_failures();
    failures += test_view_ending_at_address_space_end();
    failures += test_high_host_buffer();
    failures += test_read_u16_le();
    if (failures != 0) {
        fprintf(stderr, "entry-policy selector tests failed: %d assertion(s)\n",
            failures);
        return 1;
    }
    printf("entry-policy selector tests passed\n");
    return 0;
}
