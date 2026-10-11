#include "guest32.h"
#include "ported_1093c450.h"

#include <stdio.h>
#include <string.h>

static rome2_guest_addr32 guest_address(uint32_t value)
{
    rome2_guest_addr32 address;

    address.value = value;
    return address;
}

static void store_u32_le(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value & UINT32_C(0xff));
    destination[1] = (uint8_t)((value >> 8) & UINT32_C(0xff));
    destination[2] = (uint8_t)((value >> 16) & UINT32_C(0xff));
    destination[3] = (uint8_t)((value >> 24) & UINT32_C(0xff));
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

static int expect_value(
    const char *test_name,
    rome2_guest_addr32 actual,
    uint32_t expected)
{
    if (actual.value == expected) {
        return 0;
    }
    fprintf(stderr, "%s: value 0x%08x, expected 0x%08x\n", test_name,
        (unsigned int)actual.value, (unsigned int)expected);
    return 1;
}

static int test_read_addr32(void)
{
    uint8_t bytes[24];
    rome2_guest_read_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(bytes, 0, sizeof(bytes));
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x1000);
    view.byte_count = (uint64_t)sizeof(bytes);

    store_u32_le(bytes + 1, UINT32_C(0x78563412));
    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("unaligned read",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x1001)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("unaligned read", output, UINT32_C(0x78563412));

    store_u32_le(bytes + sizeof(bytes) - 4, UINT32_C(0x10203040));
    failures += expect_status("last complete cell",
        rome2_guest_read_addr32_le(
            &view,
            guest_address(UINT32_C(0x1000) +
                (uint32_t)sizeof(bytes) - UINT32_C(4)),
            &output),
        ROME2_GUEST_OK);
    failures += expect_value("last complete cell", output, UINT32_C(0x10203040));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("partial final cell",
        rome2_guest_read_addr32_le(
            &view,
            guest_address(UINT32_C(0x1000) +
                (uint32_t)sizeof(bytes) - UINT32_C(3)),
            &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_value("partial read leaves output", output,
        UINT32_C(0xaaaaaaaa));

    view.byte_count = UINT64_C(3);
    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("view shorter than one cell",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x1000)), &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_value("short view leaves output", output,
        UINT32_C(0xaaaaaaaa));
    view.byte_count = (uint64_t)sizeof(bytes);

    failures += expect_status("below base",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x0fff)), &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_value("below base leaves output", output,
        UINT32_C(0xaaaaaaaa));
    failures += expect_status("null cell",
        rome2_guest_read_addr32_le(&view, guest_address(0), &output),
        ROME2_GUEST_NULL_ADDRESS);
    failures += expect_value("null cell leaves output", output,
        UINT32_C(0xaaaaaaaa));
    failures += expect_status("null view",
        rome2_guest_read_addr32_le(NULL, guest_address(UINT32_C(0x1000)),
            &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_value("null view leaves output", output,
        UINT32_C(0xaaaaaaaa));
    failures += expect_status("null output",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x1000)), NULL),
        ROME2_GUEST_BAD_ARGUMENT);

    view.host_base = NULL;
    view.byte_count = 0;
    failures += expect_status("null host base",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x1000)), &output),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_value("null host leaves output", output,
        UINT32_C(0xaaaaaaaa));
    return failures;
}

static int test_view_extent(void)
{
    uint8_t bytes[16];
    rome2_guest_read_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(bytes, 0, sizeof(bytes));
    store_u32_le(bytes + 12, UINT32_C(0x01020304));
    view.host_base = bytes;
    view.guest_base = UINT32_C(0xfffffff0);
    view.byte_count = UINT64_C(16);
    failures += expect_status("view ending at 2^32",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0xfffffffc)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("view ending at 2^32", output,
        UINT32_C(0x01020304));

    store_u32_le(bytes, UINT32_C(0x89abcdef));
    view.guest_base = UINT32_C(1);
    view.byte_count = UINT64_C(0xffffffff);
    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("maximum nonzero-base view",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(1)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("maximum nonzero-base view", output,
        UINT32_C(0x89abcdef));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    view.guest_base = UINT32_C(0xfffffff0);
    view.byte_count = UINT64_C(17);
    failures += expect_status("view end overflow",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0xfffffff0)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("overflow leaves output", output,
        UINT32_C(0xaaaaaaaa));

    view.guest_base = 0;
    view.byte_count = UINT64_C(0x100000001);
    failures += expect_status("view wider than guest space",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(1)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("wide view leaves output", output,
        UINT32_C(0xaaaaaaaa));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    view.byte_count = UINT64_MAX;
    failures += expect_status("UINT64_MAX view extent",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(1)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("UINT64_MAX view leaves output", output,
        UINT32_C(0xaaaaaaaa));

    view.host_base = (const uint8_t *)(uintptr_t)(
        UINTPTR_MAX - (uintptr_t)2);
    view.guest_base = UINT32_C(0x1000);
    view.byte_count = UINT64_C(4);
    failures += expect_status("host interval overflow",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x1000)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("host overflow leaves output", output,
        UINT32_C(0xaaaaaaaa));

    view.host_base = bytes;
    view.guest_base = UINT32_C(0xfffffff0);
    view.byte_count = UINT64_C(17);
    failures += expect_status("view overflow precedes null guest address",
        rome2_guest_read_addr32_le(&view, guest_address(0), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("precedence failure leaves output", output,
        UINT32_C(0xaaaaaaaa));
    return failures;
}

static int test_loaded_null(void)
{
    uint8_t bytes[8];
    rome2_guest_read_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(bytes, 0, sizeof(bytes));
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x3000);
    view.byte_count = (uint64_t)sizeof(bytes);
    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("loaded null is representable",
        rome2_guest_read_addr32_le(
            &view, guest_address(UINT32_C(0x3001)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("loaded null value", output, 0);
    return failures;
}

static int test_checked_add(void)
{
    rome2_guest_addr32 output;
    int failures = 0;

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("ordinary add",
        rome2_guest_add_checked(
            guest_address(UINT32_C(0x1234)), UINT32_C(4), &output),
        ROME2_GUEST_OK);
    failures += expect_value("ordinary add", output, UINT32_C(0x1238));

    failures += expect_status("one plus zero",
        rome2_guest_add_checked(
            guest_address(UINT32_C(1)), UINT32_C(0), &output),
        ROME2_GUEST_OK);
    failures += expect_value("one plus zero", output, UINT32_C(1));

    failures += expect_status("largest valid result",
        rome2_guest_add_checked(
            guest_address(UINT32_C(0xfffffffb)), UINT32_C(4), &output),
        ROME2_GUEST_OK);
    failures += expect_value("largest valid result", output,
        UINT32_C(0xffffffff));

    failures += expect_status("maximum address plus zero",
        rome2_guest_add_checked(
            guest_address(UINT32_C(0xffffffff)), UINT32_C(0), &output),
        ROME2_GUEST_OK);
    failures += expect_value("maximum address plus zero", output,
        UINT32_C(0xffffffff));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("addition overflow",
        rome2_guest_add_checked(
            guest_address(UINT32_C(0xfffffffc)), UINT32_C(4), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("overflow leaves output", output,
        UINT32_C(0xaaaaaaaa));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("maximum address plus one",
        rome2_guest_add_checked(
            guest_address(UINT32_C(0xffffffff)), UINT32_C(1), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("maximum plus one leaves output", output,
        UINT32_C(0xaaaaaaaa));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("one plus maximum displacement",
        rome2_guest_add_checked(
            guest_address(UINT32_C(1)), UINT32_C(0xffffffff), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("maximum displacement leaves output", output,
        UINT32_C(0xaaaaaaaa));

    failures += expect_status("null address add",
        rome2_guest_add_checked(guest_address(0), UINT32_C(4), &output),
        ROME2_GUEST_NULL_ADDRESS);
    failures += expect_value("null add leaves output", output,
        UINT32_C(0xaaaaaaaa));

    output = guest_address(UINT32_C(0x1234));
    failures += expect_status("in-place add",
        rome2_guest_add_checked(output, UINT32_C(4), &output),
        ROME2_GUEST_OK);
    failures += expect_value("in-place add", output, UINT32_C(0x1238));

    output = guest_address(UINT32_C(0xfffffffc));
    failures += expect_status("in-place overflow",
        rome2_guest_add_checked(output, UINT32_C(4), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("in-place overflow leaves output", output,
        UINT32_C(0xfffffffc));

    failures += expect_status("null add output",
        rome2_guest_add_checked(
            guest_address(UINT32_C(0x1234)), UINT32_C(4), NULL),
        ROME2_GUEST_BAD_ARGUMENT);
    return failures;
}

static int test_ported_slice(void)
{
    uint8_t bytes[16];
    rome2_guest_read_view view;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(bytes, 0, sizeof(bytes));
    if ((uintptr_t)bytes <= (uintptr_t)UINT32_MAX) {
        fprintf(stderr,
            "x64 host test buffer unexpectedly resides below 4 GiB\n");
        failures += 1;
    }
    view.host_base = bytes;
    view.guest_base = UINT32_C(0x2000);
    view.byte_count = (uint64_t)sizeof(bytes);
    store_u32_le(bytes + 1, UINT32_C(0x34567800));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("1093c450 forwarding thunk",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2001)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("1093c450 forwarding thunk", output,
        UINT32_C(0x34567804));

    store_u32_le(bytes + 1, UINT32_C(0xdeadbeef));
    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("forward target outside view",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2001)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("forward target outside view", output,
        UINT32_C(0xdeadbef3));

    store_u32_le(bytes + 1, UINT32_C(0xfffffffb));
    failures += expect_status("forward largest valid result",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2001)), &output),
        ROME2_GUEST_OK);
    failures += expect_value("forward largest valid result", output,
        UINT32_C(0xffffffff));

    memset(bytes, 0, sizeof(bytes));
    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("forwarded null fails closed",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2001)), &output),
        ROME2_GUEST_NULL_ADDRESS);
    failures += expect_value("forwarded null leaves output", output,
        UINT32_C(0xaaaaaaaa));

    store_u32_le(bytes + 1, UINT32_C(0xfffffffc));
    failures += expect_status("forwarded addition overflow",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2001)), &output),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_value("forward overflow leaves output", output,
        UINT32_C(0xaaaaaaaa));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("forward null outer",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(0), &output),
        ROME2_GUEST_NULL_ADDRESS);
    failures += expect_value("forward null outer leaves output", output,
        UINT32_C(0xaaaaaaaa));

    store_u32_le(bytes + sizeof(bytes) - 4, UINT32_C(0x11111111));
    failures += expect_status("forward last complete outer cell",
        rome2_port_1093c450_forward_get_cstr(
            &view,
            guest_address(UINT32_C(0x2000) +
                (uint32_t)sizeof(bytes) - UINT32_C(4)),
            &output),
        ROME2_GUEST_OK);
    failures += expect_value("forward last complete outer cell", output,
        UINT32_C(0x11111115));

    output = guest_address(UINT32_C(0xaaaaaaaa));
    failures += expect_status("forward partial final outer cell",
        rome2_port_1093c450_forward_get_cstr(
            &view,
            guest_address(UINT32_C(0x2000) +
                (uint32_t)sizeof(bytes) - UINT32_C(3)),
            &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_value("forward partial leaves output", output,
        UINT32_C(0xaaaaaaaa));

    failures += expect_status("forward null result",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2001)), NULL),
        ROME2_GUEST_BAD_ARGUMENT);

    view.guest_base = UINT32_C(0xfffffff0);
    view.byte_count = UINT64_C(17);
    failures += expect_status("null result precedes malformed view",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(0), NULL),
        ROME2_GUEST_BAD_ARGUMENT);

    view.guest_base = UINT32_C(0x2000);
    view.byte_count = (uint64_t)sizeof(bytes);
    failures += expect_status("forward outer out of range",
        rome2_port_1093c450_forward_get_cstr(
            &view, guest_address(UINT32_C(0x2010)), &output),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_value("forward out of range leaves output", output,
        UINT32_C(0xaaaaaaaa));
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += test_read_addr32();
    failures += test_view_extent();
    failures += test_loaded_null();
    failures += test_checked_add();
    failures += test_ported_slice();
    if (failures != 0) {
        fprintf(stderr, "guest32 tests failed: %d assertion(s)\n", failures);
        return 1;
    }
    printf("guest32 tests passed\n");
    return 0;
}
