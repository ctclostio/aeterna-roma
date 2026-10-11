#include "ported_100f1bb0_bounded.h"
#include "ported_100f1cc0_nonowning.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_OUTPUT_SENTINEL UINT32_C(0xcccccccc)

static int expect_status(
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

static int expect_output(const char *label, uint32_t actual, uint32_t expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: output=%lu expected=%lu\n",
        label, (unsigned long)actual, (unsigned long)expected);
    return 1;
}

static int test_measure_success(void)
{
    static const uint8_t text[] = {
        0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x00, 0x00, 0xa5, 0xa5
    };
    rome2_guest_read_view view;
    rome2_guest_addr32 address;
    uint8_t unaligned[sizeof(text) + 1];
    uint32_t length;
    int failures = 0;

    view.host_base = text;
    view.guest_base = UINT32_C(0x2000);
    view.byte_count = sizeof(text);
    address.value = UINT32_C(0x2000);
    length = ROME2_TEST_OUTPUT_SENTINEL;
    failures += expect_status("three-unit string",
        rome2_port_100f1bb0_measure_utf16(&view, address, 4, &length),
        ROME2_GUEST_OK);
    failures += expect_output("three-unit string", length, 3);

    address.value = UINT32_C(0x2006);
    length = ROME2_TEST_OUTPUT_SENTINEL;
    failures += expect_status("empty string",
        rome2_port_100f1bb0_measure_utf16(&view, address, 1, &length),
        ROME2_GUEST_OK);
    failures += expect_output("empty string", length, 0);

    memset(unaligned, 0xa5, sizeof(unaligned));
    memcpy(unaligned + 1, text, sizeof(text));
    view.host_base = unaligned + 1;
    view.guest_base = UINT32_C(0x3001);
    view.byte_count = 8;
    address.value = UINT32_C(0x3001);
    length = ROME2_TEST_OUTPUT_SENTINEL;
    failures += expect_status("unaligned guest and host",
        rome2_port_100f1bb0_measure_utf16(&view, address, 4, &length),
        ROME2_GUEST_OK);
    failures += expect_output("unaligned guest and host", length, 3);
    return failures;
}

static int test_measure_failures(void)
{
    static const uint8_t no_terminator[] = {
        0x41, 0x00, 0x42, 0x00, 0x43, 0x00
    };
    rome2_guest_read_view view;
    rome2_guest_addr32 address;
    uint32_t length;
    int failures = 0;

    view.host_base = no_terminator;
    view.guest_base = UINT32_C(0x4000);
    view.byte_count = sizeof(no_terminator);
    address.value = UINT32_C(0x4000);

    length = ROME2_TEST_OUTPUT_SENTINEL;
    failures += expect_status("terminator outside bound",
        rome2_port_100f1bb0_measure_utf16(&view, address, 3, &length),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_output("terminator outside bound", length,
        ROME2_TEST_OUTPUT_SENTINEL);

    length = ROME2_TEST_OUTPUT_SENTINEL;
    failures += expect_status("view ends before declared bound",
        rome2_port_100f1bb0_measure_utf16(&view, address, 4, &length),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_output("view ends before declared bound", length,
        ROME2_TEST_OUTPUT_SENTINEL);

    length = ROME2_TEST_OUTPUT_SENTINEL;
    failures += expect_status("zero bound",
        rome2_port_100f1bb0_measure_utf16(&view, address, 0, &length),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_output("zero bound", length, ROME2_TEST_OUTPUT_SENTINEL);

    failures += expect_status("over containment bound",
        rome2_port_100f1bb0_measure_utf16(&view, address,
            ROME2_PORT_100F1BB0_MAX_UNITS + UINT32_C(1), &length),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += expect_output("over containment bound", length,
        ROME2_TEST_OUTPUT_SENTINEL);

    failures += expect_status("null output",
        rome2_port_100f1bb0_measure_utf16(&view, address, 3, NULL),
        ROME2_GUEST_BAD_ARGUMENT);

    length = ROME2_TEST_OUTPUT_SENTINEL;
    address.value = 0;
    failures += expect_status("null guest address",
        rome2_port_100f1bb0_measure_utf16(&view, address, 3, &length),
        ROME2_GUEST_NULL_ADDRESS);
    failures += expect_output("null guest address", length,
        ROME2_TEST_OUTPUT_SENTINEL);

    address.value = UINT32_C(0x3fff);
    failures += expect_status("guest address below view",
        rome2_port_100f1bb0_measure_utf16(&view, address, 3, &length),
        ROME2_GUEST_OUT_OF_RANGE);
    failures += expect_output("guest address below view", length,
        ROME2_TEST_OUTPUT_SENTINEL);

    view.guest_base = UINT32_C(0xfffffffe);
    view.byte_count = 2;
    address.value = UINT32_C(0xfffffffe);
    failures += expect_status("cursor overflow",
        rome2_port_100f1bb0_measure_utf16(&view, address, 2, &length),
        ROME2_GUEST_RANGE_OVERFLOW);
    failures += expect_output("cursor overflow", length,
        ROME2_TEST_OUTPUT_SENTINEL);
    return failures;
}

static int test_nonowning_noop(void)
{
    rome2_guest_addr32 value;
    int failures = 0;

    value.value = 0;
    failures += expect_status("null nonowning value",
        rome2_port_100f1cc0_accept_nonowning_noop(value), ROME2_GUEST_OK);
    value.value = ROME2_PORT_100F1CC0_SENTINEL;
    failures += expect_status("sentinel nonowning value",
        rome2_port_100f1cc0_accept_nonowning_noop(value), ROME2_GUEST_OK);
    value.value = ROME2_PORT_100F1CC0_SENTINEL - UINT32_C(1);
    failures += expect_status("owning value below sentinel",
        rome2_port_100f1cc0_accept_nonowning_noop(value),
        ROME2_GUEST_BAD_ARGUMENT);
    value.value = ROME2_PORT_100F1CC0_SENTINEL + UINT32_C(1);
    failures += expect_status("owning value above sentinel",
        rome2_port_100f1cc0_accept_nonowning_noop(value),
        ROME2_GUEST_BAD_ARGUMENT);
    value.value = UINT32_C(1);
    failures += expect_status("arbitrary owning value",
        rome2_port_100f1cc0_accept_nonowning_noop(value),
        ROME2_GUEST_BAD_ARGUMENT);
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += test_measure_success();
    failures += test_measure_failures();
    failures += test_nonowning_noop();
    if (failures != 0) {
        fprintf(stderr, "startup safe-seam tests failed: %d\n", failures);
        return 1;
    }
    printf("startup safe-seam tests passed\n");
    return 0;
}
