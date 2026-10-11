#include "ported_100e85d0_normal_adapter.h"

#include <stdint.h>
#include <stdio.h>

#define ROME2_ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))

typedef struct rome2_100e85d0_case {
    const char *label;
    uint32_t receiver;
    uint32_t argument;
} rome2_100e85d0_case;

typedef struct rome2_100e85d0_output_guard {
    uint8_t before;
    uint8_t output;
    uint8_t after;
} rome2_100e85d0_output_guard;

static rome2_guest_addr32 rome2_100e85d0_identity(uint32_t value)
{
    rome2_guest_addr32 identity;

    identity.value = value;
    return identity;
}

static int rome2_100e85d0_expect_success(
    const rome2_100e85d0_case *test_case)
{
    rome2_100e85d0_output_guard guard = {
        UINT8_C(0x3c), UINT8_C(0xa5), UINT8_C(0xc3)
    };
    rome2_guest_status status;

    status = rome2_port_100e85d0_normal_adapter(
        rome2_100e85d0_identity(test_case->receiver),
        rome2_100e85d0_identity(test_case->argument),
        &guard.output);
    if (status != ROME2_GUEST_OK) {
        fprintf(stderr, "FAIL %s: status=%d expected=%d\n",
            test_case->label, (int)status, (int)ROME2_GUEST_OK);
        return 1;
    }
    if (guard.output != UINT8_C(1)) {
        fprintf(stderr, "FAIL %s: AL=0x%02x expected=0x01\n",
            test_case->label, (unsigned int)guard.output);
        return 1;
    }
    if (guard.before != UINT8_C(0x3c) || guard.after != UINT8_C(0xc3)) {
        fprintf(stderr, "FAIL %s: output guard changed\n", test_case->label);
        return 1;
    }
    return 0;
}

static int rome2_100e85d0_test_identity_domain(void)
{
    static const rome2_100e85d0_case cases[] = {
        {"both identities null", UINT32_C(0), UINT32_C(0)},
        {"ordinary identities", UINT32_C(0x1000), UINT32_C(0x2000)},
        {"receiver high bit", UINT32_C(0x80000000), UINT32_C(1)},
        {"argument high bit", UINT32_C(1), UINT32_C(0x80000000)},
        {"all bits set", UINT32_MAX, UINT32_MAX},
        {"distinct opaque bits", UINT32_C(0xdeadbeef), UINT32_C(0x13579bdf)},
    };
    size_t index;
    int failures = 0;

    for (index = 0; index < ROME2_ARRAY_COUNT(cases); ++index) {
        failures += rome2_100e85d0_expect_success(&cases[index]);
    }
    return failures;
}

static int rome2_100e85d0_test_null_output_fails_closed(void)
{
    rome2_guest_status status = rome2_port_100e85d0_normal_adapter(
        rome2_100e85d0_identity(UINT32_C(0xdeadbeef)),
        rome2_100e85d0_identity(UINT32_C(0xcafebabe)),
        NULL);

    if (status == ROME2_GUEST_BAD_ARGUMENT) {
        return 0;
    }
    fprintf(stderr, "FAIL null output: status=%d expected=%d\n",
        (int)status, (int)ROME2_GUEST_BAD_ARGUMENT);
    return 1;
}

static int rome2_100e85d0_test_repeatability(void)
{
    uint32_t iteration;

    for (iteration = 0; iteration < UINT32_C(65536); ++iteration) {
        uint8_t output = UINT8_C(0xa5);
        rome2_guest_status status = rome2_port_100e85d0_normal_adapter(
            rome2_100e85d0_identity(iteration * UINT32_C(0x9e3779b1)),
            rome2_100e85d0_identity(~iteration),
            &output);

        if (status != ROME2_GUEST_OK || output != UINT8_C(1)) {
            fprintf(stderr, "FAIL repeatability at iteration %u\n",
                (unsigned int)iteration);
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += rome2_100e85d0_test_identity_domain();
    failures += rome2_100e85d0_test_null_output_fails_closed();
    failures += rome2_100e85d0_test_repeatability();
    if (failures != 0) {
        fprintf(stderr,
            "startup 100e85d0 normal adapter tests: %d failure(s)\n",
            failures);
        return 1;
    }
    puts("startup 100e85d0 normal adapter tests: pass");
    return 0;
}
