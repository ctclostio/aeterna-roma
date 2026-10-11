#include "ported_100e8240_singleton.h"

#include <assert.h>
#include <stdio.h>
#include <windows.h>

static void test_singleton_pointer_stability(void)
{
    printf("[TEST] test_singleton_pointer_stability... ");

    rome2_engine_diagnostics *d1 = rome2_port_100e8240_get_diagnostics();
    rome2_engine_diagnostics *d2 = rome2_port_100e8240_get_diagnostics();

    assert(d1 != NULL);
    assert(d2 != NULL);
    assert(d1 == d2);

    /* Verify crash paths initialized */
    assert(wcsstr(d1->crash_stack_path, L"Crash.stack") != NULL);
    assert(wcsstr(d1->crash_dmp_path, L"Crash.dmp") != NULL);

    printf("PASS\n");
}

static void test_modified_flag_behavior(void)
{
    printf("[TEST] test_modified_flag_behavior... ");

    rome2_port_100e8240_reset_diagnostics();
    assert(!rome2_port_100e8240_is_modified());

    rome2_port_100e8240_set_modified(true);
    assert(rome2_port_100e8240_is_modified());

    rome2_port_100e8240_set_modified(false);
    assert(!rome2_port_100e8240_is_modified());

    printf("PASS\n");
}

static void test_prior_allocation_release(void)
{
    printf("[TEST] test_prior_allocation_release... ");

    rome2_engine_diagnostics *diag = rome2_port_100e8240_get_diagnostics();

    /* Allocate buffer with VirtualAlloc */
    size_t alloc_size = 64 * 1024;
    void *buf = VirtualAlloc(NULL, alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    assert(buf != NULL);

    diag->prior_allocation = buf;
    diag->prior_allocation_size = alloc_size;

    /* Write test pattern */
    memset(buf, 0xAA, alloc_size);

    /* Release via singleton helper */
    rome2_port_100e8240_free_prior_allocation();
    assert(diag->prior_allocation == NULL);
    assert(diag->prior_allocation_size == 0);

    printf("PASS\n");
}

int main(void)
{
    printf("====================================================\n");
    printf(" Rome II Subsystem 2.2 (0x100e8240 Singleton) Tests\n");
    printf("====================================================\n");

    test_singleton_pointer_stability();
    test_modified_flag_behavior();
    test_prior_allocation_release();

    printf("\n>>> ALL SUBSYSTEM 2.2 TESTS PASSED SUCCESSFULLY! <<<\n");
    return 0;
}
