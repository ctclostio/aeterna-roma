#include "ported_100e8240_singleton.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>

static rome2_engine_diagnostics s_diagnostics;
static INIT_ONCE s_init_once = INIT_ONCE_STATIC_INIT;
static bool s_initialized = false;

static BOOL CALLBACK init_diagnostics_callback(
    PINIT_ONCE init_once,
    PVOID parameter,
    PVOID *context)
{
    (void)init_once;
    (void)parameter;
    (void)context;

    memset(&s_diagnostics, 0, sizeof(s_diagnostics));

    /* Default paths configured in FUN_100e8240 lines 18-24 */
    wchar_t temp_dir[260];
    DWORD len = GetTempPathW(sizeof(temp_dir) / sizeof(wchar_t), temp_dir);
    if (len > 0 && len < sizeof(temp_dir) / sizeof(wchar_t)) {
        swprintf_s(s_diagnostics.crash_stack_path,
                   sizeof(s_diagnostics.crash_stack_path) / sizeof(wchar_t),
                   L"%lsCrash.stack", temp_dir);
        swprintf_s(s_diagnostics.crash_dmp_path,
                   sizeof(s_diagnostics.crash_dmp_path) / sizeof(wchar_t),
                   L"%lsCrash.dmp", temp_dir);
    } else {
        wcscpy_s(s_diagnostics.crash_stack_path,
                 sizeof(s_diagnostics.crash_stack_path) / sizeof(wchar_t),
                 L"Crash.stack");
        wcscpy_s(s_diagnostics.crash_dmp_path,
                 sizeof(s_diagnostics.crash_dmp_path) / sizeof(wchar_t),
                 L"Crash.dmp");
    }

    s_initialized = true;
    return TRUE;
}

rome2_engine_diagnostics *rome2_port_100e8240_get_diagnostics(void)
{
    InitOnceExecuteOnce(&s_init_once, init_diagnostics_callback, NULL, NULL);
    return &s_diagnostics;
}

void rome2_port_100e8240_reset_diagnostics(void)
{
    rome2_port_100e8240_free_prior_allocation();
    memset(&s_diagnostics, 0, sizeof(s_diagnostics));
    s_init_once = (INIT_ONCE)INIT_ONCE_STATIC_INIT;
    s_initialized = false;
}

void rome2_port_100e8240_set_modified(bool modified)
{
    rome2_engine_diagnostics *diag = rome2_port_100e8240_get_diagnostics();
    diag->is_modified = modified;
}

bool rome2_port_100e8240_is_modified(void)
{
    rome2_engine_diagnostics *diag = rome2_port_100e8240_get_diagnostics();
    return diag->is_modified;
}

void rome2_port_100e8240_free_prior_allocation(void)
{
    if (s_diagnostics.prior_allocation != NULL) {
        VirtualFree(s_diagnostics.prior_allocation, 0, MEM_RELEASE);
        s_diagnostics.prior_allocation = NULL;
        s_diagnostics.prior_allocation_size = 0;
    }
}
