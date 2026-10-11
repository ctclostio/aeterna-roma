/*
 * Test-only x64 guest32 entry-policy probe DLL
 * (rome2_guest32_probe64.dll).
 *
 * The probe is the smallest readable wrapper around the already-tested
 * recovered selector rome2_port_100edd70_select_invalid_parameter_policy.
 * It reproduces no second selector, performs no recovered work under loader
 * lock, and keeps the diagnostic boundary silent.
 */

#include "probe_contract.h"

#include "guest32.h"
#include "ported_100edd70_policy.h"

#include <windows.h>

/*
 * Trivial DllMain: normal CRT startup is kept and no recovered work is
 * performed under loader lock.
 */
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}

uint64_t Rome2Guest32ProbeAbiVersion(void)
{
    return ROME2_GUEST32_PROBE_ABI_VERSION;
}

uint32_t Rome2Guest32ProbeSelectEntryPolicy(
    const uint8_t *host_base,
    uint32_t guest_base,
    uint64_t byte_count,
    uint32_t command_line,
    uint32_t *policy_out)
{
    rome2_guest_read_view view;
    rome2_guest_addr32 command_line_cell;

    /*
     * Borrowed native input only: the view wraps the caller's host pointer
     * as-is.  Guest coordinates keep their frozen 32-bit width and are never
     * used to derive a host pointer.
     */
    view.host_base = host_base;
    view.guest_base = guest_base;
    view.byte_count = byte_count;
    command_line_cell.value = command_line;

    return (uint32_t)rome2_port_100edd70_select_invalid_parameter_policy(
        &view,
        command_line_cell,
        policy_out);
}

