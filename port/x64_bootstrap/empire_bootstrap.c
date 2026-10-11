#include <windows.h>
#include <stdint.h>

#include "bootstrap_contract.h"
#include "canonical_identity.h"

_Static_assert(sizeof(void *) == 8, "the bootstrap DLL must be compiled for x64");

static const char kCanonicalFingerprint[] =
    ROME2_CANONICAL_FINGERPRINT;
static const char kPortStatus[] = ROME2_PORT_STATUS;

uint64_t Rome2PortAbiVersion(void)
{
    return ROME2_PORT_ABI_VERSION;
}

const char *Rome2PortCanonicalFingerprint(void)
{
    return kCanonicalFingerprint;
}

const char *Rome2PortStatus(void)
{
    return kPortStatus;
}

int Rome2LegacyEntryPoint(
    HINSTANCE instance,
    HINSTANCE previous_instance,
    const wchar_t *command_line,
    uint32_t region_count,
    void **region_bases,
    uint32_t reserve_size_low,
    uint32_t reserve_size_high,
    int32_t show_command,
    void *reserved9)
{
    (void)instance;
    (void)previous_instance;
    (void)command_line;
    (void)region_count;
    (void)region_bases;
    (void)reserve_size_low;
    (void)reserve_size_high;
    (void)show_command;
    (void)reserved9;
    return ROME2_LEGACY_ENTRY_RESULT;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    (void)reason;
    (void)reserved;
    return TRUE;
}
