#ifndef ROME2_GUEST32_PROBE_CONTRACT_H
#define ROME2_GUEST32_PROBE_CONTRACT_H

#include <stdint.h>

/*
 * Frozen diagnostic ABI for the test-only x64 guest32 entry-policy probe
 * (milestone entry-policy-dynamic-probe-v1).
 *
 * The probe DLL exports exactly these two names.  Export ordinals are
 * implementation-local, are never consumed by the host, and make no claim on
 * the original 1-522 ABI.  No struct, Windows wchar_t, allocator, CRT object,
 * callback, persistent state, or ownership transfer crosses this boundary.
 *
 * Numeric conventions frozen by docs/x64_entry_policy_dynamic_probe_spec.md:
 *   guest32 status values (returned by the selector adapter):
 *     0 OK, 1 BAD_ARGUMENT, 2 NULL_ADDRESS, 3 RANGE_OVERFLOW, 4 OUT_OF_RANGE
 *   policy values:
 *     0 INSTALL_HANDLER, 1 SKIP_HANDLER
 */

#define ROME2_GUEST32_PROBE_ABI_VERSION UINT64_C(0x00010000)

#ifdef __cplusplus
extern "C" {
#endif

/* Returns ROME2_GUEST32_PROBE_ABI_VERSION. */
uint64_t Rome2Guest32ProbeAbiVersion(void);

/*
 * Delegate the recovered 0x100edd70 entry-policy decision to
 * rome2_port_100edd70_select_invalid_parameter_policy across a real DLL call
 * boundary.
 *
 *  host_base    borrowed native x64 pointer to byte_count genuinely readable
 *               bytes in the calling process; never derived from a guest
 *               value;
 *  guest_base   modeled x86 base address of the borrowed interval;
 *  byte_count   length of the borrowed interval; the half-open guest range
 *               [guest_base, guest_base + byte_count) may end exactly at
 *               2^32;
 *  command_line modeled x86 address of the UTF-16LE string under test;
 *  policy_out   assigned only on success (status 0); byte-for-byte unchanged
 *               on every failure.
 *
 * Returns the numeric guest32 status listed above.  Stateless: every call is
 * independent and deterministic, with no shared or global mutable state.
 */
uint32_t Rome2Guest32ProbeSelectEntryPolicy(
    const uint8_t *host_base,
    uint32_t guest_base,
    uint64_t byte_count,
    uint32_t command_line,
    uint32_t *policy_out);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_GUEST32_PROBE_CONTRACT_H */


