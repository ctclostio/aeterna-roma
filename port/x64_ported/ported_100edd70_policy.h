#ifndef ROME2_PORTED_100EDD70_POLICY_H
#define ROME2_PORTED_100EDD70_POLICY_H

#include <stdint.h>

#include "guest32.h"

/* Pure decision value reproduced from the original entry_point comparison. */
typedef uint32_t rome2_invalid_parameter_policy;

#define ROME2_INVALID_PARAMETER_INSTALL_HANDLER UINT32_C(0)
#define ROME2_INVALID_PARAMETER_SKIP_HANDLER UINT32_C(1)

/*
 * Port-layer behavior for the original entry_point decision at
 * 0x100edecc-0x100edf04: compare exactly 22 fixed UTF-16LE units (21 ASCII
 * characters plus the NUL terminator) at command_line against the literal
 * "-no_exception_handler" and report the resulting policy.
 *
 * Units are read in order and scanning stops at the first mismatch, so a
 * mismatch is a successful INSTALL_HANDLER result even if the unread guest
 * suffix lies outside the view; a matching prefix whose required next unit
 * is unavailable fails with that read error. All guest +2 cursor steps are
 * checked. *policy_out is written only on success and remains byte-for-byte
 * unchanged on every error.
 */
rome2_guest_status rome2_port_100edd70_select_invalid_parameter_policy(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 command_line,
    rome2_invalid_parameter_policy *policy_out);

#endif

