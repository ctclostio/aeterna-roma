#ifndef ROME2_PORTED_100E85D0_NORMAL_ADAPTER_H
#define ROME2_PORTED_100E85D0_NORMAL_ADAPTER_H

#include "guest32.h"

#define ROME2_PORT_100E85D0_NORMAL_AL UINT8_C(1)

/*
 * Model the effect-free normal handler at original 0x100e85d0.  The original
 * body ignores its thiscall receiver and sole stack argument, calls the
 * authenticated one-byte RET at 0x100d6560, then defines only AL as one.
 * Both guest identities therefore remain opaque values and every guest32 bit
 * pattern, including zero, is admitted without dereference or validation.
 *
 * return_al_out is a required borrowed one-byte result object.  A null output
 * fails with BAD_ARGUMENT; success publishes exactly one and has no guest,
 * context, allocator, platform, or other externally modeled effect.  The port
 * does not call or link the original helper and makes no claim that this safe
 * C API reproduces the original native thiscall ABI or undefined upper EAX.
 * The function is bounded, allocation-free, reentrant, and thread-safe.
 */
rome2_guest_status rome2_port_100e85d0_normal_adapter(
    rome2_guest_addr32 guest_receiver,
    rome2_guest_addr32 guest_argument,
    uint8_t *return_al_out);

#endif
