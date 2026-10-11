#ifndef ROME2_PORTED_100E8240_SINGLETON_H
#define ROME2_PORTED_100E8240_SINGLETON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_100E8240_SINGLETON_PC    UINT32_C(0x100e8240)
#define ROME2_PORT_100E8240_STRUCT_ADDR     UINT32_C(0x119f3a38)
#define ROME2_PORT_100E8240_MODIFIED_OFFSET UINT32_C(0x38)

/*
 * Total War Rome II Engine Crash & Diagnostics Singleton (0x119f3a38)
 *
 * Layout corresponding to original 32-bit offsets:
 *   +0x00: crash flags & status
 *   +0x04: cmd_show configuration
 *   +0x08: param_5 configuration pointer
 *   +0x0C: param_6 configuration pointer
 *   +0x10: param_7 configuration pointer
 *   +0x38: is_modified flag (written by manifest validator FUN_100e2980)
 *   +0x3C: crash stack filepath ("Crash.stack")
 *   +0x48: crash dmp filepath ("Crash.dmp")
 */
typedef struct rome2_engine_diagnostics {
    uint32_t flags;
    uint32_t cmd_show;
    uint32_t param_5;
    uint32_t param_6;
    uint32_t param_7;

    bool is_modified;

    wchar_t crash_stack_path[260];
    wchar_t crash_dmp_path[260];

    void *prior_allocation;
    size_t prior_allocation_size;
} rome2_engine_diagnostics;

/*
 * Thread-safe singleton accessor for 0x100e8240
 */
rome2_engine_diagnostics *rome2_port_100e8240_get_diagnostics(void);

/*
 * Reset/cleanup functions for lifecycle control and test isolation
 */
void rome2_port_100e8240_reset_diagnostics(void);
void rome2_port_100e8240_set_modified(bool modified);
bool rome2_port_100e8240_is_modified(void);
void rome2_port_100e8240_free_prior_allocation(void);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_100E8240_SINGLETON_H */
