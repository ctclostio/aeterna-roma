#ifndef ROME2_RECOVERED_VFS_DISPATCH_H
#define ROME2_RECOVERED_VFS_DISPATCH_H

#include "layout_bridge.h"

typedef enum rome2_vfs_dispatch_status {
    ROME2_VFS_DISPATCH_OK = 0,
    ROME2_VFS_DISPATCH_BAD_ARGUMENT,
    ROME2_VFS_DISPATCH_RANGE_ERROR,
    ROME2_VFS_DISPATCH_NULL_TABLE,
    ROME2_VFS_DISPATCH_NULL_TARGET
} rome2_vfs_dispatch_status;

typedef struct rome2_vfs_open_dispatch32 {
    rome2_guest_addr32 interface_address;
    rome2_guest_addr32 vtable_address;
    rome2_code_address32 open_target;
} rome2_vfs_open_dispatch32;

/* Observe the XML loader's dispatch: interface=manager+4, table=[interface],
 * target=[table+4]. Object and table views can map separate address regions.
 * Only those two four-byte cells need mapping; unaligned cells are supported.
 * A returned target is a 32-bit identity, never a callable native pointer or
 * proof of executable code, complete vtable bounds, class identity or ABI.
 *
 * NULL views/output or zero manager are BAD_ARGUMENT. Checked address/range
 * failures and null table/target values report their explicit status. Every
 * failure preserves output. Valid non-overlapping host objects and backing
 * bytes remain borrowed/immutable throughout the call. No allocation, I/O,
 * callbacks, locking, manager construction or original-code execution occurs.
 * This does not choose a manager, resolve a filename or establish file status. */
rome2_vfs_dispatch_status rome2_vfs_read_open_dispatch32(
    const rome2_guest_read_view *objects, rome2_guest_addr32 manager,
    const rome2_guest_read_view *tables, rome2_vfs_open_dispatch32 *output);

#endif
