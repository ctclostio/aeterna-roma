#include "vfs_dispatch.h"

rome2_vfs_dispatch_status rome2_vfs_read_open_dispatch32(
    const rome2_guest_read_view *objects, rome2_guest_addr32 manager,
    const rome2_guest_read_view *tables, rome2_vfs_open_dispatch32 *output)
{
    rome2_vfs_open_dispatch32 result;
    rome2_guest_addr32 slot, target;
    if (objects == NULL || tables == NULL || output == NULL || manager.value == 0) {
        return ROME2_VFS_DISPATCH_BAD_ARGUMENT;
    }
    if (rome2_guest_add_checked(manager, 4, &result.interface_address) != ROME2_GUEST_OK ||
        rome2_guest_read_addr32_le(objects, result.interface_address, &result.vtable_address) != ROME2_GUEST_OK) {
        return ROME2_VFS_DISPATCH_RANGE_ERROR;
    }
    if (result.vtable_address.value == 0) { return ROME2_VFS_DISPATCH_NULL_TABLE; }
    if (rome2_guest_add_checked(result.vtable_address, 4, &slot) != ROME2_GUEST_OK ||
        rome2_guest_read_addr32_le(tables, slot, &target) != ROME2_GUEST_OK) {
        return ROME2_VFS_DISPATCH_RANGE_ERROR;
    }
    if (target.value == 0) { return ROME2_VFS_DISPATCH_NULL_TARGET; }
    result.open_target = target.value;
    *output = result;
    return ROME2_VFS_DISPATCH_OK;
}
