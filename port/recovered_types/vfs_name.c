#include "vfs_name.h"

bool rome2_vfs_hash_name_bytes(const unsigned char *bytes, size_t size,
    uint32_t *output)
{
    uint32_t even = 0, odd = 0;
    size_t i;
    if (output == NULL || (bytes == NULL && size != 0)) { return false; }
    for (i = 0; i < size && bytes[i] != 0; ++i) {
        const int32_t value = bytes[i] < 0x80 ? (int32_t)bytes[i] : (int32_t)bytes[i] - 0x100;
        if ((i & 1u) == 0) { even += (uint32_t)value; }
        else { odd += (uint32_t)value; }
    }
    *output = (even & 0xffffu) | ((odd & 0xffffu) << 16);
    return true;
}

static bool read_word(const rome2_guest_read_view *view, rome2_guest_addr32 base,
    uint32_t offset, uint32_t *output)
{
    rome2_guest_addr32 cell, word;
    if (rome2_guest_add_checked(base, offset, &cell) != ROME2_GUEST_OK ||
        rome2_guest_read_addr32_le(view, cell, &word) != ROME2_GUEST_OK) { return false; }
    *output = word.value;
    return true;
}

rome2_vfs_name_status rome2_vfs_probe_name32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 descriptor,
    const rome2_guest_read_view *slots, uint32_t name, uint32_t hash,
    uint32_t max_probes, rome2_vfs_name_match32 *output)
{
    rome2_guest_addr32 items, cell;
    rome2_vfs_name_match32 result;
    uint32_t buckets, empty, index, probe, limit, key;
    if (descriptors == NULL || slots == NULL || output == NULL || descriptor.value == 0 || max_probes == 0) {
        return ROME2_VFS_NAME_BAD_ARGUMENT;
    }
    if (!read_word(descriptors, descriptor, 0, &items.value) ||
        !read_word(descriptors, descriptor, 4, &buckets) || !read_word(descriptors, descriptor, 8, &empty)) {
        return ROME2_VFS_NAME_RANGE_ERROR;
    }
    if (items.value == 0 || buckets == 0) { return ROME2_VFS_NAME_INVALID_TABLE; }
    if ((uint64_t)buckets * 8u > UINT64_C(0x100000000) - items.value) { return ROME2_VFS_NAME_RANGE_ERROR; }
    index = hash % buckets; limit = max_probes < buckets ? max_probes : buckets;
    for (probe = 0; probe < limit; ++probe) {
        /* The full numeric extent check above makes index*8 fit uint32_t. */
        if (rome2_guest_add_checked(items, index * 8u, &cell) != ROME2_GUEST_OK ||
            !read_word(slots, cell, 0, &key)) { return ROME2_VFS_NAME_RANGE_ERROR; }
        if (key == name) {
            if (rome2_guest_add_checked(cell, 4, &result.value_address) != ROME2_GUEST_OK ||
                !read_word(slots, cell, 4, &result.value)) { return ROME2_VFS_NAME_RANGE_ERROR; }
            result.slot_index = index; result.probes = probe + 1;
            *output = result;
            return ROME2_VFS_NAME_OK;
        }
        if (key == empty) { return ROME2_VFS_NAME_NOT_FOUND; }
        index = index == buckets - 1 ? 0 : index + 1;
    }
    return max_probes < buckets ? ROME2_VFS_NAME_PROBE_LIMIT : ROME2_VFS_NAME_NOT_FOUND;
}
