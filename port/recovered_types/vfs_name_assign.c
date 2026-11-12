#include "vfs_name_assign.h"

static bool read_word(const rome2_guest_read_view *view, rome2_guest_addr32 base,
    uint32_t offset, uint32_t *output)
{
    rome2_guest_addr32 cell, word;
    if (rome2_guest_add_checked(base, offset, &cell) != ROME2_GUEST_OK ||
        rome2_guest_read_addr32_le(view, cell, &word) != ROME2_GUEST_OK) { return false; }
    *output = word.value;
    return true;
}

static void put_word(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
}

rome2_vfs_name_status rome2_vfs_assign_name32(
    const rome2_guest_read_view *descriptors, rome2_guest_addr32 descriptor,
    const rome2_vfs_name_write_view32 *slots, uint32_t name, uint32_t hash,
    rome2_data_address32 value, uint32_t max_probes,
    rome2_vfs_name_assignment32 *output)
{
    rome2_guest_read_view readable;
    rome2_guest_addr32 items, cell;
    rome2_vfs_name_assignment32 result;
    uint32_t buckets, empty, index, probe, limit, key, unused;
    if (descriptors == NULL || slots == NULL || output == NULL ||
        descriptor.value == 0 || max_probes == 0) { return ROME2_VFS_NAME_BAD_ARGUMENT; }
    if (!read_word(descriptors, descriptor, 0, &items.value) ||
        !read_word(descriptors, descriptor, 4, &buckets) ||
        !read_word(descriptors, descriptor, 8, &empty)) { return ROME2_VFS_NAME_RANGE_ERROR; }
    if (items.value == 0 || buckets == 0) { return ROME2_VFS_NAME_INVALID_TABLE; }
    if ((uint64_t)buckets * 8u > UINT64_C(0x100000000) - items.value) { return ROME2_VFS_NAME_RANGE_ERROR; }
    readable.host_base = slots->host_base;
    readable.guest_base = slots->guest_base;
    readable.byte_count = slots->byte_count;
    index = hash % buckets;
    limit = max_probes < buckets ? max_probes : buckets;
    for (probe = 0; probe < limit; ++probe) {
        if (rome2_guest_add_checked(items, index * 8u, &cell) != ROME2_GUEST_OK ||
            !read_word(&readable, cell, 0, &key)) { return ROME2_VFS_NAME_RANGE_ERROR; }
        if (key == name || key == empty) {
            unsigned char *value_bytes;
            if (rome2_guest_add_checked(cell, 4, &result.value_address) != ROME2_GUEST_OK ||
                !read_word(&readable, cell, 4, &unused)) { return ROME2_VFS_NAME_RANGE_ERROR; }
            /* The checked value read proves this host offset and all four bytes
             * valid before either key or value changes. The key was also read. */
            value_bytes = slots->host_base + (size_t)((uint64_t)result.value_address.value - slots->guest_base);
            result.slot_index = index;
            result.probes = probe + 1;
            result.matched_key = key == name;
            if (!result.matched_key) { put_word(value_bytes - 4, name); }
            put_word(value_bytes, value);
            *output = result;
            return ROME2_VFS_NAME_OK;
        }
        index = index == buckets - 1 ? 0 : index + 1;
    }
    return max_probes < buckets ? ROME2_VFS_NAME_PROBE_LIMIT : ROME2_VFS_NAME_TABLE_FULL;
}
