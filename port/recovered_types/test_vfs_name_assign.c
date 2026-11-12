#include "vfs_name_assign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static const uint32_t query = 0x11223344, empty = 0xeeeeeeee;
static const rome2_vfs_name_assignment32 sentinel = {{0xabcdef01}, 0x12345678, 0x87654321, true};

static void put32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value; p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16); p[3] = (unsigned char)(value >> 24);
}

static uint32_t get32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

typedef struct fixture {
    unsigned char descriptor_bytes[24], slot_bytes[64];
    rome2_guest_read_view descriptors;
    rome2_vfs_name_write_view32 slots;
    rome2_guest_addr32 descriptor;
    size_t d, s;
} fixture;

static void init(fixture *f, size_t d, size_t s, uint32_t count)
{
    uint32_t i;
    memset(f, 0xa5, sizeof *f);
    f->d = d; f->s = s;
    f->descriptor.value = 0x50000001 + (uint32_t)d;
    f->descriptors.host_base = f->descriptor_bytes + d;
    f->descriptors.guest_base = f->descriptor.value;
    f->descriptors.byte_count = 12;
    f->slots.host_base = f->slot_bytes + s;
    f->slots.guest_base = 0x60000003 + (uint32_t)s;
    f->slots.byte_count = (uint64_t)count * 8u;
    put32(f->descriptor_bytes + d, f->slots.guest_base);
    put32(f->descriptor_bytes + d + 4, count);
    put32(f->descriptor_bytes + d + 8, empty);
    for (i = 0; i < count; ++i) {
        put32(f->slot_bytes + s + i * 8u, empty);
        put32(f->slot_bytes + s + i * 8u + 4, 0xdead0000u + i);
    }
}

static void output_unchanged(const rome2_vfs_name_assignment32 *out)
{
    CHECK(out->value_address.value == sentinel.value_address.value &&
        out->slot_index == sentinel.slot_index && out->probes == sentinel.probes &&
        out->matched_key == sentinel.matched_key);
}

/* Independent oracle: choose the eligible slot with the smallest circular
 * distance, rather than reproducing the implementation's probing loop. */
static void check_assignment(fixture *f, uint32_t name, uint32_t hash,
    uint32_t value, uint32_t budget)
{
    const uint32_t count = get32(f->descriptor_bytes + f->d + 4);
    const uint32_t marker = get32(f->descriptor_bytes + f->d + 8);
    const uint32_t start = hash % count;
    unsigned char expected[64], descriptor_before[24];
    uint32_t i, best_distance = count, best_index = 0;
    bool matched = false;
    rome2_vfs_name_status expected_status, status;
    rome2_vfs_name_assignment32 out = sentinel;
    memcpy(expected, f->slot_bytes, sizeof expected);
    memcpy(descriptor_before, f->descriptor_bytes, sizeof descriptor_before);
    for (i = 0; i < count; ++i) {
        const uint32_t key = get32(expected + f->s + i * 8u);
        const uint32_t distance = (i + count - start) % count;
        if ((key == name || key == marker) && distance < best_distance) {
            best_index = i; best_distance = distance; matched = key == name;
        }
    }
    if (best_distance < count && best_distance < budget) {
        expected_status = ROME2_VFS_NAME_OK;
        put32(expected + f->s + best_index * 8u, name);
        put32(expected + f->s + best_index * 8u + 4, value);
    }
    else { expected_status = budget < count ? ROME2_VFS_NAME_PROBE_LIMIT : ROME2_VFS_NAME_TABLE_FULL; }
    status = rome2_vfs_assign_name32(&f->descriptors, f->descriptor, &f->slots,
        name, hash, value, budget, &out);
    CHECK(status == expected_status);
    CHECK(memcmp(expected, f->slot_bytes, sizeof expected) == 0);
    CHECK(memcmp(descriptor_before, f->descriptor_bytes, sizeof descriptor_before) == 0);
    if (status == ROME2_VFS_NAME_OK) {
        CHECK(out.value_address.value == f->slots.guest_base + best_index * 8u + 4);
        CHECK(out.slot_index == best_index && out.probes == best_distance + 1 && out.matched_key == matched);
    }
    else { output_unchanged(&out); }
}

static void exhaustive_small_tables(void)
{
    uint32_t count, variants = 1;
    for (count = 1; count <= 5; ++count) {
        uint32_t pattern;
        variants *= 3;
        for (pattern = 0; pattern < variants; ++pattern) {
            uint32_t hash_choice, budget, name_choice, value_choice;
            for (hash_choice = 0; hash_choice <= count; ++hash_choice) {
                const uint32_t hash = hash_choice == count ? UINT32_MAX : hash_choice;
                for (budget = 1; budget <= count + 1; ++budget) {
                    for (name_choice = 0; name_choice < 3; ++name_choice) {
                        for (value_choice = 0; value_choice < 2; ++value_choice) {
                            fixture f;
                            uint32_t i, digits = pattern;
                            const uint32_t keys[] = {query, empty, 0xaabb3344};
                            const uint32_t names[] = {query, empty, 0};
                            init(&f, 1, 3, count);
                            for (i = 0; i < count; ++i) {
                                put32(f.slot_bytes + f.s + i * 8u, keys[digits % 3]);
                                digits /= 3;
                            }
                            check_assignment(&f, names[name_choice], hash,
                                value_choice == 0 ? 0 : 0xfedcba98, budget);
                        }
                    }
                }
            }
        }
    }
}

static void failure(fixture *f, rome2_vfs_name_status expected)
{
    unsigned char before[64], descriptor_before[24];
    rome2_vfs_name_assignment32 out = sentinel;
    memcpy(before, f->slot_bytes, sizeof before);
    memcpy(descriptor_before, f->descriptor_bytes, sizeof descriptor_before);
    CHECK(rome2_vfs_assign_name32(&f->descriptors, f->descriptor, &f->slots,
        query, 2, 0x99887766, 5, &out) == expected);
    CHECK(memcmp(before, f->slot_bytes, sizeof before) == 0);
    CHECK(memcmp(descriptor_before, f->descriptor_bytes, sizeof descriptor_before) == 0);
    output_unchanged(&out);
}

static void alignments_and_truncation(void)
{
    size_t d, s, size;
    for (d = 0; d < 8; ++d) {
        for (s = 0; s < 8; ++s) {
            fixture f;
            rome2_vfs_name_assignment32 out;
            uint32_t i;
            for (i = 0; i < 2; ++i) {
                init(&f, d, s, 5);
                put32(f.slot_bytes + s + 16, 0xaabb3344);
                put32(f.slot_bytes + s + 24, 0x77777777);
                if (i != 0) { put32(f.slot_bytes + s + 32, query); }
                for (size = 0; size < 40; ++size) {
                    f.slots.byte_count = size;
                    failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
                }
                f.slots.byte_count = 40;
                CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
                    query, 2, 0x99887766, 5, &out) == ROME2_VFS_NAME_OK);
                CHECK(out.slot_index == 4 && out.probes == 3 && out.matched_key == (i != 0));
            }
            init(&f, d, s, 5);
            for (size = 0; size < 12; ++size) {
                f.descriptors.byte_count = size;
                failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
            }
            /* The declared table is larger than the mapped selected slot.
             * Neither unvisited keys nor unrelated values need mapping. */
            init(&f, d, s, 5);
            f.slots.host_base += 16; f.slots.guest_base += 16; f.slots.byte_count = 8;
            CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
                query, 2, 0, 1, &out) == ROME2_VFS_NAME_OK);
            CHECK(out.slot_index == 2 && out.probes == 1 && !out.matched_key);
            CHECK(get32(f.slot_bytes + s + 16) == query && get32(f.slot_bytes + s + 20) == 0);
            /* Last mapped key is a collision; its value need not be mapped
             * for a budget-limited search. */
            init(&f, d, s, 5);
            put32(f.slot_bytes + s + 16, 0xaabb3344);
            f.slots.host_base += 16; f.slots.guest_base += 16; f.slots.byte_count = 4;
            out = sentinel;
            CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
                query, 2, 0, 1, &out) == ROME2_VFS_NAME_PROBE_LIMIT);
            output_unchanged(&out);
        }
    }
}

static void arguments_and_endpoints(void)
{
    fixture f;
    rome2_vfs_name_assignment32 out = sentinel;
    rome2_guest_addr32 zero = {0};
    init(&f, 0, 0, 5);
    CHECK(rome2_vfs_assign_name32(NULL, f.descriptor, &f.slots, query, 0, 1, 1, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_assign_name32(&f.descriptors, zero, &f.slots, query, 0, 1, 1, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, NULL, query, 0, 1, 1, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots, query, 0, 1, 0, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots, query, 0, 1, 1, NULL) == ROME2_VFS_NAME_BAD_ARGUMENT);
    output_unchanged(&out);
    put32(f.descriptor_bytes, 0); failure(&f, ROME2_VFS_NAME_INVALID_TABLE);
    init(&f, 0, 0, 5); put32(f.descriptor_bytes + 4, 0); failure(&f, ROME2_VFS_NAME_INVALID_TABLE);
    init(&f, 0, 0, 5); put32(f.descriptor_bytes + 4, UINT32_MAX); failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    init(&f, 0, 0, 5); f.slots.host_base = NULL; failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    init(&f, 0, 0, 5); f.descriptors.host_base = NULL; failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    init(&f, 0, 0, 5); f.slots.byte_count = UINT64_MAX; failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    init(&f, 0, 0, 5); f.slots.guest_base = UINT32_MAX - 3; failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    init(&f, 0, 0, 5); f.slots.host_base = (unsigned char *)(UINTPTR_MAX - 2); failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    init(&f, 0, 0, 1);
    f.descriptor.value = 0xfffffff4; f.descriptors.guest_base = f.descriptor.value;
    f.slots.guest_base = 0xfffffff8; put32(f.descriptor_bytes, f.slots.guest_base);
    CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
        query, UINT32_MAX, UINT32_MAX, UINT32_MAX, &out) == ROME2_VFS_NAME_OK);
    CHECK(out.value_address.value == 0xfffffffc && out.slot_index == 0 && out.probes == 1 && !out.matched_key);
    CHECK(get32(f.slot_bytes) == query && get32(f.slot_bytes + 4) == UINT32_MAX);
    put32(f.descriptor_bytes + 4, 2); failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
    put32(f.descriptor_bytes + 4, 1); f.descriptor.value++; f.descriptors.guest_base++;
    failure(&f, ROME2_VFS_NAME_RANGE_ERROR);
}

static void population_and_replacement(void)
{
    fixture f;
    rome2_vfs_name_assignment32 out;
    rome2_vfs_name_match32 match;
    rome2_guest_read_view readable;
    uint32_t i;
    init(&f, 3, 5, 5);
    readable.host_base = f.slots.host_base;
    readable.guest_base = f.slots.guest_base; readable.byte_count = f.slots.byte_count;
    for (i = 0; i < 5; ++i) {
        CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
            0x10000000 + i, 4, i + 10, 5, &out) == ROME2_VFS_NAME_OK);
        CHECK(out.slot_index == (i + 4) % 5 && out.probes == i + 1 && !out.matched_key);
    }
    failure(&f, ROME2_VFS_NAME_TABLE_FULL);
    /* Equal-key assignment still succeeds when every slot is occupied. */
    for (i = 0; i < 5; ++i) {
        CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
            0x10000000 + i, 4, i == 2 ? 0 : i + 20, UINT32_MAX, &out) == ROME2_VFS_NAME_OK);
        CHECK(out.matched_key && out.slot_index == (i + 4) % 5);
        CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &readable,
            0x10000000 + i, 4, 5, &match) == ROME2_VFS_NAME_OK);
        CHECK(match.value == (i == 2 ? 0 : i + 20) && match.value_address.value == out.value_address.value);
    }
    init(&f, 3, 5, 5); put32(f.descriptor_bytes + f.d + 8, 0);
    put32(f.slot_bytes + f.s, 0);
    CHECK(rome2_vfs_assign_name32(&f.descriptors, f.descriptor, &f.slots,
        0, 0, 0x12345678, 1, &out) == ROME2_VFS_NAME_OK && out.matched_key);
    CHECK(get32(f.slot_bytes + f.s) == 0 && get32(f.slot_bytes + f.s + 4) == 0x12345678);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &readable,
        query, 0, 5, &match) == ROME2_VFS_NAME_NOT_FOUND);
}

int main(void)
{
    exhaustive_small_tables();
    alignments_and_truncation();
    arguments_and_endpoints();
    population_and_replacement();
    printf("VFS name assignment: %zu checks; bounded population/replacement verified.\n", checks);
    return 0;
}
