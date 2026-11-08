#include "vfs_name.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static void hash_pairs(void)
{
    unsigned first, second;
    for (first = 0; first < 256; ++first) {
        for (second = 0; second < 256; ++second) {
            const unsigned char bytes[] = {(unsigned char)first, (unsigned char)second};
            const int32_t a = first < 128 ? (int32_t)first : (int32_t)first - 256;
            const int32_t b = second < 128 ? (int32_t)second : (int32_t)second - 256;
            const uint32_t expected = first == 0 ? 0 :
                ((uint32_t)a & 0xffffu) | (((uint32_t)b & 0xffffu) << 16);
            uint32_t result;
            CHECK(rome2_vfs_hash_name_bytes(bytes, sizeof bytes, &result));
            CHECK(result == expected);
        }
    }
}

static void hash_vectors_and_wrap(void)
{
    const struct { const char *text; uint32_t hash; } cases[] = {
        {"", 0}, {"A", 0x41}, {"AB", 0x00420041}, {"ABC", 0x00420084},
        {"Script/fauna_config.xml", 0x045104b2}, {"foo/bar", 0x00ff01a9}, {"foo\\bar", 0x012c01a9}
    };
    unsigned char *long_name = malloc(131074);
    const unsigned char embedded[] = {'A', 0, 'X', 'Y'};
    uint32_t hash = 0xabcdef01;
    size_t i;
    CHECK(long_name != NULL);
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        CHECK(rome2_vfs_hash_name_bytes((const unsigned char *)cases[i].text, strlen(cases[i].text), &hash));
        CHECK(hash == cases[i].hash);
    }
    CHECK(rome2_vfs_hash_name_bytes(embedded, sizeof embedded, &hash) && hash == 0x41);
    memset(long_name, 1, 131074);
    CHECK(rome2_vfs_hash_name_bytes(long_name, 131072, &hash) && hash == 0);
    CHECK(rome2_vfs_hash_name_bytes(long_name, 131073, &hash) && hash == 1);
    CHECK(rome2_vfs_hash_name_bytes(long_name, 131074, &hash) && hash == 0x00010001);
    memset(long_name, 0xff, 131074);
    CHECK(rome2_vfs_hash_name_bytes(long_name, 131072, &hash) && hash == 0);
    CHECK(rome2_vfs_hash_name_bytes(long_name, 131073, &hash) && hash == 0xffff);
    CHECK(rome2_vfs_hash_name_bytes(NULL, 0, &hash) && hash == 0);
    hash = 0xabcdef01;
    CHECK(!rome2_vfs_hash_name_bytes(NULL, 1, &hash) && hash == 0xabcdef01);
    CHECK(!rome2_vfs_hash_name_bytes(embedded, sizeof embedded, NULL));
    free(long_name);
}

typedef struct name_fixture {
    unsigned char descriptor_bytes[24], slot_bytes[80];
    size_t descriptor_residue, slot_residue;
    rome2_guest_addr32 descriptor;
    rome2_guest_read_view descriptors, slots;
} name_fixture;

static const uint32_t empty_name = 0x00eeeeee, query_name = 0x11223344;
static const rome2_vfs_name_match32 sentinel = {{0xabcdef01}, 0x98765432, 0x12345678, 0x87654321};

static void put32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)value; bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16); bytes[3] = (unsigned char)(value >> 24);
}

static void slot(name_fixture *f, uint32_t index, uint32_t key, uint32_t value)
{
    unsigned char *p = f->slot_bytes + f->slot_residue + index * 8u;
    put32(p, key); put32(p + 4, value);
}

static void fixture(name_fixture *f, size_t descriptor_residue, size_t slot_residue)
{
    uint32_t i;
    memset(f, 0, sizeof *f); f->descriptor_residue = descriptor_residue; f->slot_residue = slot_residue;
    f->descriptor.value = 0x50000003 + (uint32_t)descriptor_residue;
    f->descriptors.host_base = f->descriptor_bytes + descriptor_residue;
    f->descriptors.guest_base = f->descriptor.value; f->descriptors.byte_count = 12;
    f->slots.host_base = f->slot_bytes + slot_residue;
    f->slots.guest_base = 0x60000001 + (uint32_t)slot_residue; f->slots.byte_count = 56;
    put32(f->descriptor_bytes + descriptor_residue, f->slots.guest_base);
    put32(f->descriptor_bytes + descriptor_residue + 4, 7);
    put32(f->descriptor_bytes + descriptor_residue + 8, empty_name);
    for (i = 0; i < 8; ++i) { slot(f, i, empty_name, 0xdeadbeef); }
}

static void unchanged(const rome2_vfs_name_match32 *out)
{
    CHECK(out->value_address.value == sentinel.value_address.value && out->value == sentinel.value &&
        out->slot_index == sentinel.slot_index && out->probes == sentinel.probes);
}

static void probe_order_and_alignment(void)
{
    size_t d, s, extent;
    for (d = 0; d < 8; ++d) {
        for (s = 0; s < 8; ++s) {
            name_fixture f;
            rome2_vfs_name_match32 out = sentinel;
            rome2_guest_read_view tail;
            uint32_t i;
            fixture(&f, d, s);
            slot(&f, 5, 0xaabbccdd, 1); slot(&f, 6, 0x99887766, 2); slot(&f, 0, query_name, 0x7ffffffe);
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 5, 7, &out) == ROME2_VFS_NAME_OK);
            CHECK(out.slot_index == 0 && out.probes == 3 && out.value_address.value == f.slots.guest_base + 4 && out.value == 0x7ffffffe);
            out = sentinel;
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 5, 2, &out) == ROME2_VFS_NAME_PROBE_LIMIT);
            unchanged(&out);
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 5, 3, &out) == ROME2_VFS_NAME_OK);
            CHECK(out.probes == 3 && out.slot_index == 0);
            slot(&f, 6, empty_name, 0xdeadbeef); out = sentinel;
            tail = f.slots; tail.host_base += 40; tail.guest_base += 40; tail.byte_count = 12;
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &tail, query_name, 5, 7, &out) == ROME2_VFS_NAME_NOT_FOUND);
            unchanged(&out); /* Empty slot's value and the wrapped target are unmapped. */
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, empty_name, 5, 7, &out) == ROME2_VFS_NAME_OK);
            CHECK(out.slot_index == 6 && out.probes == 2 && out.value == 0xdeadbeef);
            for (i = 0; i < 7; ++i) { slot(&f, i, 0x100 + i, 0); }
            out = sentinel;
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 5, UINT32_MAX, &out) == ROME2_VFS_NAME_NOT_FOUND);
            unchanged(&out);
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 5, 6, &out) == ROME2_VFS_NAME_PROBE_LIMIT);
            unchanged(&out);
            slot(&f, 0, 0, 0);
            CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, 0, 0, 1, &out) == ROME2_VFS_NAME_OK);
            CHECK(out.probes == 1 && out.slot_index == 0 && out.value == 0);
            for (extent = 0; extent < 12; ++extent) {
                f.descriptors.byte_count = extent; out = sentinel;
                CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, 0, 0, 1, &out) == ROME2_VFS_NAME_RANGE_ERROR);
                unchanged(&out);
            }
            f.descriptors.byte_count = 12;
            for (extent = 0; extent < 8; ++extent) {
                f.slots.byte_count = extent; out = sentinel;
                CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, 0, 0, 1, &out) == ROME2_VFS_NAME_RANGE_ERROR);
                unchanged(&out);
            }
        }
    }
}

static void probe_errors_and_endpoints(void)
{
    name_fixture f;
    rome2_vfs_name_match32 out = sentinel;
    const rome2_guest_addr32 zero = {0};
    fixture(&f, 0, 0);
    CHECK(rome2_vfs_probe_name32(NULL, f.descriptor, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, NULL, query_name, 0, 7, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, zero, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 0, &out) == ROME2_VFS_NAME_BAD_ARGUMENT);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 7, NULL) == ROME2_VFS_NAME_BAD_ARGUMENT);
    unchanged(&out);
    put32(f.descriptor_bytes + 4, 0);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_INVALID_TABLE);
    unchanged(&out); put32(f.descriptor_bytes + 4, 7); put32(f.descriptor_bytes, 0);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_INVALID_TABLE);
    unchanged(&out);
    fixture(&f, 0, 0);
    f.descriptor.value = 0xfffffff4; f.descriptors.guest_base = f.descriptor.value;
    f.slots.guest_base = 0xfffffff8; f.slots.byte_count = 8;
    put32(f.descriptor_bytes, f.slots.guest_base); put32(f.descriptor_bytes + 4, 1);
    slot(&f, 0, query_name, 0xfffffffe);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, UINT32_MAX, &out) == ROME2_VFS_NAME_OK);
    CHECK(out.value_address.value == 0xfffffffc && out.value == 0xfffffffe && out.probes == 1);
    out = sentinel; put32(f.descriptor_bytes + 4, 2);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_RANGE_ERROR);
    unchanged(&out); put32(f.descriptor_bytes + 4, UINT32_MAX);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_RANGE_ERROR);
    unchanged(&out); f.descriptor.value = 0xfffffff5; f.descriptors.guest_base = f.descriptor.value;
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, 0, 7, &out) == ROME2_VFS_NAME_RANGE_ERROR);
    unchanged(&out);
}

static void hash_collision_lookup(void)
{
    name_fixture f;
    rome2_vfs_name_match32 out;
    uint32_t first, second;
    fixture(&f, 1, 3); put32(f.descriptor_bytes + 1 + 4, 8); f.slots.byte_count = 64;
    CHECK(rome2_vfs_hash_name_bytes((const unsigned char *)"ACBD", 4, &first));
    CHECK(rome2_vfs_hash_name_bytes((const unsigned char *)"BCAD", 4, &second));
    CHECK(first == 0x00870083 && second == first);
    slot(&f, 3, 0xaabb3344, 0x22222222); slot(&f, 4, query_name, 0x33333333);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, second, 8, &out) == ROME2_VFS_NAME_OK);
    CHECK(out.slot_index == 4 && out.probes == 2 && out.value == 0x33333333);
    slot(&f, 4, empty_name, 0); slot(&f, 7, query_name, 0x44444444);
    CHECK(rome2_vfs_probe_name32(&f.descriptors, f.descriptor, &f.slots, query_name, UINT32_MAX, 1, &out) == ROME2_VFS_NAME_OK);
    CHECK(out.slot_index == 7 && out.probes == 1 && out.value == 0x44444444);
}

int main(void)
{
    hash_pairs(); hash_vectors_and_wrap(); probe_order_and_alignment(); probe_errors_and_endpoints(); hash_collision_lookup();
    printf("VFS names: %zu checks; signed-byte hash, all byte pairs, 16-bit wrap, name-table collisions, probe order and checked views\n", checks);
    return 0;
}
