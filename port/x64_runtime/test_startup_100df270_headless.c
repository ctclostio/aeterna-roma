#include "ported_100df270_headless.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ROME2_TEST_MEMORY_BYTES 0x900
#define ROME2_TEST_OBJECT_OFFSET 1
#define ROME2_TEST_PACKET_OFFSET 0x8c0
#define ROME2_TEST_GUEST_BASE UINT32_C(0x2000)
#define ROME2_TEST_OUTPUT_SENTINEL UINT32_C(0xc35aa53c)

typedef union rome2_test_memory {
    uint64_t alignment;
    uint8_t bytes[ROME2_TEST_MEMORY_BYTES];
} rome2_test_memory;

static rome2_guest_addr32 rome2_test_address(uint32_t value)
{
    rome2_guest_addr32 result;

    result.value = value;
    return result;
}

static void rome2_test_put_u32(uint8_t *bytes, size_t offset, uint32_t value)
{
    bytes[offset] = (uint8_t)value;
    bytes[offset + 1] = (uint8_t)(value >> 8);
    bytes[offset + 2] = (uint8_t)(value >> 16);
    bytes[offset + 3] = (uint8_t)(value >> 24);
}

static void rome2_test_put_empty(uint8_t *bytes, size_t offset)
{
    rome2_test_put_u32(bytes, offset, 0);
    rome2_test_put_u32(bytes, offset + 4, 0);
    rome2_test_put_u32(bytes, offset + 8, UINT32_C(0x11af4090));
}

static void rome2_test_set_packet(uint8_t *packet)
{
    memset(packet, 0x5c, ROME2_PORT_100DF270_PACKET_BYTES);
    rome2_test_put_u32(packet, 0x00, UINT32_C(0x10203040));
    rome2_test_put_u32(packet, 0x04, UINT32_C(0x50607080));
    rome2_test_put_u32(packet, 0x08, 0);
    rome2_test_put_u32(packet, 0x14, 0);
    rome2_test_put_u32(packet, 0x20, UINT32_C(0x90a0b0c0));
    packet[0x24] = UINT8_C(0x7b);
    rome2_test_put_u32(packet, 0x28, UINT32_C(0xd0e0f001));
    packet[0x2c] = UINT8_C(0x01);
}

static void rome2_test_apply_oracle(
    uint8_t *object,
    uint32_t guest_object)
{
    rome2_test_put_u32(object, 0x000, UINT32_C(0x1173f2f4));
    rome2_test_put_u32(object, 0x80c, UINT32_C(0x11741e08));
    rome2_test_put_u32(object, 0x810, 0);
    rome2_test_put_u32(object, 0x814, 0);
    rome2_test_put_u32(object, 0x81c, 0);
    rome2_test_put_u32(object, 0x820, 0);
    rome2_test_put_u32(object, 0x824, UINT32_C(0x10203040));
    rome2_test_put_u32(object, 0x828, UINT32_C(0x50607080));
    rome2_test_put_empty(object, 0x82c);
    rome2_test_put_empty(object, 0x838);
    rome2_test_put_u32(object, 0x844, UINT32_C(0x90a0b0c0));
    object[0x848] = UINT8_C(0x7b);
    rome2_test_put_u32(object, 0x84c, UINT32_C(0xd0e0f001));
    object[0x850] = UINT8_C(0x01);
    rome2_test_put_u32(object, 0x854, guest_object);
    rome2_test_put_u32(object, 0x858, 0);
    rome2_test_put_u32(object, 0x85c, 0);
    rome2_test_put_u32(object, 0x860, 0);
    rome2_test_put_u32(object, 0x864, guest_object);
    rome2_test_put_u32(object, 0x868, 0);
    rome2_test_put_u32(object, 0x86c, 0);
    rome2_test_put_u32(object, 0x870, 0);
    rome2_test_put_u32(object, 0x874, UINT32_C(0x1173dc18));
    rome2_test_put_u32(object, 0x878, 0);
    rome2_test_put_u32(object, 0x87c, 0);
    rome2_test_put_u32(object, 0x880, 0);
    rome2_test_put_u32(object, 0x888, 0);
    rome2_test_put_u32(object, 0x88c, 0);
    rome2_test_put_u32(object, 0x894, 0);
    rome2_test_put_u32(object, 0x898, UINT32_MAX);
    rome2_test_put_u32(object, 0x89c, 0);
    rome2_test_put_u32(object, 0x8a0, 0);
    rome2_test_put_u32(object, 0x8a4, 0);
}

static int rome2_test_expect_status(
    const char *label,
    rome2_guest_status actual,
    rome2_guest_status expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: status=%d expected=%d\n",
        label, (int)actual, (int)expected);
    return 1;
}

static int rome2_test_success(void)
{
    rome2_test_memory actual;
    rome2_test_memory expected;
    rome2_guest_write_view view;
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 object;
    rome2_guest_addr32 packet;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(actual.bytes, 0xa5, sizeof(actual.bytes));
    rome2_test_set_packet(actual.bytes + ROME2_TEST_PACKET_OFFSET);
    memcpy(expected.bytes, actual.bytes, sizeof(expected.bytes));
    object = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_OBJECT_OFFSET);
    packet = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_PACKET_OFFSET);
    rome2_test_apply_oracle(
        expected.bytes + ROME2_TEST_OBJECT_OFFSET, object.value);

    view.host_base = actual.bytes;
    view.guest_base = ROME2_TEST_GUEST_BASE;
    view.byte_count = sizeof(actual.bytes);
    view_snapshot = view;
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("exact deterministic projection",
        rome2_port_100df270_project_headless_empty_state(
            &view, object, packet, &output),
        ROME2_GUEST_OK);
    if (output.value != object.value) {
        fprintf(stderr, "FAIL exact deterministic projection: return changed\n");
        ++failures;
    }
    if (memcmp(actual.bytes, expected.bytes, sizeof(actual.bytes)) != 0) {
        fprintf(stderr, "FAIL exact deterministic projection: byte oracle differs\n");
        ++failures;
    }
    if (memcmp(&view, &view_snapshot, sizeof(view)) != 0) {
        fprintf(stderr, "FAIL exact deterministic projection: view changed\n");
        ++failures;
    }
    if (actual.bytes[ROME2_TEST_OBJECT_OFFSET + 0x004] != 0xa5 ||
        actual.bytes[ROME2_TEST_OBJECT_OFFSET + 0x808] != 0xa5 ||
        actual.bytes[ROME2_TEST_OBJECT_OFFSET + 0x818] != 0xa5 ||
        actual.bytes[ROME2_TEST_OBJECT_OFFSET + 0x884] != 0xa5 ||
        actual.bytes[ROME2_TEST_OBJECT_OFFSET + 0x890] != 0xa5) {
        fprintf(stderr, "FAIL deterministic projection: excluded holes changed\n");
        ++failures;
    }
    return failures;
}

static int rome2_test_preserved_failure(
    const char *label,
    rome2_guest_write_view *view,
    rome2_guest_addr32 object,
    rome2_guest_addr32 packet,
    rome2_guest_status expected_status,
    uint8_t *memory,
    size_t memory_bytes)
{
    uint8_t snapshot[ROME2_TEST_MEMORY_BYTES];
    rome2_guest_write_view view_snapshot;
    rome2_guest_addr32 output;
    int failures = 0;

    if (memory_bytes > sizeof(snapshot)) {
        fprintf(stderr, "FAIL %s: internal snapshot too small\n", label);
        return 1;
    }
    memcpy(snapshot, memory, memory_bytes);
    view_snapshot = *view;
    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status(label,
        rome2_port_100df270_project_headless_empty_state(
            view, object, packet, &output),
        expected_status);
    if (output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL %s: output changed on failure\n", label);
        ++failures;
    }
    if (memcmp(snapshot, memory, memory_bytes) != 0) {
        fprintf(stderr, "FAIL %s: memory changed on failure\n", label);
        ++failures;
    }
    if (memcmp(&view_snapshot, view, sizeof(*view)) != 0) {
        fprintf(stderr, "FAIL %s: view changed on failure\n", label);
        ++failures;
    }
    return failures;
}

static int rome2_test_failures(void)
{
    rome2_test_memory memory;
    rome2_guest_write_view view;
    rome2_guest_addr32 object;
    rome2_guest_addr32 packet;
    rome2_guest_addr32 output;
    int failures = 0;

    memset(memory.bytes, 0xa5, sizeof(memory.bytes));
    rome2_test_set_packet(memory.bytes + ROME2_TEST_PACKET_OFFSET);
    view.host_base = memory.bytes;
    view.guest_base = ROME2_TEST_GUEST_BASE;
    view.byte_count = sizeof(memory.bytes);
    object = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_OBJECT_OFFSET);
    packet = rome2_test_address(
        ROME2_TEST_GUEST_BASE + ROME2_TEST_PACKET_OFFSET);

    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("null view",
        rome2_port_100df270_project_headless_empty_state(
            NULL, object, packet, &output),
        ROME2_GUEST_BAD_ARGUMENT);
    if (output.value != ROME2_TEST_OUTPUT_SENTINEL) {
        fprintf(stderr, "FAIL null view: output changed\n");
        ++failures;
    }

    failures += rome2_test_preserved_failure("null object", &view,
        rome2_test_address(0), packet, ROME2_GUEST_NULL_ADDRESS,
        memory.bytes, sizeof(memory.bytes));
    failures += rome2_test_preserved_failure("null packet", &view,
        object, rome2_test_address(0), ROME2_GUEST_NULL_ADDRESS,
        memory.bytes, sizeof(memory.bytes));
    failures += rome2_test_preserved_failure("object below view", &view,
        rome2_test_address(ROME2_TEST_GUEST_BASE - 1), packet,
        ROME2_GUEST_OUT_OF_RANGE, memory.bytes, sizeof(memory.bytes));

    rome2_test_put_u32(memory.bytes + ROME2_TEST_PACKET_OFFSET, 0x08, 1);
    failures += rome2_test_preserved_failure("first descriptor nonempty", &view,
        object, packet, ROME2_GUEST_BAD_ARGUMENT,
        memory.bytes, sizeof(memory.bytes));
    rome2_test_put_u32(memory.bytes + ROME2_TEST_PACKET_OFFSET, 0x08, 0);
    rome2_test_put_u32(memory.bytes + ROME2_TEST_PACKET_OFFSET, 0x14, 7);
    failures += rome2_test_preserved_failure("second descriptor nonempty", &view,
        object, packet, ROME2_GUEST_BAD_ARGUMENT,
        memory.bytes, sizeof(memory.bytes));
    rome2_test_put_u32(memory.bytes + ROME2_TEST_PACKET_OFFSET, 0x14, 0);

    failures += rome2_test_preserved_failure("packet overlaps object", &view,
        object, rome2_test_address(object.value + UINT32_C(0x100)),
        ROME2_GUEST_BAD_ARGUMENT, memory.bytes, sizeof(memory.bytes));

    view.byte_count = ROME2_TEST_PACKET_OFFSET +
        ROME2_PORT_100DF270_PACKET_BYTES - 1;
    failures += rome2_test_preserved_failure("packet one byte short", &view,
        object, packet, ROME2_GUEST_OUT_OF_RANGE,
        memory.bytes, sizeof(memory.bytes));
    view.byte_count = sizeof(memory.bytes);

    view.guest_base = UINT32_C(0xfffff800);
    view.byte_count = sizeof(memory.bytes);
    failures += rome2_test_preserved_failure("guest view overflow", &view,
        rome2_test_address(UINT32_C(0xfffff801)),
        rome2_test_address(UINT32_C(0xfffff8c0)),
        ROME2_GUEST_RANGE_OVERFLOW, memory.bytes, sizeof(memory.bytes));
    view.guest_base = ROME2_TEST_GUEST_BASE;
    view.byte_count = sizeof(memory.bytes);

    output = rome2_test_address(ROME2_TEST_OUTPUT_SENTINEL);
    failures += rome2_test_expect_status("output aliases view bytes",
        rome2_port_100df270_project_headless_empty_state(
            &view, object, packet,
            (rome2_guest_addr32 *)(void *)(memory.bytes + 0x100)),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_test_expect_status("output aliases view structure",
        rome2_port_100df270_project_headless_empty_state(
            &view, object, packet,
            (rome2_guest_addr32 *)(void *)&view),
        ROME2_GUEST_BAD_ARGUMENT);
    failures += rome2_test_expect_status("null output",
        rome2_port_100df270_project_headless_empty_state(
            &view, object, packet, NULL),
        ROME2_GUEST_BAD_ARGUMENT);
    return failures;
}

int main(void)
{
    int failures = 0;

    failures += rome2_test_success();
    failures += rome2_test_failures();
    if (failures != 0) {
        fprintf(stderr, "startup 100df270 headless tests failed: %d\n", failures);
        return 1;
    }
    printf("startup 100df270 headless tests passed\n");
    return 0;
}
