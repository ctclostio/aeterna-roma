#include "xml_loader_policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static void put32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value; bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16); bytes[3] = (uint8_t)(value >> 24);
}

static const rome2_xml_root_observation sentinel = {{0x12345678}, 0xa5, 0xbadca11};

static void path_routing(void)
{
    const struct { const char *path; bool direct; } cases[] = {
        {"Script/fauna_config.xml", false}, {"C:/Script/fauna_config.xml", true},
        {"c:\\Script\\fauna_config.xml", true}, {"C:Script/fauna_config.xml", false},
        {"/Script/fauna_config.xml", false}, {"\\Script\\fauna_config.xml", false},
        {"\\\\server\\share\\fauna_config.xml", false},
        {"1:/", true}, {"?:\\", true}, {":/", false}, {"C:", false}, {"C", false},
        {"", false}, {"file:///C:/Script/fauna_config.xml", false},
        {"C|/Script/fauna_config.xml", false}, {"C:./", false}
    };
    const unsigned char span[] = {'X', ':', '/', 's', 'c', 'r', 'i', 'p', 't'};
    const unsigned char ignored_first[] = {0, ':', '\\'};
    size_t i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        CHECK(rome2_xml_path_is_drive_rooted((const unsigned char *)cases[i].path,
            strlen(cases[i].path)) == cases[i].direct);
    }
    CHECK(!rome2_xml_path_is_drive_rooted(NULL, 0) && !rome2_xml_path_is_drive_rooted(NULL, 3));
    for (i = 0; i <= sizeof span; ++i) {
        CHECK(rome2_xml_path_is_drive_rooted(span, i) == (i >= 3));
    }
    CHECK(rome2_xml_path_is_drive_rooted(ignored_first, sizeof ignored_first));
}

static void legacy_text(void)
{
    const unsigned char tail[] = {'A', 0, 0xe1, 0x80, 0};
    const unsigned char filtered[] = {'A', 0xe1, 0x80, 0};
    unsigned char bytes[10], before[10];
    rome2_xml_legacy_text_result out;
    uint32_t prefix;
    size_t size;
    for (prefix = 0; prefix < 65536; ++prefix) {
        memset(bytes, 0xa5, sizeof bytes);
        bytes[0] = (unsigned char)prefix; bytes[1] = (unsigned char)(prefix >> 8);
        memcpy(bytes + 2, tail, sizeof tail); memcpy(before, bytes, sizeof bytes);
        CHECK(rome2_xml_prepare_legacy_text(bytes, 7, 8, &out));
        if (prefix == 0xfeff || prefix == 0xfffe) {
            CHECK(out.stripped_bom && out.size == 3 && memcmp(bytes, filtered, sizeof filtered) == 0);
        } else {
            CHECK(!out.stripped_bom && out.size == 7 && memcmp(bytes, before, 7) == 0 && bytes[7] == 0);
        }
        CHECK(bytes[8] == 0xa5 && bytes[9] == 0xa5);
    }
    memset(bytes, 0xa5, sizeof bytes); bytes[0] = 0xff;
    for (size = 0; size <= 1; ++size) {
        bytes[0] = 0xff;
        CHECK(rome2_xml_prepare_legacy_text(bytes, size, size + 1, &out));
        CHECK(out.size == size && !out.stripped_bom && bytes[size] == 0);
        CHECK(size == 0 || bytes[0] == 0xff);
    }
    bytes[0] = 0xff; bytes[1] = 0xfe;
    CHECK(rome2_xml_prepare_legacy_text(bytes, 2, 3, &out));
    CHECK(out.size == 0 && out.stripped_bom && bytes[0] == 0);
    bytes[0] = 0xfe; bytes[1] = 0xff; bytes[2] = 0;
    CHECK(rome2_xml_prepare_legacy_text(bytes, 3, 4, &out));
    CHECK(out.size == 0 && out.stripped_bom && bytes[0] == 0);
    bytes[0] = 0xef; bytes[1] = 0xbb; bytes[2] = 0xbf; bytes[3] = 'X';
    CHECK(rome2_xml_prepare_legacy_text(bytes, 4, 5, &out));
    CHECK(out.size == 4 && !out.stripped_bom && bytes[0] == 0xef && bytes[3] == 'X' && bytes[4] == 0);
    memset(bytes, 0xa5, sizeof bytes); memcpy(before, bytes, sizeof bytes);
    out.size = 0x1234; out.stripped_bom = true;
    CHECK(!rome2_xml_prepare_legacy_text(NULL, 0, 1, &out));
    CHECK(!rome2_xml_prepare_legacy_text(bytes, 0, 0, &out));
    CHECK(!rome2_xml_prepare_legacy_text(bytes, 7, 7, &out));
    CHECK(!rome2_xml_prepare_legacy_text(bytes, SIZE_MAX, SIZE_MAX, &out));
    CHECK(!rome2_xml_prepare_legacy_text(bytes, 7, 8, NULL));
    CHECK(out.size == 0x1234 && out.stripped_bom && memcmp(bytes, before, sizeof bytes) == 0);
}

static void unchanged(const rome2_xml_root_observation *out)
{
    CHECK(out->root.value == sentinel.root.value && out->ready == sentinel.ready &&
        out->visited_nodes == sentinel.visited_nodes);
}

static void links_and_flags(void)
{
    uint8_t bytes[256 * 7] = {0};
    rome2_guest_read_view view = {bytes, 0x80000001, sizeof bytes};
    const rome2_guest_addr32 start = {view.guest_base};
    const uint32_t last = (255u * 73u) % 256u;
    const uint32_t root_address = view.guest_base + last * 7;
    rome2_xml_root_observation out;
    uint32_t i;
    size_t extent;
    /* A non-monotone permutation visits every node at all alignment residues.
     * The seven-byte stride also prevents accidental native-struct overlays. */
    for (i = 0; i < 256; ++i) {
        const uint32_t index = (i * 73u) % 256u;
        const uint32_t next = i == 255 ? 0 : view.guest_base + (((i + 1) * 73u) % 256u) * 7;
        put32(bytes + index * 7, next);
        bytes[index * 7 + 4] = (uint8_t)i;
    }
    for (i = 0; i < 256; ++i) {
        bytes[last * 7 + 4] = (uint8_t)i;
        CHECK(rome2_xml_read_root_state32(&view, start, 256, &out) == ROME2_XML_ROOT_OK);
        CHECK(out.root.value == root_address && out.ready == (uint8_t)i && out.visited_nodes == 256);
    }
    out = sentinel;
    CHECK(rome2_xml_read_root_state32(&view, start, 255, &out) == ROME2_XML_ROOT_HOP_LIMIT);
    unchanged(&out);
    /* Highest-address node is intermediate: only its link, not its flag,
     * needs mapping. Exhaust every truncation of the borrowed view. */
    for (extent = 0; extent <= sizeof bytes; ++extent) {
        view.byte_count = extent; out = sentinel;
        if (extent < sizeof bytes - 3) {
            CHECK(rome2_xml_read_root_state32(&view, start, 256, &out) == ROME2_XML_ROOT_RANGE_ERROR);
            unchanged(&out);
        } else {
            CHECK(rome2_xml_read_root_state32(&view, start, 256, &out) == ROME2_XML_ROOT_OK);
            CHECK(out.root.value == root_address && out.ready == 255 && out.visited_nodes == 256);
        }
    }
}

static void invalid_and_cycles(void)
{
    uint8_t bytes[16] = {0};
    rome2_guest_read_view view = {bytes, 0x1001, sizeof bytes};
    const rome2_guest_addr32 start = {0x1001}, zero = {0};
    rome2_xml_root_observation out = sentinel;
    CHECK(rome2_xml_read_root_state32(NULL, start, 1, &out) == ROME2_XML_ROOT_BAD_ARGUMENT);
    CHECK(rome2_xml_read_root_state32(&view, start, 1, NULL) == ROME2_XML_ROOT_BAD_ARGUMENT);
    CHECK(rome2_xml_read_root_state32(&view, zero, 1, &out) == ROME2_XML_ROOT_BAD_ARGUMENT);
    CHECK(rome2_xml_read_root_state32(&view, start, 0, &out) == ROME2_XML_ROOT_BAD_ARGUMENT);
    unchanged(&out);
    put32(bytes, start.value);
    CHECK(rome2_xml_read_root_state32(&view, start, 7, &out) == ROME2_XML_ROOT_HOP_LIMIT);
    unchanged(&out);
    put32(bytes, start.value + 7); put32(bytes + 7, start.value);
    CHECK(rome2_xml_read_root_state32(&view, start, 7, &out) == ROME2_XML_ROOT_HOP_LIMIT);
    unchanged(&out);
    put32(bytes + 7, 0); bytes[11] = 0x80;
    CHECK(rome2_xml_read_root_state32(&view, start, 1, &out) == ROME2_XML_ROOT_HOP_LIMIT);
    unchanged(&out);
    CHECK(rome2_xml_read_root_state32(&view, start, 2, &out) == ROME2_XML_ROOT_OK);
    CHECK(out.ready == 0x80 && out.root.value == start.value + 7 && out.visited_nodes == 2);
    out = sentinel; put32(bytes, 0xfffffffe);
    CHECK(rome2_xml_read_root_state32(&view, start, 2, &out) == ROME2_XML_ROOT_RANGE_ERROR);
    unchanged(&out);
    view.host_base = NULL;
    CHECK(rome2_xml_read_root_state32(&view, start, 2, &out) == ROME2_XML_ROOT_RANGE_ERROR);
    unchanged(&out);
}

static void address_space_end(void)
{
    const uint8_t bytes[] = {0, 0, 0, 0, 0x7f};
    rome2_guest_read_view view = {bytes, 0xfffffffb, sizeof bytes};
    rome2_guest_addr32 start = {view.guest_base};
    rome2_xml_root_observation out;
    CHECK(rome2_xml_read_root_state32(&view, start, 1, &out) == ROME2_XML_ROOT_OK);
    CHECK(out.ready == 0x7f && out.root.value == start.value && out.visited_nodes == 1);
    out = sentinel; view.byte_count = 4;
    CHECK(rome2_xml_read_root_state32(&view, start, 1, &out) == ROME2_XML_ROOT_RANGE_ERROR);
    unchanged(&out);
    start.value = 0xfffffffc; view.guest_base = start.value;
    CHECK(rome2_xml_read_root_state32(&view, start, 1, &out) == ROME2_XML_ROOT_RANGE_ERROR);
    unchanged(&out);
    view.byte_count = 5;
    CHECK(rome2_xml_read_root_state32(&view, start, 1, &out) == ROME2_XML_ROOT_RANGE_ERROR);
    unchanged(&out);
}

int main(void)
{
    path_routing(); legacy_text(); links_and_flags(); invalid_and_cycles(); address_space_end();
    printf("XML loader policy: %zu checks; path routing, legacy BOM bytes, root-state links, raw flags, bounds and cycle budgets\n", checks);
    return 0;
}
