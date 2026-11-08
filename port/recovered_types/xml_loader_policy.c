#include "xml_loader_policy.h"

bool rome2_xml_path_is_drive_rooted(const unsigned char *bytes, size_t size)
{
    return bytes != NULL && size >= 3 && bytes[1] == ':' &&
        (bytes[2] == '/' || bytes[2] == '\\');
}

bool rome2_xml_prepare_legacy_text(unsigned char *buffer, size_t size,
    size_t capacity, rome2_xml_legacy_text_result *output)
{
    rome2_xml_legacy_text_result result;
    size_t read, written = 0;
    if (buffer == NULL || output == NULL || size >= capacity) { return false; }
    result.stripped_bom = size >= 2 &&
        ((buffer[0] == 0xff && buffer[1] == 0xfe) || (buffer[0] == 0xfe && buffer[1] == 0xff));
    if (result.stripped_bom) {
        for (read = 2; read < size; ++read) {
            if (buffer[read] != 0) { buffer[written++] = buffer[read]; }
        }
    } else { written = size; }
    buffer[written] = 0; result.size = written; *output = result;
    return true;
}

rome2_xml_root_status rome2_xml_read_root_state32(
    const rome2_guest_read_view *nodes, rome2_guest_addr32 start,
    uint32_t max_nodes, rome2_xml_root_observation *output)
{
    rome2_guest_addr32 current = start, parent, flag_cell;
    uint32_t visited;
    uint16_t pair;
    rome2_xml_root_observation result;
    if (nodes == NULL || output == NULL || start.value == 0 || max_nodes == 0) {
        return ROME2_XML_ROOT_BAD_ARGUMENT;
    }
    for (visited = 0; visited < max_nodes; ++visited) {
        if (rome2_guest_read_addr32_le(nodes, current, &parent) != ROME2_GUEST_OK) {
            return ROME2_XML_ROOT_RANGE_ERROR;
        }
        if (parent.value == 0) {
            /* Reuse the checked LE accessor over bytes +3/+4. This requires
             * exactly five mapped bytes, without adding a read of byte +5. */
            if (rome2_guest_add_checked(current, 3, &flag_cell) != ROME2_GUEST_OK ||
                rome2_guest_read_u16_le(nodes, flag_cell, &pair) != ROME2_GUEST_OK) {
                return ROME2_XML_ROOT_RANGE_ERROR;
            }
            result.root = current; result.ready = (uint8_t)(pair >> 8);
            result.visited_nodes = visited + 1;
            *output = result;
            return ROME2_XML_ROOT_OK;
        }
        current = parent;
    }
    return ROME2_XML_ROOT_HOP_LIMIT;
}
