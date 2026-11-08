#ifndef ROME2_RECOVERED_XML_LOADER_POLICY_H
#define ROME2_RECOVERED_XML_LOADER_POLICY_H

#include "layout_bridge.h"
#include <stdbool.h>

/* FUN_100f3b20's narrow-prefix predicate, not a Win32 path canonicalizer.
 * For an already-normalized byte span it checks only byte 1 == ':' and
 * byte 2 == '/' or '\\'; byte 0 is not validated as a drive letter.
 * NULL/short spans return false as a host bounds adaptation. No path
 * normalization, existence check, mount search, I/O or allocation occurs. */
bool rome2_xml_path_is_drive_rooted(const unsigned char *bytes, size_t size);

typedef struct rome2_xml_legacy_text_result {
    size_t size;
    bool stripped_bom;
} rome2_xml_legacy_text_result;

/* Byte preparation observed at 112a7d4b..112a7d92. For FF FE or FE FF,
 * remove the two-byte prefix and compact every remaining nonzero BYTE in
 * place, preserving byte order. Otherwise preserve all input bytes. Append
 * NUL at result.size in either case; this is not Unicode transcoding.
 * For unfiltered input result.size can include embedded NUL bytes and is
 * therefore not necessarily strlen(buffer).
 *
 * buffer must name capacity writable bytes, capacity > size, and output must
 * be a valid separate host object. NULL arguments or insufficient capacity
 * return false without changing buffer or output. No allocation or I/O.
 * Unlike the original unchecked initial word read, spans shorter than two
 * bytes are deterministically treated as not having either prefix. */
bool rome2_xml_prepare_legacy_text(unsigned char *buffer, size_t size,
    size_t capacity, rome2_xml_legacy_text_result *output);

typedef enum rome2_xml_root_status {
    ROME2_XML_ROOT_OK = 0,
    ROME2_XML_ROOT_BAD_ARGUMENT,
    ROME2_XML_ROOT_RANGE_ERROR,
    ROME2_XML_ROOT_HOP_LIMIT
} rome2_xml_root_status;

typedef struct rome2_xml_root_observation {
    rome2_guest_addr32 root;
    uint8_t ready;
    uint32_t visited_nodes;
} rome2_xml_root_observation;

/* Checked adaptation of FUN_101b9270. Follow 32-bit links at +0 and return
 * the final node's raw byte +4; intermediate flag bytes are not consulted.
 * Each node needs only its four-byte link mapped; the final node needs five
 * bytes. No guest address is cast to a host pointer or callable object.
 *
 * The original walk is unbounded. max_nodes is an explicit host work budget,
 * including the final node; exhaustion (including cycles) fails closed.
 * NULL view/output, zero address or zero budget are bad arguments. Unmapped
 * cells, guest/host numeric overflow or invalid views report RANGE_ERROR.
 * Every failure preserves output. Inputs/output are non-overlapping valid
 * host objects; backing bytes stay borrowed and immutable throughout call.
 * No allocation, callbacks or original-game execution occurs. */
rome2_xml_root_status rome2_xml_read_root_state32(
    const rome2_guest_read_view *nodes, rome2_guest_addr32 start,
    uint32_t max_nodes, rome2_xml_root_observation *output);

#endif
