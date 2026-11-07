#ifndef ROME2_RECOVERED_UNIT_CARD_RESOURCE_H
#define ROME2_RECOVERED_UNIT_CARD_RESOURCE_H

#include "owned_unit_card.h"
#include "pack_resource.h"
#include "fauna_config.h"

typedef enum rome2_card_resource_status {
    ROME2_CARD_RESOURCE_OK = 0,
    ROME2_CARD_RESOURCE_BAD_ARGUMENT,
    ROME2_CARD_RESOURCE_PACK_ERROR,
    ROME2_CARD_RESOURCE_CONFIG_ERROR,
    ROME2_CARD_RESOURCE_CARD_ERROR
} rome2_card_resource_status;
typedef struct rome2_card_resource_diagnostic {
    rome2_pack_status pack;
    rome2_fauna_config_status config;
    rome2_xml_status xml;
    rome2_unit_card_status card;
    size_t selected_archive; /* SIZE_MAX until a matching archive is selected */
} rome2_card_resource_diagnostic;

/* Default setup path observed at 101a97f0: Script/fauna_config.xml, root
 * fauna_config, decoded children in order. archive_paths is an explicit list
 * of NUL-terminated UTF-16 paths in HIGHEST PRIORITY FIRST order. This API
 * does not infer the game's complete mount/dependency/mod precedence. It
 * tries the next archive only for NOT_FOUND; malformed/unreadable/unsupported
 * archives are explicit failures. Maximum XML payload16MiB.
 *
 * The factory requires *out=NULL. All failures preserve *out; all intermediate
 * blobs, XML trees and decoded records are destroyed before success returns.
 * Missing resources/root are explicit failures; the original quiet empty
 * fallback/exception ordering is not reproduced. Diagnostics are optional and
 * contain the failing stage. Native source/allocator/callback rules follow
 * owned_unit_card.h. Paths and args are borrowed only during this call. */
rome2_card_resource_status rome2_owned_unit_card_create_from_packs(
    rome2_owned_unit_card **out, const rome2_unit_card_args *args,
    const rome2_unit_card_globals *globals, const uint16_t *const *archive_paths,
    size_t archive_count, const rome2_owned_string_allocator *allocator,
    rome2_card_resource_diagnostic *diagnostic);

/* Transactional reload into an existing native owner. Configuration errors
 * preserve the previous records/capacity; successful replacement keeps at
 * least the previous capacity. Ownership and observer rules are those of
 * rome2_owned_unit_card_replace_config. */
rome2_card_resource_status rome2_owned_unit_card_reload_from_packs(
    rome2_owned_unit_card *card, const uint16_t *const *archive_paths,
    size_t archive_count, const rome2_owned_string_allocator *allocator,
    rome2_card_resource_diagnostic *diagnostic);

#endif
