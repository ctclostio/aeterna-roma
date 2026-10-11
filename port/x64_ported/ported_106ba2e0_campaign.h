#ifndef ROME2_PORTED_106BA2E0_CAMPAIGN_H
#define ROME2_PORTED_106BA2E0_CAMPAIGN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>
#include "ported_100e3360_vfs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_106BA2E0_CAMPAIGN_ENV_PC     UINT32_C(0x106ba2e0)

/* Magic number for ESF (Empire/Rome 2 Save Format) */
#define ROME2_ESF_MAGIC_LE                      UINT32_C(0x0000abca)
#define ROME2_ESF_MAGIC_BE                      UINT32_C(0xcaab0000)

/* Standard decompression pre-allocation buffer size (1 MB, matches FUN_106ba2e0) */
#define ROME2_ESF_DECOMPRESS_BUFFER_SIZE        UINT32_C(0x100000)

/* Maximum tag count and string limits */
#define ROME2_ESF_MAX_TAGS                      256U
#define ROME2_ESF_MAX_NAME_LEN                  128U
#define ROME2_CAMPAIGN_PATH_MAX                 512U

/* Node tag flags in ESF binary stream */
#define ROME2_ESF_NODE_RECORD                   0x80U
#define ROME2_ESF_NODE_RECORD_ARRAY             0x81U

/* Known tag strings in FUN_106ba2e0 */
#define ROME2_ESF_TAG_COMPRESSED_DATA           "COMPRESSED_DATA"
#define ROME2_ESF_TAG_COMPRESSED_DATA_INFO      "COMPRESSED_DATA_INFO"
#define ROME2_ESF_TAG_BUILD                     "BUILD"
#define ROME2_ESF_TAG_STARTPOS                  "CAMPAIGN_STARTPOS"
#define ROME2_ESF_TAG_SAVE_HEADER               "SAVE_GAME_HEADER"

/* Canonical diagnostics recovered from 0x106ba2e0 */
#define ROME2_CAMPAIGN_DIAG_BUILD_ABSENT        "Build info not present - Patch 3 or before"
#define ROME2_CAMPAIGN_FILE_OVERLOAD_PREFIX     "file_overload\\"
#define ROME2_CAMPAIGN_DEFAULT_SCRIPT_ENTRY     "data/lua_scripts/all_scripted.lua"

typedef enum rome2_campaign_status {
    ROME2_CAMPAIGN_OK = 0,
    ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT = 1,
    ROME2_CAMPAIGN_ERR_INVALID_MAGIC = 2,
    ROME2_CAMPAIGN_ERR_CORRUPT_TAG_TABLE = 3,
    ROME2_CAMPAIGN_ERR_CORRUPT_RECORD = 4,
    ROME2_CAMPAIGN_ERR_DECOMPRESS_FAILED = 5,
    ROME2_CAMPAIGN_ERR_FILE_NOT_FOUND = 6,
    ROME2_CAMPAIGN_ERR_OUT_OF_MEMORY = 7,
    ROME2_CAMPAIGN_ERR_ALREADY_INITIALIZED = 8,
    ROME2_CAMPAIGN_ERR_NOT_INITIALIZED = 9
} rome2_campaign_status;

/*
 * Header of ESF (v4 / Rome II formatted)
 */
typedef struct rome2_esf_header {
    uint32_t magic;              /* 0xabca */
    uint32_t flags;              /* 0 = uncompressed v4 */
    uint32_t timestamp;          /* UNIX timestamp */
    uint32_t tag_table_offset;   /* byte offset to the string dictionary */
} rome2_esf_header;

/*
 * Tag descriptor from ESF string dictionary
 */
typedef struct rome2_esf_tag_entry {
    char name[ROME2_ESF_MAX_NAME_LEN];
    uint16_t length;
} rome2_esf_tag_entry;

/*
 * In-memory representation of ESF tag table
 */
typedef struct rome2_esf_tag_table {
    uint16_t count;
    rome2_esf_tag_entry entries[ROME2_ESF_MAX_TAGS];
} rome2_esf_tag_table;

/*
 * Decoded ESF node summary
 */
typedef struct rome2_esf_node_info {
    char tag_name[ROME2_ESF_MAX_NAME_LEN];
    uint16_t tag_index;
    uint8_t version;
    size_t payload_offset;
    size_t payload_length;
    bool is_record;
} rome2_esf_node_info;

/*
 * Campaign Environment struct (CAMPAIGN_ENV singleton / instance from 0x106ba2e0)
 */
typedef struct rome2_campaign_env {
    CRITICAL_SECTION cs;
    bool initialized;
    bool is_savegame;
    bool has_compressed_data;
    bool command_queue_initialized;
    bool scripting_initialized;
    
    float elapsed_session_time;
    uint32_t esf_timestamp;
    
    char campaign_name[ROME2_ESF_MAX_NAME_LEN];      /* e.g. "main_rome" */
    char local_faction[ROME2_ESF_MAX_NAME_LEN];     /* e.g. "rom_rome" */
    char startpos_path[ROME2_CAMPAIGN_PATH_MAX];    /* "data/campaigns/%s/startpos.esf" */
    char campaign_dir[ROME2_CAMPAIGN_PATH_MAX];     /* "campaigns/%s" */
    char scripting_path[ROME2_CAMPAIGN_PATH_MAX];   /* "campaigns/%s/scripting.lua" */
    char all_scripted_path[ROME2_CAMPAIGN_PATH_MAX];/* "data/lua_scripts/all_scripted.lua" */
    char file_overload_prefix[64];                  /* "file_overload\\" */
    char build_info[256];                           /* Build version string or diagnostic */

    /* Decompression staging buffer */
    uint8_t *decompression_buffer;
    size_t decompression_capacity;
    size_t decompression_size;

    /* ESF Metadata */
    rome2_esf_header esf_header;
    rome2_esf_tag_table esf_tag_table;
    
    /* Engine Subsystem Handles */
    void *command_queue;
    void *scripting_env_ptr;
    void *shortcut_handler;
} rome2_campaign_env;

/*
 * Campaign Environment API
 */
rome2_campaign_status rome2_campaign_env_init(
    rome2_campaign_env *env,
    const char *campaign_name);

void rome2_campaign_env_cleanup(
    rome2_campaign_env *env);

rome2_campaign_status rome2_esf_parse_header(
    const uint8_t *data,
    size_t size,
    rome2_esf_header *out_hdr,
    rome2_esf_tag_table *out_tags);

int32_t rome2_esf_find_tag(
    const rome2_esf_tag_table *tags,
    const char *tag_name);

rome2_campaign_status rome2_campaign_env_load_startpos_memory(
    rome2_campaign_env *env,
    const uint8_t *esf_bytes,
    size_t esf_size);

rome2_campaign_status rome2_campaign_env_load_startpos_file(
    rome2_campaign_env *env,
    const char *file_path);

rome2_campaign_status rome2_campaign_env_load_from_vfs(
    rome2_campaign_env *env,
    rome2_vfs *vfs,
    const char *campaign_name);

rome2_campaign_status rome2_campaign_env_set_local_faction(
    rome2_campaign_env *env,
    const char *faction_name);

rome2_campaign_status rome2_campaign_env_decompress_block(
    rome2_campaign_env *env,
    const uint8_t *comp_data,
    size_t comp_size,
    size_t expected_uncompressed_size);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_106BA2E0_CAMPAIGN_H */
