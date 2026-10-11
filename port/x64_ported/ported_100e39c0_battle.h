#ifndef ROME2_PORTED_100E39C0_BATTLE_H
#define ROME2_PORTED_100E39C0_BATTLE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "ported_100e3360_vfs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_100E39C0_BATTLE_MAP_PC       UINT32_C(0x100e39c0)

/* Magic for Battle Location Map: 'BLMF' (0x464d4c42) */
#define ROME2_BLM_MAGIC                         UINT32_C(0x464d4c42)

/* Stride for each vector location in BLM layers: 36 bytes (0x24) */
#define ROME2_BLM_ENTRY_STRIDE                  UINT32_C(36)
#define ROME2_BLM_MAX_LAYERS                    16U
#define ROME2_BLM_MAX_LAYER_NAME                64U
#define ROME2_BATTLE_PATH_MAX                   512U

/* Factions and cultures recovered from 0x100e39c0 */
#define ROME2_BATTLE_FACTION_ATTACKER           "rom_rome"
#define ROME2_BATTLE_FACTION_DEFENDER           "rom_ptolemaics"
#define ROME2_BATTLE_CULTURE                    "rom_Roman"
#define ROME2_BATTLE_SUBCULTURE                 "sc_rom_roman"
#define ROME2_BATTLE_ROAD_MATERIAL              "road"
#define ROME2_BATTLE_DEFAULT_BLM_PATH           "terrain/battles/main_rome_map/locations.blm"
#define ROME2_BATTLE_DEFAULT_TILE_DB            "terrain/tiles/battle_tile_database"

typedef enum rome2_battle_status {
    ROME2_BATTLE_OK = 0,
    ROME2_BATTLE_ERR_INVALID_ARGUMENT = 1,
    ROME2_BATTLE_ERR_INVALID_MAGIC = 2,
    ROME2_BATTLE_ERR_CORRUPT_LAYER = 3,
    ROME2_BATTLE_ERR_LAYER_NOT_FOUND = 4,
    ROME2_BATTLE_ERR_OUT_OF_MEMORY = 5,
    ROME2_BATTLE_ERR_FILE_NOT_FOUND = 6,
    ROME2_BATTLE_ERR_NOT_INITIALIZED = 7
} rome2_battle_status;

/*
 * Entry in a BLM vector location layer (36 bytes / 0x24)
 */
typedef struct rome2_blm_entry {
    uint32_t min_x;
    uint32_t min_y;
    uint32_t max_x;
    uint32_t max_y;
    uint32_t center_x;
    uint32_t center_y;
    int32_t settlement_id;
    uint32_t flags;
    uint32_t reserved;
} rome2_blm_entry;

/*
 * BLM Layer
 */
typedef struct rome2_blm_layer {
    char name[ROME2_BLM_MAX_LAYER_NAME];
    uint32_t entry_count;
    rome2_blm_entry *entries;
} rome2_blm_layer;

/*
 * BLM Map Document
 */
typedef struct rome2_blm_map {
    uint32_t magic;
    uint32_t version;
    uint32_t layer_count;
    uint32_t width;
    uint32_t height;
    rome2_blm_layer layers[ROME2_BLM_MAX_LAYERS];
    uint8_t *grid_data;
    size_t grid_data_size;
} rome2_blm_map;

/*
 * Battle Context (Orchestrator state from 0x100e39c0)
 */
typedef struct rome2_battle_context {
    bool initialized;
    bool blm_loaded;
    uint32_t rng_seed;

    char attacker_faction[64];
    char defender_faction[64];
    char culture[64];
    char subculture[64];
    char road_material[64];
    char battle_map_path[ROME2_BATTLE_PATH_MAX];
    char tile_db_path[ROME2_BATTLE_PATH_MAX];

    rome2_blm_map map;

    /* Settlement benchmark state */
    uint32_t total_settlements;
    uint32_t tested_settlement_index;
    float selected_pos_x;
    float selected_pos_y;
    char benchmark_log[256];
} rome2_battle_context;

/*
 * Battle Subsystem API
 */
rome2_battle_status rome2_battle_context_init(
    rome2_battle_context *ctx);

void rome2_battle_context_cleanup(
    rome2_battle_context *ctx);

rome2_battle_status rome2_blm_parse(
    const uint8_t *data,
    size_t size,
    rome2_blm_map *out_map);

void rome2_blm_free(
    rome2_blm_map *map);

const rome2_blm_layer *rome2_blm_find_layer(
    const rome2_blm_map *map,
    const char *layer_name);

rome2_battle_status rome2_battle_context_load_blm_memory(
    rome2_battle_context *ctx,
    const uint8_t *blm_data,
    size_t blm_size);

rome2_battle_status rome2_battle_context_load_blm_file(
    rome2_battle_context *ctx,
    const char *file_path);

rome2_battle_status rome2_battle_context_load_from_vfs(
    rome2_battle_context *ctx,
    rome2_vfs *vfs,
    const char *blm_path);

rome2_battle_status rome2_battle_run_settlement_benchmark(
    rome2_battle_context *ctx,
    uint32_t settlement_arg,
    char *out_log_buf,
    size_t log_buf_size);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_100E39C0_BATTLE_H */
