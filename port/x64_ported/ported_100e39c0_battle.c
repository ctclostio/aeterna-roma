#include "ported_100e39c0_battle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

rome2_battle_status rome2_battle_context_init(
    rome2_battle_context *ctx)
{
    if (ctx == NULL) {
        return ROME2_BATTLE_ERR_INVALID_ARGUMENT;
    }

    memset(ctx, 0, sizeof(*ctx));

    strncpy_s(ctx->attacker_faction, sizeof(ctx->attacker_faction),
              ROME2_BATTLE_FACTION_ATTACKER, _TRUNCATE);
    strncpy_s(ctx->defender_faction, sizeof(ctx->defender_faction),
              ROME2_BATTLE_FACTION_DEFENDER, _TRUNCATE);
    strncpy_s(ctx->culture, sizeof(ctx->culture),
              ROME2_BATTLE_CULTURE, _TRUNCATE);
    strncpy_s(ctx->subculture, sizeof(ctx->subculture),
              ROME2_BATTLE_SUBCULTURE, _TRUNCATE);
    strncpy_s(ctx->road_material, sizeof(ctx->road_material),
              ROME2_BATTLE_ROAD_MATERIAL, _TRUNCATE);
    strncpy_s(ctx->battle_map_path, sizeof(ctx->battle_map_path),
              ROME2_BATTLE_DEFAULT_BLM_PATH, _TRUNCATE);
    strncpy_s(ctx->tile_db_path, sizeof(ctx->tile_db_path),
              ROME2_BATTLE_DEFAULT_TILE_DB, _TRUNCATE);

    ctx->rng_seed = 0x269ec3; /* Linear congruential constant from FUN_100e39c0 */
    ctx->initialized = true;
    ctx->blm_loaded = false;

    return ROME2_BATTLE_OK;
}

void rome2_battle_context_cleanup(
    rome2_battle_context *ctx)
{
    if (ctx == NULL || !ctx->initialized) {
        return;
    }

    rome2_blm_free(&ctx->map);
    memset(ctx, 0, sizeof(*ctx));
}

rome2_battle_status rome2_blm_parse(
    const uint8_t *data,
    size_t size,
    rome2_blm_map *out_map)
{
    if (data == NULL || size < 20 || out_map == NULL) {
        return ROME2_BATTLE_ERR_INVALID_ARGUMENT;
    }

    memset(out_map, 0, sizeof(*out_map));

    /* Check magic 'BLMF' (little endian) */
    uint32_t magic = (uint32_t)data[0] |
                     ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 24);

    if (magic != ROME2_BLM_MAGIC) {
        return ROME2_BATTLE_ERR_INVALID_MAGIC;
    }

    uint32_t version = (uint32_t)data[4] |
                       ((uint32_t)data[5] << 8) |
                       ((uint32_t)data[6] << 16) |
                       ((uint32_t)data[7] << 24);

    uint32_t layer_count = (uint32_t)data[8] |
                           ((uint32_t)data[9] << 8) |
                           ((uint32_t)data[10] << 16) |
                           ((uint32_t)data[11] << 24);

    uint32_t width = (uint32_t)data[12] |
                     ((uint32_t)data[13] << 8) |
                     ((uint32_t)data[14] << 16) |
                     ((uint32_t)data[15] << 24);

    uint32_t height = (uint32_t)data[16] |
                      ((uint32_t)data[17] << 8) |
                      ((uint32_t)data[18] << 16) |
                      ((uint32_t)data[19] << 24);

    out_map->magic = magic;
    out_map->version = version;
    out_map->layer_count = layer_count > ROME2_BLM_MAX_LAYERS ? ROME2_BLM_MAX_LAYERS : layer_count;
    out_map->width = width;
    out_map->height = height;

    size_t offset = 20;

    for (uint32_t i = 0; i < out_map->layer_count; ++i) {
        if (offset + 2 > size) {
            rome2_blm_free(out_map);
            return ROME2_BATTLE_ERR_CORRUPT_LAYER;
        }

        uint16_t str_len = (uint16_t)data[offset] | ((uint16_t)data[offset + 1] << 8);
        offset += 2;

        if (offset + str_len + 4 > size) {
            rome2_blm_free(out_map);
            return ROME2_BATTLE_ERR_CORRUPT_LAYER;
        }

        uint16_t copy_len = str_len;
        if (copy_len >= ROME2_BLM_MAX_LAYER_NAME) {
            copy_len = (uint16_t)(ROME2_BLM_MAX_LAYER_NAME - 1);
        }

        memcpy(out_map->layers[i].name, data + offset, copy_len);
        out_map->layers[i].name[copy_len] = '\0';
        offset += str_len;

        uint32_t entry_count = (uint32_t)data[offset] |
                               ((uint32_t)data[offset + 1] << 8) |
                               ((uint32_t)data[offset + 2] << 16) |
                               ((uint32_t)data[offset + 3] << 24);
        offset += 4;

        out_map->layers[i].entry_count = entry_count;

        size_t layer_bytes = (size_t)entry_count * ROME2_BLM_ENTRY_STRIDE;
        if (offset + layer_bytes > size) {
            rome2_blm_free(out_map);
            return ROME2_BATTLE_ERR_CORRUPT_LAYER;
        }

        if (entry_count > 0) {
            out_map->layers[i].entries = (rome2_blm_entry *)malloc(entry_count * sizeof(rome2_blm_entry));
            if (out_map->layers[i].entries == NULL) {
                rome2_blm_free(out_map);
                return ROME2_BATTLE_ERR_OUT_OF_MEMORY;
            }

            for (uint32_t j = 0; j < entry_count; ++j) {
                const uint8_t *e_ptr = data + offset + (j * ROME2_BLM_ENTRY_STRIDE);
                rome2_blm_entry *e = &out_map->layers[i].entries[j];

                e->min_x = (uint32_t)e_ptr[0] | ((uint32_t)e_ptr[1] << 8) | ((uint32_t)e_ptr[2] << 16) | ((uint32_t)e_ptr[3] << 24);
                e->min_y = (uint32_t)e_ptr[4] | ((uint32_t)e_ptr[5] << 8) | ((uint32_t)e_ptr[6] << 16) | ((uint32_t)e_ptr[7] << 24);
                e->max_x = (uint32_t)e_ptr[8] | ((uint32_t)e_ptr[9] << 8) | ((uint32_t)e_ptr[10] << 16) | ((uint32_t)e_ptr[11] << 24);
                e->max_y = (uint32_t)e_ptr[12] | ((uint32_t)e_ptr[13] << 8) | ((uint32_t)e_ptr[14] << 16) | ((uint32_t)e_ptr[15] << 24);
                e->center_x = (uint32_t)e_ptr[16] | ((uint32_t)e_ptr[17] << 8) | ((uint32_t)e_ptr[18] << 16) | ((uint32_t)e_ptr[19] << 24);
                e->center_y = (uint32_t)e_ptr[20] | ((uint32_t)e_ptr[21] << 8) | ((uint32_t)e_ptr[22] << 16) | ((uint32_t)e_ptr[23] << 24);
                e->settlement_id = (int32_t)((uint32_t)e_ptr[24] | ((uint32_t)e_ptr[25] << 8) | ((uint32_t)e_ptr[26] << 16) | ((uint32_t)e_ptr[27] << 24));
                e->flags = (uint32_t)e_ptr[28] | ((uint32_t)e_ptr[29] << 8) | ((uint32_t)e_ptr[30] << 16) | ((uint32_t)e_ptr[31] << 24);
                e->reserved = (uint32_t)e_ptr[32] | ((uint32_t)e_ptr[33] << 8) | ((uint32_t)e_ptr[34] << 16) | ((uint32_t)e_ptr[35] << 24);
            }

            offset += layer_bytes;
        } else {
            out_map->layers[i].entries = NULL;
        }
    }

    /* Store remaining payload as grid data */
    if (offset < size) {
        out_map->grid_data_size = size - offset;
        out_map->grid_data = (uint8_t *)malloc(out_map->grid_data_size);
        if (out_map->grid_data != NULL) {
            memcpy(out_map->grid_data, data + offset, out_map->grid_data_size);
        }
    }

    return ROME2_BATTLE_OK;
}

void rome2_blm_free(
    rome2_blm_map *map)
{
    if (map == NULL) {
        return;
    }

    for (uint32_t i = 0; i < ROME2_BLM_MAX_LAYERS; ++i) {
        if (map->layers[i].entries != NULL) {
            free(map->layers[i].entries);
            map->layers[i].entries = NULL;
        }
        map->layers[i].entry_count = 0;
        map->layers[i].name[0] = '\0';
    }

    if (map->grid_data != NULL) {
        free(map->grid_data);
        map->grid_data = NULL;
    }
    map->grid_data_size = 0;
    map->layer_count = 0;
}

const rome2_blm_layer *rome2_blm_find_layer(
    const rome2_blm_map *map,
    const char *layer_name)
{
    if (map == NULL || layer_name == NULL) {
        return NULL;
    }

    for (uint32_t i = 0; i < map->layer_count; ++i) {
        if (strcmp(map->layers[i].name, layer_name) == 0) {
            return &map->layers[i];
        }
    }
    return NULL;
}

rome2_battle_status rome2_battle_context_load_blm_memory(
    rome2_battle_context *ctx,
    const uint8_t *blm_data,
    size_t blm_size)
{
    if (ctx == NULL || !ctx->initialized || blm_data == NULL || blm_size == 0) {
        return ROME2_BATTLE_ERR_INVALID_ARGUMENT;
    }

    rome2_battle_status status = rome2_blm_parse(blm_data, blm_size, &ctx->map);
    if (status != ROME2_BATTLE_OK) {
        return status;
    }

    /* Count total settlements across settlement layers */
    uint32_t total = 0;
    for (uint32_t i = 0; i < ctx->map.layer_count; ++i) {
        if (strstr(ctx->map.layers[i].name, "settlement") != NULL ||
            strstr(ctx->map.layers[i].name, "port") != NULL) {
            total += ctx->map.layers[i].entry_count;
        }
    }
    ctx->total_settlements = total > 0 ? total : 1;
    ctx->blm_loaded = true;

    return ROME2_BATTLE_OK;
}

rome2_battle_status rome2_battle_context_load_blm_file(
    rome2_battle_context *ctx,
    const char *file_path)
{
    if (ctx == NULL || file_path == NULL) {
        return ROME2_BATTLE_ERR_INVALID_ARGUMENT;
    }

    FILE *fp = NULL;
    errno_t err = fopen_s(&fp, file_path, "rb");
    if (err != 0 || fp == NULL) {
        return ROME2_BATTLE_ERR_FILE_NOT_FOUND;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return ROME2_BATTLE_ERR_CORRUPT_LAYER;
    }

    long file_size = ftell(fp);
    if (file_size <= 0) {
        fclose(fp);
        return ROME2_BATTLE_ERR_CORRUPT_LAYER;
    }
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc((size_t)file_size);
    if (buf == NULL) {
        fclose(fp);
        return ROME2_BATTLE_ERR_OUT_OF_MEMORY;
    }

    size_t read_bytes = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);

    if (read_bytes != (size_t)file_size) {
        free(buf);
        return ROME2_BATTLE_ERR_CORRUPT_LAYER;
    }

    rome2_battle_status status = rome2_battle_context_load_blm_memory(
        ctx, buf, (size_t)file_size);
    free(buf);

    return status;
}

rome2_battle_status rome2_battle_context_load_from_vfs(
    rome2_battle_context *ctx,
    rome2_vfs *vfs,
    const char *blm_path)
{
    if (ctx == NULL || vfs == NULL) {
        return ROME2_BATTLE_ERR_INVALID_ARGUMENT;
    }

    const char *query_path = (blm_path != NULL && blm_path[0] != '\0')
                                 ? blm_path
                                 : ctx->battle_map_path;

    void *blm_buf = NULL;
    size_t out_bytes = 0;
    rome2_vfs_status vfs_status = rome2_vfs_read_file(
        vfs, query_path, &blm_buf, &out_bytes);

    if (vfs_status != ROME2_VFS_OK || out_bytes == 0 || blm_buf == NULL) {
        return ROME2_BATTLE_ERR_FILE_NOT_FOUND;
    }

    rome2_battle_status status = rome2_battle_context_load_blm_memory(
        ctx, (const uint8_t *)blm_buf, out_bytes);
    free(blm_buf);

    return status;
}

rome2_battle_status rome2_battle_run_settlement_benchmark(
    rome2_battle_context *ctx,
    uint32_t settlement_arg,
    char *out_log_buf,
    size_t log_buf_size)
{
    if (ctx == NULL || !ctx->initialized || !ctx->blm_loaded) {
        return ROME2_BATTLE_ERR_NOT_INITIALIZED;
    }

    if (ctx->total_settlements == 0) {
        return ROME2_BATTLE_ERR_LAYER_NOT_FOUND;
    }

    /* Exact modulo selection from 0x100e39c0: uVar13 = local_24 % local_20 */
    uint32_t chosen_idx = settlement_arg % ctx->total_settlements;
    ctx->tested_settlement_index = chosen_idx;

    /* Find target entry in settlement layers */
    uint32_t accum = 0;
    const rome2_blm_entry *target_entry = NULL;

    for (uint32_t i = 0; i < ctx->map.layer_count; ++i) {
        if (strstr(ctx->map.layers[i].name, "settlement") != NULL ||
            strstr(ctx->map.layers[i].name, "port") != NULL) {
            if (chosen_idx < accum + ctx->map.layers[i].entry_count) {
                uint32_t local_idx = chosen_idx - accum;
                target_entry = &ctx->map.layers[i].entries[local_idx];
                break;
            }
            accum += ctx->map.layers[i].entry_count;
        }
    }

    if (target_entry != NULL && ctx->map.width > 0 && ctx->map.height > 0) {
        ctx->selected_pos_x = (float)target_entry->center_x / (float)ctx->map.width;
        ctx->selected_pos_y = (float)target_entry->center_y / (float)ctx->map.height;
    } else {
        ctx->selected_pos_x = 0.5f;
        ctx->selected_pos_y = 0.5f;
    }

    /* Recovered printf string from 0x100e39c0 */
    snprintf(ctx->benchmark_log, sizeof(ctx->benchmark_log),
             "Settlement battle test %u/%u\n",
             chosen_idx, ctx->total_settlements);

    if (out_log_buf != NULL && log_buf_size > 0) {
        strncpy_s(out_log_buf, log_buf_size, ctx->benchmark_log, _TRUNCATE);
    }

    return ROME2_BATTLE_OK;
}
