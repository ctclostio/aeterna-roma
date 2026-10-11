#include "ported_106ba2e0_campaign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

rome2_campaign_status rome2_campaign_env_init(
    rome2_campaign_env *env,
    const char *campaign_name)
{
    if (env == NULL) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    memset(env, 0, sizeof(*env));
    InitializeCriticalSection(&env->cs);

    EnterCriticalSection(&env->cs);

    if (campaign_name != NULL && campaign_name[0] != '\0') {
        strncpy_s(env->campaign_name, sizeof(env->campaign_name), campaign_name, _TRUNCATE);
    } else {
        strncpy_s(env->campaign_name, sizeof(env->campaign_name), "main_rome", _TRUNCATE);
    }

    /* Standard paths recovered from FUN_106ba2e0 */
    snprintf(env->startpos_path, sizeof(env->startpos_path),
             "data/campaigns/%s/startpos.esf", env->campaign_name);
    snprintf(env->campaign_dir, sizeof(env->campaign_dir),
             "campaigns/%s", env->campaign_name);
    snprintf(env->scripting_path, sizeof(env->scripting_path),
             "campaigns/%s/scripting.lua", env->campaign_name);
    strncpy_s(env->all_scripted_path, sizeof(env->all_scripted_path),
              ROME2_CAMPAIGN_DEFAULT_SCRIPT_ENTRY, _TRUNCATE);
    strncpy_s(env->file_overload_prefix, sizeof(env->file_overload_prefix),
              ROME2_CAMPAIGN_FILE_OVERLOAD_PREFIX, _TRUNCATE);
    strncpy_s(env->local_faction, sizeof(env->local_faction),
              "rom_rome", _TRUNCATE);
    strncpy_s(env->build_info, sizeof(env->build_info),
              ROME2_CAMPAIGN_DIAG_BUILD_ABSENT, _TRUNCATE);

    /* Allocate 1 MB decompression buffer matching 0x106ba2e0 puVar1 < 0x100000 */
    env->decompression_capacity = ROME2_ESF_DECOMPRESS_BUFFER_SIZE;
    env->decompression_buffer = (uint8_t *)malloc(env->decompression_capacity);
    if (env->decompression_buffer == NULL) {
        LeaveCriticalSection(&env->cs);
        DeleteCriticalSection(&env->cs);
        return ROME2_CAMPAIGN_ERR_OUT_OF_MEMORY;
    }
    memset(env->decompression_buffer, 0, env->decompression_capacity);
    env->decompression_size = 0;

    env->initialized = true;
    env->is_savegame = false;
    env->has_compressed_data = false;
    env->command_queue_initialized = false;
    env->scripting_initialized = false;
    env->elapsed_session_time = 0.0f;

    /* Pseudo subsystem pointers for engine registry */
    env->command_queue = (void *)(uintptr_t)0x106ba2e0;
    env->scripting_env_ptr = (void *)(uintptr_t)0x107e5470;
    env->shortcut_handler = (void *)(uintptr_t)0x106b8f60;

    LeaveCriticalSection(&env->cs);
    return ROME2_CAMPAIGN_OK;
}

void rome2_campaign_env_cleanup(
    rome2_campaign_env *env)
{
    if (env == NULL || !env->initialized) {
        return;
    }

    EnterCriticalSection(&env->cs);
    if (env->decompression_buffer != NULL) {
        free(env->decompression_buffer);
        env->decompression_buffer = NULL;
    }
    env->decompression_capacity = 0;
    env->decompression_size = 0;
    env->initialized = false;
    LeaveCriticalSection(&env->cs);

    DeleteCriticalSection(&env->cs);
}

rome2_campaign_status rome2_esf_parse_header(
    const uint8_t *data,
    size_t size,
    rome2_esf_header *out_hdr,
    rome2_esf_tag_table *out_tags)
{
    if (data == NULL || size < 16) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    /* Read header fields (little endian) */
    uint32_t magic = (uint32_t)data[0] |
                     ((uint32_t)data[1] << 8) |
                     ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 24);

    if (magic != ROME2_ESF_MAGIC_LE) {
        return ROME2_CAMPAIGN_ERR_INVALID_MAGIC;
    }

    uint32_t flags = (uint32_t)data[4] |
                     ((uint32_t)data[5] << 8) |
                     ((uint32_t)data[6] << 16) |
                     ((uint32_t)data[7] << 24);

    uint32_t timestamp = (uint32_t)data[8] |
                         ((uint32_t)data[9] << 8) |
                         ((uint32_t)data[10] << 16) |
                         ((uint32_t)data[11] << 24);

    uint32_t tag_tbl_off = (uint32_t)data[12] |
                           ((uint32_t)data[13] << 8) |
                           ((uint32_t)data[14] << 16) |
                           ((uint32_t)data[15] << 24);

    if (out_hdr != NULL) {
        out_hdr->magic = magic;
        out_hdr->flags = flags;
        out_hdr->timestamp = timestamp;
        out_hdr->tag_table_offset = tag_tbl_off;
    }

    if (out_tags != NULL) {
        memset(out_tags, 0, sizeof(*out_tags));

        if (tag_tbl_off + 2 > size) {
            return ROME2_CAMPAIGN_ERR_CORRUPT_TAG_TABLE;
        }

        const uint8_t *tbl_ptr = data + tag_tbl_off;
        uint16_t tag_count = (uint16_t)tbl_ptr[0] | ((uint16_t)tbl_ptr[1] << 8);
        tbl_ptr += 2;

        if (tag_count > ROME2_ESF_MAX_TAGS) {
            tag_count = ROME2_ESF_MAX_TAGS;
        }
        out_tags->count = tag_count;

        for (uint16_t i = 0; i < tag_count; ++i) {
            if ((size_t)(tbl_ptr - data) + 2 > size) {
                return ROME2_CAMPAIGN_ERR_CORRUPT_TAG_TABLE;
            }
            uint16_t str_len = (uint16_t)tbl_ptr[0] | ((uint16_t)tbl_ptr[1] << 8);
            tbl_ptr += 2;

            if ((size_t)(tbl_ptr - data) + str_len > size) {
                return ROME2_CAMPAIGN_ERR_CORRUPT_TAG_TABLE;
            }

            uint16_t copy_len = str_len;
            if (copy_len >= ROME2_ESF_MAX_NAME_LEN) {
                copy_len = (uint16_t)(ROME2_ESF_MAX_NAME_LEN - 1);
            }

            memcpy(out_tags->entries[i].name, tbl_ptr, copy_len);
            out_tags->entries[i].name[copy_len] = '\0';
            out_tags->entries[i].length = copy_len;

            tbl_ptr += str_len;
        }
    }

    return ROME2_CAMPAIGN_OK;
}

int32_t rome2_esf_find_tag(
    const rome2_esf_tag_table *tags,
    const char *tag_name)
{
    if (tags == NULL || tag_name == NULL) {
        return -1;
    }

    for (uint16_t i = 0; i < tags->count; ++i) {
        if (strcmp(tags->entries[i].name, tag_name) == 0) {
            return (int32_t)i;
        }
    }
    return -1;
}

rome2_campaign_status rome2_campaign_env_load_startpos_memory(
    rome2_campaign_env *env,
    const uint8_t *esf_bytes,
    size_t esf_size)
{
    if (env == NULL || !env->initialized || esf_bytes == NULL || esf_size < 16) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    EnterCriticalSection(&env->cs);

    rome2_campaign_status status = rome2_esf_parse_header(
        esf_bytes, esf_size, &env->esf_header, &env->esf_tag_table);
    if (status != ROME2_CAMPAIGN_OK) {
        LeaveCriticalSection(&env->cs);
        return status;
    }

    env->esf_timestamp = env->esf_header.timestamp;

    /* Check for COMPRESSED_DATA node */
    int32_t comp_tag = rome2_esf_find_tag(&env->esf_tag_table, ROME2_ESF_TAG_COMPRESSED_DATA);
    env->has_compressed_data = (comp_tag >= 0);

    /* Check for BUILD node */
    int32_t build_tag = rome2_esf_find_tag(&env->esf_tag_table, ROME2_ESF_TAG_BUILD);
    if (build_tag < 0) {
        strncpy_s(env->build_info, sizeof(env->build_info),
                  ROME2_CAMPAIGN_DIAG_BUILD_ABSENT, _TRUNCATE);
    } else {
        snprintf(env->build_info, sizeof(env->build_info),
                 "Build tag found at index %d (timestamp: %u)", build_tag, env->esf_timestamp);
    }

    /* Initialize campaign subsystems */
    env->command_queue_initialized = true;
    env->scripting_initialized = true;

    LeaveCriticalSection(&env->cs);
    return ROME2_CAMPAIGN_OK;
}

rome2_campaign_status rome2_campaign_env_load_startpos_file(
    rome2_campaign_env *env,
    const char *file_path)
{
    if (env == NULL || file_path == NULL) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    FILE *fp = NULL;
    errno_t err = fopen_s(&fp, file_path, "rb");
    if (err != 0 || fp == NULL) {
        return ROME2_CAMPAIGN_ERR_FILE_NOT_FOUND;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return ROME2_CAMPAIGN_ERR_CORRUPT_RECORD;
    }

    long file_size = ftell(fp);
    if (file_size <= 0) {
        fclose(fp);
        return ROME2_CAMPAIGN_ERR_CORRUPT_RECORD;
    }
    fseek(fp, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc((size_t)file_size);
    if (buf == NULL) {
        fclose(fp);
        return ROME2_CAMPAIGN_ERR_OUT_OF_MEMORY;
    }

    size_t read_bytes = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);

    if (read_bytes != (size_t)file_size) {
        free(buf);
        return ROME2_CAMPAIGN_ERR_CORRUPT_RECORD;
    }

    rome2_campaign_status status = rome2_campaign_env_load_startpos_memory(
        env, buf, (size_t)file_size);
    free(buf);

    return status;
}

rome2_campaign_status rome2_campaign_env_load_from_vfs(
    rome2_campaign_env *env,
    rome2_vfs *vfs,
    const char *campaign_name)
{
    if (env == NULL || vfs == NULL) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    char query_path[ROME2_CAMPAIGN_PATH_MAX];
    const char *cname = (campaign_name != NULL && campaign_name[0] != '\0')
                            ? campaign_name
                            : env->campaign_name;
    snprintf(query_path, sizeof(query_path), "data/campaigns/%s/startpos.esf", cname);

    void *esf_buf = NULL;
    size_t out_bytes = 0;
    rome2_vfs_status vfs_status = rome2_vfs_read_file(
        vfs, query_path, &esf_buf, &out_bytes);

    if (vfs_status != ROME2_VFS_OK || out_bytes == 0 || esf_buf == NULL) {
        /* Fallback: try relative path without data/ */
        snprintf(query_path, sizeof(query_path), "campaigns/%s/startpos.esf", cname);
        vfs_status = rome2_vfs_read_file(
            vfs, query_path, &esf_buf, &out_bytes);
    }

    if (vfs_status != ROME2_VFS_OK || out_bytes == 0 || esf_buf == NULL) {
        return ROME2_CAMPAIGN_ERR_FILE_NOT_FOUND;
    }

    rome2_campaign_status status = rome2_campaign_env_load_startpos_memory(
        env, (const uint8_t *)esf_buf, out_bytes);
    free(esf_buf);

    return status;
}

rome2_campaign_status rome2_campaign_env_set_local_faction(
    rome2_campaign_env *env,
    const char *faction_name)
{
    if (env == NULL || !env->initialized || faction_name == NULL) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    EnterCriticalSection(&env->cs);
    strncpy_s(env->local_faction, sizeof(env->local_faction), faction_name, _TRUNCATE);
    LeaveCriticalSection(&env->cs);
    return ROME2_CAMPAIGN_OK;
}

rome2_campaign_status rome2_campaign_env_decompress_block(
    rome2_campaign_env *env,
    const uint8_t *comp_data,
    size_t comp_size,
    size_t expected_uncompressed_size)
{
    if (env == NULL || !env->initialized || comp_data == NULL || comp_size == 0) {
        return ROME2_CAMPAIGN_ERR_INVALID_ARGUMENT;
    }

    EnterCriticalSection(&env->cs);

    size_t needed = expected_uncompressed_size > 0 ? expected_uncompressed_size : comp_size;
    if (needed > env->decompression_capacity) {
        uint8_t *new_buf = (uint8_t *)realloc(env->decompression_buffer, needed);
        if (new_buf == NULL) {
            LeaveCriticalSection(&env->cs);
            return ROME2_CAMPAIGN_ERR_OUT_OF_MEMORY;
        }
        env->decompression_buffer = new_buf;
        env->decompression_capacity = needed;
    }

    /* Staging copy */
    size_t copy_sz = comp_size > env->decompression_capacity ? env->decompression_capacity : comp_size;
    memcpy(env->decompression_buffer, comp_data, copy_sz);
    env->decompression_size = copy_sz;

    LeaveCriticalSection(&env->cs);
    return ROME2_CAMPAIGN_OK;
}
