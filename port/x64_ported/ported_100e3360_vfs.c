#include "ported_100e3360_vfs.h"

#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

const char *const g_rome2_vfs_dlc_exclusions_a[ROME2_VFS_DLC_EXCLUSION_COUNT] = {
    "manifest.txt",
    "nomadic.pack",
    "gaul.pack",
    "campaigns/main_gaul/startpos.esf",
    "punic.pack",
    "campaigns/main_punic/startpos.esf",
    "greeks.pack",
    "campaigns/main_greek/startpos.esf",
    "blood.pack",
    "blood_rome2.pack"
};

const wchar_t *const g_rome2_vfs_dlc_exclusions_w[ROME2_VFS_DLC_EXCLUSION_COUNT] = {
    L"manifest.txt",
    L"nomadic.pack",
    L"gaul.pack",
    L"campaigns/main_gaul/startpos.esf",
    L"punic.pack",
    L"campaigns/main_punic/startpos.esf",
    L"greeks.pack",
    L"campaigns/main_greek/startpos.esf",
    L"blood.pack",
    L"blood_rome2.pack"
};

/* =========================================================================
 * Path Normalization & Helpers
 * ========================================================================= */

void rome2_vfs_normalize_path_a(char *dest, size_t dest_size, const char *src)
{
    if (dest == NULL || dest_size == 0) {
        return;
    }
    if (src == NULL) {
        dest[0] = '\0';
        return;
    }

    /* Skip leading "./" or ".\\" or "/" or "\\" */
    while ((src[0] == '.' && (src[1] == '/' || src[1] == '\\')) ||
           src[0] == '/' || src[0] == '\\') {
        if (src[0] == '.') {
            src += 2;
        } else {
            src += 1;
        }
    }

    size_t i = 0;
    while (src[i] != '\0' && i + 1 < dest_size) {
        if (src[i] == '\\') {
            dest[i] = '/';
        } else {
            dest[i] = src[i];
        }
        i++;
    }
    dest[i] = '\0';
}

void rome2_vfs_normalize_path_w(wchar_t *dest, size_t dest_size, const wchar_t *src)
{
    if (dest == NULL || dest_size == 0) {
        return;
    }
    if (src == NULL) {
        dest[0] = L'\0';
        return;
    }

    while ((src[0] == L'.' && (src[1] == L'/' || src[1] == L'\\')) ||
           src[0] == L'/' || src[0] == L'\\') {
        if (src[0] == L'.') {
            src += 2;
        } else {
            src += 1;
        }
    }

    size_t i = 0;
    while (src[i] != L'\0' && i + 1 < dest_size) {
        if (src[i] == L'\\') {
            dest[i] = L'/';
        } else {
            dest[i] = src[i];
        }
        i++;
    }
    dest[i] = L'\0';
}

bool rome2_vfs_is_excluded_dlc_file_a(const char *rel_path)
{
    if (rel_path == NULL) {
        return false;
    }
    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    for (size_t i = 0; i < ROME2_VFS_DLC_EXCLUSION_COUNT; i++) {
        if (_stricmp(norm, g_rome2_vfs_dlc_exclusions_a[i]) == 0) {
            return true;
        }
    }
    return false;
}

bool rome2_vfs_is_excluded_dlc_file_w(const wchar_t *rel_path)
{
    if (rel_path == NULL) {
        return false;
    }
    wchar_t norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_w(norm, sizeof(norm) / sizeof(wchar_t), rel_path);

    for (size_t i = 0; i < ROME2_VFS_DLC_EXCLUSION_COUNT; i++) {
        if (_wcsicmp(norm, g_rome2_vfs_dlc_exclusions_w[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* =========================================================================
 * VFS File Map Operations (Sorted Array with Binary Search)
 * ========================================================================= */

rome2_vfs_status rome2_vfs_file_map_init(rome2_vfs_file_map *map)
{
    if (map == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }
    map->entries = NULL;
    map->count = 0;
    map->capacity = 0;
    return ROME2_VFS_OK;
}

void rome2_vfs_file_map_free(rome2_vfs_file_map *map)
{
    if (map == NULL) {
        return;
    }
    if (map->entries != NULL) {
        free(map->entries);
        map->entries = NULL;
    }
    map->count = 0;
    map->capacity = 0;
}

void rome2_vfs_file_map_clear(rome2_vfs_file_map *map)
{
    if (map != NULL) {
        map->count = 0;
    }
}

static int compare_file_entries(const void *a, const void *b)
{
    const rome2_vfs_file_entry *ea = (const rome2_vfs_file_entry *)a;
    const rome2_vfs_file_entry *eb = (const rome2_vfs_file_entry *)b;
    return _stricmp(ea->rel_path, eb->rel_path);
}

static size_t find_insert_index(const rome2_vfs_file_map *map, const char *norm_path, bool *exact_match)
{
    *exact_match = false;
    if (map->count == 0) {
        return 0;
    }

    size_t low = 0;
    size_t high = map->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = _stricmp(map->entries[mid].rel_path, norm_path);
        if (cmp == 0) {
            *exact_match = true;
            return mid;
        }
        if (cmp < 0) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return low;
}

rome2_vfs_status rome2_vfs_file_map_insert_a(
    rome2_vfs_file_map *map,
    const char *rel_path,
    uint64_t file_size)
{
    if (map == NULL || rel_path == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    bool exact_match = false;
    size_t idx = find_insert_index(map, norm, &exact_match);
    if (exact_match) {
        map->entries[idx].file_size = file_size;
        return ROME2_VFS_OK;
    }

    if (map->count >= map->capacity) {
        size_t new_cap = (map->capacity == 0) ? 16 : map->capacity * 2;
        rome2_vfs_file_entry *new_entries = (rome2_vfs_file_entry *)realloc(
            map->entries, new_cap * sizeof(rome2_vfs_file_entry));
        if (new_entries == NULL) {
            return ROME2_VFS_ERR_OUT_OF_MEMORY;
        }
        map->entries = new_entries;
        map->capacity = new_cap;
    }

    if (idx < map->count) {
        memmove(&map->entries[idx + 1], &map->entries[idx],
                (map->count - idx) * sizeof(rome2_vfs_file_entry));
    }

    strncpy_s(map->entries[idx].rel_path, sizeof(map->entries[idx].rel_path),
              norm, _TRUNCATE);
    map->entries[idx].file_size = file_size;
    map->count++;

    return ROME2_VFS_OK;
}

rome2_vfs_status rome2_vfs_file_map_insert_w(
    rome2_vfs_file_map *map,
    const wchar_t *rel_path,
    uint64_t file_size)
{
    if (map == NULL || rel_path == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }
    char utf8[ROME2_VFS_MAX_PATH];
    int res = WideCharToMultiByte(CP_UTF8, 0, rel_path, -1, utf8, sizeof(utf8), NULL, NULL);
    if (res <= 0) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }
    return rome2_vfs_file_map_insert_a(map, utf8, file_size);
}

const rome2_vfs_file_entry *rome2_vfs_file_map_find_a(
    const rome2_vfs_file_map *map,
    const char *rel_path)
{
    if (map == NULL || map->count == 0 || rel_path == NULL) {
        return NULL;
    }
    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    bool exact_match = false;
    size_t idx = find_insert_index(map, norm, &exact_match);
    if (exact_match) {
        return &map->entries[idx];
    }
    return NULL;
}

const rome2_vfs_file_entry *rome2_vfs_file_map_find_w(
    const rome2_vfs_file_map *map,
    const wchar_t *rel_path)
{
    if (map == NULL || rel_path == NULL) {
        return NULL;
    }
    char utf8[ROME2_VFS_MAX_PATH];
    int res = WideCharToMultiByte(CP_UTF8, 0, rel_path, -1, utf8, sizeof(utf8), NULL, NULL);
    if (res <= 0) {
        return NULL;
    }
    return rome2_vfs_file_map_find_a(map, utf8);
}

bool rome2_vfs_file_map_remove_a(
    rome2_vfs_file_map *map,
    const char *rel_path)
{
    if (map == NULL || map->count == 0 || rel_path == NULL) {
        return false;
    }
    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    bool exact_match = false;
    size_t idx = find_insert_index(map, norm, &exact_match);
    if (!exact_match) {
        return false;
    }

    if (idx + 1 < map->count) {
        memmove(&map->entries[idx], &map->entries[idx + 1],
                (map->count - idx - 1) * sizeof(rome2_vfs_file_entry));
    }
    map->count--;
    return true;
}

bool rome2_vfs_file_map_remove_w(
    rome2_vfs_file_map *map,
    const wchar_t *rel_path)
{
    if (map == NULL || rel_path == NULL) {
        return false;
    }
    char utf8[ROME2_VFS_MAX_PATH];
    int res = WideCharToMultiByte(CP_UTF8, 0, rel_path, -1, utf8, sizeof(utf8), NULL, NULL);
    if (res <= 0) {
        return false;
    }
    return rome2_vfs_file_map_remove_a(map, utf8);
}

/* =========================================================================
 * 0x100e3360 Directory Scanner Implementation
 * ========================================================================= */

rome2_vfs_status rome2_port_100e3360_scan_directory_w(
    const wchar_t *base_directory,
    const wchar_t *current_rel_prefix,
    rome2_vfs_file_map *map)
{
    if (base_directory == NULL || map == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    wchar_t search_pattern[ROME2_VFS_MAX_PATH];
    swprintf_s(search_pattern, sizeof(search_pattern) / sizeof(wchar_t),
               L"%ls\\*", base_directory);

    WIN32_FIND_DATAW find_data;
    HANDLE hFind = FindFirstFileW(search_pattern, &find_data);
    if (hFind == INVALID_HANDLE_VALUE) {
        return ROME2_VFS_ERR_PATH_NOT_FOUND;
    }

    do {
        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Skip "." and ".." */
            if (wcscmp(find_data.cFileName, L".") == 0 ||
                wcscmp(find_data.cFileName, L"..") == 0) {
                continue;
            }

            /* Skip "encyclopedia" directory as in FUN_100e3360 line 233 */
            if (_wcsicmp(find_data.cFileName, L"encyclopedia") == 0) {
                continue;
            }

            /* Recurse into subdirectory */
            wchar_t sub_dir[ROME2_VFS_MAX_PATH];
            swprintf_s(sub_dir, sizeof(sub_dir) / sizeof(wchar_t),
                       L"%ls\\%ls", base_directory, find_data.cFileName);

            wchar_t sub_rel[ROME2_VFS_MAX_PATH];
            if (current_rel_prefix != NULL && current_rel_prefix[0] != L'\0') {
                swprintf_s(sub_rel, sizeof(sub_rel) / sizeof(wchar_t),
                           L"%ls/%ls", current_rel_prefix, find_data.cFileName);
            } else {
                swprintf_s(sub_rel, sizeof(sub_rel) / sizeof(wchar_t),
                           L"%ls", find_data.cFileName);
            }

            rome2_port_100e3360_scan_directory_w(sub_dir, sub_rel, map);
        } else {
            /* Regular file */
            wchar_t file_rel[ROME2_VFS_MAX_PATH];
            if (current_rel_prefix != NULL && current_rel_prefix[0] != L'\0') {
                swprintf_s(file_rel, sizeof(file_rel) / sizeof(wchar_t),
                           L"%ls/%ls", current_rel_prefix, find_data.cFileName);
            } else {
                swprintf_s(file_rel, sizeof(file_rel) / sizeof(wchar_t),
                           L"%ls", find_data.cFileName);
            }

            /* Check DLC blacklist filter */
            if (rome2_vfs_is_excluded_dlc_file_w(file_rel)) {
                continue;
            }

            /* Skip modified.log if generated in data directory */
            if (_wcsicmp(find_data.cFileName, L"modified.log") == 0) {
                continue;
            }

            uint64_t file_size = ((uint64_t)find_data.nFileSizeHigh << 32) |
                                 (uint64_t)find_data.nFileSizeLow;

            rome2_vfs_file_map_insert_w(map, file_rel, file_size);
        }
    } while (FindNextFileW(hFind, &find_data) != 0);

    FindClose(hFind);
    return ROME2_VFS_OK;
}

rome2_vfs_status rome2_port_100e3360_scan_directory_a(
    const char *base_directory,
    const char *current_rel_prefix,
    rome2_vfs_file_map *map)
{
    if (base_directory == NULL || map == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    wchar_t base_w[ROME2_VFS_MAX_PATH];
    wchar_t prefix_w[ROME2_VFS_MAX_PATH];

    MultiByteToWideChar(CP_UTF8, 0, base_directory, -1, base_w,
                        sizeof(base_w) / sizeof(wchar_t));

    if (current_rel_prefix != NULL && current_rel_prefix[0] != '\0') {
        MultiByteToWideChar(CP_UTF8, 0, current_rel_prefix, -1, prefix_w,
                            sizeof(prefix_w) / sizeof(wchar_t));
    } else {
        prefix_w[0] = L'\0';
    }

    return rome2_port_100e3360_scan_directory_w(base_w, prefix_w, map);
}

/* =========================================================================
 * 0x100e2980 Manifest Integrity Validator Implementation
 * ========================================================================= */

rome2_vfs_status rome2_port_100e2980_verify_manifest_w(
    const wchar_t *data_directory,
    const wchar_t *custom_log_path_or_null,
    rome2_vfs_manifest_report *report_out)
{
    if (data_directory == NULL || report_out == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    memset(report_out, 0, sizeof(*report_out));

    wchar_t log_path[ROME2_VFS_MAX_PATH];
    if (custom_log_path_or_null != NULL) {
        wcscpy_s(log_path, sizeof(log_path) / sizeof(wchar_t), custom_log_path_or_null);
    } else {
        swprintf_s(log_path, sizeof(log_path) / sizeof(wchar_t),
                   L"%ls\\modified.log", data_directory);
    }

    FILE *log_file = NULL;
    _wfopen_s(&log_file, log_path, L"w");

    wchar_t manifest_path[ROME2_VFS_MAX_PATH];
    swprintf_s(manifest_path, sizeof(manifest_path) / sizeof(wchar_t),
               L"%ls\\manifest.txt", data_directory);

    FILE *manifest_file = NULL;
    errno_t err = _wfopen_s(&manifest_file, manifest_path, L"r");
    if (err != 0 || manifest_file == NULL) {
        if (log_file != NULL) {
            fwprintf(log_file, L"Failed to open %ls\\manifest.txt for reading!\n", data_directory);
            fclose(log_file);
        }
        report_out->is_modified = true;
        return ROME2_VFS_ERR_OPEN_FAILED;
    }

    rome2_vfs_file_map disk_map;
    rome2_vfs_file_map_init(&disk_map);
    rome2_port_100e3360_scan_directory_w(data_directory, L"", &disk_map);

    char line_buf[1024];
    while (fgets(line_buf, sizeof(line_buf), manifest_file) != NULL) {
        /* Strip newline characters */
        size_t len = strlen(line_buf);
        while (len > 0 && (line_buf[len - 1] == '\r' || line_buf[len - 1] == '\n')) {
            line_buf[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }

        report_out->total_manifest_files++;

        /* Format is: <rel_path>\t<file_size> */
        char *tab_pos = strchr(line_buf, '\t');
        if (tab_pos == NULL) {
            continue;
        }
        *tab_pos = '\0';
        const char *rel_path = line_buf;
        const char *size_str = tab_pos + 1;
        uint64_t expected_size = _strtoui64(size_str, NULL, 10);

        const rome2_vfs_file_entry *entry = rome2_vfs_file_map_find_a(&disk_map, rel_path);
        if (entry == NULL) {
            if (log_file != NULL) {
                fprintf(log_file, "%s missing\n", rel_path);
            }
            report_out->missing_files++;
            report_out->is_modified = true;
        } else {
            if (entry->file_size != expected_size) {
                if (log_file != NULL) {
                    fprintf(log_file, "%s size mismatch\n", rel_path);
                }
                report_out->size_mismatch_files++;
                report_out->is_modified = true;
            } else {
                report_out->matched_files++;
            }
            rome2_vfs_file_map_remove_a(&disk_map, rel_path);
        }
    }

    fclose(manifest_file);

    /* Any remaining files in disk_map were not in manifest.txt */
    if (disk_map.count > 0) {
        for (size_t i = 0; i < disk_map.count; i++) {
            if (log_file != NULL) {
                fprintf(log_file, "%s unknown file\n", disk_map.entries[i].rel_path);
            }
            report_out->unknown_files++;
            report_out->is_modified = true;
        }
    }

    rome2_vfs_file_map_free(&disk_map);

    /* Check for user scripts (user.script.txt) */
    wchar_t script_check[ROME2_VFS_MAX_PATH];
    swprintf_s(script_check, sizeof(script_check) / sizeof(wchar_t),
               L"%ls\\user.script.txt", data_directory);
    DWORD attr = GetFileAttributesW(script_check);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if (log_file != NULL) {
            fprintf(log_file, "user.script.txt user script existing\n");
        }
        report_out->user_script_detected = true;
        report_out->is_modified = true;
    }

    if (log_file != NULL) {
        fclose(log_file);
    }

    return ROME2_VFS_OK;
}

rome2_vfs_status rome2_port_100e2980_verify_manifest_a(
    const char *data_directory,
    const char *custom_log_path_or_null,
    rome2_vfs_manifest_report *report_out)
{
    if (data_directory == NULL || report_out == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    wchar_t data_w[ROME2_VFS_MAX_PATH];
    wchar_t log_w[ROME2_VFS_MAX_PATH];

    MultiByteToWideChar(CP_UTF8, 0, data_directory, -1, data_w,
                        sizeof(data_w) / sizeof(wchar_t));

    if (custom_log_path_or_null != NULL) {
        MultiByteToWideChar(CP_UTF8, 0, custom_log_path_or_null, -1, log_w,
                            sizeof(log_w) / sizeof(wchar_t));
        return rome2_port_100e2980_verify_manifest_w(data_w, log_w, report_out);
    }

    return rome2_port_100e2980_verify_manifest_w(data_w, NULL, report_out);
}

/* =========================================================================
 * Packfile (PFH4/PFH5) Operations Implementation
 * ========================================================================= */

rome2_vfs_status rome2_packfile_open(
    rome2_packfile *pack,
    const char *path)
{
    if (pack == NULL || path == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    memset(pack, 0, sizeof(*pack));
    strncpy_s(pack->pack_path, sizeof(pack->pack_path), path, _TRUNCATE);

    errno_t err = fopen_s(&pack->handle, path, "rb");
    if (err != 0 || pack->handle == NULL) {
        return ROME2_VFS_ERR_OPEN_FAILED;
    }

    /* Read header bytes (24 bytes minimum for PFH4) */
    uint8_t hdr_bytes[28];
    size_t read_bytes = fread(hdr_bytes, 1, 24, pack->handle);
    if (read_bytes < 24) {
        fclose(pack->handle);
        pack->handle = NULL;
        return ROME2_VFS_ERR_CORRUPT_PACK;
    }

    memcpy(pack->header.magic, hdr_bytes, 4);
    if (memcmp(pack->header.magic, "PFH4", 4) != 0 &&
        memcmp(pack->header.magic, "PFH5", 4) != 0 &&
        memcmp(pack->header.magic, "PFH0", 4) != 0 &&
        memcmp(pack->header.magic, "PFH2", 4) != 0 &&
        memcmp(pack->header.magic, "PFH3", 4) != 0) {
        fclose(pack->handle);
        pack->handle = NULL;
        return ROME2_VFS_ERR_CORRUPT_PACK;
    }

    memcpy(&pack->header.pack_type, hdr_bytes + 4, 4);
    memcpy(&pack->header.dep_count, hdr_bytes + 8, 4);
    memcpy(&pack->header.dep_index_size, hdr_bytes + 12, 4);
    memcpy(&pack->header.file_count, hdr_bytes + 16, 4);
    memcpy(&pack->header.index_size, hdr_bytes + 20, 4);

    if (pack->header.file_count > ROME2_PACK_MAX_FILES) {
        fclose(pack->handle);
        pack->handle = NULL;
        return ROME2_VFS_ERR_CORRUPT_PACK;
    }

    if (pack->header.file_count == 0) {
        pack->files = NULL;
        pack->file_count = 0;
        return ROME2_VFS_OK;
    }

    /* Total War Rome II packs include a 4-byte header_timestamp at offset 24 */
    size_t index_read_size = pack->header.index_size;
    uint32_t timestamp = 0;
    if (fread(&timestamp, 1, 4, pack->handle) == 4) {
        pack->header.header_timestamp = timestamp;
    }

    uint8_t *index_buf = (uint8_t *)malloc(index_read_size);
    if (index_buf == NULL) {
        fclose(pack->handle);
        pack->handle = NULL;
        return ROME2_VFS_ERR_OUT_OF_MEMORY;
    }

    if (fread(index_buf, 1, index_read_size, pack->handle) != index_read_size) {
        free(index_buf);
        fclose(pack->handle);
        pack->handle = NULL;
        return ROME2_VFS_ERR_CORRUPT_PACK;
    }

    pack->files = (rome2_pack_file *)calloc(pack->header.file_count, sizeof(rome2_pack_file));
    if (pack->files == NULL) {
        free(index_buf);
        fclose(pack->handle);
        pack->handle = NULL;
        return ROME2_VFS_ERR_OUT_OF_MEMORY;
    }

    uint64_t data_start = 24 + 4 + index_read_size;
    uint64_t current_data_offset = data_start;
    size_t buf_pos = 0;

    for (uint32_t i = 0; i < pack->header.file_count; i++) {
        if (buf_pos + 4 > index_read_size) {
            free(index_buf);
            free(pack->files);
            pack->files = NULL;
            fclose(pack->handle);
            pack->handle = NULL;
            return ROME2_VFS_ERR_CORRUPT_PACK;
        }

        uint32_t file_size = 0;
        memcpy(&file_size, index_buf + buf_pos, 4);
        buf_pos += 4;

        /* Find null terminator */
        size_t str_start = buf_pos;
        while (buf_pos < index_read_size && index_buf[buf_pos] != '\0') {
            buf_pos++;
        }
        if (buf_pos >= index_read_size) {
            free(index_buf);
            free(pack->files);
            pack->files = NULL;
            fclose(pack->handle);
            pack->handle = NULL;
            return ROME2_VFS_ERR_CORRUPT_PACK;
        }

        const char *raw_name = (const char *)(index_buf + str_start);
        buf_pos++; /* skip null terminator */

        rome2_vfs_normalize_path_a(pack->files[i].path, sizeof(pack->files[i].path), raw_name);
        pack->files[i].file_size = file_size;
        pack->files[i].data_offset = current_data_offset;

        current_data_offset += file_size;
    }

    free(index_buf);
    pack->file_count = pack->header.file_count;
    return ROME2_VFS_OK;
}

void rome2_packfile_close(rome2_packfile *pack)
{
    if (pack == NULL) {
        return;
    }
    if (pack->handle != NULL) {
        fclose(pack->handle);
        pack->handle = NULL;
    }
    if (pack->files != NULL) {
        free(pack->files);
        pack->files = NULL;
    }
    pack->file_count = 0;
}

const rome2_pack_file *rome2_packfile_find(
    const rome2_packfile *pack,
    const char *rel_path)
{
    if (pack == NULL || pack->files == NULL || rel_path == NULL) {
        return NULL;
    }

    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    for (uint32_t i = 0; i < pack->file_count; i++) {
        if (_stricmp(pack->files[i].path, norm) == 0) {
            return &pack->files[i];
        }
    }
    return NULL;
}

rome2_vfs_status rome2_packfile_read_data(
    const rome2_packfile *pack,
    const rome2_pack_file *entry,
    void *buffer,
    size_t buffer_size,
    size_t *bytes_read_out)
{
    if (pack == NULL || pack->handle == NULL || entry == NULL || buffer == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    if (buffer_size < entry->file_size) {
        return ROME2_VFS_ERR_BUFFER_TOO_SMALL;
    }

    if (_fseeki64(pack->handle, (int64_t)entry->data_offset, SEEK_SET) != 0) {
        return ROME2_VFS_ERR_READ_FAILED;
    }

    size_t read_bytes = fread(buffer, 1, entry->file_size, pack->handle);
    if (read_bytes != entry->file_size) {
        return ROME2_VFS_ERR_READ_FAILED;
    }

    if (bytes_read_out != NULL) {
        *bytes_read_out = read_bytes;
    }
    return ROME2_VFS_OK;
}

/* =========================================================================
 * Unified VFS Aggregation Implementation
 * ========================================================================= */

rome2_vfs_status rome2_vfs_init(rome2_vfs *vfs)
{
    if (vfs == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }
    vfs->packs = NULL;
    vfs->pack_count = 0;
    vfs->pack_capacity = 0;
    vfs->loose_dirs = NULL;
    vfs->loose_dir_count = 0;
    vfs->loose_dir_capacity = 0;
    return ROME2_VFS_OK;
}

void rome2_vfs_free(rome2_vfs *vfs)
{
    if (vfs == NULL) {
        return;
    }

    if (vfs->packs != NULL) {
        for (size_t i = 0; i < vfs->pack_count; i++) {
            if (vfs->packs[i] != NULL) {
                rome2_packfile_close(vfs->packs[i]);
                free(vfs->packs[i]);
            }
        }
        free(vfs->packs);
        vfs->packs = NULL;
    }
    vfs->pack_count = 0;
    vfs->pack_capacity = 0;

    if (vfs->loose_dirs != NULL) {
        free(vfs->loose_dirs);
        vfs->loose_dirs = NULL;
    }
    vfs->loose_dir_count = 0;
    vfs->loose_dir_capacity = 0;
}

rome2_vfs_status rome2_vfs_mount_pack(
    rome2_vfs *vfs,
    const char *pack_path)
{
    if (vfs == NULL || pack_path == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    rome2_packfile *new_pack = (rome2_packfile *)malloc(sizeof(rome2_packfile));
    if (new_pack == NULL) {
        return ROME2_VFS_ERR_OUT_OF_MEMORY;
    }

    rome2_vfs_status status = rome2_packfile_open(new_pack, pack_path);
    if (status != ROME2_VFS_OK) {
        free(new_pack);
        return status;
    }

    if (vfs->pack_count >= vfs->pack_capacity) {
        size_t new_cap = (vfs->pack_capacity == 0) ? 8 : vfs->pack_capacity * 2;
        rome2_packfile **new_packs = (rome2_packfile **)realloc(
            vfs->packs, new_cap * sizeof(rome2_packfile *));
        if (new_packs == NULL) {
            rome2_packfile_close(new_pack);
            free(new_pack);
            return ROME2_VFS_ERR_OUT_OF_MEMORY;
        }
        vfs->packs = new_packs;
        vfs->pack_capacity = new_cap;
    }

    vfs->packs[vfs->pack_count++] = new_pack;
    return ROME2_VFS_OK;
}

rome2_vfs_status rome2_vfs_mount_loose_dir(
    rome2_vfs *vfs,
    const char *dir_path)
{
    if (vfs == NULL || dir_path == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    if (vfs->loose_dir_count >= vfs->loose_dir_capacity) {
        size_t new_cap = (vfs->loose_dir_capacity == 0) ? 4 : vfs->loose_dir_capacity * 2;
        typedef char path_buf[ROME2_VFS_MAX_PATH];
        path_buf *new_dirs = (path_buf *)realloc(vfs->loose_dirs, new_cap * sizeof(path_buf));
        if (new_dirs == NULL) {
            return ROME2_VFS_ERR_OUT_OF_MEMORY;
        }
        vfs->loose_dirs = new_dirs;
        vfs->loose_dir_capacity = new_cap;
    }

    strncpy_s(vfs->loose_dirs[vfs->loose_dir_count],
              sizeof(vfs->loose_dirs[vfs->loose_dir_count]),
              dir_path, _TRUNCATE);
    vfs->loose_dir_count++;
    return ROME2_VFS_OK;
}

bool rome2_vfs_file_exists(
    const rome2_vfs *vfs,
    const char *rel_path)
{
    if (vfs == NULL || rel_path == NULL) {
        return false;
    }

    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    /* 1. Check loose directories first */
    for (size_t i = 0; i < vfs->loose_dir_count; i++) {
        char full_path[ROME2_VFS_MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", vfs->loose_dirs[i], norm);
        DWORD attr = GetFileAttributesA(full_path);
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return true;
        }
    }

    /* 2. Check mounted packfiles (in reverse mount order: latest packs override) */
    if (vfs->pack_count > 0) {
        for (size_t i = vfs->pack_count; i > 0; i--) {
            const rome2_pack_file *entry = rome2_packfile_find(vfs->packs[i - 1], norm);
            if (entry != NULL) {
                return true;
            }
        }
    }

    return false;
}

rome2_vfs_status rome2_vfs_read_file(
    const rome2_vfs *vfs,
    const char *rel_path,
    void **data_out,
    size_t *size_out)
{
    if (vfs == NULL || rel_path == NULL || data_out == NULL || size_out == NULL) {
        return ROME2_VFS_ERR_INVALID_ARGUMENT;
    }

    *data_out = NULL;
    *size_out = 0;

    char norm[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm, sizeof(norm), rel_path);

    /* 1. Try loose directories first */
    for (size_t i = 0; i < vfs->loose_dir_count; i++) {
        char full_path[ROME2_VFS_MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", vfs->loose_dirs[i], norm);

        FILE *f = NULL;
        if (fopen_s(&f, full_path, "rb") == 0 && f != NULL) {
            _fseeki64(f, 0, SEEK_END);
            int64_t len = _ftelli64(f);
            _fseeki64(f, 0, SEEK_SET);

            if (len >= 0) {
                void *buf = malloc((size_t)len + 1);
                if (buf == NULL) {
                    fclose(f);
                    return ROME2_VFS_ERR_OUT_OF_MEMORY;
                }
                size_t read_bytes = fread(buf, 1, (size_t)len, f);
                fclose(f);
                ((char *)buf)[read_bytes] = '\0';
                *data_out = buf;
                *size_out = read_bytes;
                return ROME2_VFS_OK;
            }
            fclose(f);
        }
    }

    /* 2. Try mounted packfiles (in reverse mount order) */
    if (vfs->pack_count > 0) {
        for (size_t i = vfs->pack_count; i > 0; i--) {
            const rome2_pack_file *entry = rome2_packfile_find(vfs->packs[i - 1], norm);
            if (entry != NULL) {
                void *buf = malloc(entry->file_size + 1);
                if (buf == NULL) {
                    return ROME2_VFS_ERR_OUT_OF_MEMORY;
                }
                size_t bytes_read = 0;
                rome2_vfs_status st = rome2_packfile_read_data(
                    vfs->packs[i - 1], entry, buf, entry->file_size, &bytes_read);
                if (st == ROME2_VFS_OK) {
                    ((char *)buf)[bytes_read] = '\0';
                    *data_out = buf;
                    *size_out = bytes_read;
                    return ROME2_VFS_OK;
                }
                free(buf);
                return st;
            }
        }
    }

    return ROME2_VFS_ERR_PATH_NOT_FOUND;
}
