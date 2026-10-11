#ifndef ROME2_PORTED_100E3360_VFS_H
#define ROME2_PORTED_100E3360_VFS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_100E3360_SCAN_ENTRY_PC       UINT32_C(0x100e3360)
#define ROME2_PORT_100E2980_VALIDATE_ENTRY_PC   UINT32_C(0x100e2980)

#define ROME2_VFS_DLC_EXCLUSION_COUNT           10U
#define ROME2_VFS_MAX_PATH                      512U
#define ROME2_PACK_MAX_FILES                    65536U

/*
 * The 10 DLC and special items excluded from base game manifest indexing
 * in FUN_100e3360:
 *   1. manifest.txt
 *   2. nomadic.pack
 *   3. gaul.pack
 *   4. campaigns/main_gaul/startpos.esf
 *   5. punic.pack
 *   6. campaigns/main_punic/startpos.esf
 *   7. greeks.pack
 *   8. campaigns/main_greek/startpos.esf
 *   9. blood.pack
 *  10. blood_rome2.pack
 */
extern const char *const g_rome2_vfs_dlc_exclusions_a[ROME2_VFS_DLC_EXCLUSION_COUNT];
extern const wchar_t *const g_rome2_vfs_dlc_exclusions_w[ROME2_VFS_DLC_EXCLUSION_COUNT];

typedef enum rome2_vfs_status {
    ROME2_VFS_OK = 0,
    ROME2_VFS_ERR_INVALID_ARGUMENT = 1,
    ROME2_VFS_ERR_PATH_NOT_FOUND = 2,
    ROME2_VFS_ERR_OPEN_FAILED = 3,
    ROME2_VFS_ERR_CORRUPT_PACK = 4,
    ROME2_VFS_ERR_OUT_OF_MEMORY = 5,
    ROME2_VFS_ERR_READ_FAILED = 6,
    ROME2_VFS_ERR_BUFFER_TOO_SMALL = 7
} rome2_vfs_status;

/*
 * Normalized in-memory VFS file entry
 */
typedef struct rome2_vfs_file_entry {
    char rel_path[ROME2_VFS_MAX_PATH];
    uint64_t file_size;
} rome2_vfs_file_entry;

/*
 * Dynamic map representing the std::map<wstring, uint64_t> in FUN_100e3360
 */
typedef struct rome2_vfs_file_map {
    rome2_vfs_file_entry *entries;
    size_t count;
    size_t capacity;
} rome2_vfs_file_map;

/*
 * Report of manifest verification against disk in FUN_100e2980
 */
typedef struct rome2_vfs_manifest_report {
    uint32_t total_manifest_files;
    uint32_t matched_files;
    uint32_t missing_files;
    uint32_t size_mismatch_files;
    uint32_t unknown_files;
    bool user_script_detected;
    bool is_modified;
} rome2_vfs_manifest_report;

/*
 * Total War Rome II Packfile (PFH4/PFH5) Header
 */
typedef struct rome2_pack_header {
    char magic[4];                   /* "PFH4" or "PFH5" */
    uint32_t pack_type;              /* bitmask: 0=boot, 1=release, 2=patch, 3=mod, 4=movie */
    uint32_t dep_count;              /* dependency pack count */
    uint32_t dep_index_size;         /* dependency pack index byte size */
    uint32_t file_count;             /* number of files contained */
    uint32_t index_size;             /* byte size of file index block */
    uint32_t header_timestamp;       /* pack build timestamp (if present in header) */
} rome2_pack_header;

/*
 * Index entry for a packed file
 */
typedef struct rome2_pack_file {
    char path[ROME2_VFS_MAX_PATH];
    uint32_t file_size;
    uint64_t data_offset;            /* absolute byte offset within pack file */
} rome2_pack_file;

/*
 * In-memory handle to an opened Total War packfile
 */
typedef struct rome2_packfile {
    char pack_path[ROME2_VFS_MAX_PATH];
    rome2_pack_header header;
    rome2_pack_file *files;
    uint32_t file_count;
    FILE *handle;
} rome2_packfile;

/*
 * Virtual File System aggregating multiple mounted packfiles and loose directories
 */
typedef struct rome2_vfs {
    rome2_packfile **packs;
    size_t pack_count;
    size_t pack_capacity;

    char (*loose_dirs)[ROME2_VFS_MAX_PATH];
    size_t loose_dir_count;
    size_t loose_dir_capacity;
} rome2_vfs;

/* =========================================================================
 * Path Normalization & Exclusion Check
 * ========================================================================= */
void rome2_vfs_normalize_path_a(char *dest, size_t dest_size, const char *src);
void rome2_vfs_normalize_path_w(wchar_t *dest, size_t dest_size, const wchar_t *src);

bool rome2_vfs_is_excluded_dlc_file_a(const char *rel_path);
bool rome2_vfs_is_excluded_dlc_file_w(const wchar_t *rel_path);

/* =========================================================================
 * VFS File Map Operations (replaces std::map<wstring, uint64_t>)
 * ========================================================================= */
rome2_vfs_status rome2_vfs_file_map_init(rome2_vfs_file_map *map);
void rome2_vfs_file_map_free(rome2_vfs_file_map *map);
void rome2_vfs_file_map_clear(rome2_vfs_file_map *map);

rome2_vfs_status rome2_vfs_file_map_insert_a(
    rome2_vfs_file_map *map,
    const char *rel_path,
    uint64_t file_size);

rome2_vfs_status rome2_vfs_file_map_insert_w(
    rome2_vfs_file_map *map,
    const wchar_t *rel_path,
    uint64_t file_size);

const rome2_vfs_file_entry *rome2_vfs_file_map_find_a(
    const rome2_vfs_file_map *map,
    const char *rel_path);

const rome2_vfs_file_entry *rome2_vfs_file_map_find_w(
    const rome2_vfs_file_map *map,
    const wchar_t *rel_path);

bool rome2_vfs_file_map_remove_a(
    rome2_vfs_file_map *map,
    const char *rel_path);

bool rome2_vfs_file_map_remove_w(
    rome2_vfs_file_map *map,
    const wchar_t *rel_path);

/* =========================================================================
 * 0x100e3360 Directory Scanner & 0x100e2980 Manifest Verifier
 * ========================================================================= */
rome2_vfs_status rome2_port_100e3360_scan_directory_w(
    const wchar_t *base_directory,
    const wchar_t *current_rel_prefix,
    rome2_vfs_file_map *map);

rome2_vfs_status rome2_port_100e3360_scan_directory_a(
    const char *base_directory,
    const char *current_rel_prefix,
    rome2_vfs_file_map *map);

rome2_vfs_status rome2_port_100e2980_verify_manifest_w(
    const wchar_t *data_directory,
    const wchar_t *custom_log_path_or_null,
    rome2_vfs_manifest_report *report_out);

rome2_vfs_status rome2_port_100e2980_verify_manifest_a(
    const char *data_directory,
    const char *custom_log_path_or_null,
    rome2_vfs_manifest_report *report_out);

/* =========================================================================
 * Packfile (PFH4/PFH5) Operations
 * ========================================================================= */
rome2_vfs_status rome2_packfile_open(
    rome2_packfile *pack,
    const char *path);

void rome2_packfile_close(
    rome2_packfile *pack);

const rome2_pack_file *rome2_packfile_find(
    const rome2_packfile *pack,
    const char *rel_path);

rome2_vfs_status rome2_packfile_read_data(
    const rome2_packfile *pack,
    const rome2_pack_file *entry,
    void *buffer,
    size_t buffer_size,
    size_t *bytes_read_out);

/* =========================================================================
 * Unified VFS Aggregation
 * ========================================================================= */
rome2_vfs_status rome2_vfs_init(rome2_vfs *vfs);
void rome2_vfs_free(rome2_vfs *vfs);

rome2_vfs_status rome2_vfs_mount_pack(
    rome2_vfs *vfs,
    const char *pack_path);

rome2_vfs_status rome2_vfs_mount_loose_dir(
    rome2_vfs *vfs,
    const char *dir_path);

bool rome2_vfs_file_exists(
    const rome2_vfs *vfs,
    const char *rel_path);

rome2_vfs_status rome2_vfs_read_file(
    const rome2_vfs *vfs,
    const char *rel_path,
    void **data_out,
    size_t *size_out);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_100E3360_VFS_H */
