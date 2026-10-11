#include "ported_100e3360_vfs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static void test_path_normalization(void)
{
    printf("[TEST] test_path_normalization... ");

    char norm_a[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_a(norm_a, sizeof(norm_a), ".\\data\\ui\\cursor.png");
    assert(strcmp(norm_a, "data/ui/cursor.png") == 0);

    rome2_vfs_normalize_path_a(norm_a, sizeof(norm_a), "campaigns\\main_gaul\\startpos.esf");
    assert(strcmp(norm_a, "campaigns/main_gaul/startpos.esf") == 0);

    wchar_t norm_w[ROME2_VFS_MAX_PATH];
    rome2_vfs_normalize_path_w(norm_w, sizeof(norm_w) / sizeof(wchar_t), L"/retail\\data/sound.pack");
    assert(wcscmp(norm_w, L"retail/data/sound.pack") == 0);

    printf("PASS\n");
}

static void test_dlc_exclusions(void)
{
    printf("[TEST] test_dlc_exclusions... ");

    /* All 10 DLC items must be recognized */
    assert(rome2_vfs_is_excluded_dlc_file_a("manifest.txt"));
    assert(rome2_vfs_is_excluded_dlc_file_a("nomadic.pack"));
    assert(rome2_vfs_is_excluded_dlc_file_a("gaul.pack"));
    assert(rome2_vfs_is_excluded_dlc_file_a("campaigns\\main_gaul\\startpos.esf"));
    assert(rome2_vfs_is_excluded_dlc_file_a("campaigns/main_gaul/startpos.esf"));
    assert(rome2_vfs_is_excluded_dlc_file_a("punic.pack"));
    assert(rome2_vfs_is_excluded_dlc_file_a("campaigns\\main_punic\\startpos.esf"));
    assert(rome2_vfs_is_excluded_dlc_file_a("greeks.pack"));
    assert(rome2_vfs_is_excluded_dlc_file_a("campaigns/main_greek/startpos.esf"));
    assert(rome2_vfs_is_excluded_dlc_file_a("blood.pack"));
    assert(rome2_vfs_is_excluded_dlc_file_a("blood_rome2.pack"));

    /* Wide versions */
    assert(rome2_vfs_is_excluded_dlc_file_w(L"manifest.txt"));
    assert(rome2_vfs_is_excluded_dlc_file_w(L"nomadic.pack"));
    assert(rome2_vfs_is_excluded_dlc_file_w(L"campaigns\\main_gaul\\startpos.esf"));
    assert(rome2_vfs_is_excluded_dlc_file_w(L"blood_rome2.pack"));

    /* Base game files must NOT be excluded */
    assert(!rome2_vfs_is_excluded_dlc_file_a("data.pack"));
    assert(!rome2_vfs_is_excluded_dlc_file_a("boot.pack"));
    assert(!rome2_vfs_is_excluded_dlc_file_a("sound.pack"));
    assert(!rome2_vfs_is_excluded_dlc_file_a("ui/cursors/ping0009.cur"));

    printf("PASS\n");
}

static void test_file_map_operations(void)
{
    printf("[TEST] test_file_map_operations... ");

    rome2_vfs_file_map map;
    rome2_vfs_status st = rome2_vfs_file_map_init(&map);
    assert(st == ROME2_VFS_OK);
    assert(map.count == 0);

    /* Insert entries in arbitrary order */
    assert(rome2_vfs_file_map_insert_a(&map, "sound.pack", 290617014) == ROME2_VFS_OK);
    assert(rome2_vfs_file_map_insert_a(&map, "data.pack", 512039065) == ROME2_VFS_OK);
    assert(rome2_vfs_file_map_insert_a(&map, "boot.pack", 12345) == ROME2_VFS_OK);
    assert(rome2_vfs_file_map_insert_w(&map, L"ui/cursors/ping0009.cur", 9662) == ROME2_VFS_OK);
    assert(map.count == 4);

    /* Verify sorted order invariant */
    for (size_t i = 1; i < map.count; i++) {
        assert(_stricmp(map.entries[i - 1].rel_path, map.entries[i].rel_path) < 0);
    }

    /* Lookup existing entries */
    const rome2_vfs_file_entry *e1 = rome2_vfs_file_map_find_a(&map, "data.pack");
    assert(e1 != NULL && e1->file_size == 512039065);

    const rome2_vfs_file_entry *e2 = rome2_vfs_file_map_find_a(&map, "DATA.PACK");
    assert(e2 != NULL && e2->file_size == 512039065);

    const rome2_vfs_file_entry *e3 = rome2_vfs_file_map_find_w(&map, L"ui\\cursors\\ping0009.cur");
    assert(e3 != NULL && e3->file_size == 9662);

    /* Lookup non-existent entry */
    assert(rome2_vfs_file_map_find_a(&map, "nonexistent.pack") == NULL);

    /* Remove entry */
    assert(rome2_vfs_file_map_remove_a(&map, "boot.pack"));
    assert(map.count == 3);
    assert(rome2_vfs_file_map_find_a(&map, "boot.pack") == NULL);
    assert(!rome2_vfs_file_map_remove_a(&map, "boot.pack"));

    rome2_vfs_file_map_free(&map);
    assert(map.entries == NULL && map.count == 0);

    printf("PASS\n");
}

static void create_test_file(const char *path, const char *content)
{
    FILE *f = NULL;
    fopen_s(&f, path, "wb");
    if (f != NULL) {
        if (content != NULL) {
            fwrite(content, 1, strlen(content), f);
        }
        fclose(f);
    }
}

static void test_directory_scan_and_manifest(void)
{
    printf("[TEST] test_directory_scan_and_manifest... ");

    /* Create temporary sandbox directory structure */
    char temp_dir[MAX_PATH];
    GetTempPathA(sizeof(temp_dir), temp_dir);
    strcat_s(temp_dir, sizeof(temp_dir), "rome2_vfs_test_data");

    /* Remove any leftover files from previous runs */
    char leftover[MAX_PATH];
    snprintf(leftover, sizeof(leftover), "%s/manifest.txt", temp_dir);
    DeleteFileA(leftover);
    snprintf(leftover, sizeof(leftover), "%s/modified.log", temp_dir);
    DeleteFileA(leftover);
    snprintf(leftover, sizeof(leftover), "%s/data.pack", temp_dir);
    DeleteFileA(leftover);
    snprintf(leftover, sizeof(leftover), "%s/sound.pack", temp_dir);
    DeleteFileA(leftover);
    snprintf(leftover, sizeof(leftover), "%s/ui/cursor.png", temp_dir);
    DeleteFileA(leftover);
    snprintf(leftover, sizeof(leftover), "%s/encyclopedia/index.html", temp_dir);
    DeleteFileA(leftover);
    snprintf(leftover, sizeof(leftover), "%s/nomadic.pack", temp_dir);
    DeleteFileA(leftover);

    CreateDirectoryA(temp_dir, NULL);

    char sub_ui[MAX_PATH];
    snprintf(sub_ui, sizeof(sub_ui), "%s/ui", temp_dir);
    CreateDirectoryA(sub_ui, NULL);

    char sub_enc[MAX_PATH];
    snprintf(sub_enc, sizeof(sub_enc), "%s/encyclopedia", temp_dir);
    CreateDirectoryA(sub_enc, NULL);

    /* Create files */
    char file1[MAX_PATH], file2[MAX_PATH], file3[MAX_PATH], file_enc[MAX_PATH], file_dlc[MAX_PATH];
    snprintf(file1, sizeof(file1), "%s/data.pack", temp_dir);
    snprintf(file2, sizeof(file2), "%s/sound.pack", temp_dir);
    snprintf(file3, sizeof(file3), "%s/ui/cursor.png", temp_dir);
    snprintf(file_enc, sizeof(file_enc), "%s/encyclopedia/index.html", temp_dir);
    snprintf(file_dlc, sizeof(file_dlc), "%s/nomadic.pack", temp_dir);

    create_test_file(file1, "DATA_PACK_CONTENT");         /* 17 bytes */
    create_test_file(file2, "SOUND_PACK_CONTENT_123");     /* 21 bytes */
    create_test_file(file3, "PNG_IMAGE_BYTES");            /* 15 bytes */
    create_test_file(file_enc, "ENCYCLOPEDIA_CONTENT");
    create_test_file(file_dlc, "NOMADIC_DLC_PACK");

    /* 1. Test directory scanner */
    rome2_vfs_file_map scanned_map;
    rome2_vfs_file_map_init(&scanned_map);
    rome2_vfs_status st = rome2_port_100e3360_scan_directory_a(temp_dir, "", &scanned_map);
    assert(st == ROME2_VFS_OK);

    /* Should contain: data.pack (17), sound.pack (21), ui/cursor.png (15) */
    /* Must NOT contain: encyclopedia/index.html (skipped) or nomadic.pack (DLC exclusion) */
    assert(scanned_map.count == 3);
    assert(rome2_vfs_file_map_find_a(&scanned_map, "data.pack") != NULL);
    assert(rome2_vfs_file_map_find_a(&scanned_map, "sound.pack") != NULL);
    assert(rome2_vfs_file_map_find_a(&scanned_map, "ui/cursor.png") != NULL);
    assert(rome2_vfs_file_map_find_a(&scanned_map, "nomadic.pack") == NULL);
    assert(rome2_vfs_file_map_find_a(&scanned_map, "encyclopedia/index.html") == NULL);

    rome2_vfs_file_map_free(&scanned_map);

    /* 2. Test manifest verification with valid manifest */
    char manifest_file[MAX_PATH];
    snprintf(manifest_file, sizeof(manifest_file), "%s/manifest.txt", temp_dir);
    create_test_file(manifest_file,
                     "data.pack\t17\n"
                     "sound.pack\t22\n"
                     "ui/cursor.png\t15\n");

    rome2_vfs_manifest_report report;
    st = rome2_port_100e2980_verify_manifest_a(temp_dir, NULL, &report);
    assert(st == ROME2_VFS_OK);
    assert(report.total_manifest_files == 3);
    assert(report.matched_files == 3);
    assert(report.missing_files == 0);
    assert(report.size_mismatch_files == 0);
    assert(report.unknown_files == 0);
    assert(!report.is_modified);

    /* 3. Test manifest verification with size mismatch */
    create_test_file(manifest_file,
                     "data.pack\t17\n"
                     "sound.pack\t9999\n"  /* Mismatch! Actual is 22 */
                     "ui/cursor.png\t15\n");
    memset(&report, 0, sizeof(report));
    st = rome2_port_100e2980_verify_manifest_a(temp_dir, NULL, &report);
    assert(st == ROME2_VFS_OK);
    assert(report.matched_files == 2);
    assert(report.size_mismatch_files == 1);
    assert(report.is_modified);

    /* 4. Test manifest verification with missing file */
    create_test_file(manifest_file,
                     "data.pack\t17\n"
                     "sound.pack\t22\n"
                     "ui/cursor.png\t15\n"
                     "missing_texture.dds\t12345\n");  /* Missing on disk! */
    memset(&report, 0, sizeof(report));
    st = rome2_port_100e2980_verify_manifest_a(temp_dir, NULL, &report);
    assert(st == ROME2_VFS_OK);
    assert(report.matched_files == 3);
    assert(report.missing_files == 1);
    assert(report.is_modified);

    /* 5. Test manifest verification with unknown file */
    create_test_file(manifest_file,
                     "data.pack\t17\n");  /* Missing sound.pack and ui/cursor.png */
    memset(&report, 0, sizeof(report));
    st = rome2_port_100e2980_verify_manifest_a(temp_dir, NULL, &report);
    assert(st == ROME2_VFS_OK);
    assert(report.matched_files == 1);
    assert(report.unknown_files == 2);
    assert(report.is_modified);

    /* Cleanup temp files */
    DeleteFileA(file1);
    DeleteFileA(file2);
    DeleteFileA(file3);
    DeleteFileA(file_enc);
    DeleteFileA(file_dlc);
    DeleteFileA(manifest_file);
    char log_file[MAX_PATH];
    snprintf(log_file, sizeof(log_file), "%s/modified.log", temp_dir);
    DeleteFileA(log_file);
    RemoveDirectoryA(sub_ui);
    RemoveDirectoryA(sub_enc);
    RemoveDirectoryA(temp_dir);

    printf("PASS\n");
}

static void test_packfile_reader_live(void)
{
    printf("[TEST] test_packfile_reader_live... ");

    const char *pack_path = "Total War Rome II\\data\\divided.pack";
    DWORD attr = GetFileAttributesA(pack_path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("SKIPPED (divided.pack not found)\n");
        return;
    }

    rome2_packfile pack;
    rome2_vfs_status st = rome2_packfile_open(&pack, pack_path);
    assert(st == ROME2_VFS_OK);
    assert(memcmp(pack.header.magic, "PFH4", 4) == 0);
    assert(pack.header.pack_type == 1);
    assert(pack.file_count == 23);

    /* Lookup known entry inside divided.pack */
    const rome2_pack_file *entry = rome2_packfile_find(&pack, "campaigns/main_3c/3c_start.lua");
    assert(entry != NULL);
    assert(entry->file_size == 1431);

    /* Read packed file data */
    char *buf = (char *)malloc(entry->file_size + 1);
    assert(buf != NULL);

    size_t bytes_read = 0;
    st = rome2_packfile_read_data(&pack, entry, buf, entry->file_size, &bytes_read);
    assert(st == ROME2_VFS_OK);
    assert(bytes_read == 1431);
    buf[bytes_read] = '\0';

    /* Verify content contains Lua code */
    assert(strstr(buf, "campaigns") != NULL || strstr(buf, "3c") != NULL || strstr(buf, "function") != NULL || strstr(buf, "--") != NULL);

    free(buf);
    rome2_packfile_close(&pack);

    printf("PASS\n");
}

static void test_unified_vfs_overlay(void)
{
    printf("[TEST] test_unified_vfs_overlay... ");

    rome2_vfs vfs;
    assert(rome2_vfs_init(&vfs) == ROME2_VFS_OK);

    const char *pack_path = "Total War Rome II\\data\\divided.pack";
    DWORD attr = GetFileAttributesA(pack_path);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        assert(rome2_vfs_mount_pack(&vfs, pack_path) == ROME2_VFS_OK);
        assert(rome2_vfs_file_exists(&vfs, "campaigns\\main_3c\\3c_start.lua"));

        void *data = NULL;
        size_t size = 0;
        assert(rome2_vfs_read_file(&vfs, "campaigns/main_3c/3c_start.lua", &data, &size) == ROME2_VFS_OK);
        assert(data != NULL && size == 1431);
        free(data);
    }

    rome2_vfs_free(&vfs);
    printf("PASS\n");
}

int main(void)
{
    printf("====================================================\n");
    printf(" Rome II Subsystem 2.1 (VFS & Packfile) Test Suite\n");
    printf("====================================================\n");

    test_path_normalization();
    test_dlc_exclusions();
    test_file_map_operations();
    test_directory_scan_and_manifest();
    test_packfile_reader_live();
    test_unified_vfs_overlay();

    printf("\n>>> ALL SUBSYSTEM 2.1 TESTS PASSED SUCCESSFULLY! <<<\n");
    return 0;
}
