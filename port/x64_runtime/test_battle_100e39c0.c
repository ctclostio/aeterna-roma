#include "ported_100e39c0_battle.h"
#include "ported_100e3360_vfs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_battle_lifecycle(void)
{
    printf("[TEST] test_battle_lifecycle... ");

    rome2_battle_context ctx;
    rome2_battle_status status = rome2_battle_context_init(&ctx);
    assert(status == ROME2_BATTLE_OK);
    assert(ctx.initialized);
    assert(!ctx.blm_loaded);
    assert(strcmp(ctx.attacker_faction, "rom_rome") == 0);
    assert(strcmp(ctx.defender_faction, "rom_ptolemaics") == 0);
    assert(strcmp(ctx.culture, "rom_Roman") == 0);
    assert(strcmp(ctx.subculture, "sc_rom_roman") == 0);
    assert(strcmp(ctx.road_material, "road") == 0);
    assert(strcmp(ctx.battle_map_path, "terrain/battles/main_rome_map/locations.blm") == 0);

    rome2_battle_context_cleanup(&ctx);
    assert(!ctx.initialized);

    printf("PASS\n");
}

static void test_blm_parsing_synthetic(void)
{
    printf("[TEST] test_blm_parsing_synthetic... ");

    /* Construct synthetic BLM buffer */
    uint8_t synth_blm[512];
    memset(synth_blm, 0, sizeof(synth_blm));

    /* Magic 'BLMF' (42 4c 4d 46) */
    synth_blm[0] = 'B';
    synth_blm[1] = 'L';
    synth_blm[2] = 'M';
    synth_blm[3] = 'F';

    /* Version: 7 */
    synth_blm[4] = 7;
    /* Layers: 2 */
    synth_blm[8] = 2;
    /* Width: 2000 */
    synth_blm[12] = (uint8_t)(2000 & 0xff);
    synth_blm[13] = (uint8_t)(2000 >> 8);
    /* Height: 1000 */
    synth_blm[16] = (uint8_t)(1000 & 0xff);
    synth_blm[17] = (uint8_t)(1000 >> 8);

    size_t off = 20;

    /* Layer 0: "unfortified_port" (len=16), 1 entry (36 bytes) */
    synth_blm[off] = 16;
    synth_blm[off + 1] = 0;
    off += 2;
    memcpy(&synth_blm[off], "unfortified_port", 16);
    off += 16;
    synth_blm[off] = 1; /* 1 entry */
    synth_blm[off + 1] = 0;
    synth_blm[off + 2] = 0;
    synth_blm[off + 3] = 0;
    off += 4;

    /* Entry 0: min_x=100, min_y=200, max_x=120, max_y=220, center_x=110, center_y=210, settlement_id=42 */
    uint32_t *entry_words = (uint32_t *)&synth_blm[off];
    entry_words[0] = 100;
    entry_words[1] = 200;
    entry_words[2] = 120;
    entry_words[3] = 220;
    entry_words[4] = 110;
    entry_words[5] = 210;
    entry_words[6] = 42;
    entry_words[7] = 1;
    entry_words[8] = 0;
    off += 36;

    /* Layer 1: "settlement_standard" (len=19), 1 entry */
    synth_blm[off] = 19;
    synth_blm[off + 1] = 0;
    off += 2;
    memcpy(&synth_blm[off], "settlement_standard", 19);
    off += 19;
    synth_blm[off] = 1;
    synth_blm[off + 1] = 0;
    synth_blm[off + 2] = 0;
    synth_blm[off + 3] = 0;
    off += 4;

    entry_words = (uint32_t *)&synth_blm[off];
    entry_words[0] = 500;
    entry_words[1] = 600;
    entry_words[2] = 520;
    entry_words[3] = 620;
    entry_words[4] = 510;
    entry_words[5] = 610;
    entry_words[6] = 99;
    entry_words[7] = 2;
    entry_words[8] = 0;
    off += 36;

    rome2_blm_map map;
    rome2_battle_status status = rome2_blm_parse(synth_blm, off, &map);
    assert(status == ROME2_BATTLE_OK);
    assert(map.magic == ROME2_BLM_MAGIC);
    assert(map.version == 7);
    assert(map.layer_count == 2);
    assert(map.width == 2000);
    assert(map.height == 1000);

    const rome2_blm_layer *l0 = rome2_blm_find_layer(&map, "unfortified_port");
    assert(l0 != NULL);
    assert(l0->entry_count == 1);
    assert(l0->entries[0].center_x == 110);
    assert(l0->entries[0].center_y == 210);
    assert(l0->entries[0].settlement_id == 42);

    const rome2_blm_layer *l1 = rome2_blm_find_layer(&map, "settlement_standard");
    assert(l1 != NULL);
    assert(l1->entry_count == 1);
    assert(l1->entries[0].center_x == 510);
    assert(l1->entries[0].center_y == 610);
    assert(l1->entries[0].settlement_id == 99);

    rome2_blm_free(&map);

    /* Invalid magic check */
    synth_blm[0] = 'X';
    status = rome2_blm_parse(synth_blm, off, &map);
    assert(status == ROME2_BATTLE_ERR_INVALID_MAGIC);

    printf("PASS\n");
}

static void test_battle_benchmark_synthetic(void)
{
    printf("[TEST] test_battle_benchmark_synthetic... ");

    rome2_battle_context ctx;
    rome2_battle_status status = rome2_battle_context_init(&ctx);
    assert(status == ROME2_BATTLE_OK);

    /* Construct synthetic map with 3 settlements */
    ctx.map.magic = ROME2_BLM_MAGIC;
    ctx.map.version = 7;
    ctx.map.layer_count = 1;
    ctx.map.width = 2000;
    ctx.map.height = 1000;

    strncpy_s(ctx.map.layers[0].name, sizeof(ctx.map.layers[0].name), "settlement_standard", _TRUNCATE);
    ctx.map.layers[0].entry_count = 3;
    ctx.map.layers[0].entries = (rome2_blm_entry *)malloc(3 * sizeof(rome2_blm_entry));
    assert(ctx.map.layers[0].entries != NULL);

    for (uint32_t i = 0; i < 3; ++i) {
        ctx.map.layers[0].entries[i].center_x = (i + 1) * 400;
        ctx.map.layers[0].entries[i].center_y = (i + 1) * 200;
        ctx.map.layers[0].entries[i].settlement_id = (int32_t)i;
    }

    ctx.total_settlements = 3;
    ctx.blm_loaded = true;

    char log_buf[256];
    /* Test arg 4: 4 % 3 = 1 */
    status = rome2_battle_run_settlement_benchmark(&ctx, 4, log_buf, sizeof(log_buf));
    assert(status == ROME2_BATTLE_OK);
    assert(ctx.tested_settlement_index == 1);
    assert(strcmp(log_buf, "Settlement battle test 1/3\n") == 0);
    assert(ctx.selected_pos_x > 0.39f && ctx.selected_pos_x < 0.41f); /* 800 / 2000 = 0.4 */
    assert(ctx.selected_pos_y > 0.39f && ctx.selected_pos_y < 0.41f); /* 400 / 1000 = 0.4 */

    rome2_battle_context_cleanup(&ctx);
    printf("PASS\n");
}

static void test_live_retail_blm_packfile_loading(void)
{
    printf("[TEST] test_live_retail_blm_packfile_loading... ");

    const char *pack_path = "Total War Rome II/data/terrain2_rome2.pack";
    FILE *test_fp = NULL;
    if (fopen_s(&test_fp, pack_path, "rb") != 0 || test_fp == NULL) {
        printf("SKIPPED (terrain2_rome2.pack not found)\n");
        return;
    }
    fclose(test_fp);

    rome2_vfs vfs;
    rome2_vfs_status vfs_status = rome2_vfs_init(&vfs);
    assert(vfs_status == ROME2_VFS_OK);

    vfs_status = rome2_vfs_mount_pack(&vfs, pack_path);
    assert(vfs_status == ROME2_VFS_OK);

    rome2_battle_context ctx;
    rome2_battle_status status = rome2_battle_context_init(&ctx);
    assert(status == ROME2_BATTLE_OK);

    /* Load BLM via VFS from packfile */
    status = rome2_battle_context_load_from_vfs(
        &ctx, &vfs, "terrain/battles/main_rome_map/locations.blm");
    assert(status == ROME2_BATTLE_OK);
    assert(ctx.blm_loaded);
    assert(ctx.map.magic == ROME2_BLM_MAGIC);
    assert(ctx.map.version == 7);
    assert(ctx.map.layer_count == 9);
    assert(ctx.map.width == 2032);
    assert(ctx.map.height == 1437);

    /* Verify layer names and counts */
    const rome2_blm_layer *port_l = rome2_blm_find_layer(&ctx.map, "unfortified_port");
    assert(port_l != NULL);
    assert(port_l->entry_count == 48);

    const rome2_blm_layer *std_settle = rome2_blm_find_layer(&ctx.map, "settlement_standard");
    assert(std_settle != NULL);
    assert(std_settle->entry_count == 56);

    const rome2_blm_layer *ambush_l = rome2_blm_find_layer(&ctx.map, "land_ambush");
    assert(ambush_l != NULL);
    assert(ambush_l->entry_count == 16252);

    /* Run settlement benchmark across 10 iterations */
    char bench_log[256];
    for (uint32_t i = 0; i < 10; ++i) {
        status = rome2_battle_run_settlement_benchmark(&ctx, i, bench_log, sizeof(bench_log));
        assert(status == ROME2_BATTLE_OK);
        assert(strstr(bench_log, "Settlement battle test") != NULL);
        assert(ctx.selected_pos_x >= 0.0f && ctx.selected_pos_x <= 1.0f);
        assert(ctx.selected_pos_y >= 0.0f && ctx.selected_pos_y <= 1.0f);
    }

    rome2_battle_context_cleanup(&ctx);
    rome2_vfs_free(&vfs);

    printf("PASS\n");
}

int main(void)
{
    printf("=== Starting Subsystem 3.2 (Battle Map & Benchmark Loader) Tests ===\n");
    test_battle_lifecycle();
    test_blm_parsing_synthetic();
    test_battle_benchmark_synthetic();
    test_live_retail_blm_packfile_loading();
    printf("=== All Subsystem 3.2 Tests PASSED ===\n");
    return 0;
}
