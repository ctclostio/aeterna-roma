#include "ported_106ba2e0_campaign.h"
#include "ported_100e3360_vfs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_campaign_env_lifecycle(void)
{
    printf("[TEST] test_campaign_env_lifecycle... ");

    rome2_campaign_env env;
    rome2_campaign_status status = rome2_campaign_env_init(&env, "main_rome");
    assert(status == ROME2_CAMPAIGN_OK);
    assert(env.initialized);
    assert(strcmp(env.campaign_name, "main_rome") == 0);
    assert(strcmp(env.local_faction, "rom_rome") == 0);
    assert(strcmp(env.startpos_path, "data/campaigns/main_rome/startpos.esf") == 0);
    assert(strcmp(env.scripting_path, "campaigns/main_rome/scripting.lua") == 0);
    assert(strcmp(env.all_scripted_path, "data/lua_scripts/all_scripted.lua") == 0);
    assert(strcmp(env.file_overload_prefix, "file_overload\\") == 0);
    assert(env.decompression_buffer != NULL);
    assert(env.decompression_capacity == ROME2_ESF_DECOMPRESS_BUFFER_SIZE);

    /* Modify faction */
    status = rome2_campaign_env_set_local_faction(&env, "rom_carthage");
    assert(status == ROME2_CAMPAIGN_OK);
    assert(strcmp(env.local_faction, "rom_carthage") == 0);

    /* Test buffer expansion */
    uint8_t test_chunk[1024];
    memset(test_chunk, 0x5a, sizeof(test_chunk));
    status = rome2_campaign_env_decompress_block(&env, test_chunk, sizeof(test_chunk), 2 * 1024 * 1024);
    assert(status == ROME2_CAMPAIGN_OK);
    assert(env.decompression_capacity >= 2 * 1024 * 1024);
    assert(env.decompression_size == sizeof(test_chunk));

    rome2_campaign_env_cleanup(&env);
    assert(!env.initialized);
    assert(env.decompression_buffer == NULL);

    printf("PASS\n");
}

static void test_esf_header_and_tag_parsing(void)
{
    printf("[TEST] test_esf_header_and_tag_parsing... ");

    /* Build synthetic ESF buffer */
    uint8_t synth_esf[256];
    memset(synth_esf, 0, sizeof(synth_esf));

    /* Magic 0xabca (little-endian: ca ab 00 00) */
    synth_esf[0] = 0xca;
    synth_esf[1] = 0xab;
    synth_esf[2] = 0x00;
    synth_esf[3] = 0x00;

    /* Flags: 0 */
    synth_esf[4] = 0x00;
    /* Timestamp: 1532349743 */
    synth_esf[8] = 0x2f;
    synth_esf[9] = 0xcd;
    synth_esf[10] = 0x55;
    synth_esf[11] = 0x5b;

    /* Tag table offset: 64 */
    synth_esf[12] = 64;
    synth_esf[13] = 0;
    synth_esf[14] = 0;
    synth_esf[15] = 0;

    /* At offset 64: tag count = 3 */
    synth_esf[64] = 3;
    synth_esf[65] = 0;

    /* Tag 0: "CAMPAIGN_STARTPOS" (len=17) */
    synth_esf[66] = 17;
    synth_esf[67] = 0;
    memcpy(&synth_esf[68], "CAMPAIGN_STARTPOS", 17);

    /* Tag 1: "BUILD" (len=5) */
    synth_esf[85] = 5;
    synth_esf[86] = 0;
    memcpy(&synth_esf[87], "BUILD", 5);

    /* Tag 2: "COMPRESSED_DATA" (len=15) */
    synth_esf[92] = 15;
    synth_esf[93] = 0;
    memcpy(&synth_esf[94], "COMPRESSED_DATA", 15);

    rome2_esf_header hdr;
    rome2_esf_tag_table tags;
    rome2_campaign_status status = rome2_esf_parse_header(synth_esf, sizeof(synth_esf), &hdr, &tags);
    assert(status == ROME2_CAMPAIGN_OK);
    assert(hdr.magic == ROME2_ESF_MAGIC_LE);
    assert(hdr.timestamp == 1532349743);
    assert(hdr.tag_table_offset == 64);
    assert(tags.count == 3);
    assert(strcmp(tags.entries[0].name, "CAMPAIGN_STARTPOS") == 0);
    assert(strcmp(tags.entries[1].name, "BUILD") == 0);
    assert(strcmp(tags.entries[2].name, "COMPRESSED_DATA") == 0);

    /* Tag lookup */
    assert(rome2_esf_find_tag(&tags, "CAMPAIGN_STARTPOS") == 0);
    assert(rome2_esf_find_tag(&tags, "BUILD") == 1);
    assert(rome2_esf_find_tag(&tags, "COMPRESSED_DATA") == 2);
    assert(rome2_esf_find_tag(&tags, "NON_EXISTENT") == -1);

    /* Invalid magic check */
    synth_esf[0] = 0x00;
    status = rome2_esf_parse_header(synth_esf, sizeof(synth_esf), &hdr, &tags);
    assert(status == ROME2_CAMPAIGN_ERR_INVALID_MAGIC);

    printf("PASS\n");
}

static void test_live_retail_startpos_file(void)
{
    printf("[TEST] test_live_retail_startpos_file... ");

    const char *startpos_paths[] = {
        "Total War Rome II/data/campaigns/main_rome/startpos.esf",
        "Total War Rome II/data/campaigns/main_gaul/startpos.esf",
        "Total War Rome II/data/campaigns/main_punic/startpos.esf"
    };

    for (size_t i = 0; i < sizeof(startpos_paths) / sizeof(startpos_paths[0]); ++i) {
        rome2_campaign_env env;
        rome2_campaign_status status = rome2_campaign_env_init(&env, "main_rome");
        assert(status == ROME2_CAMPAIGN_OK);

        status = rome2_campaign_env_load_startpos_file(&env, startpos_paths[i]);
        if (status == ROME2_CAMPAIGN_OK) {
            /* Verified valid retail ESF structure */
            assert(env.esf_header.magic == ROME2_ESF_MAGIC_LE);
            assert(env.esf_header.timestamp > 0);
            assert(env.esf_tag_table.count >= 40);

            /* Check essential nodes */
            int32_t startpos_tag = rome2_esf_find_tag(&env.esf_tag_table, "CAMPAIGN_STARTPOS");
            assert(startpos_tag == 0);

            int32_t save_hdr_tag = rome2_esf_find_tag(&env.esf_tag_table, "SAVE_GAME_HEADER");
            assert(save_hdr_tag == 1);

            assert(env.command_queue_initialized);
            assert(env.scripting_initialized);
        }

        rome2_campaign_env_cleanup(&env);
    }

    printf("PASS\n");
}

static void test_campaign_vfs_integration(void)
{
    printf("[TEST] test_campaign_vfs_integration... ");

    rome2_vfs vfs;
    rome2_vfs_status vfs_status = rome2_vfs_init(&vfs);
    assert(vfs_status == ROME2_VFS_OK);

    /* Mount loose game directory */
    vfs_status = rome2_vfs_mount_loose_dir(&vfs, "Total War Rome II/data");
    assert(vfs_status == ROME2_VFS_OK);

    rome2_campaign_env env;
    rome2_campaign_status status = rome2_campaign_env_init(&env, "main_rome");
    assert(status == ROME2_CAMPAIGN_OK);

    /* Load through VFS abstraction */
    status = rome2_campaign_env_load_from_vfs(&env, &vfs, "main_rome");
    assert(status == ROME2_CAMPAIGN_OK);
    assert(env.esf_header.magic == ROME2_ESF_MAGIC_LE);
    assert(env.esf_tag_table.count >= 50);
    assert(strcmp(env.esf_tag_table.entries[0].name, "CAMPAIGN_STARTPOS") == 0);

    rome2_campaign_env_cleanup(&env);
    rome2_vfs_free(&vfs);

    printf("PASS\n");
}

int main(void)
{
    printf("=== Starting Subsystem 3.1 (Campaign Environment & ESF Loader) Tests ===\n");
    test_campaign_env_lifecycle();
    test_esf_header_and_tag_parsing();
    test_live_retail_startpos_file();
    test_campaign_vfs_integration();
    printf("=== All Subsystem 3.1 Tests PASSED ===\n");
    return 0;
}
