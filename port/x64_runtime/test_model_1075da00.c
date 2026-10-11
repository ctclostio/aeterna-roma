#include "ported_1075da00_model.h"
#include "ported_106ba2e0_campaign.h"
#include "ported_100e3360_vfs.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void test_model_lifecycle(void)
{
    printf("[TEST] test_model_lifecycle... ");

    rome2_campaign_model model;
    rome2_model_status status = rome2_campaign_model_init(&model);
    assert(status == ROME2_MODEL_OK);
    assert(model.initialized);
    assert(!model.world_ready);
    assert(model.turn_number == 1);
    assert(model.current_season == ROME2_SEASON_SUMMER);
    assert(model.trade_manager.active);
    assert(model.trade_manager.active_trade_routes == 4);
    assert(model.cdir.initialized);
    assert(model.cdir.ai_factions_count == 54);
    assert(strcmp(model.cdir.personality, "expansionist") == 0);
    assert(model.deferred_payloads.entries != NULL);
    assert(model.deferred_payloads.capacity == ROME2_MODEL_DEFAULT_DEFERRED_CAPACITY);
    assert(model.deferred_payloads.count == 0);

    rome2_campaign_model_cleanup(&model);
    assert(!model.initialized);
    assert(model.deferred_payloads.entries == NULL);

    printf("PASS\n");
}

static void test_session_init_and_seasons(void)
{
    printf("[TEST] test_session_init_and_seasons... ");

    rome2_campaign_model model;
    rome2_model_status status = rome2_campaign_model_init(&model);
    assert(status == ROME2_MODEL_OK);

    status = rome2_campaign_model_init_session(&model, "main_rome", "rom_rome", 1);
    assert(status == ROME2_MODEL_OK);
    assert(model.world_ready);
    assert(strcmp(model.campaign_name, "main_rome") == 0);
    assert(strcmp(model.active_faction, "rom_rome") == 0);
    assert(model.turn_number == 1);
    assert(model.current_season == ROME2_SEASON_SUMMER);

    uint32_t prev_checksum = model.state_checksum;
    assert(prev_checksum != 0);

    /* Turn 1 -> Turn 2: Autumn */
    status = rome2_campaign_model_process_turn(&model);
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 2);
    assert(model.current_season == ROME2_SEASON_AUTUMN);
    assert(model.state_checksum != prev_checksum);
    prev_checksum = model.state_checksum;

    /* Turn 2 -> Turn 3: Winter */
    status = rome2_campaign_model_process_turn(&model);
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 3);
    assert(model.current_season == ROME2_SEASON_WINTER);
    assert(model.state_checksum != prev_checksum);
    prev_checksum = model.state_checksum;

    /* Turn 3 -> Turn 4: Spring */
    status = rome2_campaign_model_process_turn(&model);
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 4);
    assert(model.current_season == ROME2_SEASON_SPRING);
    assert(model.state_checksum != prev_checksum);
    prev_checksum = model.state_checksum;

    /* Turn 4 -> Turn 5: Summer */
    status = rome2_campaign_model_process_turn(&model);
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 5);
    assert(model.current_season == ROME2_SEASON_SUMMER);
    assert(model.state_checksum != prev_checksum);

    rome2_campaign_model_cleanup(&model);
    printf("PASS\n");
}

static void test_culture_osmosis_table(void)
{
    printf("[TEST] test_culture_osmosis_table... ");

    rome2_campaign_model model;
    rome2_model_status status = rome2_campaign_model_init(&model);
    assert(status == ROME2_MODEL_OK);

    status = rome2_campaign_model_add_osmosis_culture(&model, "rom_Roman", 10.0f, 2.5f);
    assert(status == ROME2_MODEL_OK);
    assert(model.osmosis.count == 1);
    assert(strcmp(model.osmosis.entries[0].culture_name, "rom_Roman") == 0);
    assert(model.osmosis.entries[0].base_influence > 9.9f && model.osmosis.entries[0].base_influence < 10.1f);

    status = rome2_campaign_model_add_osmosis_culture(&model, "rom_Hellenic", 8.0f, 1.8f);
    assert(status == ROME2_MODEL_OK);
    assert(model.osmosis.count == 2);

    status = rome2_campaign_model_add_osmosis_culture(&model, "rom_Barbarian", 6.0f, 1.2f);
    assert(status == ROME2_MODEL_OK);
    assert(model.osmosis.count == 3);

    rome2_campaign_model_cleanup(&model);
    printf("PASS\n");
}

static void test_deferred_payloads_queue(void)
{
    printf("[TEST] test_deferred_payloads_queue... ");

    rome2_campaign_model model;
    rome2_model_status status = rome2_campaign_model_init(&model);
    assert(status == ROME2_MODEL_OK);
    status = rome2_campaign_model_init_session(&model, "main_rome", "rom_rome", 1);
    assert(status == ROME2_MODEL_OK);

    /* Queue payloads for turn 2, turn 3, and turn 5 */
    status = rome2_campaign_model_queue_payload(&model, 101, 2, "mission_reward_01");
    assert(status == ROME2_MODEL_OK);
    status = rome2_campaign_model_queue_payload(&model, 102, 3, "script_spawn_army");
    assert(status == ROME2_MODEL_OK);
    status = rome2_campaign_model_queue_payload(&model, 103, 5, "cai_invasion_plan");
    assert(status == ROME2_MODEL_OK);
    assert(model.deferred_payloads.count == 3);

    /* Advance to turn 2: payload 101 should be processed and retired */
    status = rome2_campaign_model_process_turn(&model);
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 2);
    assert(model.deferred_payloads.count == 2);
    assert(model.deferred_payloads.entries[0].payload_id == 102);
    assert(model.deferred_payloads.entries[1].payload_id == 103);

    /* Advance to turn 4: payload 102 should be processed, 103 remains */
    status = rome2_campaign_model_process_turn(&model); /* Turn 3 */
    assert(status == ROME2_MODEL_OK);
    status = rome2_campaign_model_process_turn(&model); /* Turn 4 */
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 4);
    assert(model.deferred_payloads.count == 1);
    assert(model.deferred_payloads.entries[0].payload_id == 103);

    /* Advance to turn 6: all retired */
    status = rome2_campaign_model_process_turn(&model); /* Turn 5 */
    assert(status == ROME2_MODEL_OK);
    status = rome2_campaign_model_process_turn(&model); /* Turn 6 */
    assert(status == ROME2_MODEL_OK);
    assert(model.turn_number == 6);
    assert(model.deferred_payloads.count == 0);

    /* Test dynamic growth: queue 100 entries beyond initial capacity 64 */
    for (uint32_t i = 0; i < 100; ++i) {
        char tag[32];
        snprintf(tag, sizeof(tag), "bulk_event_%u", i);
        status = rome2_campaign_model_queue_payload(&model, 200 + i, 10 + i, tag);
        assert(status == ROME2_MODEL_OK);
    }
    assert(model.deferred_payloads.count == 100);
    assert(model.deferred_payloads.capacity >= 100);

    rome2_campaign_model_cleanup(&model);
    printf("PASS\n");
}

static void test_live_campaign_env_integration(void)
{
    printf("[TEST] test_live_campaign_env_integration... ");

    const char *startpos_path = "Total War Rome II/data/campaigns/main_rome/startpos.esf";
    FILE *fp = NULL;
    if (fopen_s(&fp, startpos_path, "rb") != 0 || fp == NULL) {
        printf("SKIPPED (main_rome/startpos.esf not found)\n");
        return;
    }
    fclose(fp);

    rome2_campaign_env env;
    rome2_campaign_status env_status = rome2_campaign_env_init(&env, "main_rome");
    assert(env_status == ROME2_CAMPAIGN_OK);

    env_status = rome2_campaign_env_load_startpos_file(&env, startpos_path);
    assert(env_status == ROME2_CAMPAIGN_OK);

    rome2_campaign_model model;
    rome2_model_status model_status = rome2_campaign_model_init(&model);
    assert(model_status == ROME2_MODEL_OK);

    /* Load model state from parsed environment */
    model_status = rome2_campaign_model_load_from_esf(&model, &env, NULL, 0);
    assert(model_status == ROME2_MODEL_OK);
    assert(model.world_ready);
    assert(strcmp(model.campaign_name, "main_rome") == 0);
    assert(strcmp(model.active_faction, "rom_rome") == 0);
    assert(model.turn_number == 1);
    assert(model.osmosis.count == 5); /* 5 base cultures seeded */
    assert(model.state_checksum != 0);

    /* Verify turn progression with full model */
    model_status = rome2_campaign_model_process_turn(&model);
    assert(model_status == ROME2_MODEL_OK);
    assert(model.turn_number == 2);
    assert(model.current_season == ROME2_SEASON_AUTUMN);

    rome2_campaign_model_cleanup(&model);
    rome2_campaign_env_cleanup(&env);

    printf("PASS\n");
}

int main(void)
{
    printf("=== Starting Phase 4.1 (Campaign Model & AI Serialization) Tests ===\n");
    test_model_lifecycle();
    test_session_init_and_seasons();
    test_culture_osmosis_table();
    test_deferred_payloads_queue();
    test_live_campaign_env_integration();
    printf("=== All Phase 4.1 Tests PASSED ===\n");
    return 0;
}
