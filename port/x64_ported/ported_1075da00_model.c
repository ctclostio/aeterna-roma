#include "ported_1075da00_model.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

rome2_model_status rome2_campaign_model_init(
    rome2_campaign_model *model)
{
    if (model == NULL) {
        return ROME2_MODEL_ERR_INVALID_ARGUMENT;
    }

    memset(model, 0, sizeof(*model));

    model->turn_number = 1;
    model->current_season = ROME2_SEASON_SUMMER;
    model->world_ready = false;

    strncpy_s(model->campaign_name, sizeof(model->campaign_name), "main_rome", _TRUNCATE);
    strncpy_s(model->active_faction, sizeof(model->active_faction), "rom_rome", _TRUNCATE);

    /* Allocate deferred payloads queue */
    model->deferred_payloads.capacity = ROME2_MODEL_DEFAULT_DEFERRED_CAPACITY;
    model->deferred_payloads.count = 0;
    model->deferred_payloads.entries = (rome2_deferred_payload_entry *)malloc(
        model->deferred_payloads.capacity * sizeof(rome2_deferred_payload_entry));
    if (model->deferred_payloads.entries == NULL) {
        return ROME2_MODEL_ERR_OUT_OF_MEMORY;
    }
    memset(model->deferred_payloads.entries, 0,
           model->deferred_payloads.capacity * sizeof(rome2_deferred_payload_entry));

    /* Initialize episodic restrictions */
    model->restrictions.enabled = false;
    model->restrictions.current_chapter = 1;
    model->restrictions.turn_limit = 0;
    strncpy_s(model->restrictions.active_objective, sizeof(model->restrictions.active_objective),
              "unrestricted", _TRUNCATE);

    /* Initialize trade manager */
    model->trade_manager.active = true;
    model->trade_manager.active_trade_routes = 4;
    model->trade_manager.tariff_income = 1250;
    model->trade_manager.sea_lane_efficiency = 100;

    /* Initialize CDIR (Campaign Direction / CAI Interface) */
    model->cdir.initialized = true;
    model->cdir.ai_factions_count = 54;
    model->cdir.strategic_budget = 5000;
    model->cdir.difficulty_rating = 2; /* Normal */
    strncpy_s(model->cdir.personality, sizeof(model->cdir.personality),
              "expansionist", _TRUNCATE);

    model->state_checksum = 0;
    model->initialized = true;

    return ROME2_MODEL_OK;
}

void rome2_campaign_model_cleanup(
    rome2_campaign_model *model)
{
    if (model == NULL || !model->initialized) {
        return;
    }

    if (model->deferred_payloads.entries != NULL) {
        free(model->deferred_payloads.entries);
        model->deferred_payloads.entries = NULL;
    }
    model->deferred_payloads.count = 0;
    model->deferred_payloads.capacity = 0;

    memset(model, 0, sizeof(*model));
}

rome2_model_status rome2_campaign_model_init_session(
    rome2_campaign_model *model,
    const char *campaign_name,
    const char *faction_name,
    uint32_t start_turn)
{
    if (model == NULL || !model->initialized) {
        return ROME2_MODEL_ERR_NOT_INITIALIZED;
    }

    if (campaign_name != NULL && campaign_name[0] != '\0') {
        strncpy_s(model->campaign_name, sizeof(model->campaign_name), campaign_name, _TRUNCATE);
    }
    if (faction_name != NULL && faction_name[0] != '\0') {
        strncpy_s(model->active_faction, sizeof(model->active_faction), faction_name, _TRUNCATE);
    }

    model->turn_number = start_turn > 0 ? start_turn : 1;
    model->current_season = (rome2_season)((model->turn_number - 1) % 4);
    model->world_ready = true;

    model->state_checksum = rome2_campaign_model_compute_checksum(model);

    snprintf(model->log_message, sizeof(model->log_message),
             "%s: initialized session '%s' faction '%s' turn %u season %u\n",
             ROME2_MODEL_STR_MODEL_TAG, model->campaign_name, model->active_faction,
             model->turn_number, (uint32_t)model->current_season);

    return ROME2_MODEL_OK;
}

rome2_model_status rome2_campaign_model_add_osmosis_culture(
    rome2_campaign_model *model,
    const char *culture_name,
    float base_influence,
    float border_pressure)
{
    if (model == NULL || !model->initialized || culture_name == NULL) {
        return ROME2_MODEL_ERR_INVALID_ARGUMENT;
    }

    if (model->osmosis.count >= ROME2_MODEL_MAX_CULTURES) {
        return ROME2_MODEL_ERR_OUT_OF_MEMORY;
    }

    uint32_t idx = model->osmosis.count;
    strncpy_s(model->osmosis.entries[idx].culture_name,
              sizeof(model->osmosis.entries[idx].culture_name),
              culture_name, _TRUNCATE);
    model->osmosis.entries[idx].base_influence = base_influence;
    model->osmosis.entries[idx].border_pressure = border_pressure;
    model->osmosis.count++;

    model->state_checksum = rome2_campaign_model_compute_checksum(model);
    return ROME2_MODEL_OK;
}

rome2_model_status rome2_campaign_model_queue_payload(
    rome2_campaign_model *model,
    uint32_t payload_id,
    uint32_t trigger_turn,
    const char *event_tag)
{
    if (model == NULL || !model->initialized || event_tag == NULL) {
        return ROME2_MODEL_ERR_INVALID_ARGUMENT;
    }

    if (model->deferred_payloads.count >= model->deferred_payloads.capacity) {
        uint32_t new_cap = model->deferred_payloads.capacity * 2;
        rome2_deferred_payload_entry *new_entries = (rome2_deferred_payload_entry *)realloc(
            model->deferred_payloads.entries, new_cap * sizeof(rome2_deferred_payload_entry));
        if (new_entries == NULL) {
            return ROME2_MODEL_ERR_OUT_OF_MEMORY;
        }
        model->deferred_payloads.entries = new_entries;
        model->deferred_payloads.capacity = new_cap;
    }

    uint32_t idx = model->deferred_payloads.count;
    model->deferred_payloads.entries[idx].payload_id = payload_id;
    model->deferred_payloads.entries[idx].trigger_turn = trigger_turn;
    strncpy_s(model->deferred_payloads.entries[idx].event_tag,
              sizeof(model->deferred_payloads.entries[idx].event_tag),
              event_tag, _TRUNCATE);
    model->deferred_payloads.count++;

    return ROME2_MODEL_OK;
}

rome2_model_status rome2_campaign_model_process_turn(
    rome2_campaign_model *model)
{
    if (model == NULL || !model->initialized || !model->world_ready) {
        return ROME2_MODEL_ERR_NOT_INITIALIZED;
    }

    model->turn_number++;
    model->current_season = (rome2_season)((model->turn_number - 1) % 4);

    /* Process and retire triggered payloads */
    uint32_t write_idx = 0;
    for (uint32_t i = 0; i < model->deferred_payloads.count; ++i) {
        if (model->deferred_payloads.entries[i].trigger_turn > model->turn_number) {
            if (write_idx != i) {
                model->deferred_payloads.entries[write_idx] = model->deferred_payloads.entries[i];
            }
            write_idx++;
        }
    }
    model->deferred_payloads.count = write_idx;

    /* Trade update */
    if (model->trade_manager.active) {
        model->trade_manager.tariff_income = 1000 + (model->turn_number * 50);
    }

    model->state_checksum = rome2_campaign_model_compute_checksum(model);

    snprintf(model->log_message, sizeof(model->log_message),
             "%s: advanced to turn %u season %u checksum=0x%08x\n",
             ROME2_MODEL_STR_MODEL_TAG, model->turn_number,
             (uint32_t)model->current_season, model->state_checksum);

    return ROME2_MODEL_OK;
}

uint32_t rome2_campaign_model_compute_checksum(
    const rome2_campaign_model *model)
{
    if (model == NULL) {
        return 0;
    }

    /* Recovered rotate-xor checksum formula from FUN_1075da00 lines 1324-1327:
     *   bVar3 = ((byte)uVar20 ^ (byte)uVar21) + 0xd & 0x1f;
     *   uVar21 = (uVar21 >> bVar3 | uVar21 << (bVar3 ^ 0x1f)) ^ uVar20;
     */
    uint32_t hash = 0x811c9dc5; /* FNV-1a basis */
    uint32_t u20 = model->turn_number * 0x1f + (uint32_t)model->current_season;
    uint32_t u21 = hash ^ (model->trade_manager.active_trade_routes * 0x3d);

    uint8_t rot = (uint8_t)(((uint8_t)u20 ^ (uint8_t)u21) + 0xd) & 0x1f;
    uint8_t inv_rot = (uint8_t)(rot ^ 0x1f);
    hash = ((u21 >> rot) | (u21 << inv_rot)) ^ u20;

    /* Mix osmosis culture names */
    for (uint32_t i = 0; i < model->osmosis.count; ++i) {
        const char *name = model->osmosis.entries[i].culture_name;
        while (*name != '\0') {
            hash ^= (uint8_t)(*name++);
            hash *= 0x01000193;
        }
    }

    return hash;
}

rome2_model_status rome2_campaign_model_load_from_esf(
    rome2_campaign_model *model,
    const rome2_campaign_env *env,
    const uint8_t *esf_data,
    size_t esf_size)
{
    if (model == NULL || !model->initialized || env == NULL) {
        return ROME2_MODEL_ERR_INVALID_ARGUMENT;
    }

    (void)esf_data;
    (void)esf_size;

    /* Initialize session from environment */
    rome2_model_status status = rome2_campaign_model_init_session(
        model, env->campaign_name, env->local_faction, 1);
    if (status != ROME2_MODEL_OK) {
        return status;
    }

    /* Seed standard base game cultures if osmosis table empty */
    if (model->osmosis.count == 0) {
        rome2_campaign_model_add_osmosis_culture(model, "rom_Roman", 10.0f, 2.5f);
        rome2_campaign_model_add_osmosis_culture(model, "rom_Hellenic", 8.0f, 1.8f);
        rome2_campaign_model_add_osmosis_culture(model, "rom_Barbarian", 6.0f, 1.2f);
        rome2_campaign_model_add_osmosis_culture(model, "rom_Eastern", 7.0f, 1.5f);
        rome2_campaign_model_add_osmosis_culture(model, "rom_Punic", 9.0f, 2.0f);
    }

    model->state_checksum = rome2_campaign_model_compute_checksum(model);
    return ROME2_MODEL_OK;
}
