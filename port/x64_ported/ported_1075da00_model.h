#ifndef ROME2_PORTED_1075DA00_MODEL_H
#define ROME2_PORTED_1075DA00_MODEL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "ported_106ba2e0_campaign.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_1075DA00_CAMPAIGN_MODEL_PC   UINT32_C(0x1075da00)
#define ROME2_PORT_106B1510_SESSION_INIT_PC     UINT32_C(0x106b1510)

/* Canonical log strings recovered from 0x1075da00 */
#define ROME2_MODEL_STR_CREATING_RESTRICTIONS   "Creating EPISODIC_RESTRICTIONS"
#define ROME2_MODEL_STR_CREATED_RESTRICTIONS    "Created EPISODIC_RESTRICTIONS"
#define ROME2_MODEL_STR_OSMOSIS_CULTURES        "OSMOSIS_CULTURES"
#define ROME2_MODEL_STR_DEFERRED_PAYLOADS       "DEFERRED PAYLOADS"
#define ROME2_MODEL_STR_DEFERRED_DEATHS         "DEFERRED DEATHS"
#define ROME2_MODEL_STR_CREATING_TRADE_MGR      "Creating CAMPAIGN_TRADE_MANAGER"
#define ROME2_MODEL_STR_CREATED_TRADE_MGR       "Created CAMPAIGN_TRADE_MANAGER"
#define ROME2_MODEL_STR_CREATING_CDIR           "Creating CDIR_INTERFACE"
#define ROME2_MODEL_STR_CREATED_CDIR            "Created CDIR_INTERFACE"
#define ROME2_MODEL_STR_MODEL_TAG               "CAMPAIGN_MODEL::CAMPAIGN_MODEL"

#define ROME2_MODEL_MAX_CULTURES                32U
#define ROME2_MODEL_MAX_NAME_LEN                64U
#define ROME2_MODEL_DEFAULT_DEFERRED_CAPACITY   64U

typedef enum rome2_model_status {
    ROME2_MODEL_OK = 0,
    ROME2_MODEL_ERR_INVALID_ARGUMENT = 1,
    ROME2_MODEL_ERR_OUT_OF_MEMORY = 2,
    ROME2_MODEL_ERR_NOT_INITIALIZED = 3,
    ROME2_MODEL_ERR_CORRUPT_STATE = 4,
    ROME2_MODEL_ERR_TAG_NOT_FOUND = 5
} rome2_model_status;

/*
 * Seasons enum
 */
typedef enum rome2_season {
    ROME2_SEASON_SUMMER = 0,
    ROME2_SEASON_AUTUMN = 1,
    ROME2_SEASON_WINTER = 2,
    ROME2_SEASON_SPRING = 3
} rome2_season;

/*
 * Episodic restrictions subsystem (narrative chapter limits and tech gating)
 */
typedef struct rome2_episodic_restrictions {
    bool enabled;
    uint32_t current_chapter;
    uint32_t turn_limit;
    char active_objective[ROME2_MODEL_MAX_NAME_LEN];
} rome2_episodic_restrictions;

/*
 * Cultural osmosis entry (inter-provincial cultural pressure)
 */
typedef struct rome2_culture_osmosis_entry {
    char culture_name[ROME2_MODEL_MAX_NAME_LEN];
    float base_influence;
    float border_pressure;
} rome2_culture_osmosis_entry;

/*
 * Cultural osmosis table
 */
typedef struct rome2_culture_osmosis_table {
    uint32_t count;
    rome2_culture_osmosis_entry entries[ROME2_MODEL_MAX_CULTURES];
} rome2_culture_osmosis_table;

/*
 * Deferred payload entry (queued scripted events and triggers)
 */
typedef struct rome2_deferred_payload_entry {
    uint32_t payload_id;
    uint32_t trigger_turn;
    char event_tag[ROME2_MODEL_MAX_NAME_LEN];
} rome2_deferred_payload_entry;

/*
 * Deferred payload queue
 */
typedef struct rome2_deferred_payload_queue {
    uint32_t count;
    uint32_t capacity;
    rome2_deferred_payload_entry *entries;
} rome2_deferred_payload_queue;

/*
 * Trade manager subsystem
 */
typedef struct rome2_trade_manager {
    bool active;
    uint32_t active_trade_routes;
    uint32_t tariff_income;
    uint32_t sea_lane_efficiency;
} rome2_trade_manager;

/*
 * Campaign Direction Interface (CDIR / Campaign AI)
 */
typedef struct rome2_cdir_interface {
    bool initialized;
    uint32_t ai_factions_count;
    uint32_t strategic_budget;
    uint32_t difficulty_rating;
    char personality[ROME2_MODEL_MAX_NAME_LEN];
} rome2_cdir_interface;

/*
 * Campaign Model (Master World Model from 0x1075da00)
 */
typedef struct rome2_campaign_model {
    bool initialized;
    bool world_ready;
    uint32_t turn_number;
    rome2_season current_season;
    uint32_t state_checksum;

    char campaign_name[ROME2_MODEL_MAX_NAME_LEN];
    char active_faction[ROME2_MODEL_MAX_NAME_LEN];

    rome2_episodic_restrictions restrictions;
    rome2_culture_osmosis_table osmosis;
    rome2_deferred_payload_queue deferred_payloads;
    rome2_trade_manager trade_manager;
    rome2_cdir_interface cdir;

    char log_message[256];
} rome2_campaign_model;

/*
 * Campaign Model API
 */
rome2_model_status rome2_campaign_model_init(
    rome2_campaign_model *model);

void rome2_campaign_model_cleanup(
    rome2_campaign_model *model);

rome2_model_status rome2_campaign_model_init_session(
    rome2_campaign_model *model,
    const char *campaign_name,
    const char *faction_name,
    uint32_t start_turn);

rome2_model_status rome2_campaign_model_load_from_esf(
    rome2_campaign_model *model,
    const rome2_campaign_env *env,
    const uint8_t *esf_data,
    size_t esf_size);

rome2_model_status rome2_campaign_model_add_osmosis_culture(
    rome2_campaign_model *model,
    const char *culture_name,
    float base_influence,
    float border_pressure);

rome2_model_status rome2_campaign_model_queue_payload(
    rome2_campaign_model *model,
    uint32_t payload_id,
    uint32_t trigger_turn,
    const char *event_tag);

rome2_model_status rome2_campaign_model_process_turn(
    rome2_campaign_model *model);

uint32_t rome2_campaign_model_compute_checksum(
    const rome2_campaign_model *model);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_1075DA00_MODEL_H */
