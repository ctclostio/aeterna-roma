#ifndef ROME2_PORTED_100E8E80_AUDIO_H
#define ROME2_PORTED_100E8E80_AUDIO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_100E8E80_AUDIO_INIT_PC UINT32_C(0x100e8e80)

#define ROME2_AUDIO_CHANNEL_COUNT         8U
#define ROME2_AUDIO_CH_MASTER             0U
#define ROME2_AUDIO_CH_VOICE              1U
#define ROME2_AUDIO_CH_MUSIC              2U
#define ROME2_AUDIO_CH_SFX                3U
#define ROME2_AUDIO_CH_AMBIENT            4U
#define ROME2_AUDIO_CH_SPECIAL            5U
#define ROME2_AUDIO_CH_UI                 6U
#define ROME2_AUDIO_CH_EXTRA              7U

#define ROME2_AUDIO_DEFAULT_VOLUME        100U
#define ROME2_AUDIO_FALLBACK_VOLUME       75U

typedef enum rome2_audio_status {
    ROME2_AUDIO_OK = 0,
    ROME2_AUDIO_ERR_INVALID_ARGUMENT = 1,
    ROME2_AUDIO_ERR_DEVICE_UNAVAILABLE = 2,
    ROME2_AUDIO_ERR_CHANNEL_OUT_OF_RANGE = 3,
    ROME2_AUDIO_ERR_ALREADY_INITIALIZED = 4,
    ROME2_AUDIO_ERR_NOT_INITIALIZED = 5
} rome2_audio_status;

typedef struct rome2_audio_channel_state {
    bool enabled;
    uint32_t volume;            /* 0 to 100 scale */
    float normalized_volume;    /* 0.0f to 1.0f scale */
} rome2_audio_channel_state;

typedef struct rome2_audio_subsystem {
    bool initialized;
    bool window_minimized_or_hidden;
    uint32_t sample_rate;
    uint32_t channels;
    rome2_audio_channel_state channel_states[ROME2_AUDIO_CHANNEL_COUNT];
    char log_message[128];
} rome2_audio_subsystem;

/*
 * Lifecycle and Configuration API
 */
rome2_audio_status rome2_audio_subsystem_init(
    rome2_audio_subsystem *audio,
    uint32_t sample_rate,
    uint32_t channels);

void rome2_audio_subsystem_shutdown(
    rome2_audio_subsystem *audio);

rome2_audio_status rome2_audio_set_channel_enabled(
    rome2_audio_subsystem *audio,
    uint32_t channel_id,
    bool enabled);

rome2_audio_status rome2_audio_set_channel_volume(
    rome2_audio_subsystem *audio,
    uint32_t channel_id,
    uint32_t volume);

rome2_audio_status rome2_audio_get_channel_state(
    const rome2_audio_subsystem *audio,
    uint32_t channel_id,
    rome2_audio_channel_state *state_out);

/*
 * Reconstruction of FUN_100e8e80 ("Finished sound init part 1")
 *
 * Configures the 7 standard game channels:
 *   - Channel 0: Master
 *   - Channel 1: Voice / Speech
 *   - Channel 2: Music
 *   - Channel 3: Sound Effects (SFX)
 *   - Channel 4: Ambient
 *   - Channel 6: UI / Movies
 *   - Channel 7: Extra / Cinematics
 *
 * Applies master volume calibration (re-scaling 75 -> 100 if at default),
 * processes Windows message queue, and records "Finished sound init part 1".
 */
rome2_audio_status rome2_port_100e8e80_sound_init_part1(
    rome2_audio_subsystem *audio,
    bool is_minimized);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_100E8E80_AUDIO_H */
