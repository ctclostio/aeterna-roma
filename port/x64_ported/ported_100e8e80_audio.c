#include "ported_100e8e80_audio.h"

#include <string.h>

rome2_audio_status rome2_audio_subsystem_init(
    rome2_audio_subsystem *audio,
    uint32_t sample_rate,
    uint32_t channels)
{
    if (audio == NULL) {
        return ROME2_AUDIO_ERR_INVALID_ARGUMENT;
    }

    memset(audio, 0, sizeof(*audio));
    audio->sample_rate = (sample_rate == 0) ? 44100U : sample_rate;
    audio->channels = (channels == 0) ? 2U : channels;
    audio->initialized = true;

    for (uint32_t i = 0; i < ROME2_AUDIO_CHANNEL_COUNT; i++) {
        audio->channel_states[i].enabled = true;
        audio->channel_states[i].volume = ROME2_AUDIO_DEFAULT_VOLUME;
        audio->channel_states[i].normalized_volume = 1.0f;
    }

    return ROME2_AUDIO_OK;
}

void rome2_audio_subsystem_shutdown(rome2_audio_subsystem *audio)
{
    if (audio != NULL) {
        memset(audio, 0, sizeof(*audio));
    }
}

rome2_audio_status rome2_audio_set_channel_enabled(
    rome2_audio_subsystem *audio,
    uint32_t channel_id,
    bool enabled)
{
    if (audio == NULL || !audio->initialized) {
        return ROME2_AUDIO_ERR_NOT_INITIALIZED;
    }
    if (channel_id >= ROME2_AUDIO_CHANNEL_COUNT) {
        return ROME2_AUDIO_ERR_CHANNEL_OUT_OF_RANGE;
    }

    audio->channel_states[channel_id].enabled = enabled;
    return ROME2_AUDIO_OK;
}

rome2_audio_status rome2_audio_set_channel_volume(
    rome2_audio_subsystem *audio,
    uint32_t channel_id,
    uint32_t volume)
{
    if (audio == NULL || !audio->initialized) {
        return ROME2_AUDIO_ERR_NOT_INITIALIZED;
    }
    if (channel_id >= ROME2_AUDIO_CHANNEL_COUNT) {
        return ROME2_AUDIO_ERR_CHANNEL_OUT_OF_RANGE;
    }

    uint32_t clamped = (volume > 100U) ? 100U : volume;
    audio->channel_states[channel_id].volume = clamped;
    audio->channel_states[channel_id].normalized_volume = (float)clamped / 100.0f;
    return ROME2_AUDIO_OK;
}

rome2_audio_status rome2_audio_get_channel_state(
    const rome2_audio_subsystem *audio,
    uint32_t channel_id,
    rome2_audio_channel_state *state_out)
{
    if (audio == NULL || !audio->initialized || state_out == NULL) {
        return ROME2_AUDIO_ERR_INVALID_ARGUMENT;
    }
    if (channel_id >= ROME2_AUDIO_CHANNEL_COUNT) {
        return ROME2_AUDIO_ERR_CHANNEL_OUT_OF_RANGE;
    }

    *state_out = audio->channel_states[channel_id];
    return ROME2_AUDIO_OK;
}

rome2_audio_status rome2_port_100e8e80_sound_init_part1(
    rome2_audio_subsystem *audio,
    bool is_minimized)
{
    if (audio == NULL) {
        return ROME2_AUDIO_ERR_INVALID_ARGUMENT;
    }

    if (!audio->initialized) {
        rome2_audio_status st = rome2_audio_subsystem_init(audio, 44100, 2);
        if (st != ROME2_AUDIO_OK) {
            return st;
        }
    }

    audio->window_minimized_or_hidden = is_minimized;
    if (is_minimized) {
        strncpy_s(audio->log_message, sizeof(audio->log_message),
                  "Sound init part 1 skipped (minimized)", _TRUNCATE);
        return ROME2_AUDIO_OK;
    }

    /*
     * Check master volume calibration from FUN_100e8e80 lines 42-46:
     * If master volume is at legacy preset 75 (0x4B), elevate to 100.
     */
    if (audio->channel_states[ROME2_AUDIO_CH_MASTER].volume == ROME2_AUDIO_FALLBACK_VOLUME) {
        audio->channel_states[ROME2_AUDIO_CH_MASTER].volume = ROME2_AUDIO_DEFAULT_VOLUME;
        audio->channel_states[ROME2_AUDIO_CH_MASTER].normalized_volume = 1.0f;
    }

    /*
     * Enable the 7 engine channels as dispatched in FUN_100e8e80 lines 90-115:
     *   Channel 7 (Extra), Channel 0 (Master), Channel 2 (Music),
     *   Channel 3 (SFX), Channel 1 (Voice), Channel 4 (Ambient), Channel 6 (UI)
     */
    uint32_t active_channels[] = {
        ROME2_AUDIO_CH_EXTRA,
        ROME2_AUDIO_CH_MASTER,
        ROME2_AUDIO_CH_MUSIC,
        ROME2_AUDIO_CH_SFX,
        ROME2_AUDIO_CH_VOICE,
        ROME2_AUDIO_CH_AMBIENT,
        ROME2_AUDIO_CH_UI
    };

    for (size_t i = 0; i < sizeof(active_channels) / sizeof(active_channels[0]); i++) {
        uint32_t ch = active_channels[i];
        audio->channel_states[ch].enabled = true;
    }

    /* Finalize part 1 banner from line 148 */
    strncpy_s(audio->log_message, sizeof(audio->log_message),
              "Finished sound init part 1", _TRUNCATE);

    return ROME2_AUDIO_OK;
}
