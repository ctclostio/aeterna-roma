#include "ported_100e8e80_audio.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_audio_init_and_channels(void)
{
    printf("[TEST] test_audio_init_and_channels... ");

    rome2_audio_subsystem audio;
    rome2_audio_status st = rome2_audio_subsystem_init(&audio, 48000, 2);
    assert(st == ROME2_AUDIO_OK);
    assert(audio.initialized);
    assert(audio.sample_rate == 48000);
    assert(audio.channels == 2);

    /* Verify channel getters */
    rome2_audio_channel_state state;
    assert(rome2_audio_get_channel_state(&audio, ROME2_AUDIO_CH_MASTER, &state) == ROME2_AUDIO_OK);
    assert(state.enabled);
    assert(state.volume == 100);

    /* Modify channel volume */
    assert(rome2_audio_set_channel_volume(&audio, ROME2_AUDIO_CH_MUSIC, 80) == ROME2_AUDIO_OK);
    assert(rome2_audio_get_channel_state(&audio, ROME2_AUDIO_CH_MUSIC, &state) == ROME2_AUDIO_OK);
    assert(state.volume == 80);
    assert(state.normalized_volume > 0.79f && state.normalized_volume < 0.81f);

    /* Test clamping */
    assert(rome2_audio_set_channel_volume(&audio, ROME2_AUDIO_CH_SFX, 150) == ROME2_AUDIO_OK);
    assert(rome2_audio_get_channel_state(&audio, ROME2_AUDIO_CH_SFX, &state) == ROME2_AUDIO_OK);
    assert(state.volume == 100);

    /* Out of range channel */
    assert(rome2_audio_set_channel_volume(&audio, 99, 50) == ROME2_AUDIO_ERR_CHANNEL_OUT_OF_RANGE);

    rome2_audio_subsystem_shutdown(&audio);
    assert(!audio.initialized);

    printf("PASS\n");
}

static void test_sound_init_part1(void)
{
    printf("[TEST] test_sound_init_part1... ");

    rome2_audio_subsystem audio;
    rome2_audio_status st = rome2_audio_subsystem_init(&audio, 44100, 2);
    assert(st == ROME2_AUDIO_OK);

    /* Set master volume to legacy 75 preset */
    rome2_audio_set_channel_volume(&audio, ROME2_AUDIO_CH_MASTER, 75);

    /* Run part 1 init */
    st = rome2_port_100e8e80_sound_init_part1(&audio, false);
    assert(st == ROME2_AUDIO_OK);

    /* Verify master volume was calibrated from 75 to 100 */
    rome2_audio_channel_state master_state;
    assert(rome2_audio_get_channel_state(&audio, ROME2_AUDIO_CH_MASTER, &master_state) == ROME2_AUDIO_OK);
    assert(master_state.volume == 100);

    /* Verify log message */
    assert(strcmp(audio.log_message, "Finished sound init part 1") == 0);

    /* Verify active channels enabled */
    uint32_t expected_channels[] = { 0, 1, 2, 3, 4, 6, 7 };
    for (size_t i = 0; i < sizeof(expected_channels) / sizeof(expected_channels[0]); i++) {
        rome2_audio_channel_state ch_state;
        assert(rome2_audio_get_channel_state(&audio, expected_channels[i], &ch_state) == ROME2_AUDIO_OK);
        assert(ch_state.enabled);
    }

    /* Test minimized skip */
    st = rome2_port_100e8e80_sound_init_part1(&audio, true);
    assert(st == ROME2_AUDIO_OK);
    assert(strstr(audio.log_message, "skipped") != NULL);

    rome2_audio_subsystem_shutdown(&audio);
    printf("PASS\n");
}

int main(void)
{
    printf("====================================================\n");
    printf(" Rome II Subsystem 2.3 (0x100e8e80 Audio) Tests\n");
    printf("====================================================\n");

    test_audio_init_and_channels();
    test_sound_init_part1();

    printf("\n>>> ALL SUBSYSTEM 2.3 TESTS PASSED SUCCESSFULLY! <<<\n");
    return 0;
}
