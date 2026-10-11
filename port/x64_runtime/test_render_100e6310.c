#include "ported_100e6310_render.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_render_device_init_and_modes(void)
{
    printf("[TEST] test_render_device_init_and_modes... ");

    rome2_render_device dev;
    rome2_render_status st = rome2_render_device_init(&dev, NULL);
    assert(st == ROME2_RENDER_OK);
    assert(dev.initialized);
    assert(dev.config.width == 1920);
    assert(dev.config.height == 1080);
    assert(dev.mode_count > 0);

    /* Test mode lookup */
    rome2_display_mode mode;
    st = rome2_render_device_find_best_mode(&dev, 1920, 1080, &mode);
    assert(st == ROME2_RENDER_OK);
    assert(mode.width == 1920 && mode.height == 1080);

    st = rome2_render_device_find_best_mode(&dev, 1280, 720, &mode);
    assert(st == ROME2_RENDER_OK);
    assert(mode.width == 1280 && mode.height == 720);

    /* Test arbitrary resolution best-match */
    st = rome2_render_device_find_best_mode(&dev, 1900, 1000, &mode);
    assert(st == ROME2_RENDER_OK);
    assert(mode.width == 1920 && mode.height == 1080);

    rome2_render_device_shutdown(&dev);
    assert(!dev.initialized);

    printf("PASS\n");
}

static void test_render_device_create_and_resize(void)
{
    printf("[TEST] test_render_device_create_and_resize... ");

    rome2_render_device dev;
    rome2_render_status st = rome2_render_device_init(&dev, NULL);
    assert(st == ROME2_RENDER_OK);

    /* Headless test device creation */
    st = rome2_render_device_create(&dev, NULL);
    assert(st == ROME2_RENDER_OK);
    assert(dev.device_active);
    assert(dev.is_headless_test_device);
    assert(strstr(dev.status_message, "Render device active") != NULL);

    /* Resize test */
    st = rome2_render_device_resize(&dev, 2560, 1440, false);
    assert(st == ROME2_RENDER_OK);
    assert(dev.config.width == 2560);
    assert(dev.config.height == 1440);
    assert(!dev.config.windowed);
    assert(dev.config.aspect_ratio > 1.77f && dev.config.aspect_ratio < 1.78f);

    rome2_render_device_shutdown(&dev);
    printf("PASS\n");
}

static void test_init_display_100e6310(void)
{
    printf("[TEST] test_init_display_100e6310... ");

    rome2_render_device dev;
    rome2_render_status st = rome2_port_100e6310_init_display(
        &dev, "main", 1920, 1080, true);
    assert(st == ROME2_RENDER_OK);
    assert(dev.initialized);
    assert(dev.device_active);
    assert(strcmp(dev.config.campaign_mode, "main") == 0);
    assert(strcmp(dev.status_message, "FUN_100e6310 display initialization complete") == 0);

    /* Test campaign_edit route */
    st = rome2_port_100e6310_init_display(
        &dev, "campaign_edit", 1280, 720, false);
    assert(st == ROME2_RENDER_OK);
    assert(strcmp(dev.config.campaign_mode, "campaign_edit") == 0);
    assert(dev.config.width == 1280);
    assert(dev.config.height == 720);
    assert(!dev.config.windowed);

    rome2_render_device_shutdown(&dev);
    printf("PASS\n");
}

int main(void)
{
    printf("====================================================\n");
    printf(" Rome II Subsystem 2.4 (0x100e6310 Render) Tests\n");
    printf("====================================================\n");

    test_render_device_init_and_modes();
    test_render_device_create_and_resize();
    test_init_display_100e6310();

    printf("\n>>> ALL SUBSYSTEM 2.4 TESTS PASSED SUCCESSFULLY! <<<\n");
    return 0;
}
