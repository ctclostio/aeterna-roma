#include "ported_100e6310_render.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")

static const rome2_display_mode s_standard_modes[] = {
    { 1024,  768, 60, 0x15 },   /* 4:3 */
    { 1280,  720, 60, 0x15 },   /* 16:9 720p */
    { 1280,  720, 120, 0x15 },
    { 1280, 1024, 60, 0x15 },   /* 5:4 */
    { 1366,  768, 60, 0x15 },
    { 1600,  900, 60, 0x15 },
    { 1680, 1050, 60, 0x15 },   /* 16:10 */
    { 1920, 1080, 60, 0x15 },   /* 16:9 1080p */
    { 1920, 1080, 120, 0x15 },
    { 1920, 1080, 144, 0x15 },
    { 1920, 1200, 60, 0x15 },   /* 16:10 */
    { 2560, 1440, 60, 0x15 },   /* 1440p */
    { 2560, 1440, 144, 0x15 },
    { 3440, 1440, 60, 0x15 },   /* 21:9 Ultrawide */
    { 3840, 2160, 60, 0x15 }    /* 4K UHD */
};

rome2_render_status rome2_render_device_init(
    rome2_render_device *dev,
    const rome2_render_config *config_or_null)
{
    if (dev == NULL) {
        return ROME2_RENDER_ERR_INVALID_ARGUMENT;
    }

    memset(dev, 0, sizeof(*dev));

    if (config_or_null != NULL) {
        dev->config = *config_or_null;
    } else {
        dev->config.width = ROME2_RENDER_DEFAULT_WIDTH;
        dev->config.height = ROME2_RENDER_DEFAULT_HEIGHT;
        dev->config.refresh_rate = ROME2_RENDER_DEFAULT_REFRESH;
        dev->config.windowed = true;
        dev->config.aspect_ratio = 16.0f / 9.0f;
        dev->config.fov = 75.0f;
        dev->config.vsync = true;
        dev->config.multisample_count = 1;
        dev->config.adapter_index = 0;
        strncpy_s(dev->config.campaign_mode, sizeof(dev->config.campaign_mode),
                  "main", _TRUNCATE);
    }

    if (dev->config.height > 0) {
        dev->config.aspect_ratio = (float)dev->config.width / (float)dev->config.height;
    }

    /* Populate standard baseline modes */
    size_t count = sizeof(s_standard_modes) / sizeof(s_standard_modes[0]);
    if (count > ROME2_RENDER_MAX_DISPLAY_MODES) {
        count = ROME2_RENDER_MAX_DISPLAY_MODES;
    }

    for (size_t i = 0; i < count; i++) {
        dev->modes[i] = s_standard_modes[i];
    }
    dev->mode_count = (uint32_t)count;

    dev->initialized = true;
    strncpy_s(dev->status_message, sizeof(dev->status_message),
              "Render device initialized", _TRUNCATE);

    return ROME2_RENDER_OK;
}

void rome2_render_device_shutdown(rome2_render_device *dev)
{
    if (dev != NULL) {
        memset(dev, 0, sizeof(*dev));
    }
}

rome2_render_status rome2_render_device_enumerate_modes(rome2_render_device *dev)
{
    if (dev == NULL || !dev->initialized) {
        return ROME2_RENDER_ERR_NOT_INITIALIZED;
    }

    DEVMODEW dm;
    memset(&dm, 0, sizeof(dm));
    dm.dmSize = sizeof(dm);

    uint32_t mode_idx = 0;
    uint32_t collected = 0;

    while (EnumDisplaySettingsW(NULL, mode_idx, &dm) && collected < ROME2_RENDER_MAX_DISPLAY_MODES) {
        if (dm.dmBitsPerPel >= 32 && dm.dmPelsWidth >= 800 && dm.dmPelsHeight >= 600) {
            /* Avoid duplicate resolutions/refreshes */
            bool exists = false;
            for (uint32_t i = 0; i < collected; i++) {
                if (dev->modes[i].width == dm.dmPelsWidth &&
                    dev->modes[i].height == dm.dmPelsHeight &&
                    dev->modes[i].refresh_rate == dm.dmDisplayFrequency) {
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                dev->modes[collected].width = dm.dmPelsWidth;
                dev->modes[collected].height = dm.dmPelsHeight;
                dev->modes[collected].refresh_rate = dm.dmDisplayFrequency;
                dev->modes[collected].format = 0x15; /* 32-bit color */
                collected++;
            }
        }
        mode_idx++;
    }

    if (collected > 0) {
        dev->mode_count = collected;
    }

    return ROME2_RENDER_OK;
}

rome2_render_status rome2_render_device_find_best_mode(
    const rome2_render_device *dev,
    uint32_t target_width,
    uint32_t target_height,
    rome2_display_mode *mode_out)
{
    if (dev == NULL || !dev->initialized || mode_out == NULL) {
        return ROME2_RENDER_ERR_INVALID_ARGUMENT;
    }

    if (dev->mode_count == 0) {
        return ROME2_RENDER_ERR_MODE_NOT_SUPPORTED;
    }

    uint32_t best_idx = 0;
    int32_t best_diff = 0x7FFFFFFF;

    for (uint32_t i = 0; i < dev->mode_count; i++) {
        int32_t dw = (int32_t)dev->modes[i].width - (int32_t)target_width;
        int32_t dh = (int32_t)dev->modes[i].height - (int32_t)target_height;
        int32_t diff = abs(dw) + abs(dh);

        if (diff < best_diff) {
            best_diff = diff;
            best_idx = i;
        }
    }

    *mode_out = dev->modes[best_idx];
    return ROME2_RENDER_OK;
}

rome2_render_status rome2_render_device_create(
    rome2_render_device *dev,
    HWND target_hwnd_or_null)
{
    if (dev == NULL || !dev->initialized) {
        return ROME2_RENDER_ERR_NOT_INITIALIZED;
    }

    dev->hwnd = target_hwnd_or_null;
    if (target_hwnd_or_null == NULL) {
        dev->is_headless_test_device = true;
    } else {
        dev->is_headless_test_device = false;
    }

    dev->device_active = true;
    snprintf(dev->status_message, sizeof(dev->status_message),
             "Render device active: %ux%u @ %uHz (%s)",
             dev->config.width, dev->config.height, dev->config.refresh_rate,
             dev->config.windowed ? "Windowed" : "Fullscreen");

    return ROME2_RENDER_OK;
}

rome2_render_status rome2_render_device_resize(
    rome2_render_device *dev,
    uint32_t new_width,
    uint32_t new_height,
    bool windowed)
{
    if (dev == NULL || !dev->initialized) {
        return ROME2_RENDER_ERR_NOT_INITIALIZED;
    }

    uint32_t w = (new_width < 640U) ? 640U : new_width;
    uint32_t h = (new_height < 480U) ? 480U : new_height;

    dev->config.width = w;
    dev->config.height = h;
    dev->config.windowed = windowed;
    dev->config.aspect_ratio = (float)w / (float)h;

    snprintf(dev->status_message, sizeof(dev->status_message),
             "Render device resized: %ux%u (%s)",
             w, h, windowed ? "Windowed" : "Fullscreen");

    return ROME2_RENDER_OK;
}

/*
 * Reconstruction of FUN_100e6310
 */
rome2_render_status rome2_port_100e6310_init_display(
    rome2_render_device *dev,
    const char *campaign_name_or_null,
    uint32_t width,
    uint32_t height,
    bool windowed)
{
    if (dev == NULL) {
        return ROME2_RENDER_ERR_INVALID_ARGUMENT;
    }

    rome2_render_config cfg;
    cfg.width = (width == 0) ? ROME2_RENDER_DEFAULT_WIDTH : width;
    cfg.height = (height == 0) ? ROME2_RENDER_DEFAULT_HEIGHT : height;
    cfg.refresh_rate = ROME2_RENDER_DEFAULT_REFRESH;
    cfg.windowed = windowed;
    cfg.aspect_ratio = (float)cfg.width / (float)cfg.height;
    cfg.fov = 75.0f;
    cfg.vsync = true;
    cfg.multisample_count = 1;
    cfg.adapter_index = 0;

    const char *camp = (campaign_name_or_null != NULL) ? campaign_name_or_null : "main";
    strncpy_s(cfg.campaign_mode, sizeof(cfg.campaign_mode), camp, _TRUNCATE);

    rome2_render_status st = rome2_render_device_init(dev, &cfg);
    if (st != ROME2_RENDER_OK) {
        return st;
    }

    st = rome2_render_device_create(dev, NULL);
    if (st != ROME2_RENDER_OK) {
        return st;
    }

    strncpy_s(dev->status_message, sizeof(dev->status_message),
              "FUN_100e6310 display initialization complete", _TRUNCATE);

    return ROME2_RENDER_OK;
}
