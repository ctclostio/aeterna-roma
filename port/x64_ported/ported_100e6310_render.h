#ifndef ROME2_PORTED_100E6310_RENDER_H
#define ROME2_PORTED_100E6310_RENDER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_100E6310_RENDER_INIT_PC UINT32_C(0x100e6310)

#define ROME2_RENDER_DEFAULT_WIDTH         1920U
#define ROME2_RENDER_DEFAULT_HEIGHT        1080U
#define ROME2_RENDER_DEFAULT_REFRESH       60U
#define ROME2_RENDER_MAX_DISPLAY_MODES     64U

typedef enum rome2_render_status {
    ROME2_RENDER_OK = 0,
    ROME2_RENDER_ERR_INVALID_ARGUMENT = 1,
    ROME2_RENDER_ERR_DEVICE_CREATION_FAILED = 2,
    ROME2_RENDER_ERR_MODE_NOT_SUPPORTED = 3,
    ROME2_RENDER_ERR_ALREADY_INITIALIZED = 4,
    ROME2_RENDER_ERR_NOT_INITIALIZED = 5,
    ROME2_RENDER_ERR_OUT_OF_MEMORY = 6
} rome2_render_status;

typedef struct rome2_display_mode {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_rate;
    uint32_t format;            /* DXGI_FORMAT_R8G8B8A8_UNORM / D3DFMT_X8R8G8B8 */
} rome2_display_mode;

typedef struct rome2_render_config {
    uint32_t width;
    uint32_t height;
    uint32_t refresh_rate;
    bool windowed;
    float aspect_ratio;
    float fov;
    bool vsync;
    uint32_t multisample_count;
    uint32_t adapter_index;
    char campaign_mode[64];     /* "main", "campaign_edit", etc. */
} rome2_render_config;

typedef struct rome2_render_device {
    bool initialized;
    bool device_active;
    bool is_headless_test_device;
    HWND hwnd;
    rome2_render_config config;
    rome2_display_mode modes[ROME2_RENDER_MAX_DISPLAY_MODES];
    uint32_t mode_count;
    char status_message[128];
} rome2_render_device;

/*
 * Lifecycle and Configuration APIs
 */
rome2_render_status rome2_render_device_init(
    rome2_render_device *dev,
    const rome2_render_config *config_or_null);

void rome2_render_device_shutdown(
    rome2_render_device *dev);

rome2_render_status rome2_render_device_enumerate_modes(
    rome2_render_device *dev);

rome2_render_status rome2_render_device_find_best_mode(
    const rome2_render_device *dev,
    uint32_t target_width,
    uint32_t target_height,
    rome2_display_mode *mode_out);

rome2_render_status rome2_render_device_create(
    rome2_render_device *dev,
    HWND target_hwnd_or_null);

rome2_render_status rome2_render_device_resize(
    rome2_render_device *dev,
    uint32_t new_width,
    uint32_t new_height,
    bool windowed);

/*
 * Native 64-bit reconstruction of FUN_100e6310
 * (Display Mode Query, Viewport Setup, and Render Device Initialization)
 */
rome2_render_status rome2_port_100e6310_init_display(
    rome2_render_device *dev,
    const char *campaign_name_or_null,
    uint32_t width,
    uint32_t height,
    bool windowed);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_100E6310_RENDER_H */
