#include "startup_input_msg_console_ops.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned g_checks = 0u;

static void check_impl(int cond, const char *expr, int line) {
    if (!cond) {
        fprintf(stderr, "CHECK FAILED line %d: %s\n", line, expr);
        exit(1);
    }
    g_checks += 1u;
}

#define CHECK(cond) check_impl((cond) != 0, #cond, __LINE__)

static void fill_u16_ascii(uint16_t *dst, size_t cap, const char *s) {
    size_t i = 0u;
    while (s[i] != '\0' && i + 1u < cap) {
        dst[i] = (uint8_t)s[i];
        i += 1u;
    }
    dst[i] = 0u;
}

static size_t u16_len(const uint16_t *s) {
    size_t n = 0u;
    while (s[n] != 0u) {
        n += 1u;
    }
    return n;
}

static int u16_eq_ascii(const uint16_t *s, const char *ascii) {
    size_t i = 0u;
    while (ascii[i] != '\0') {
        if (s[i] != (uint8_t)ascii[i]) {
            return 0;
        }
        i += 1u;
    }
    return s[i] == 0u;
}

static void test_layouts_math_power_msg_dinput(void) {
    uint64_t a = 5000000ULL;
    uint64_t b = 1500000ULL;
    uint64_t diff = 0ULL;
    double d_hi = 0.0;
    float sec_f = 0.0f;
    rome2_startup_sys_power_status12_32 pwr_raw;
    rome2_startup_power_info pwr_out;
    rome2_startup_msg_pump_env pump;
    rome2_startup_dinput_env *di =
        (rome2_startup_dinput_env *)calloc(1u, sizeof(*di));

    CHECK(di != NULL);
    CHECK(sizeof(rome2_startup_dinput_mouse16_32) == 0x10u);
    CHECK(offsetof(rome2_startup_dinput_mouse16_32, rgb_buttons_0c) == 0x0cu);
    CHECK(sizeof(rome2_startup_mouse_pub16_32) == 0x10u);
    CHECK(offsetof(rome2_startup_mouse_pub16_32, btn2_0d) == 0x0du);
    CHECK(offsetof(rome2_startup_mouse_pub16_32, btn1_0e) == 0x0eu);
    CHECK(sizeof(rome2_startup_sys_power_status12_32) == 0x0cu);
    CHECK(offsetof(rome2_startup_sys_power_status12_32, battery_life_time_04) == 4u);
    CHECK(sizeof(rome2_startup_console_node_prefix64_32) == 0x40u);
    CHECK(offsetof(rome2_startup_console_node_prefix64_32, index_34) == 0x34u);
    CHECK(offsetof(rome2_startup_console_node_prefix64_32, tag_or_slot_3c) == 0x3cu);

    CHECK(rome2_startup_get_vfs_flag_112bff20(0u) == 0u);
    CHECK(rome2_startup_get_vfs_flag_112bff20(1u) == 1u);

    rome2_startup_sub_u64_112ac3f0(&diff, &a, &b);
    CHECK(diff == 3500000ULL);
    CHECK(rome2_startup_u64_us_to_ms_112e2c20(diff) == 3500u);
    sec_f = rome2_startup_u64_us_to_seconds_112e2b00(diff);
    CHECK(fabsf(sec_f - 3.5f) < 1e-4f);
    d_hi = rome2_startup_crt_ultod3_11683d60(0x80000001u, 1u);
    CHECK(fabs(d_hi - 6442450945.0) < 1.0);

    memset(&pwr_raw, 0, sizeof(pwr_raw));
    pwr_raw.ac_line_status_00 = 0u;
    pwr_raw.battery_flag_01 = 0x0Au; /* low | charging */
    pwr_raw.battery_life_time_04 = 900u;
    CHECK(rome2_startup_query_power_info_10101980(&pwr_out, &pwr_raw) == &pwr_out);
    CHECK(pwr_out.ac_status == 1 && pwr_out.battery_state == 1);
    CHECK(pwr_out.is_charging == 1u && pwr_out.battery_life_time_sec == 900u);

    pwr_raw.ac_line_status_00 = 1u;
    pwr_raw.battery_flag_01 = 0x80u;
    CHECK(rome2_startup_query_power_info_10101980(&pwr_out, &pwr_raw)->ac_status == 0);
    CHECK(pwr_out.battery_state == 3);

    memset(&pump, 0, sizeof(pump));
    pump.count = 3u;
    pump.queue[0].message = 0x0100u;
    pump.queue[1].message = ROME2_STARTUP_MSG_WM_QUIT;
    pump.queue[2].message = 0x0200u;
    CHECK(rome2_startup_pump_messages_101061b0(&pump) == 1u);
    CHECK(pump.cursor == 2u && pump.dispatched_count == 2u);

    pump.cursor = 0u;
    pump.count = 2u;
    pump.queue[0].message = 0x0119u;
    pump.queue[1].message = 0x0100u;
    CHECK(rome2_startup_pump_messages_101061b0(&pump) == 0x100u);
    CHECK(pump.cursor == 1u);

    di->has_keyboard = 1u;
    di->has_mouse = 1u;
    di->curr_keys[0x1eu] = 0x80u;
    di->kbd_poll_hr = ROME2_STARTUP_DIERR_INPUTLOST;
    di->next_keys[0x20u] = 0x80u;
    di->next_mouse.lX_00 = 15;
    di->next_mouse.lY_04 = -8;
    di->next_mouse.lZ_08 = 120;
    di->next_mouse.rgb_buttons_0c[0] = 0x80u;
    di->next_mouse.rgb_buttons_0c[1] = 0x00u;
    di->next_mouse.rgb_buttons_0c[2] = 0x80u;
    CHECK(rome2_startup_poll_dinput_1010eda0(di) == 1u);
    CHECK(di->kbd_acquire_calls == 1u && di->prev_keys[0x1eu] == 0x80u && di->curr_keys[0x20u] == 0x80u);
    CHECK(fabsf(di->pub_mouse.dx_f32_00 - 15.0f) < 1e-5f);
    CHECK(fabsf(di->pub_mouse.neg_dy_f32_04 - 8.0f) < 1e-5f);
    CHECK(fabsf(di->pub_mouse.neg_dz_f32_08 - (-120.0f)) < 1e-5f);
    CHECK(di->pub_mouse.btn0_0c == 1u && di->pub_mouse.btn2_0d == 1u && di->pub_mouse.btn1_0e == 0u);

    di->mouse_poll_hr = ROME2_STARTUP_DIERR_NOTACQUIRED;
    di->mouse_retry_hr = 0x80004005u;
    CHECK(rome2_startup_poll_dinput_1010eda0(di) == 0u);
    CHECK(di->mouse_unacquire_calls == 1u);
    free(di);
}

static void test_rb_tree_strings_paths_and_filebuf(void) {
    rome2_startup_rb_tree *tree =
        (rome2_startup_rb_tree *)calloc(1u, sizeof(*tree));
    rome2_startup_path_env *penv =
        (rome2_startup_path_env *)calloc(1u, sizeof(*penv));
    rome2_startup_crt_stdio_env *crt =
        (rome2_startup_crt_stdio_env *)calloc(1u, sizeof(*crt));
    rome2_startup_crt_stream_model *fb_stream =
        (rome2_startup_crt_stream_model *)calloc(1u, sizeof(*fb_stream));
    rome2_startup_wfstream_filebuf_state fb;
    static const uint16_t k_keys[5][2] = { {'b',0}, {'a',0}, {'d',0}, {'c',0}, {'e',0} };
    uint32_t ids[5] = {0};
    uint32_t cur = 0u;
    uint16_t appdata[64];
    uint16_t u16_out[160];
    uint16_t u16_rhs[16];
    char cbuf[64];
    char diag[80];
    size_t clen = 0u;
    rome2_startup_utf16_cslice sl_l;
    rome2_startup_utf16_cslice sl_r;

    CHECK(tree != NULL && penv != NULL && crt != NULL && fb_stream != NULL);
    rome2_startup_rb_tree_init(tree);
    CHECK(rome2_startup_rb_insert_hint_100ea5e0(tree, 1u, 0u, k_keys[0], 1u, 10ULL, &ids[0]) == ROME2_VFS_REG_OK);
    CHECK(rome2_startup_rb_insert_hint_100ea5e0(tree, 1u, ids[0], k_keys[1], 1u, 20ULL, &ids[1]) == ROME2_VFS_REG_OK);
    CHECK(rome2_startup_rb_insert_hint_100ea5e0(tree, 0u, ids[0], k_keys[2], 1u, 30ULL, &ids[2]) == ROME2_VFS_REG_OK);
    CHECK(rome2_startup_rb_insert_hint_100ea5e0(tree, 1u, ids[2], k_keys[3], 1u, 40ULL, &ids[3]) == ROME2_VFS_REG_OK);
    CHECK(rome2_startup_rb_insert_hint_100ea5e0(tree, 0u, ids[2], k_keys[4], 1u, 50ULL, &ids[4]) == ROME2_VFS_REG_OK);

    CHECK(rome2_startup_dir_rb_min_100eac10(tree, tree->root_idx) == ids[1]);
    CHECK(rome2_startup_dir_rb_max_100eabf0(tree, tree->root_idx) == ids[4]);
    cur = tree->leftmost_idx;
    rome2_startup_dir_rb_iter_next_100e0ff0(tree, &cur);
    CHECK(cur == ids[0]);

    /* Erase root/internal two-child node and leaf/min node */
    cur = rome2_startup_dir_rb_erase_100e7960(tree, ids[0]);
    CHECK(cur == ids[3] && tree->count == 4u);
    cur = rome2_startup_dir_rb_erase_100e7960(tree, ids[1]);
    CHECK(tree->leftmost_idx == ids[3] && tree->count == 3u);
    rome2_startup_dir_rb_erase_subtree_100e7920(tree, tree->root_idx);
    CHECK(tree->count == 0u);

    CHECK(rome2_startup_concat_cstr_and_str_100f2d60(
              "Warscape/Reload ", "FX", cbuf, sizeof(cbuf), &clen) == ROME2_VFS_REG_OK);
    CHECK(strcmp(cbuf, "Warscape/Reload FX") == 0 && clen == 18u);

    fill_u16_ascii(u16_out, 160u, "alpha\\save");
    fill_u16_ascii(u16_rhs, 16u, "save");
    sl_l.len = (uint32_t)u16_len(u16_out);
    sl_l.cap = 160u;
    sl_l.buf = u16_out;
    sl_r.len = (uint32_t)u16_len(u16_rhs);
    sl_r.cap = 16u;
    sl_r.buf = u16_rhs;
    CHECK(rome2_startup_utf16_slice_compare_range_100f7260(&sl_l, 6u, UINT32_MAX, &sl_r) == 0);
    CHECK(rome2_startup_utf16_slice_rfind_char_10114380(&sl_l, '\\', UINT32_MAX) == 5);
    CHECK(rome2_startup_utf16_slice_rfind_char_10114380(&sl_l, 'z', UINT32_MAX) == -1);

    clen = 0u;
    u16_out[0] = 0u;
    diag[0] = '\0';
    CHECK(rome2_startup_format_utf16_str_spec_100f5f20(
              u16_out, 160u, &clen, 'd', u16_rhs, diag, sizeof(diag)) == 0u);
    CHECK(strcmp(diag, "Unexpected format %d used with type const UniChar16*") == 0);
    CHECK(rome2_startup_format_utf16_str_spec_100f5f20(
              u16_out, 160u, &clen, 's', u16_rhs, diag, sizeof(diag)) == 1u);
    CHECK(u16_eq_ascii(u16_out, "save"));

    fill_u16_ascii(appdata, 64u, "C:\\Users\\Test\\AppData\\Roaming");
    penv->appdata_root_u16 = appdata;
    penv->shgetfolder_ok = 1u;
    CHECK(rome2_startup_format_user_appdata_rel_100ddfc0(penv, u16_out, 160u, &clen) == ROME2_VFS_REG_OK);
    CHECK(u16_eq_ascii(
        u16_out, "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\scripts\\user.script.txt"));
    /* Direct test for omitted suffix when rel already ends with col0 suffix ".save" */
    fill_u16_ascii(u16_rhs, 16u, "mod.save");
    CHECK(rome2_startup_build_user_subpath_10121350(penv, 0u, u16_rhs, u16_out, 160u, &clen) == ROME2_VFS_REG_OK);
    CHECK(u16_eq_ascii(
        u16_out, "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\save_games\\mod.save"));
    /* Normal test where ".save" suffix is appended */
    fill_u16_ascii(u16_rhs, 16u, "sub\\game");
    CHECK(rome2_startup_build_user_subpath_10121350(penv, 0u, u16_rhs, u16_out, 160u, &clen) == ROME2_VFS_REG_OK);
    CHECK(u16_eq_ascii(
        u16_out, "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\save_games\\sub\\game.save"));

    crt->nhandle = 4u;
    crt->io_slots[2].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[2].osfhnd_18 = 0x222u;
    fb_stream->guest.file_10 = 2;
    fb_stream->guest.flags_0c = ROME2_STARTUP_IOALLOCATED | ROME2_STARTUP_IOBUFFER_CRT;
    fb_stream->guest.bufsiz_18 = 16;
    rome2_startup_wfstream_filebuf_init_open_11349100(&fb, fb_stream, 1, 0xCAFEu);
    CHECK(fb.is_wide_mode_3c == 1u && fb.locale_38 == 0xCAFEu && fb.file_40 == fb_stream);
    CHECK(rome2_startup_wfstream_filebuf_close_11347290(&fb, crt, 0xBEEFu) == &fb);
    CHECK(fb.is_wide_mode_3c == 0u && fb.file_40 == NULL && fb.locale_38 == 0xBEEFu);

    free(fb_stream);
    free(crt);
    free(penv);
    free(tree);
}

static void test_warscape_console_registry(void) {
    rome2_startup_console_registry_env *reg =
        (rome2_startup_console_registry_env *)calloc(1u, sizeof(*reg));
    rome2_startup_warscape_console_group *grp =
        (rome2_startup_warscape_console_group *)calloc(1u, sizeof(*grp));
    rome2_startup_ptr_vec12 vec;
    size_t i = 0u;

    CHECK(reg != NULL && grp != NULL);
    memset(&vec, 0, sizeof(vec));
    reg->handler_va = 0x70001000u;
    reg->crash_singleton_va = 0x80001000u;
    for (i = 0u; i < 5u; ++i) {
        reg->crash_iface_slots[i] = 0x90000000u + (uint32_t)i;
    }

    CHECK(rome2_startup_handler_warscape_console_init_100e8660(
              reg, 0x1234u, 0x50000000u, grp, &vec) == 1u);
    CHECK(reg->handler_vtable_00 == ROME2_STARTUP_VTABLE_CONSOLE_HANDLER);
    CHECK(reg->global_registry_va == 0x60001004u);
    CHECK(reg->registry_vtable_00 == ROME2_STARTUP_VTABLE_CONSOLE_REG);
    CHECK(reg->registry_observer_vtable_3c == ROME2_STARTUP_VTABLE_OBSERVER_NODE);
    CHECK(reg->cfg_field_04 == 0x5000080cu && reg->cfg_field_08 == 0x1000u);
    CHECK(reg->registered_count == 7u);
    CHECK(strcmp(grp->slots[0].name, "Warscape/Show profiler") == 0);
    CHECK(strcmp(grp->slots[1].name, "Warscape/Reload FX") == 0);
    CHECK(strcmp(grp->slots[2].name, "Warscape/Reload Textures") == 0);
    CHECK(grp->slots[1].layout.vtable_00 == ROME2_STARTUP_VTABLE_WARSCAPE_RELOAD);
    CHECK(grp->slots[0].layout.vtable_00 == ROME2_STARTUP_VTABLE_WARSCAPE_CVAR);
    CHECK(strcmp(grp->slots[7].name, "Warscape/TexelDensity") == 0);

    vec.count = 2u;
    vec.element_vas[0] = 0x71001000u;
    vec.element_vas[1] = 0x71002000u;
    vec.backing_va = 0x71000000u;

    CHECK(rome2_startup_handler_warscape_console_dtor_100e12e0(reg, 1u) == 0x70001000u);
    CHECK(vec.destroyed_count == 2u && vec.backing_freed == 1u);
    CHECK(grp->destroyed_count == 7u);
    CHECK(reg->global_registry_va == 0u && reg->handler_vtable_00 == ROME2_STARTUP_VTABLE_BASE_ADAPTER);
    CHECK(reg->freed_count == 4u);

    free(grp);
    free(reg);
}

int main(void) {
    test_layouts_math_power_msg_dinput();
    test_rb_tree_strings_paths_and_filebuf();
    test_warscape_console_registry();
    printf("test_startup_input_msg_console_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
