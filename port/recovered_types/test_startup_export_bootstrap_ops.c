#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "startup_export_bootstrap_ops.h"

static unsigned int g_checks = 0u;

#define CHECK(cond)                                                               \
    do {                                                                          \
        if (!(cond)) {                                                            \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
            return 1;                                                             \
        }                                                                         \
        g_checks++;                                                               \
    } while (0)

static int u16_eq_ascii(const uint16_t *u16, const char *ascii) {
    size_t i = 0u;
    if (!u16 || !ascii) {
        return 0;
    }
    while (ascii[i] != '\0') {
        if (u16[i] != (uint16_t)(uint8_t)ascii[i]) {
            return 0;
        }
        ++i;
    }
    return u16[i] == 0u;
}

static void fill_u16_ascii(uint16_t *dst, size_t cap, const char *src) {
    size_t i = 0u;
    while (src[i] != '\0' && i + 1u < cap) {
        dst[i] = (uint16_t)(uint8_t)src[i];
        ++i;
    }
    dst[i] = 0u;
}

static int verify_rb_invariants(
    const rome2_startup_rb_tree *tree,
    uint32_t idx,
    uint32_t *out_black_height) {
    uint32_t lh = 0u;
    uint32_t rh = 0u;
    if (idx == 0u) {
        *out_black_height = 1u;
        return 1;
    }
    if (idx > ROME2_STARTUP_MAX_RB_NODES || idx > tree->count || tree->nodes[idx].guest.is_nil_29 != 0u) {
        return 0;
    }
    if (tree->nodes[idx].guest.color_28 == 0u) {
        uint32_t l = tree->nodes[idx].left_idx;
        uint32_t r = tree->nodes[idx].right_idx;
        if (l > ROME2_STARTUP_MAX_RB_NODES || r > ROME2_STARTUP_MAX_RB_NODES ||
            tree->nodes[l].guest.color_28 == 0u || tree->nodes[r].guest.color_28 == 0u) {
            return 0;
        }
    }
    if (!verify_rb_invariants(tree, tree->nodes[idx].left_idx, &lh) ||
        !verify_rb_invariants(tree, tree->nodes[idx].right_idx, &rh) ||
        lh != rh) {
        return 0;
    }
    *out_black_height = lh + (tree->nodes[idx].guest.color_28 != 0u ? 1u : 0u);
    return 1;
}

static int test_mod_options_exports(void) {
    rome2_startup_reg_env env;
    rome2_startup_mod_options2_32 opts;

    memset(&env, 0, sizeof(env));
    CHECK(rome2_startup_read_mod_option_reg_bool_11302cc0(&env, "allow_user_script_packs") == 0xffffffffu);
    CHECK(env.cached_subkey_va == 0x117e2eacu); /* Launcher\214950 absent -> cached Rome2 */
    CHECK(rome2_startup_need_to_show_mod_options_notification_113048b0(&env) == 0u);

    /* Enable Launcher\214950 key and test notification + mod options roundtrip */
    memset(&env, 0, sizeof(env));
    env.has_launcher_214950_key = 1u;
    CHECK(rome2_startup_need_to_show_mod_options_notification_113048b0(&env) == 1u);
    CHECK(env.cached_subkey_va == 0x117e2e7cu);
    CHECK(env.write_count == 1u);
    CHECK(rome2_startup_need_to_show_mod_options_notification_113048b0(&env) == 0u);
    CHECK(env.write_count == 1u);
    CHECK(env.open_count == env.close_count);

    /* only_if_missing guard in 0x11303db0 */
    rome2_startup_write_mod_option_reg_bool_11303db0(&env, "allow_user_script_packs", 1u, 1u);
    CHECK(env.write_count == 2u);
    rome2_startup_write_mod_option_reg_bool_11303db0(&env, "allow_user_script_packs", 0u, 1u);
    CHECK(env.write_count == 2u); /* skipped write when already present */
    CHECK(rome2_startup_read_mod_option_reg_bool_11302cc0(&env, "allow_user_script_packs") == 1u);

    /* Export #522 set_or_get_mod_options */
    opts.allow_user_script_packs_00 = 1u;
    opts.allow_unknown_movie_packs_01 = 0u;
    rome2_startup_set_or_get_mod_options_11304980(&env, &opts, 1u);
    CHECK(rome2_startup_read_mod_option_reg_bool_11302cc0(&env, "allow_unknown_movie_packs") == 0u);
    CHECK(rome2_startup_read_mod_option_reg_bool_11302cc0(&env, "allow_user_script_packs") == 1u);

    opts.allow_user_script_packs_00 = 0u;
    opts.allow_unknown_movie_packs_01 = 1u;
    rome2_startup_set_or_get_mod_options_11304980(&env, &opts, 0u);
    CHECK(opts.allow_user_script_packs_00 == 1u);
    CHECK(opts.allow_unknown_movie_packs_01 == 0u);
    return 0;
}

static int test_paths_crash_singleton_and_strstr(void) {
    rome2_startup_path_env *penv = (rome2_startup_path_env *)calloc(1u, sizeof(*penv));
    rome2_startup_crash_singleton *cs = (rome2_startup_crash_singleton *)calloc(1u, sizeof(*cs));
    uint16_t appdata[64];
    uint16_t modpath[128];
    uint16_t out[ROME2_STARTUP_MAX_PATH_U16];
    size_t out_len = 0u;
    uint32_t flags = 0u;
    const uint16_t *cached = NULL;
    CHECK(penv != NULL && cs != NULL);

    CHECK(strcmp(rome2_startup_get_user_folder_subpath_10122e30(0u, &flags), "save_games\\") == 0);
    CHECK(flags == 1u);
    CHECK(strcmp(rome2_startup_get_user_folder_subpath_10122e30(0x11u, &flags), "logs\\") == 0);
    CHECK(flags == 3u);
    CHECK(strcmp(rome2_startup_get_user_folder_subpath_10122e30(49u, &flags), "logs\\graphics\\") == 0);
    CHECK(rome2_startup_get_user_folder_subpath_10122e30(50u, &flags) == NULL);

    fill_u16_ascii(appdata, 64u, "C:\\Users\\Test\\AppData\\Roaming");
    fill_u16_ascii(modpath, 128u, "X:\\depot\\rome2_dev\\build\\binaries\\Rome2.exe");

    penv->appdata_root_u16 = appdata;
    penv->module_file_name_u16 = modpath;
    penv->shgetfolder_ok = 0u;
    CHECK(rome2_startup_resolve_appdata_dir_101016c0(penv, 0x11u, out, ROME2_STARTUP_MAX_PATH_U16, &out_len) ==
          ROME2_VFS_REG_OK);
    CHECK(out_len == 0u && out[0] == 0u);

    /* Normal path without flags */
    penv->shgetfolder_ok = 1u;
    CHECK(rome2_startup_resolve_appdata_dir_101016c0(penv, 0u, out, ROME2_STARTUP_MAX_PATH_U16, &out_len) ==
          ROME2_VFS_REG_OK);
    CHECK(u16_eq_ascii(out, "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2\\save_games\\"));
    CHECK(penv->created_dirs == 1u);

    /* With branch_profile and -sptest */
    memset(penv, 0, sizeof(*penv));
    penv->appdata_root_u16 = appdata;
    penv->module_file_name_u16 = modpath;
    penv->shgetfolder_ok = 1u;
    penv->command_line_a = "Rome2.exe -branch_profile -sptest";
    cached = rome2_startup_get_cached_user_folder_path_10120d90(penv, 0x11u);
    CHECK(cached != NULL);
    CHECK(u16_eq_ascii(
        cached, "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2_rome2_dev_autotest\\logs\\"));
    CHECK(penv->created_dirs == 1u);
    (void)rome2_startup_get_cached_user_folder_path_10120d90(penv, 0x11u);
    CHECK(penv->created_dirs == 1u); /* Cached on repeat lookup */

    /* Crash singleton 0x100e8240 */
    cs->init_epoch = -1;
    CHECK(rome2_startup_crash_reporter_instance_100e8240(cs, penv, 0) == cs);
    CHECK(cs->initialized == 1u && cs->atexit_registered == 1u && cs->zeroed_fields_ok == 1u);
    CHECK(cs->init_epoch == 0);
    CHECK(u16_eq_ascii(
        cs->crash_stack_path,
        "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2_rome2_dev_autotest\\logs\\Crash.stack"));
    CHECK(u16_eq_ascii(
        cs->crash_dmp_path,
        "C:\\Users\\Test\\AppData\\Roaming\\The Creative Assembly\\Rome2_rome2_dev_autotest\\logs\\Crash.dmp"));

    /* strstr across ISA modes 0, 1, 2 */
    for (uint32_t isa = 0u; isa < 3u; ++isa) {
        const char *h = "alpha_beta_gamma";
        CHECK(rome2_startup_strstr_116be670(h, "", isa) == h);
        CHECK(rome2_startup_strstr_116be670(h, "g", isa) == h + 11);
        CHECK(rome2_startup_strstr_116be670(h, "beta", isa) == h + 6);
        CHECK(rome2_startup_strstr_116be670(h, "delta", isa) == NULL);
    }
    free(cs);
    free(penv);
    return 0;
}

static int test_dir_scan_and_rb_tree(void) {
    uint16_t raw[16];
    rome2_startup_utf16_slice sl;
    uint16_t a_u16[8], b_u16[8];
    rome2_startup_utf16_cslice ca, cb;
    rome2_startup_rb_tree *tree = (rome2_startup_rb_tree *)calloc(1u, sizeof(*tree));
    uint32_t bh = 0u;
    uint64_t fsz = 0u;

    static const rome2_startup_dir_entry k_entries[] = {
        { "data", ".", 1u, 0u },
        { "data", "..", 1u, 0u },
        { "data", "Encyclopedia", 1u, 0u },
        { "data", "Manifest.txt", 0u, 100u },
        { "data", "Nomadic.pack", 0u, 200u },
        { "data", "Gaul.pack", 0u, 300u },
        { "data", "Punic.pack", 0u, 400u },
        { "data", "Greeks.pack", 0u, 500u },
        { "data", "Blood.pack", 0u, 600u },
        { "data", "Blood_Rome2.pack", 0u, 700u },
        { "data", "DATA.PACK", 0u, 0x100000005ULL },
        { "data", "Local_EN.pack", 0u, 12345u },
        { "data", "Campaigns", 1u, 0u },
        { "data\\campaigns", "Main_Gaul", 1u, 0u },
        { "data\\campaigns\\main_gaul", "startpos.esf", 0u, 800u },
        { "data\\campaigns\\main_gaul", "Custom.esf", 0u, 999u },
        { "data\\campaigns", "Main_Punic", 1u, 0u },
        { "data\\campaigns\\main_punic", "startpos.esf", 0u, 810u },
        { "data\\campaigns", "Main_Greek", 1u, 0u },
        { "data\\campaigns\\main_greek", "startpos.esf", 0u, 820u },
        { "data\\campaigns", "Encyclopedia", 1u, 0u },
        { "data\\campaigns\\encyclopedia", "Index.html", 0u, 555u },
    };

    CHECK(tree != NULL);
    fill_u16_ascii(raw, 16u, "AbC_123.PACK");
    rome2_startup_utf16_slice_init_lower_ascii_10102c10(&sl, 12u, 16u, raw);
    CHECK(sl.len == 12u && u16_eq_ascii(sl.buf, "abc_123.pack"));

    fill_u16_ascii(a_u16, 8u, "abc");
    fill_u16_ascii(b_u16, 8u, "abcd");
    ca = (rome2_startup_utf16_cslice){ 3u, 8u, a_u16 };
    cb = (rome2_startup_utf16_cslice){ 4u, 8u, b_u16 };
    CHECK(rome2_startup_utf16_slice_compare_100f71b0(&ca, &cb) < 0);
    CHECK(rome2_startup_utf16_slice_compare_100f71b0(&cb, &ca) > 0);
    CHECK(rome2_startup_utf16_slice_compare_100f71b0(&ca, &ca) == 0);
    CHECK(rome2_startup_utf16_slice_less_100f3000(&ca, &cb) == 1u);
    CHECK(rome2_startup_utf16_slice_less_100f3000(&cb, &ca) == 0u);

    rome2_startup_rb_tree_init(tree);
    CHECK(rome2_startup_scan_dir_tree_100e3360(k_entries, sizeof(k_entries) / sizeof(k_entries[0]), "data", "", tree) ==
          ROME2_VFS_REG_OK);
    CHECK(tree->count == 4u); /* data.pack, local_en.pack, campaigns/main_gaul/custom.esf, campaigns/encyclopedia/index.html */
    CHECK(verify_rb_invariants(tree, tree->root_idx, &bh));

    {
        uint16_t k1[64], k2[64], kx[64];
        fill_u16_ascii(k1, 64u, "data.pack");
        CHECK(rome2_startup_rb_find(tree, k1, 9u, NULL, &fsz) == ROME2_VFS_REG_OK);
        CHECK(fsz == 0x100000005ULL);
        fill_u16_ascii(k2, 64u, "campaigns/encyclopedia/index.html");
        CHECK(rome2_startup_rb_find(tree, k2, 33u, NULL, &fsz) == ROME2_VFS_REG_OK);
        CHECK(fsz == 555u);
        fill_u16_ascii(kx, 64u, "campaigns/main_gaul/startpos.esf");
        CHECK(rome2_startup_rb_find(tree, kx, 32u, NULL, &fsz) == ROME2_VFS_REG_NOT_FOUND);
    }

    /* Stress RB rotations across 20 descending keys */
    rome2_startup_rb_tree_init(tree);
    for (uint32_t k = 20u; k >= 1u; --k) {
        char buf[16];
        uint16_t ku[16];
        int n = snprintf(buf, sizeof(buf), "file_%02u.pack", k);
        CHECK(n > 0);
        fill_u16_ascii(ku, 16u, buf);
        CHECK(rome2_startup_rb_insert_hint_100ea5e0(
                  tree, 1u, tree->leftmost_idx, ku, (uint32_t)n, (uint64_t)k, NULL) ==
              ROME2_VFS_REG_OK);
        CHECK(verify_rb_invariants(tree, tree->root_idx, &bh));
    }
    CHECK(tree->count == 20u);
    free(tree);
    return 0;
}

static int test_handlers_timings_perf_and_format(void) {
    uint8_t keeper_b = 0u;
    uint32_t keeper_dw = 0u;
    rome2_startup_crash_singleton *cs = (rome2_startup_crash_singleton *)calloc(1u, sizeof(*cs));
    rome2_startup_path_env *penv = (rome2_startup_path_env *)calloc(1u, sizeof(*penv));
    rome2_startup_handler_queue *queue = (rome2_startup_handler_queue *)calloc(1u, sizeof(*queue));
    uint16_t fmt_u16[32];
    char out_buf[64];
    char diag_buf[96];
    size_t out_len = 0u;
    uint8_t fmt_ok = 0u;
    uint32_t obj12_count = 0u;
    CHECK(cs != NULL && penv != NULL && queue != NULL);

    rome2_startup_set_keeper_flag_101136d0(&keeper_b, 1u);
    rome2_startup_set_keeper_dword_101150f0(&keeper_dw, 0x100d6560u);
    CHECK(keeper_b == 1u && keeper_dw == 0x100d6560u);

    cs->init_epoch = -1;
    cs->alloc_ptrs[0] = 0x20001000u;
    cs->alloc_ptrs[1] = 0x20002000u;
    cs->alloc_ptr_count = 2u;

    queue->fail_on_push_index = UINT32_MAX;
    queue->crash_singleton = cs;
    queue->path_env = penv;
    queue->alloc_tbl.slots[0] = 0x11110000u;
    queue->alloc_tbl.slot3 = 0x33330000u;

    CHECK(rome2_startup_get_allocator_slot_100fcc30(&queue->alloc_tbl, 3) == 0x33330000u);
    CHECK(rome2_startup_get_allocator_slot_100fcc30(&queue->alloc_tbl, 0) == 0x11110000u);

    CHECK(rome2_startup_register_handlers_part1_100ea060(queue) == ROME2_VFS_REG_OK);
    CHECK(queue->count == 23u);
    CHECK(queue->items[0].vtable_va == 0x1173f22cu);
    CHECK(queue->items[22].vtable_va == 0x1173f2d4u);
    CHECK(cs->virtual_free_count == 2u && cs->alloc_ptr_count == 0u);
    CHECK(cs->has_perf_config == 1u);
    CHECK(cs->perf_config.sentinel_04 == 0xffffffffu);
    CHECK(cs->perf_config.val_14 == 0x3f800000u);
    CHECK(cs->perf_config.val_30 == 0x3dcccccdu);
    CHECK(cs->perf_config.val_7c == 0x41700000u);
    CHECK(cs->perf_config.val_b0 == 0x7f7fffffu);
    CHECK(strcmp(queue->timing_env.active_label, "POST_DB_APP_INIT") == 0);
    CHECK(strcmp(queue->timing_env.log_banner, "POST_DB_APP_INIT: section timings initialised\n") == 0);
    CHECK(queue->timing_env.cached_allocator == 0x33330000u);

    CHECK(rome2_startup_register_handlers_part2_100ea4d0(queue) == ROME2_VFS_REG_OK);
    CHECK(queue->count == 29u);
    CHECK(queue->items[23].vtable_va == 0x1173f20cu);
    CHECK(queue->items[28].vtable_va == 0x1173f2dcu);
    for (uint32_t i = 0u; i < queue->count; ++i) {
        if (queue->items[i].alloc_bytes == 0x0cu) {
            obj12_count += 1u;
            CHECK(queue->items[i].vtable_va == 0x1173f2acu);
        } else {
            CHECK(queue->items[i].alloc_bytes == 4u);
        }
    }
    CHECK(obj12_count == 1u);

    /* Section timings growth check */
    CHECK(rome2_startup_init_section_timings_112dc9f0(&queue->timing_env, &queue->alloc_tbl, "BOOT", 8u, 4242u) ==
          ROME2_VFS_REG_OK);
    CHECK(queue->timing_env.alloc_cap == 8u && queue->timing_env.init_start_ms == 4242u);

    /* Formatters 0x101c89e0 / 0x100de500 / 0x100f4920 */
    {
        const char *args[1] = { "Rome2" };
        fill_u16_ascii(fmt_u16, 32u, "[%ls] ok");
        CHECK(rome2_startup_format_ansi_va_101c89e0(
                  fmt_u16, args, 1u, out_buf, sizeof(out_buf), &out_len, &fmt_ok, diag_buf, sizeof(diag_buf)) ==
              ROME2_VFS_REG_OK);
        CHECK(fmt_ok == 1u && strcmp(out_buf, "[Rome2] ok") == 0);

        fill_u16_ascii(fmt_u16, 32u, "val=%d");
        memset(diag_buf, 0, sizeof(diag_buf));
        CHECK(rome2_startup_format_ansi_va_101c89e0(
                  fmt_u16, args, 1u, out_buf, sizeof(out_buf), &out_len, &fmt_ok, diag_buf, sizeof(diag_buf)) ==
              ROME2_VFS_REG_OK);
        CHECK(fmt_ok == 0u);
        CHECK(strcmp(diag_buf, "Unexpected format %d used with type const char*") == 0);
    }
    free(queue);
    free(penv);
    free(cs);
    return 0;
}

int main(void) {
    if (test_mod_options_exports() != 0 ||
        test_paths_crash_singleton_and_strstr() != 0 ||
        test_dir_scan_and_rb_tree() != 0 ||
        test_handlers_timings_perf_and_format() != 0) {
        return 1;
    }
    printf("test_startup_export_bootstrap_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
