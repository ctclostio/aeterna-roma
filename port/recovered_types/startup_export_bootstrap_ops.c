#include "startup_export_bootstrap_ops.h"

#include <stdio.h>
#include <string.h>

typedef struct l59_user_folder_row {
    const char *subpath;
    uint32_t flags;
} l59_user_folder_row;

static const l59_user_folder_row g_user_folders[ROME2_STARTUP_USER_FOLDER_COUNT] = {
    { "save_games\\", 1u },                       /* 00 */
    { "save_games_multiplayer\\", 1u },           /* 01 */
    { "replays\\", 1u },                          /* 02 */
    { "logs\\", 3u },                             /* 03 */
    { "logs\\campaign_ai\\", 3u },                /* 04 */
    { "logs\\campaign_ai\\", 3u },                /* 05 */
    { "logs\\campaign_ai\\", 3u },                /* 06 */
    { "logs\\campaign_ai\\", 3u },                /* 07 */
    { "scripts\\", 1u },                          /* 08 */
    { "editor\\", 1u },                           /* 09 */
    { "editor\\", 1u },                           /* 10 */
    { "screenshots\\", 2u },                      /* 11 */
    { "editor\\", 0u },                           /* 12 */
    { "editor\\", 0u },                           /* 13 */
    { "custom_keys\\", 1u },                      /* 14 */
    { "battle_preferences\\", 1u },               /* 15 */
    { "army_setups\\", 1u },                      /* 16 */
    { "logs\\", 3u },                             /* 17 (0x11) */
    { "fx_cache\\", 0u },                         /* 18 */
    { "editor_fx_cache\\", 0u },                  /* 19 */
    { "advice_history\\", 0u },                   /* 20 */
    { "logs\\campaign_ai\\", 3u },                /* 21 */
    { "ui_cache\\", 0u },                         /* 22 */
    { "logs\\campaign_ai\\", 3u },                /* 23 */
    { "logs\\director\\", 3u },                   /* 24 */
    { "logs\\director\\", 3u },                   /* 25 */
    { "logs\\campaign_ai\\", 3u },                /* 26 */
    { "Profile\\", 1u },                          /* 27 */
    { "avatar\\", 0u },                           /* 28 */
    { "avatar\\", 0u },                           /* 29 */
    { "campaign_preferences\\", 1u },             /* 30 */
    { "logs\\init_timing\\", 3u },                /* 31 */
    { "maps\\", 0u },                             /* 32 */
    { "temp\\", 0u },                             /* 33 */
    { "camera bookmarks\\", 1u },                 /* 34 */
    { "console_spools\\", 0u },                   /* 35 */
    { "logs\\", 3u },                             /* 36 */
    { "logs\\battle_visibility_debug\\cpu\\", 3u }, /* 37 */
    { "logs\\battle_visibility_debug\\gpu\\", 3u }, /* 38 */
    { "logs\\campaign_ai\\", 3u },                /* 39 */
    { "benchmarks\\", 1u },                       /* 40 */
    { "resume\\", 0u },                           /* 41 */
    { "battle_preferences\\", 1u },               /* 42 */
    { "chat\\", 0u },                             /* 43 */
    { "logs\\campaign_ai\\", 0u },                /* 44 */
    { "texturedb\\", 0u },                        /* 45 */
    { "logs\\campaign_ai\\", 3u },                /* 46 */
    { "logs\\campaign_ai\\diplomacy\\", 3u },     /* 47 */
    { "registry\\", 1u },                         /* 48 */
    { "logs\\graphics\\", 3u },                   /* 49 */
};

static const char *const g_excluded_rel_paths[] = {
    "manifest.txt",
    "nomadic.pack",
    "gaul.pack",
    "campaigns/main_gaul/startpos.esf",
    "punic.pack",
    "campaigns/main_punic/startpos.esf",
    "greeks.pack",
    "campaigns/main_greek/startpos.esf",
    "blood.pack",
    "blood_rome2.pack",
};

static const uint32_t g_part1_vtables_before_clean[6] = {
    0x1173f22cu,
    0x1173f24cu,
    0x1173f234u,
    0x1173f23cu,
    0x1173f264u,
    0x1173f26cu,
};

static const uint32_t g_part1_vtables_mid[2] = {
    0x1173f244u,
    0x1173f254u,
};

static const uint32_t g_part1_vtables_post_timing[14] = {
    0x1173f274u,
    0x1173f27cu,
    0x1173f284u,
    0x1173f28cu,
    0x1173f294u,
    0x1173f2acu, /* 12-byte object */
    0x1173f2b4u,
    0x1173f25cu,
    0x1173f2e4u,
    0x1173f2bcu,
    0x1173f2c4u,
    0x1173f29cu,
    0x1173f2a4u,
    0x1173f2ccu,
};

static const uint32_t g_part2_vtables[6] = {
    0x1173f20cu,
    0x1173f214u,
    0x1173f21cu,
    0x1173f224u,
    0x1173f2ecu,
    0x1173f2dcu,
};

static size_t l59_u16_len(const uint16_t *s) {
    size_t n = 0u;
    if (!s) {
        return 0u;
    }
    while (s[n] != 0u) {
        ++n;
    }
    return n;
}

static uint8_t l59_ascii_tolower(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + ('a' - 'A')) : c;
}

static rome2_vfs_reg_status l59_append_ascii_to_u16(
    const char *src,
    uint16_t *dst,
    size_t dst_cap,
    size_t *inout_len) {
    size_t i = 0u;
    size_t pos = *inout_len;
    if (!src || !dst || pos >= dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; src[i] != '\0'; ++i) {
        if (pos + 1u >= dst_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        dst[pos++] = (uint8_t)src[i];
    }
    dst[pos] = 0u;
    *inout_len = pos;
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status l59_append_u16_to_u16(
    const uint16_t *src,
    size_t count,
    uint16_t *dst,
    size_t dst_cap,
    size_t *inout_len) {
    size_t i = 0u;
    size_t pos = *inout_len;
    if (!src || !dst || pos >= dst_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    for (i = 0u; i < count; ++i) {
        if (pos + 1u >= dst_cap) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        dst[pos++] = src[i];
    }
    dst[pos] = 0u;
    *inout_len = pos;
    return ROME2_VFS_REG_OK;
}

static void l59_path_append_u16_sep(
    uint16_t *dst,
    size_t dst_cap,
    size_t *inout_len,
    const uint16_t *more,
    size_t more_len) {
    size_t pos = *inout_len;
    if (!dst || !more || more_len == 0u || pos >= dst_cap) {
        return;
    }
    if (pos > 0u && dst[pos - 1u] != L'\\' && dst[pos - 1u] != L'/' && more[0] != L'\\' && more[0] != L'/') {
        if (pos + 1u >= dst_cap) {
            return;
        }
        dst[pos++] = L'\\';
        dst[pos] = 0u;
    }
    *inout_len = pos;
    (void)l59_append_u16_to_u16(more, more_len, dst, dst_cap, inout_len);
}

static void l59_ensure_reg_root(rome2_startup_reg_env *env) {
    if (!env || env->cached_subkey_va != 0u) {
        return;
    }
    if (env->has_launcher_214950_key != 0u) {
        env->open_count += 1u;
        env->close_count += 1u;
        env->cached_subkey_va = 0x117e2e7cu;
    } else {
        env->cached_subkey_va = 0x117e2eacu;
    }
}

static uint8_t l59_reg_open_active_key(const rome2_startup_reg_env *env) {
    if (!env) {
        return 0u;
    }
    if (env->cached_subkey_va == 0x117e2e7cu) {
        return env->has_launcher_214950_key;
    }
    return env->has_rome2_key;
}

static int32_t l59_find_reg_entry(const rome2_startup_reg_env *env, const char *name) {
    uint32_t i = 0u;
    if (!env || !name) {
        return -1;
    }
    for (i = 0u; i < env->entry_count && i < ROME2_STARTUP_MAX_REG_ENTRIES; ++i) {
        if (env->entries[i].valid && strcmp(env->entries[i].name, name) == 0) {
            return (int32_t)i;
        }
    }
    return -1;
}

uint32_t rome2_startup_read_mod_option_reg_bool_11302cc0(
    rome2_startup_reg_env *env,
    const char *value_name) {
    int32_t idx = -1;
    if (!env || !value_name) {
        return 0xffffffffu;
    }
    l59_ensure_reg_root(env);
    if (!l59_reg_open_active_key(env)) {
        return 0xffffffffu;
    }
    env->open_count += 1u;
    idx = l59_find_reg_entry(env, value_name);
    env->close_count += 1u;
    if (idx < 0) {
        return 0xffffffffu;
    }
    return (env->entries[idx].value != 0u) ? 1u : 0u;
}

void rome2_startup_write_mod_option_reg_bool_11303db0(
    rome2_startup_reg_env *env,
    const char *value_name,
    uint8_t value,
    uint8_t only_if_missing) {
    int32_t idx = -1;
    size_t nlen = 0u;
    if (!env || !value_name) {
        return;
    }
    l59_ensure_reg_root(env);
    if (!l59_reg_open_active_key(env)) {
        return;
    }
    env->open_count += 1u;
    idx = l59_find_reg_entry(env, value_name);
    if (only_if_missing != 0u && idx >= 0) {
        env->close_count += 1u;
        return;
    }
    if (idx >= 0) {
        env->entries[idx].value = (uint32_t)value;
        env->write_count += 1u;
    } else if (env->entry_count < ROME2_STARTUP_MAX_REG_ENTRIES) {
        nlen = strlen(value_name);
        if (nlen < sizeof(env->entries[0].name)) {
            uint32_t slot = env->entry_count++;
            memset(&env->entries[slot], 0, sizeof(env->entries[slot]));
            memcpy(env->entries[slot].name, value_name, nlen + 1u);
            env->entries[slot].value = (uint32_t)value;
            env->entries[slot].valid = 1u;
            env->write_count += 1u;
        }
    }
    env->close_count += 1u;
}

uint8_t rome2_startup_need_to_show_mod_options_notification_113048b0(
    rome2_startup_reg_env *env) {
    int32_t idx = -1;
    uint8_t ret = 0u;
    if (!env) {
        return 0u;
    }
    l59_ensure_reg_root(env);
    if (!l59_reg_open_active_key(env)) {
        return 0u;
    }
    env->open_count += 1u;
    idx = l59_find_reg_entry(env, "show_new_options_notification");
    if (idx < 0 || env->entries[idx].value != ROME2_STARTUP_MOD_OPT_NOTIFY_EXPECTED) {
        if (idx >= 0) {
            env->entries[idx].value = ROME2_STARTUP_MOD_OPT_NOTIFY_EXPECTED;
            env->write_count += 1u;
        } else if (env->entry_count < ROME2_STARTUP_MAX_REG_ENTRIES) {
            uint32_t slot = env->entry_count++;
            const char *k = "show_new_options_notification";
            memset(&env->entries[slot], 0, sizeof(env->entries[slot]));
            memcpy(env->entries[slot].name, k, strlen(k) + 1u);
            env->entries[slot].value = ROME2_STARTUP_MOD_OPT_NOTIFY_EXPECTED;
            env->entries[slot].valid = 1u;
            env->write_count += 1u;
        }
        ret = 1u;
    }
    env->close_count += 1u;
    return ret;
}

void rome2_startup_set_or_get_mod_options_11304980(
    rome2_startup_reg_env *env,
    rome2_startup_mod_options2_32 *options,
    uint8_t write_mode) {
    int32_t v = 0;
    if (!env || !options) {
        return;
    }
    if (write_mode == 0u) {
        v = (int32_t)rome2_startup_read_mod_option_reg_bool_11302cc0(env, "allow_unknown_movie_packs");
        options->allow_unknown_movie_packs_01 = (v > 0) ? 1u : 0u;
        v = (int32_t)rome2_startup_read_mod_option_reg_bool_11302cc0(env, "allow_user_script_packs");
        options->allow_user_script_packs_00 = (v > 0) ? 1u : 0u;
        return;
    }
    rome2_startup_write_mod_option_reg_bool_11303db0(
        env, "allow_unknown_movie_packs", options->allow_unknown_movie_packs_01, 0u);
    rome2_startup_write_mod_option_reg_bool_11303db0(
        env, "allow_user_script_packs", options->allow_user_script_packs_00, 0u);
}

const char *rome2_startup_get_user_folder_subpath_10122e30(
    uint32_t category_idx,
    uint32_t *out_flags) {
    if (category_idx >= ROME2_STARTUP_USER_FOLDER_COUNT) {
        return NULL;
    }
    if (out_flags) {
        *out_flags = g_user_folders[category_idx].flags;
    }
    return g_user_folders[category_idx].subpath;
}

rome2_vfs_reg_status rome2_startup_utf16_concat_100e1050(
    const uint16_t *prefix_u16,
    const uint16_t *suffix_u16,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len) {
    size_t plen = 0u;
    size_t slen = 0u;
    if (!prefix_u16 || !suffix_u16 || !out_u16 || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    plen = l59_u16_len(prefix_u16);
    slen = l59_u16_len(suffix_u16);
    if (plen + slen + 1u > out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    if (plen > 0u) {
        memcpy(out_u16, prefix_u16, plen * sizeof(uint16_t));
    }
    if (slen > 0u) {
        memcpy(out_u16 + plen, suffix_u16, slen * sizeof(uint16_t));
    }
    out_u16[plen + slen] = 0u;
    if (out_len) {
        *out_len = plen + slen;
    }
    return ROME2_VFS_REG_OK;
}

static ptrdiff_t l59_find_u16_substr(const uint16_t *hay, size_t hay_len, const char *needle_ascii) {
    size_t nlen = strlen(needle_ascii);
    size_t i = 0u;
    if (nlen == 0u || hay_len < nlen) {
        return -1;
    }
    for (i = 0u; i + nlen <= hay_len; ++i) {
        size_t j = 0u;
        uint8_t eq = 1u;
        for (j = 0u; j < nlen; ++j) {
            if (hay[i + j] != (uint16_t)(uint8_t)needle_ascii[j]) {
                eq = 0u;
                break;
            }
        }
        if (eq) {
            return (ptrdiff_t)i;
        }
    }
    return -1;
}

rome2_vfs_reg_status rome2_startup_resolve_appdata_dir_101016c0(
    rome2_startup_path_env *env,
    uint32_t category_idx,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len) {
    uint16_t profile_dir[128];
    size_t prof_len = 0u;
    uint16_t work_u16[ROME2_STARTUP_MAX_PATH_U16];
    size_t work_len = 0u;
    const char *subpath = NULL;
    size_t i = 0u;

    if (!env || !out_u16 || out_cap == 0u || category_idx >= ROME2_STARTUP_USER_FOLDER_COUNT) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (out_len) {
        *out_len = 0u;
    }
    out_u16[0] = 0u;

    memset(profile_dir, 0, sizeof(profile_dir));
    if (l59_append_ascii_to_u16("Rome2\\", profile_dir, 128u, &prof_len) != ROME2_VFS_REG_OK) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }

    if (env->command_line_a &&
        rome2_startup_strstr_116be670(env->command_line_a, "branch_profile", 2u) != NULL &&
        env->module_file_name_u16 != NULL) {
        uint16_t mod_buf[ROME2_STARTUP_MAX_PATH_U16];
        size_t mod_len = l59_u16_len(env->module_file_name_u16);
        ptrdiff_t cut = -1;
        size_t sep_pos = 0u;
        uint8_t found_sep = 0u;
        if (mod_len >= ROME2_STARTUP_MAX_PATH_U16) {
            mod_len = ROME2_STARTUP_MAX_PATH_U16 - 1u;
        }
        memset(mod_buf, 0, sizeof(mod_buf));
        if (mod_len > 0u) {
            memcpy(mod_buf, env->module_file_name_u16, mod_len * sizeof(uint16_t));
        }
        mod_buf[mod_len] = 0u;
        cut = l59_find_u16_substr(mod_buf, mod_len, "\\src\\..");
        if (cut < 0) {
            cut = l59_find_u16_substr(mod_buf, mod_len, "\\binaries");
        }
        if (cut >= 0) {
            mod_len = (size_t)cut;
            mod_buf[mod_len] = 0u;
        }
        for (i = mod_len; i > 0u; --i) {
            if (mod_buf[i - 1u] == L'\\') {
                mod_len = i - 1u;
                mod_buf[mod_len] = 0u;
                break;
            }
        }
        for (i = mod_len; i > 0u; --i) {
            if (mod_buf[i - 1u] == L'\\') {
                sep_pos = i - 1u;
                found_sep = 1u;
                break;
            }
        }
        if (found_sep) {
            if (prof_len > 0u) {
                prof_len -= 1u;
                profile_dir[prof_len] = 0u;
            }
            if (l59_append_ascii_to_u16("_", profile_dir, 128u, &prof_len) != ROME2_VFS_REG_OK ||
                l59_append_u16_to_u16(
                    mod_buf + sep_pos + 1u,
                    mod_len - (sep_pos + 1u),
                    profile_dir,
                    128u,
                    &prof_len) != ROME2_VFS_REG_OK) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
        }
    }

    if (env->command_line_a &&
        rome2_startup_strstr_116be670(env->command_line_a, "-sptest", 2u) != NULL) {
        if (prof_len > 0u && profile_dir[prof_len - 1u] == L'\\') {
            prof_len -= 1u;
            profile_dir[prof_len] = 0u;
        }
        if (l59_append_ascii_to_u16("_autotest\\", profile_dir, 128u, &prof_len) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
    }

    if (!env->shgetfolder_ok || !env->appdata_root_u16) {
        return ROME2_VFS_REG_OK;
    }

    subpath = rome2_startup_get_user_folder_subpath_10122e30(category_idx, NULL);
    if (!subpath) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }

    memset(work_u16, 0, sizeof(work_u16));
    {
        size_t app_len = l59_u16_len(env->appdata_root_u16);
        uint16_t sub_u16[96];
        size_t sub_len = 0u;
        uint16_t ca_u16[32];
        size_t ca_len = 0u;
        if (app_len >= ROME2_STARTUP_MAX_PATH_U16) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (l59_append_u16_to_u16(env->appdata_root_u16, app_len, work_u16, ROME2_STARTUP_MAX_PATH_U16, &work_len) !=
            ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        memset(ca_u16, 0, sizeof(ca_u16));
        memset(sub_u16, 0, sizeof(sub_u16));
        if (l59_append_ascii_to_u16("The Creative Assembly\\", ca_u16, 32u, &ca_len) != ROME2_VFS_REG_OK ||
            l59_append_ascii_to_u16(subpath, sub_u16, 96u, &sub_len) != ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        l59_path_append_u16_sep(work_u16, ROME2_STARTUP_MAX_PATH_U16, &work_len, ca_u16, ca_len);
        l59_path_append_u16_sep(work_u16, ROME2_STARTUP_MAX_PATH_U16, &work_len, profile_dir, prof_len);
        l59_path_append_u16_sep(work_u16, ROME2_STARTUP_MAX_PATH_U16, &work_len, sub_u16, sub_len);
    }

    if (work_len + 1u > out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(out_u16, work_u16, (work_len + 1u) * sizeof(uint16_t));
    env->created_dirs += 1u;
    if (out_len) {
        *out_len = work_len;
    }
    return ROME2_VFS_REG_OK;
}

const uint16_t *rome2_startup_get_cached_user_folder_path_10120d90(
    rome2_startup_path_env *env,
    uint32_t category_idx) {
    size_t len = 0u;
    if (!env || category_idx >= ROME2_STARTUP_USER_FOLDER_COUNT) {
        return NULL;
    }
    if (env->cache_paths[category_idx][0] == 0u) {
        if (rome2_startup_resolve_appdata_dir_101016c0(
                env,
                category_idx,
                env->cache_paths[category_idx],
                ROME2_STARTUP_MAX_PATH_U16,
                &len) == ROME2_VFS_REG_OK) {
            env->cache_populated[category_idx] = 1u;
        }
    }
    return env->cache_paths[category_idx];
}

rome2_startup_crash_singleton *rome2_startup_crash_reporter_instance_100e8240(
    rome2_startup_crash_singleton *singleton,
    rome2_startup_path_env *path_env,
    int32_t tls_epoch) {
    static const uint16_t k_crash_stack[] = { 'C','r','a','s','h','.','s','t','a','c','k',0 };
    static const uint16_t k_crash_dmp[] = { 'C','r','a','s','h','.','d','m','p',0 };
    if (!singleton) {
        return NULL;
    }
    /* In MSVC magic-static ABI, uninitialized guard is either -1 (init claimed) or 0 > tls_epoch (< 0). */
    if (!singleton->initialized &&
        (singleton->init_epoch == -1 || tls_epoch < singleton->init_epoch)) {
        const uint16_t *logs_dir = NULL;
        if (path_env) {
            logs_dir = rome2_startup_get_cached_user_folder_path_10120d90(path_env, 0x11u);
        }
        if (logs_dir) {
            (void)rome2_startup_utf16_concat_100e1050(
                logs_dir,
                k_crash_stack,
                singleton->crash_stack_path,
                ROME2_STARTUP_MAX_PATH_U16,
                &singleton->crash_stack_len);
            (void)rome2_startup_utf16_concat_100e1050(
                logs_dir,
                k_crash_dmp,
                singleton->crash_dmp_path,
                ROME2_STARTUP_MAX_PATH_U16,
                &singleton->crash_dmp_len);
        }
        singleton->zeroed_fields_ok = 1u;
        singleton->atexit_registered = 1u;
        singleton->initialized = 1u;
        singleton->init_epoch = tls_epoch;
    }
    return singleton;
}

const char *rome2_startup_strstr_116be670(
    const char *haystack,
    const char *needle,
    uint32_t isa_available) {
    size_t i = 0u;
    size_t j = 0u;
    (void)isa_available; /* Scalar, SSE2, and 32-bit word lanes share identical C string semantics. */
    if (!haystack || !needle) {
        return NULL;
    }
    if (needle[0] == '\0') {
        return haystack;
    }
    if (needle[1] == '\0') {
        char target = needle[0];
        for (i = 0u; haystack[i] != '\0'; ++i) {
            if (haystack[i] == target) {
                return haystack + i;
            }
        }
        return NULL;
    }
    for (i = 0u; haystack[i] != '\0'; ++i) {
        for (j = 0u; needle[j] != '\0' && haystack[i + j] == needle[j]; ++j) {
        }
        if (needle[j] == '\0') {
            return haystack + i;
        }
    }
    return NULL;
}

void rome2_startup_utf16_slice_init_lower_ascii_10102c10(
    rome2_startup_utf16_slice *out_slice,
    uint32_t len,
    uint32_t cap,
    uint16_t *buf) {
    uint32_t i = 0u;
    if (!out_slice) {
        return;
    }
    if (buf && len > 0u) {
        for (i = 0u; i < len; ++i) {
            uint16_t ch = buf[i];
            if (ch >= 0x0041u && ch <= 0x005au) {
                buf[i] = (uint16_t)(ch + 0x0020u);
            }
        }
    }
    out_slice->len = len;
    out_slice->cap = cap;
    out_slice->buf = buf;
}

int32_t rome2_startup_utf16_slice_compare_100f71b0(
    const rome2_startup_utf16_cslice *lhs,
    const rome2_startup_utf16_cslice *rhs) {
    uint32_t n = 0u;
    uint32_t i = 0u;
    if (!lhs || !rhs) {
        return 0;
    }
    n = (lhs->len < rhs->len) ? lhs->len : rhs->len;
    for (i = 0u; i < n; ++i) {
        if (lhs->buf[i] != rhs->buf[i]) {
            return (int32_t)lhs->buf[i] - (int32_t)rhs->buf[i];
        }
    }
    if (lhs->len < rhs->len) {
        return -1;
    }
    if (lhs->len > rhs->len) {
        return 1;
    }
    return 0;
}

uint32_t rome2_startup_utf16_slice_less_100f3000(
    const rome2_startup_utf16_cslice *lhs,
    const rome2_startup_utf16_cslice *rhs) {
    return (rome2_startup_utf16_slice_compare_100f71b0(lhs, rhs) < 0) ? 1u : 0u;
}

void rome2_startup_rb_tree_init(rome2_startup_rb_tree *tree) {
    if (!tree) {
        return;
    }
    memset(tree, 0, sizeof(*tree));
    tree->nodes[0].guest.color_28 = 1u; /* BLACK sentinel */
    tree->nodes[0].guest.is_nil_29 = 1u;
}

static rome2_startup_rb_slot *l59_rb_slot(rome2_startup_rb_tree *tree, uint32_t idx) {
    return (tree && idx <= ROME2_STARTUP_MAX_RB_NODES) ? &tree->nodes[idx] : NULL;
}

static const rome2_startup_rb_slot *l59_rb_cslot(const rome2_startup_rb_tree *tree, uint32_t idx) {
    return (tree && idx <= ROME2_STARTUP_MAX_RB_NODES) ? &tree->nodes[idx] : NULL;
}

static void l59_rb_rotate(rome2_startup_rb_tree *tree, uint32_t x, uint8_t dir_left) {
    rome2_startup_rb_slot *nx = (x != 0u) ? l59_rb_slot(tree, x) : NULL;
    uint32_t y = 0u;
    rome2_startup_rb_slot *ny = NULL;
    uint32_t child = 0u;
    uint32_t px = 0u;
    if (!nx) {
        return;
    }
    y = dir_left ? nx->right_idx : nx->left_idx;
    ny = (y != 0u) ? l59_rb_slot(tree, y) : NULL;
    if (!ny) {
        return;
    }
    child = dir_left ? ny->left_idx : ny->right_idx;
    if (dir_left) {
        nx->right_idx = child;
    } else {
        nx->left_idx = child;
    }
    if (child != 0u) {
        rome2_startup_rb_slot *nc = l59_rb_slot(tree, child);
        if (nc) {
            nc->parent_idx = x;
        }
    }
    px = nx->parent_idx;
    ny->parent_idx = px;
    if (x == tree->root_idx || px == 0u) {
        tree->root_idx = y;
    } else {
        rome2_startup_rb_slot *npx = l59_rb_slot(tree, px);
        if (!npx) {
            tree->root_idx = y;
        } else if (x == npx->left_idx) {
            npx->left_idx = y;
        } else {
            npx->right_idx = y;
        }
    }
    if (dir_left) {
        ny->left_idx = x;
    } else {
        ny->right_idx = x;
    }
    nx->parent_idx = y;
}

rome2_vfs_reg_status rome2_startup_rb_insert_hint_100ea5e0(
    rome2_startup_rb_tree *tree,
    uint8_t insert_left,
    uint32_t hint_idx,
    const uint16_t *key_u16,
    uint32_t key_len,
    uint64_t size_bytes,
    uint32_t *out_idx) {
    uint32_t z = 0u;
    rome2_startup_rb_slot *nz = NULL;
    rome2_startup_rb_slot *nroot = NULL;
    if (!tree || !key_u16 || key_len >= 128u || hint_idx > tree->count || tree->count >= ROME2_STARTUP_MAX_RB_NODES) {
        return (!tree || !key_u16 || key_len >= 128u || hint_idx > tree->count)
            ? ROME2_VFS_REG_BAD_ARGUMENT
            : ROME2_VFS_REG_RANGE_ERROR;
    }
    z = ++tree->count;
    nz = l59_rb_slot(tree, z);
    if (!nz) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memset(nz, 0, sizeof(*nz));
    if (key_len > 0u) {
        memcpy(nz->key_u16, key_u16, key_len * sizeof(uint16_t));
    }
    nz->key_u16[key_len] = 0u;
    nz->guest.key_len_10 = key_len;
    nz->guest.key_cap_14 = 127u;
    nz->guest.size_lo_20 = (uint32_t)(size_bytes & 0xffffffffu);
    nz->guest.size_hi_24 = (uint32_t)(size_bytes >> 32);
    nz->guest.color_28 = 0u; /* RED */
    nz->guest.is_nil_29 = 0u;
    nz->parent_idx = hint_idx;

    if (hint_idx == 0u) {
        tree->root_idx = z;
        tree->leftmost_idx = z;
        tree->rightmost_idx = z;
    } else {
        rome2_startup_rb_slot *nh = l59_rb_slot(tree, hint_idx);
        if (!nh) {
            return ROME2_VFS_REG_BAD_ARGUMENT;
        }
        if (insert_left != 0u) {
            nh->left_idx = z;
            if (hint_idx == tree->leftmost_idx) {
                tree->leftmost_idx = z;
            }
        } else {
            nh->right_idx = z;
            if (hint_idx == tree->rightmost_idx) {
                tree->rightmost_idx = z;
            }
        }
    }

    {
        uint32_t cur = z;
        while (cur != tree->root_idx) {
            rome2_startup_rb_slot *ncur = (cur != 0u) ? l59_rb_slot(tree, cur) : NULL;
            uint32_t p = ncur ? ncur->parent_idx : 0u;
            rome2_startup_rb_slot *np = (p != 0u) ? l59_rb_slot(tree, p) : NULL;
            uint32_t gp = 0u;
            rome2_startup_rb_slot *ngp = NULL;
            if (!np || np->guest.color_28 != 0u) {
                break;
            }
            gp = np->parent_idx;
            ngp = (gp != 0u) ? l59_rb_slot(tree, gp) : NULL;
            if (!ngp) {
                break;
            }
            {
                uint8_t p_is_left = (p == ngp->left_idx) ? 1u : 0u;
                uint32_t u = p_is_left ? ngp->right_idx : ngp->left_idx;
                rome2_startup_rb_slot *nu = l59_rb_slot(tree, u);
                if (nu && nu->guest.color_28 == 0u) {
                    np->guest.color_28 = 1u;
                    nu->guest.color_28 = 1u;
                    ngp->guest.color_28 = 0u;
                    cur = gp;
                } else {
                    uint32_t pivot_child = p_is_left ? np->right_idx : np->left_idx;
                    if (cur == pivot_child) {
                        cur = p;
                        l59_rb_rotate(tree, cur, p_is_left);
                        ncur = l59_rb_slot(tree, cur);
                        p = ncur ? ncur->parent_idx : 0u;
                        np = (p != 0u) ? l59_rb_slot(tree, p) : NULL;
                        if (!np) {
                            break;
                        }
                        gp = np->parent_idx;
                        ngp = (gp != 0u) ? l59_rb_slot(tree, gp) : NULL;
                        if (!ngp) {
                            break;
                        }
                    }
                    np->guest.color_28 = 1u;
                    ngp->guest.color_28 = 0u;
                    l59_rb_rotate(tree, gp, (uint8_t)(!p_is_left));
                }
            }
        }
    }
    nroot = l59_rb_slot(tree, tree->root_idx);
    if (nroot) {
        nroot->guest.color_28 = 1u;
    }
    if (out_idx) {
        *out_idx = z;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_startup_rb_find(
    const rome2_startup_rb_tree *tree,
    const uint16_t *key_u16,
    uint32_t key_len,
    uint32_t *out_idx,
    uint64_t *out_size) {
    uint32_t cur = 0u;
    rome2_startup_utf16_cslice query;
    if (!tree || !key_u16) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    query.len = key_len;
    query.cap = key_len;
    query.buf = key_u16;
    cur = tree->root_idx;
    while (cur != 0u) {
        const rome2_startup_rb_slot *nc = l59_rb_cslot(tree, cur);
        rome2_startup_utf16_cslice cur_key;
        int32_t cmp = 0;
        if (!nc) {
            break;
        }
        cur_key.len = nc->guest.key_len_10;
        cur_key.cap = nc->guest.key_cap_14;
        cur_key.buf = nc->key_u16;
        cmp = rome2_startup_utf16_slice_compare_100f71b0(&query, &cur_key);
        if (cmp == 0) {
            if (out_idx) {
                *out_idx = cur;
            }
            if (out_size) {
                *out_size = ((uint64_t)nc->guest.size_hi_24 << 32) |
                    (uint64_t)nc->guest.size_lo_20;
            }
            return ROME2_VFS_REG_OK;
        }
        cur = (cmp < 0) ? nc->left_idx : nc->right_idx;
    }
    return ROME2_VFS_REG_NOT_FOUND;
}

uint8_t rome2_startup_is_excluded_dlc_or_manifest(const char *lower_rel_path) {
    size_t i = 0u;
    if (!lower_rel_path) {
        return 0u;
    }
    for (i = 0u; i < sizeof(g_excluded_rel_paths) / sizeof(g_excluded_rel_paths[0]); ++i) {
        if (strcmp(lower_rel_path, g_excluded_rel_paths[i]) == 0) {
            return 1u;
        }
    }
    return 0u;
}

static rome2_vfs_reg_status l59_rb_insert_unique(
    rome2_startup_rb_tree *tree,
    const uint16_t *key_u16,
    uint32_t key_len,
    uint64_t size_bytes) {
    uint32_t cur = tree->root_idx;
    uint32_t parent = 0u;
    uint8_t go_left = 1u;
    rome2_startup_utf16_cslice ins_key;
    ins_key.len = key_len;
    ins_key.cap = key_len;
    ins_key.buf = key_u16;
    while (cur != 0u) {
        const rome2_startup_rb_slot *nc = l59_rb_cslot(tree, cur);
        rome2_startup_utf16_cslice cur_key;
        if (!nc) {
            break;
        }
        cur_key.len = nc->guest.key_len_10;
        cur_key.cap = nc->guest.key_cap_14;
        cur_key.buf = nc->key_u16;
        parent = cur;
        go_left = (uint8_t)rome2_startup_utf16_slice_less_100f3000(&ins_key, &cur_key);
        cur = go_left ? nc->left_idx : nc->right_idx;
    }
    {
        uint32_t dummy_idx = 0u;
        if (rome2_startup_rb_find(tree, key_u16, key_len, &dummy_idx, NULL) == ROME2_VFS_REG_OK) {
            return ROME2_VFS_REG_OK;
        }
    }
    return rome2_startup_rb_insert_hint_100ea5e0(tree, go_left, parent, key_u16, key_len, size_bytes, NULL);
}

static rome2_vfs_reg_status l59_scan_dir_recursive(
    const rome2_startup_dir_entry *entries,
    size_t entry_count,
    const char *parent_rel,
    const char *vfs_prefix,
    rome2_startup_rb_tree *tree,
    uint32_t depth) {
    size_t i = 0u;
    if (depth > 8u) {
        return ROME2_VFS_REG_STEP_LIMIT;
    }
    for (i = 0u; i < entry_count; ++i) {
        const rome2_startup_dir_entry *e = &entries[i];
        char lower_name[64];
        size_t nlen = 0u;
        size_t j = 0u;
        if (!e->parent_rel || !e->name_ascii || strcmp(e->parent_rel, parent_rel) != 0) {
            continue;
        }
        nlen = strlen(e->name_ascii);
        if (nlen >= sizeof(lower_name)) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        for (j = 0u; j < nlen; ++j) {
            lower_name[j] = (char)l59_ascii_tolower((uint8_t)e->name_ascii[j]);
        }
        lower_name[nlen] = '\0';

        if (!e->is_dir) {
            char rel_path[128];
            uint16_t rel_u16[128];
            uint16_t lower_u16[128];
            rome2_startup_utf16_slice slice;
            size_t rlen = 0u;
            int n = snprintf(rel_path, sizeof(rel_path), "%s%s", vfs_prefix, lower_name);
            if (n < 0 || (size_t)n >= sizeof(rel_path)) {
                return ROME2_VFS_REG_RANGE_ERROR;
            }
            rlen = (size_t)n;
            for (j = 0u; j <= rlen; ++j) {
                rel_u16[j] = (uint8_t)rel_path[j];
                lower_u16[j] = (uint8_t)rel_path[j];
            }
            rome2_startup_utf16_slice_init_lower_ascii_10102c10(&slice, (uint32_t)rlen, 127u, lower_u16);
            if (!rome2_startup_is_excluded_dlc_or_manifest(rel_path)) {
                rome2_vfs_reg_status st = l59_rb_insert_unique(tree, slice.buf, slice.len, e->file_size);
                if (st != ROME2_VFS_REG_OK) {
                    return st;
                }
            }
        } else {
            if (strcmp(lower_name, ".") != 0 &&
                strcmp(lower_name, "..") != 0 &&
                (vfs_prefix[0] != '\0' || strcmp(lower_name, "encyclopedia") != 0)) {
                char next_parent[96];
                char next_vfs[96];
                int np = snprintf(next_parent, sizeof(next_parent), "%s\\%s", parent_rel, lower_name);
                int nv = snprintf(next_vfs, sizeof(next_vfs), "%s%s/", vfs_prefix, lower_name);
                if (np < 0 || (size_t)np >= sizeof(next_parent) || nv < 0 || (size_t)nv >= sizeof(next_vfs)) {
                    return ROME2_VFS_REG_RANGE_ERROR;
                }
                {
                    rome2_vfs_reg_status st = l59_scan_dir_recursive(
                        entries, entry_count, next_parent, next_vfs, tree, depth + 1u);
                    if (st != ROME2_VFS_REG_OK) {
                        return st;
                    }
                }
            }
        }
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_startup_scan_dir_tree_100e3360(
    const rome2_startup_dir_entry *entries,
    size_t entry_count,
    const char *parent_rel,
    const char *vfs_prefix,
    rome2_startup_rb_tree *tree) {
    if (!entries || !parent_rel || !vfs_prefix || !tree) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    return l59_scan_dir_recursive(entries, entry_count, parent_rel, vfs_prefix, tree, 0u);
}

void rome2_startup_set_keeper_flag_101136d0(uint8_t *keeper_byte, uint8_t value) {
    if (keeper_byte) {
        *keeper_byte = value;
    }
}

void rome2_startup_set_keeper_dword_101150f0(uint32_t *keeper_dword, uint32_t value) {
    if (keeper_dword) {
        *keeper_dword = value;
    }
}

rome2_vfs_reg_status rome2_startup_init_perf_config_100d24c0(
    rome2_startup_perf_config228_32 *cfg) {
    if (!cfg) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->flag_00 = 0u;
    cfg->sentinel_04 = 0xffffffffu;
    cfg->val_14 = 0x3f800000u;
    cfg->val_18 = 0x38d1b717u;
    cfg->val_1c = 0x3e4ccccdu;
    cfg->val_20 = 0x3e4ccccdu;
    cfg->val_24 = 0x3e19999au;
    cfg->val_28 = 0x3f000000u;
    cfg->val_2c = 0x3f800000u;
    cfg->val_30 = 0x3dcccccdu;
    cfg->val_34 = 0u;
    cfg->val_38 = 0x3dcccccdu;
    cfg->val_3c = 0xffffffffu;
    cfg->val_5c = 0x3f800000u;
    cfg->val_60 = 0x3e4ccccdu;
    cfg->val_64 = 0u;
    cfg->flag_68 = 0u;
    cfg->val_78 = 0x3d4ccccdu;
    cfg->val_7c = 0x41700000u;
    cfg->val_b0 = 0x7f7fffffu;
    cfg->u16_c8 = 0u;
    cfg->flag_ca = 0u;
    return ROME2_VFS_REG_OK;
}

uint32_t rome2_startup_get_allocator_slot_100fcc30(
    const rome2_startup_alloc_table *tbl,
    int32_t slot_index) {
    if (!tbl || slot_index < 0 || slot_index >= 8) {
        return 0u;
    }
    if (slot_index == 3) {
        return tbl->slot3;
    }
    return tbl->slots[slot_index];
}

rome2_vfs_reg_status rome2_startup_init_section_timings_112dc9f0(
    rome2_startup_timing_env *env,
    const rome2_startup_alloc_table *alloc_tbl,
    const char *section_label,
    uint32_t capacity,
    uint32_t current_time_ms) {
    if (!env || !alloc_tbl || !section_label) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    if (capacity > ROME2_STARTUP_MAX_TIMING_SLOTS) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    env->active_label = section_label;
    env->init_start_ms = current_time_ms;
    env->init_last_ms = current_time_ms;
    (void)snprintf(env->log_banner, sizeof(env->log_banner), "%s: section timings initialised\n", section_label);
    env->active_count = 0u;
    env->max_cap_param = capacity;
    if (capacity != 0u && env->alloc_cap < capacity) {
        env->alloc_cap = capacity;
        memset(env->slots, 0, capacity * sizeof(env->slots[0]));
    }
    env->cached_allocator = rome2_startup_get_allocator_slot_100fcc30(alloc_tbl, 3);
    return ROME2_VFS_REG_OK;
}

static rome2_vfs_reg_status l59_push_handler_batch(
    rome2_startup_handler_queue *queue,
    const uint32_t *vtables,
    size_t count) {
    size_t i = 0u;
    if (!queue || !vtables) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    for (i = 0u; i < count; ++i) {
        uint32_t idx = queue->count;
        if (idx == queue->fail_on_push_index || idx >= ROME2_STARTUP_MAX_HANDLERS) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        queue->items[idx].vtable_va = vtables[i];
        queue->items[idx].alloc_bytes = (vtables[i] == 0x1173f2acu) ? 0x0cu : 4u;
        queue->count += 1u;
    }
    return ROME2_VFS_REG_OK;
}

rome2_vfs_reg_status rome2_startup_register_handlers_part1_100ea060(
    rome2_startup_handler_queue *queue) {
    rome2_vfs_reg_status st = ROME2_VFS_REG_OK;
    if (!queue) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    st = l59_push_handler_batch(queue, g_part1_vtables_before_clean, sizeof(g_part1_vtables_before_clean) / 4u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (queue->crash_singleton) {
        rome2_startup_crash_singleton *cs =
            rome2_startup_crash_reporter_instance_100e8240(queue->crash_singleton, queue->path_env, 0);
        while (cs->alloc_ptr_count > 0u) {
            cs->alloc_ptr_count -= 1u;
            if (cs->alloc_ptrs[cs->alloc_ptr_count] != 0u) {
                cs->alloc_ptrs[cs->alloc_ptr_count] = 0u;
                cs->virtual_free_count += 1u;
            }
        }
    }
    st = l59_push_handler_batch(queue, g_part1_vtables_mid, sizeof(g_part1_vtables_mid) / 4u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = rome2_startup_init_section_timings_112dc9f0(
        &queue->timing_env, &queue->alloc_tbl, "POST_DB_APP_INIT", 0u, 1000u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    st = l59_push_handler_batch(queue, g_part1_vtables_post_timing, sizeof(g_part1_vtables_post_timing) / 4u);
    if (st != ROME2_VFS_REG_OK) {
        return st;
    }
    if (queue->crash_singleton) {
        rome2_startup_crash_singleton *cs =
            rome2_startup_crash_reporter_instance_100e8240(queue->crash_singleton, queue->path_env, 0);
        st = rome2_startup_init_perf_config_100d24c0(&cs->perf_config);
        if (st != ROME2_VFS_REG_OK) {
            return st;
        }
        cs->has_perf_config = 1u;
    }
    {
        uint32_t last_vt = 0x1173f2d4u;
        return l59_push_handler_batch(queue, &last_vt, 1u);
    }
}

rome2_vfs_reg_status rome2_startup_register_handlers_part2_100ea4d0(
    rome2_startup_handler_queue *queue) {
    return l59_push_handler_batch(queue, g_part2_vtables, sizeof(g_part2_vtables) / 4u);
}

uint8_t rome2_startup_format_const_char_spec_100f4920(
    const char *val,
    char spec_char,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    char *diag_buf,
    size_t diag_cap) {
    size_t cur = 0u;
    size_t vlen = 0u;
    if (!out_buf || out_cap == 0u || !out_len) {
        return 0u;
    }
    cur = *out_len;
    if (spec_char != 'C' && spec_char != 'S' && spec_char != 's') {
        if (diag_buf && diag_cap > 0u) {
            (void)snprintf(
                diag_buf,
                diag_cap,
                "Unexpected format %%%c used with type const char*",
                spec_char);
        }
        return 0u;
    }
    if (!val) {
        return 0u;
    }
    vlen = strlen(val);
    if (cur + vlen + 1u > out_cap) {
        return 0u;
    }
    memcpy(out_buf + cur, val, vlen);
    cur += vlen;
    out_buf[cur] = '\0';
    *out_len = cur;
    return 1u;
}

uint8_t rome2_startup_format_named_kv_100de500(
    const uint16_t *fmt_u16,
    const char *const *str_args,
    size_t str_arg_count,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    char *diag_buf,
    size_t diag_cap) {
    size_t pos = 0u;
    size_t cur = 0u;
    size_t arg_idx = 0u;
    if (!fmt_u16 || !out_buf || out_cap == 0u || !out_len) {
        return 0u;
    }
    cur = *out_len;
    while (fmt_u16[pos] != 0u) {
        uint8_t ch = (uint8_t)(fmt_u16[pos] & 0xffu);
        if (ch == '%') {
            do {
                pos += 1u;
                ch = (uint8_t)(fmt_u16[pos] & 0xffu);
            } while (ch == 'l');
            if (ch != '%') {
                if (!str_args || arg_idx >= str_arg_count) {
                    return 0u;
                }
                *out_len = cur;
                return rome2_startup_format_const_char_spec_100f4920(
                    str_args[arg_idx], (char)ch, out_buf, out_cap, out_len, diag_buf, diag_cap);
            }
        }
        if (cur + 2u > out_cap) {
            return 0u;
        }
        out_buf[cur++] = (char)ch;
        out_buf[cur] = '\0';
        pos += 1u;
    }
    *out_len = cur;
    return 1u;
}

rome2_vfs_reg_status rome2_startup_format_ansi_va_101c89e0(
    const uint16_t *fmt_u16,
    const char *const *str_args,
    size_t str_arg_count,
    char *out_buf,
    size_t out_cap,
    size_t *out_len,
    uint8_t *out_ok,
    char *diag_buf,
    size_t diag_cap) {
    size_t len = 0u;
    uint8_t ok = 0u;
    if (!fmt_u16 || !out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    out_buf[0] = '\0';
    ok = rome2_startup_format_named_kv_100de500(
        fmt_u16, str_args, str_arg_count, out_buf, out_cap, &len, diag_buf, diag_cap);
    if (ok) {
        /* Append trailing literal tail following the single '%s' token in this bounded model. */
        size_t pos = 0u;
        while (fmt_u16[pos] != 0u) {
            if (fmt_u16[pos] == '%' && fmt_u16[pos + 1u] != '%') {
                pos += 1u;
                while (fmt_u16[pos] == 'l') {
                    pos += 1u;
                }
                if (fmt_u16[pos] != 0u) {
                    pos += 1u;
                }
                while (fmt_u16[pos] != 0u) {
                    if (len + 2u > out_cap) {
                        return ROME2_VFS_REG_RANGE_ERROR;
                    }
                    out_buf[len++] = (char)(fmt_u16[pos++] & 0xffu);
                    out_buf[len] = '\0';
                }
                break;
            }
            if (fmt_u16[pos] == '%' && fmt_u16[pos + 1u] == '%') {
                pos += 2u;
            } else {
                pos += 1u;
            }
        }
    }
    if (out_len) {
        *out_len = len;
    }
    if (out_ok) {
        *out_ok = ok;
    }
    return ROME2_VFS_REG_OK;
}
