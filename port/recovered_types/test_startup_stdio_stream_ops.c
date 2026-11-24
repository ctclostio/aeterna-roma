#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guest32_layouts.h"
#include "startup_stdio_stream_ops.h"

static int g_checks = 0;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        ++g_checks;                                                                      \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

static rome2_startup_l65_crt_env *alloc_env(void)
{
    rome2_startup_l65_crt_env *env = (rome2_startup_l65_crt_env *)calloc(1, sizeof(*env));
    if (env != NULL) {
        rome2_startup_l65_env_init(env);
    }
    return env;
}

static void free_env(rome2_startup_l65_crt_env *env)
{
    rome2_startup_l65_env_destroy(env);
    free(env);
}

static int test_layouts_and_string_helpers(void)
{
    CHECK(sizeof(rome2_startup_crt_stdio_mode12_32) == 12u);
    CHECK(sizeof(rome2_startup_crt_file_options24_32) == 24u);
    CHECK(sizeof(rome2_startup_crt_seek_guard28_32) == 28u);

    CHECK(rome2_startup_crt_strncmp_1168d030("abcdef", "abcxyz", 3u) == 0);
    CHECK(rome2_startup_crt_strncmp_1168d030("abc", "abd", 3u) == -1);
    CHECK(rome2_startup_crt_strncmp_1168d030("abd", "abc", 3u) == 1);
    CHECK(rome2_startup_crt_strncmp_1168d030("a", "b", 0u) == 0);

    rome2_startup_l65_crt_env *env = alloc_env();
    CHECK(env != NULL);

    const uint16_t w1[] = {'U', 'T', 'F', '-', '8', 0};
    const uint16_t w2[] = {'u', 't', 'f', '-', '8', 'x', 0};
    const uint16_t w3[] = {'u', 't', 'f', '-', '9', 0};
    CHECK(rome2_startup_crt_wcsnicmp_116b844f(env, w1, w2, 5u) == 0);
    CHECK(rome2_startup_crt_wcsnicmp_116b844f(env, w1, w3, 5u) < 0);
    env->has_custom_locale = 1u;
    CHECK(rome2_startup_crt_wcsnicmp_116b844f(env, w1, w2, 0u) == 0);
    CHECK(rome2_startup_crt_wcsnicmp_l_116b849b(env, NULL, w2, 3u, 1u) == 0x7fffffff);
    CHECK(env->last_errno == 22 && env->invalid_param_calls == 1u);

    rome2_startup_l65_critsec_state cs;
    memset(&cs, 0, sizeof(cs));
    CHECK(rome2_startup_crt_init_cs_ex_116a896e(env, &cs, 4000u, 2u) == 1u);
    CHECK(cs.initialized == 1u && cs.spin_count == 4000u && cs.flags == 2u && cs.used_ex_api == 1u);
    env->has_ex_cs_api = 0u;
    CHECK(rome2_startup_crt_init_cs_ex_116a896e(env, &cs, 1000u, 2u) == 1u);
    CHECK(cs.flags == 0u && cs.used_ex_api == 0u);

    free_env(env);
    return 0;
}

static int test_parse_mode_variants(void)
{
    rome2_startup_l65_crt_env *env = alloc_env();
    CHECK(env != NULL);
    env->commode = 0x4000u;

    rome2_startup_crt_stdio_mode12_32 m1 = rome2_startup_crt_parse_mode_char_116aa31d(env, "  r+bNSD, ccs = utf-8 ");
    CHECK(m1.ok_08 == 1u);
    CHECK((m1.lowio_mode_00 & (ROME2_STARTUP_O_RDWR | ROME2_STARTUP_O_BINARY | ROME2_STARTUP_O_NOINHERIT |
                               ROME2_STARTUP_O_SEQUENTIAL | ROME2_STARTUP_O_TEMPORARY | ROME2_STARTUP_O_U8TEXT)) ==
          (ROME2_STARTUP_O_RDWR | ROME2_STARTUP_O_BINARY | ROME2_STARTUP_O_NOINHERIT |
           ROME2_STARTUP_O_SEQUENTIAL | ROME2_STARTUP_O_TEMPORARY | ROME2_STARTUP_O_U8TEXT));
    CHECK((m1.stdio_mode_04 & ROME2_STARTUP_IORW) != 0u);

    rome2_startup_crt_stdio_mode12_32 m2 = rome2_startup_crt_parse_mode_char_116aa31d(env, "wxTc");
    CHECK(m2.ok_08 == 1u);
    CHECK((m2.lowio_mode_00 & (ROME2_STARTUP_O_CREAT | ROME2_STARTUP_O_TRUNC | ROME2_STARTUP_O_EXCL |
                               ROME2_STARTUP_O_SHORT_LIVED)) ==
          (ROME2_STARTUP_O_CREAT | ROME2_STARTUP_O_TRUNC | ROME2_STARTUP_O_EXCL | ROME2_STARTUP_O_SHORT_LIVED));
    CHECK((m2.stdio_mode_04 & ROME2_STARTUP_IOCOMMIT) != 0u);

    const uint16_t wm16[] = {'a', 't', 'n', ',', 'c', 'c', 's', '=', 'U', 'T', 'F', '-', '1', '6', 'L', 'E', 0};
    rome2_startup_crt_stdio_mode12_32 m3 = rome2_startup_crt_parse_mode_wchar_116aa547(env, wm16);
    CHECK(m3.ok_08 == 1u);
    CHECK((m3.lowio_mode_00 & (ROME2_STARTUP_O_APPEND | ROME2_STARTUP_O_TEXT | ROME2_STARTUP_O_U16TEXT)) ==
          (ROME2_STARTUP_O_APPEND | ROME2_STARTUP_O_TEXT | ROME2_STARTUP_O_U16TEXT));
    CHECK((m3.stdio_mode_04 & ROME2_STARTUP_IOCOMMIT) == 0u);

    const uint16_t wmuni[] = {'r', ',', 'c', 'c', 's', '=', 'u', 'n', 'i', 'c', 'o', 'd', 'e', 0};
    rome2_startup_crt_stdio_mode12_32 m4 = rome2_startup_crt_parse_mode_wchar_116aa547(env, wmuni);
    CHECK(m4.ok_08 == 1u && (m4.lowio_mode_00 & ROME2_STARTUP_O_WTEXT) != 0u);

    /* Reject conflicting b+t, R+S, x without w/TRUNC, bad initial char, bad ccs */
    CHECK(rome2_startup_crt_parse_mode_char_116aa31d(env, "rbt").ok_08 == 0u);
    CHECK(rome2_startup_crt_parse_mode_char_116aa31d(env, "rRS").ok_08 == 0u);
    CHECK(rome2_startup_crt_parse_mode_char_116aa31d(env, "rx").ok_08 == 0u);
    CHECK(rome2_startup_crt_parse_mode_char_116aa31d(env, "z").ok_08 == 0u);
    CHECK(rome2_startup_crt_parse_mode_char_116aa31d(env, "r,ccs=BOGUS").ok_08 == 0u);
    CHECK(env->invalid_param_calls >= 5u);

    free_env(env);
    return 0;
}

static int test_lowio_alloc_open_bom_and_chsize(void)
{
    rome2_startup_l65_crt_env *env = alloc_env();
    CHECK(env != NULL);
    env->is_gui_app = 1u;

    /* __alloc_osfhnd + ___acrt_lowio_set_os_handle + SetStdHandle check */
    int32_t fh0 = rome2_startup_crt_alloc_osfhnd_116ae8b5(env);
    int32_t fh1 = rome2_startup_crt_alloc_osfhnd_116ae8b5(env);
    CHECK(fh0 == 0 && fh1 == 1 && env->nhandle == 64u);
    CHECK(env->lowio_lock_count == 2u && env->lowio_unlock_count == 2u);
    CHECK(rome2_startup_crt_lowio_set_os_handle_116ae800(env, 0, 0xaaaa0001u) == 0);
    CHECK(env->set_std_handle_calls == 1u && env->last_std_handle_id == 0xfffffff6u);
    CHECK(rome2_startup_crt_lowio_set_os_handle_116ae800(env, 0, 0xbbbb0001u) == -1 && env->last_errno == 9);

    /* decode_open_create_flags */
    CHECK(rome2_startup_crt_decode_open_create_flags_116aef71(env, 0x000) == 3u);
    CHECK(rome2_startup_crt_decode_open_create_flags_116aef71(env, 0x100) == 4u);
    CHECK(rome2_startup_crt_decode_open_create_flags_116aef71(env, 0x200) == 5u);
    CHECK(rome2_startup_crt_decode_open_create_flags_116aef71(env, 0x300) == 2u);
    CHECK(rome2_startup_crt_decode_open_create_flags_116aef71(env, 0x500) == 1u);
    CHECK(rome2_startup_crt_decode_open_create_flags_116aef71(env, 0x700) == 1u);

    /* common_openfile<char> write UTF-8 with BOM + chsize grow/shrink + truncate_ctrl_z */
    rome2_startup_l65_stdio_stream st_w;
    memset(&st_w, 0, sizeof(st_w));
    CHECK(rome2_startup_crt_common_openfile_char_116aa7b2(
              env, "data/manifest.txt", "w,ccs=UTF-8", ROME2_STARTUP_SH_DENYNO, &st_w) == &st_w);
    CHECK(st_w.file_handle >= 2 && env->open_stream_count == 1u);
    int32_t fidx = env->pages[st_w.file_handle >> 6][st_w.file_handle & 0x3f].backed_file_idx;
    CHECK(fidx >= 0 && env->files[fidx].len == 3u &&
          env->files[fidx].data[0] == 0xefu && env->files[fidx].data[1] == 0xbbu && env->files[fidx].data[2] == 0xbfu);
    CHECK(env->pages[st_w.file_handle >> 6][st_w.file_handle & 0x3f].guest.textmode_29 == ROME2_STARTUP_LOWIO_TM_UTF8);

    /* Extend via __chsize_nolock then truncate ^Z + shrink */
    CHECK(rome2_startup_crt_chsize_nolock_116bc827(env, st_w.file_handle, 7) == 0);
    CHECK(env->files[fidx].len == 7u && env->files[fidx].data[6] == 0u);
    env->files[fidx].data[6] = 0x1au;
    CHECK(rome2_startup_crt_truncate_ctrl_z_116af15b(env, st_w.file_handle) == 0);
    CHECK(env->files[fidx].len == 6u);
    CHECK(rome2_startup_crt_setmode_nolock_116bc70b(env, st_w.file_handle, ROME2_STARTUP_O_BINARY) == ROME2_STARTUP_O_U8TEXT);
    CHECK(rome2_startup_crt_setmode_nolock_116bc70b(env, st_w.file_handle, ROME2_STARTUP_O_WTEXT) == ROME2_STARTUP_O_BINARY);

    /* common_openfile<wchar_t> reading existing UTF-16LE BOM file + BE BOM 0xFFFE error */
    const uint8_t u16_bom_data[] = {0xffu, 0xfeu, 'A', 0x00u, 'B', 0x00u};
    CHECK(rome2_startup_l65_env_add_file(env, "cfg.ini", u16_bom_data, sizeof(u16_bom_data), 1u, 0u) >= 0);
    const uint16_t wcfg[] = {'c', 'f', 'g', '.', 'i', 'n', 'i', 0};
    const uint16_t wruni[] = {'r', ',', 'c', 'c', 's', '=', 'U', 'N', 'I', 'C', 'O', 'D', 'E', 0};
    rome2_startup_l65_stdio_stream st_r;
    memset(&st_r, 0, sizeof(st_r));
    CHECK(rome2_startup_crt_common_openfile_wchar_116aa835(
              env, wcfg, wruni, ROME2_STARTUP_SH_DENYNO, &st_r) == &st_r);
    CHECK(env->pages[st_r.file_handle >> 6][st_r.file_handle & 0x3f].guest.textmode_29 == ROME2_STARTUP_LOWIO_TM_UTF16LE);

    const uint8_t be_bom[] = {0xfeu, 0xffu, 0x00u, 'X'};
    CHECK(rome2_startup_l65_env_add_file(env, "be.txt", be_bom, sizeof(be_bom), 1u, 0u) >= 0);
    int32_t bad_fh = -1;
    CHECK(rome2_startup_crt_sopen_s_116af28b(
              env, &bad_fh, "be.txt", ROME2_STARTUP_O_RDONLY | ROME2_STARTUP_O_WTEXT, ROME2_STARTUP_SH_DENYNO, 0) == 22);
    CHECK(bad_fh == -1);

    /* Validation guard in common_sopen_dispatch */
    int32_t sec_fh = 0;
    CHECK(rome2_startup_crt_sopen_s_116af28b(env, &sec_fh, "be.txt", 0, ROME2_STARTUP_SH_DENYNO, 0x200) == 22);
    CHECK(sec_fh == -1);

    free_env(env);
    return 0;
}

int main(void)
{
    if (test_layouts_and_string_helpers() != 0) {
        return 1;
    }
    if (test_parse_mode_variants() != 0) {
        return 1;
    }
    if (test_lowio_alloc_open_bom_and_chsize() != 0) {
        return 1;
    }
    printf("test_startup_stdio_stream_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
