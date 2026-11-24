#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guest32_layouts.h"
#include "startup_fopen_fread_init_ops.h"

static int g_checks = 0;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        ++g_checks;                                                                      \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "CHECK FAILED (%s:%d): %s\n", __FILE__, __LINE__, #cond);   \
            return 1;                                                                    \
        }                                                                                \
    } while (0)

static rome2_startup_l66_env *alloc_l66_env(void)
{
    rome2_startup_l66_env *env = (rome2_startup_l66_env *)calloc(1, sizeof(*env));
    if (env != NULL) {
        rome2_startup_l66_env_init(env);
    }
    return env;
}

static void free_l66_env(rome2_startup_l66_env *env)
{
    rome2_startup_l66_env_destroy(env);
    free(env);
}

static int test_layouts_and_math_helpers(void)
{
    CHECK(sizeof(rome2_startup_engine_file_box8_32) == 8u);
    CHECK(sizeof(rome2_startup_crt_iobuf_full56_32) == 56u);
    CHECK(sizeof(rome2_startup_fiopen_entry12_32) == 12u);

    CHECK(rome2_startup_crt_alldiv_11684670(-100000000000ll, 3ll) == -33333333333ll);
    CHECK(rome2_startup_crt_alldiv_11684670(10ll, 0ll) == 0ll);

    int64_t sub_out = 0;
    CHECK(rome2_startup_crt_longlongsub_11699fb7(100ll, 42ll, &sub_out) == 0 && sub_out == 58ll);
    CHECK((uint32_t)rome2_startup_crt_longlongsub_11699fb7(INT64_MIN, 1ll, &sub_out) ==
          ROME2_STARTUP_L66_INTSAFE_E_OVERFLOW);

    const uint8_t narrow_txt[] = {'A', '\n', 'B', '\n', 'C'};
    CHECK(rome2_startup_crt_count_newline_bytes_1169a8a1(narrow_txt, narrow_txt + sizeof(narrow_txt), 0u) == 2ll);
    const uint8_t u16_txt[] = {'A', 0u, '\n', 0u, 'B', 0u};
    CHECK(rome2_startup_crt_count_newline_bytes_1169a8a1(u16_txt, u16_txt + sizeof(u16_txt), 2u) == 2ll);
    return 0;
}

static int test_fopen_fread_fseek_ftell_and_fiopen(void)
{
    rome2_startup_l66_env *env = alloc_l66_env();
    CHECK(env != NULL);

    const uint8_t sample[] = "hello\nworld\n0123456789";
    CHECK(rome2_startup_l65_env_add_file(&env->io, "data/test.bin", sample, sizeof(sample) - 1u, 1u, 0u) >= 0);

    rome2_startup_l66_stream *fp = rome2_startup_crt_fopen_1168e9a2(env, "data/test.bin", "rb");
    CHECK(fp != NULL && (fp->guest.flag_0c & ROME2_STARTUP_L66_IOALLOCATED) != 0u);
    CHECK(env->stdio_table_lock_count == 1u && env->stdio_table_unlock_count == 1u);

    char buf[8];
    memset(buf, 0, sizeof(buf));
    CHECK(rome2_startup_crt_fread_s_1168ec03(env, buf, sizeof(buf), 1u, 5u, fp) == 5u);
    CHECK(memcmp(buf, "hello", 5u) == 0);
    CHECK(rome2_startup_crt_ftell_i32_thunk_1169a92a(env, fp) == 5ll);

    /* Fast-track SEEK_CUR rewind within buffered binary stream */
    CHECK(rome2_startup_crt_fseek_1169a28e(env, fp, -2, 1) == 0);
    CHECK(rome2_startup_crt_ftell_i64_nolock_1169a3c5(env, fp) == 3ll);

    /* SEEK_END via _Fiopen (ios::in | ios::binary | ios::ate = 0x25) */
    const uint16_t wpath[] = {'d', 'a', 't', 'a', '/', 't', 'e', 's', 't', '.', 'b', 'i', 'n', 0};
    rome2_startup_l66_stream *fp_ate = rome2_startup_engine_fiopen_113471f0(env, wpath, 0x25u);
    CHECK(fp_ate != NULL);
    CHECK(rome2_startup_crt_ftell_i64_nolock_1169a3c5(env, fp_ate) == (int64_t)(sizeof(sample) - 1u));

    /* fopen_s & fread_s error guards */
    rome2_startup_l66_stream *bad_fp = NULL;
    CHECK(rome2_startup_crt_fopen_s_1168e9b9(env, &bad_fp, "", "rb") == 22 && bad_fp == NULL);
    CHECK(rome2_startup_crt_fread_s_1168ec03(env, buf, sizeof(buf), 1u, 32u, fp) <= sizeof(buf));
    CHECK(rome2_startup_crt_fseek_1169a28e(env, fp, 0, 99) == -1);

    /* Telemetry exit box & _exit(0) */
    rome2_startup_engine_exit_with_telemetry_100edcd0(env, "exit.log", 42);
    CHECK(env->exit_called == 1u && env->exit_code == 0);
    int32_t exit_idx = -1;
    for (int32_t i = 0; i < (int32_t)ROME2_STARTUP_L65_MAX_FILES; ++i) {
        if (env->io.files[i].exists && strcmp(env->io.files[i].path, "exit.log") == 0) {
            exit_idx = i;
            break;
        }
    }
    CHECK(exit_idx >= 0 && env->io.files[exit_idx].len == 2u &&
          memcmp(env->io.files[exit_idx].data, "42", 2u) == 0);

    free_l66_env(env);
    return 0;
}

static int test_manifest_verification_100e2980(void)
{
    rome2_startup_l66_env *env = alloc_l66_env();
    CHECK(env != NULL);

    const char manifest[] =
        "a.pack\t10\n"
        "b.pack\t20\n"
        "c.pack\t30\n";
    CHECK(rome2_startup_l65_env_add_file(
              &env->io, "data/manifest.txt", (const uint8_t *)manifest, sizeof(manifest) - 1u, 1u, 0u) >= 0);

    const rome2_startup_l66_disk_entry disk_ok[] = {
        {"a.pack", 10u},
        {"b.pack", 20u},
        {"c.pack", 30u},
    };
    char log[512];
    rome2_startup_engine_verify_data_manifest_100e2980(
        env, "C:\\Rome2\\rome2.exe", "data/manifest.txt", "modified.log",
        disk_ok, 3u, 0u, log, sizeof(log));
    CHECK(env->manifest_mismatch_flag == 0u && log[0] == '\0');

    const rome2_startup_l66_disk_entry disk_bad[] = {
        {"a.pack", 99u},
        {"c.pack", 30u},
        {"mod.pack", 5u},
    };
    rome2_startup_engine_verify_data_manifest_100e2980(
        env, "C:\\Rome2\\rome2.exe", "data/manifest.txt", "modified.log",
        disk_bad, 3u, 1u, log, sizeof(log));
    CHECK(env->manifest_mismatch_flag == 1u);
    CHECK(strstr(log, "a.pack size mismatch\n") != NULL);
    CHECK(strstr(log, "b.pack missing\n") != NULL);
    CHECK(strstr(log, "mod.pack unknown file\n") != NULL);
    CHECK(strstr(log, "user.script.txt user script existing\n") != NULL);

    free_l66_env(env);
    return 0;
}

int main(void)
{
    if (test_layouts_and_math_helpers() != 0) {
        return 1;
    }
    if (test_fopen_fread_fseek_ftell_and_fiopen() != 0) {
        return 1;
    }
    if (test_manifest_verification_100e2980() != 0) {
        return 1;
    }
    printf("test_startup_fopen_fread_init_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
