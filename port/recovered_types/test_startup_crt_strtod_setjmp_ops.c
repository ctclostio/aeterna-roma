#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "startup_crt_strtod_setjmp_ops.h"

typedef struct test_longjmp_log {
    uint32_t rtl_calls;
    uint32_t rtl_target_frame;
    uint32_t rtl_code;
    uint32_t seh4_calls;
    uint32_t eh3_calls;
    uint32_t nlg_calls;
    uint32_t transfer_calls;
    uint32_t transfer_ip;
    int32_t transfer_val;
} test_longjmp_log;

static void mock_rtl_unwind(void *user, uint32_t target_frame, uint32_t target_ip, const rome2_startup_crt_exc_record24_32 *rec) {
    test_longjmp_log *log = (test_longjmp_log *)user;
    (void)target_ip;
    log->rtl_calls++;
    log->rtl_target_frame = target_frame;
    log->rtl_code = rec->exception_code_00;
}

static void mock_seh4_unwind(void *user, const rome2_startup_crt_jump_buf64_32 *jbuf) {
    (void)jbuf;
    ((test_longjmp_log *)user)->seh4_calls++;
}

static void mock_eh3_unwind(void *user, uint32_t seh_frame, uint32_t trylevel) {
    (void)seh_frame;
    (void)trylevel;
    ((test_longjmp_log *)user)->eh3_calls++;
}

static void mock_nlg(void *user, uint32_t target_ip, uint32_t ebp, uint32_t code) {
    (void)target_ip;
    (void)ebp;
    (void)code;
    ((test_longjmp_log *)user)->nlg_calls++;
}

static void mock_transfer(void *user, uint32_t target_ip, int32_t ret_val) {
    test_longjmp_log *log = (test_longjmp_log *)user;
    log->transfer_calls++;
    log->transfer_ip = target_ip;
    log->transfer_val = ret_val;
}

static int32_t mock_custom_collate(void *user, uint32_t lcid, const char *a, const char *b) {
    (void)user;
    (void)lcid;
    int c = strcmp(a, b);
    return (c < 0) ? 1 : (c > 0 ? 3 : 2);
}

int main(void) {
    rome2_l73_locale_info loc;
    const char *endp = NULL;
    double d = 0.0;
    int32_t err = 0;
    char buf[32];
    const char *cur = NULL;
    char ch = 'x';
    rome2_startup_crt_jump_buf64_32 jb;
    uint32_t extras[4] = { 0x10004000u, 3u, 0x11111111u, 0x22222222u };
    test_longjmp_log lj;
    rome2_l74_longjmp_env env;
    uint32_t pv = 0u;
    uint32_t checks = 0u;

    memset(&loc, 0, sizeof(loc));
    loc.decimal_point = '.';

    /* 1. cstr FP parser + rollback + pow/powf */
    assert(rome2_l74_cstr_parse_fp_double(&loc, "2.5e2;", &endp, &d, &err) == ROME2_L73_SLD_OK);
    assert(fabs(d - 250.0) < 1e-12 && strcmp(endp, ";") == 0);
    assert(fabs(rome2_l74_strtod("-0x1.0p3!", &endp, NULL, &err) - (-8.0)) < 1e-12 && strcmp(endp, "!") == 0);
    assert(rome2_l74_cstr_source_rollback(&cur, &ch, "start") == 1u && ch == '\0' && strcmp(cur, "start") == 0);
    assert(fabsf(rome2_l74_powf(2.0f, 5.0f) - 32.0f) < 1e-6f);
    assert(fabs(rome2_l74_pow(3.0, 4.0) - 81.0) < 1e-12);
    checks += 5u;

    /* 2. strtoul, strncpy, strcspn, strncat, strcoll_l */
    assert(rome2_l74_strtoul("  -0x10z", &endp, 0, &err) == (uint32_t)(-16) && err == 0 && *endp == 'z');
    assert(rome2_l74_strtoul("999999999999", &endp, 10, &err) == 0xffffffffu && err == 0x22);
    memset(buf, 'A', sizeof(buf));
    assert(rome2_l74_strncpy(buf, "hi", 6u) == buf && buf[0] == 'h' && buf[1] == 'i' && buf[2] == '\0' && buf[5] == '\0');
    assert(rome2_l74_strcspn("hello,world", ",;") == 5u);
    assert(rome2_l74_strncat(buf, "1234", 2u) == buf && strcmp(buf, "hi12") == 0);
    assert(rome2_l74_strcoll("alpha", "beta", &err) == -1 && err == 0);
    assert(rome2_l74_strcoll_l("beta", "alpha", 0x409u, mock_custom_collate, NULL, &err) == 1 && err == 0);
    checks += 7u;

    /* 3. _setjmp3, probe_read4, _longjmp (SEH4 VC20 vs EH3 fallback) */
    assert(rome2_l74_setjmp3_init(&jb, 0x0019ff00u, 1u, 0x10001234u, 0x0019fe00u, 0x0019fdd0u, 4u, 0u, extras) == 0);
    assert(jb.cookie_20 == ROME2_L74_VC20_COOKIE && jb.unwind_func_24 == 0x10004000u && jb.trylevel_1c == 3u);
    assert(jb.unwind_data_28[0] == 0x11111111u && jb.unwind_data_28[1] == 0x22222222u);
    assert(rome2_l74_except_validate_jump_buffer(&jb) == 1u);
    assert(rome2_l74_probe_read4(&jb.cookie_20, 0u, &pv) == 1u && pv == ROME2_L74_VC20_COOKIE);
    assert(rome2_l74_probe_read4(&jb.cookie_20, 1u, &pv) == 0u);

    memset(&lj, 0, sizeof(lj));
    memset(&env, 0, sizeof(env));
    env.user = &lj;
    env.current_seh_frame = 0x0019fe80u;
    env.cookie_mem_valid = 1u;
    env.rtl_unwind = mock_rtl_unwind;
    env.seh4_unwind = mock_seh4_unwind;
    env.eh3_local_unwind = mock_eh3_unwind;
    env.nlg_notify = mock_nlg;
    env.target_transfer = mock_transfer;
    /* value == 0 normalizes to 1 */
    rome2_l74_longjmp(&env, &jb, 0);
    assert(lj.rtl_calls == 1u && lj.rtl_target_frame == 0x0019ff00u && lj.rtl_code == ROME2_L74_STATUS_LONGJUMP);
    assert(lj.seh4_calls == 1u && lj.eh3_calls == 0u && lj.nlg_calls == 1u);
    assert(lj.transfer_calls == 1u && lj.transfer_ip == 0x10001234u && lj.transfer_val == 1);

    /* non-VC20 falls back to EH3 local_unwind2 */
    env.cookie_mem_valid = 0u;
    rome2_l74_longjmp(&env, &jb, 42);
    assert(lj.eh3_calls == 1u && lj.transfer_val == 42);
    checks += 10u;

    (void)checks;
    return 0;
}
