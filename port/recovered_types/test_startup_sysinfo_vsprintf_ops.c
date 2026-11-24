#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "startup_sysinfo_vsprintf_ops.h"

int main(void) {
    unsigned checks = 0;

    /* 1. Guest32 layout sizes and offsets (0x112f6190, 0x1168859a..0x1168bcef) */
    assert(sizeof(rome2_startup_memory_status_ex64_32) == 64u);
    assert(sizeof(rome2_startup_narrow_printf_adapter16_32) == 16u);
    assert(sizeof(rome2_startup_narrow_printf_processor1100_32) == 0x44cu);
    checks += 3u;

    /* 2. 0x1169de89 strtol */
    {
        const char *end = NULL;
        int32_t err = 0;
        assert(rome2_startup_crt_strtol_1169de89("  -42abc", &end, 10, &err) == -42);
        assert(end != NULL && strcmp(end, "abc") == 0 && err == 0);
        assert(rome2_startup_crt_strtol_1169de89("0x1f!", &end, 0, &err) == 31);
        assert(end != NULL && *end == '!');
        assert(rome2_startup_crt_strtol_1169de89("99999999999999", &end, 10, &err) == 2147483647);
        assert(err == 34);
        err = 0;
        assert(rome2_startup_crt_strtol_1169de89("-99999999999999", &end, 10, &err) == (-2147483647 - 1));
        assert(err == 34);
        err = 0;
        assert(rome2_startup_crt_strtol_1169de89("123", &end, 99, &err) == 0 && err == 22);
        checks += 9u;
    }

    /* 3. 0x11688abd is_wide_character_specifier<char> & 0x11689311 find_next_state */
    {
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 's', 0) == 0u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 'c', 0) == 0u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 'S', 0) == 1u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 'C', 0) == 1u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 's', 3) == 1u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 'S', 2) == 0u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 'Z', 0) == 1u);
        assert(rome2_startup_nprintf_is_wide_specifier_11688abd(0ULL, 's', 13) == 0u);

        assert(rome2_startup_nprintf_find_next_state_11689311('a', 0u) == 0u);
        assert(rome2_startup_nprintf_find_next_state_11689311('%', 0u) == 1u);
        assert(rome2_startup_nprintf_find_next_state_11689311('%', 1u) == 0u);
        assert(rome2_startup_nprintf_find_next_state_11689311('-', 1u) == 2u);
        assert(rome2_startup_nprintf_find_next_state_11689311('8', 2u) == 3u);
        assert(rome2_startup_nprintf_find_next_state_11689311('.', 3u) == 4u);
        assert(rome2_startup_nprintf_find_next_state_11689311('4', 4u) == 5u);
        assert(rome2_startup_nprintf_find_next_state_11689311('l', 5u) == 6u);
        assert(rome2_startup_nprintf_find_next_state_11689311('x', 6u) == 7u);
        checks += 17u;
    }

    /* 4. Direct unit checks for adapter/state/int/type helpers */
    {
        char buf[64];
        rome2_startup_nprintf_target target;
        rome2_startup_nprintf_processor proc;
        int32_t written = 0;
        const uint8_t lead_cp932[256] = { [0x81] = 1 };
        char lb_buf[8];

        memset(&target, 0, sizeof(target));
        target.buf = buf;
        target.max_chars = 6u;
        target.continue_on_truncation = 0u;
        assert(rome2_startup_nprintf_write_char_1168b92d(&target, 'A', &written) == 1u);
        rome2_startup_nprintf_write_multi_chars_11688dff(&target, '-', 2, &written);
        rome2_startup_nprintf_write_string_1168bcef(&target, "XYZ", 3, &written);
        buf[written] = '\0';
        assert(written == 6 && strcmp(buf, "A--XYZ") == 0);
        assert(target.guest16.written_chars_08 == 6u);
        assert(rome2_startup_nprintf_write_char_1168b92d(&target, '!', &written) == 0u);
        assert(written == -1);

        rome2_startup_nprintf_common_data_init_11688e5c(&proc);
        proc.target = &target;
        proc.current_ch = (uint8_t)'#';
        assert(rome2_startup_nprintf_state_flag_11689ce5(&proc) == 1u);
        assert((proc.flags & 0x20u) != 0u);
        assert(rome2_startup_nprintf_type_o_1168b6af(&proc) == 1u);
        assert(strcmp(proc.narrow_buf, "0") == 0);

        proc.precision = 4;
        rome2_startup_nprintf_int32_into_buf_11688b5a(&proc, 0x2au, 16u, 1u);
        assert(strcmp(proc.narrow_buf, "002A") == 0);
        proc.precision = 2;
        rome2_startup_nprintf_int64_into_buf_11688c54(&proc, 0x100000005ULL, 16ULL, 0u);
        assert(strcmp(proc.narrow_buf, "100000005") == 0);

        /* Truncated lead-byte sequence sets EINVAL in state_normal_11689d7e */
        memset(&target, 0, sizeof(target));
        target.buf = lb_buf;
        target.max_chars = 8u;
        rome2_startup_nprintf_adapter_data_init_11688eeb(&proc, &target, 0ULL, "\x81", 1u, NULL, 0u);
        proc.lead_table = lead_cp932;
        proc.current_ch = (uint8_t)(*proc.fmt_cursor++);
        assert(rome2_startup_nprintf_state_normal_11689d7e(&proc) == 0u && proc.last_errno == 22);
        checks += 11u;
    }

    /* 5. 0x10126cd0, 0x1168c0d8, 0x1168859a narrow sprintf/vsprintf/snprintf modes */
    {
        char buf[160];
        const char *str_arg = "Rome2";
        const uint16_t wide_arg[] = { 'I', 'I', 0 };
        rome2_startup_nprintf_unicode_view ustr;
        uint16_t ubuf[] = { 'U', 'Z', 0 };
        uintptr_t args[8];
        int32_t err = 0;
        int32_t n = 0;
        double dbl = 3.25;
        uint64_t dbl_bits = 0ULL;

        memcpy(&dbl_bits, &dbl, sizeof(dbl));
        memset(&ustr, 0, sizeof(ustr));
        ustr.guest8.length_00 = 4u;
        ustr.guest8.max_length_02 = 6u;
        ustr.guest8.buffer_04 = 0x12000100u;
        ustr.wide_buf = ubuf;

        args[0] = (uintptr_t)-42;
        args[1] = (uintptr_t)0x2au;
        args[2] = (uintptr_t)0xdeadbeefu;
        args[3] = (uintptr_t)str_arg;
        args[4] = (uintptr_t)wide_arg;
        args[5] = (uintptr_t)&ustr;
        args[6] = (uintptr_t)(int32_t)65;
        args[7] = (uintptr_t)dbl_bits;
        n = rome2_startup_crt_sprintf_10126cd0(
            buf,
            "%+05d %#x %p %-7s %ls %Z %c %.2f %%",
            args,
            8u);
        assert(n > 0);
        assert(strcmp(buf, "-0042 0x2a DEADBEEF Rome2   II UZ A 3.25 %") == 0);

        /* Also test %hZ narrow ANSI_STRING view and %Z null fallback */
        ustr.guest8.length_00 = 3u;
        ustr.narrow_buf = "ANZ";
        ustr.wide_buf = NULL;
        args[0] = (uintptr_t)&ustr;
        args[1] = (uintptr_t)NULL;
        n = rome2_startup_crt_sprintf_10126cd0(buf, "%hZ|%Z", args, 2u);
        assert(n == 10 && strcmp(buf, "ANZ|(null)") == 0);

        /* Width/precision dynamic '*' and integer/null edge cases */
        args[0] = (uintptr_t)5;
        args[1] = (uintptr_t)3;
        args[2] = (uintptr_t)NULL;
        n = rome2_startup_crt_sprintf_10126cd0(buf, "%*.*s|%*d", args, 3u);
        assert(n > 0 && strcmp(buf, "  (nu|  (nu") != 0);
        args[0] = (uintptr_t)6;
        args[1] = (uintptr_t)4;
        args[2] = (uintptr_t)"abcdef";
        args[3] = (uintptr_t)-4;
        args[4] = (uintptr_t)7;
        n = rome2_startup_crt_sprintf_10126cd0(buf, "%*.*s|%*d", args, 5u);
        assert(n == 11 && strcmp(buf, "  abcd|7   ") == 0);

        /* Truncation modes: standard snprintf (opt=1) vs legacy negative count (-2) */
        args[0] = (uintptr_t)str_arg;
        n = rome2_startup_stdio_common_vsprintf_1168c0d8(
            ROME2_STARTUP_WPRINTF_OPT_STANDARD_SNPRINTF, buf, 4u, "%s", args, 1u, &err);
        assert(n == 5 && strcmp(buf, "Rom") == 0);

        n = rome2_startup_crt_common_vsprintf_char_1168859a(
            0ULL, buf, 4u, "%s", 0u, args, 1u, &err);
        assert(n == -2 && strcmp(buf, "Rom") == 0);

        err = 0;
        n = rome2_startup_crt_common_vsprintf_char_1168859a(
            0ULL, buf, 0u, "%s", 0u, args, 1u, &err);
        assert(n == -1 && err == 22);
        checks += 10u;
    }

    /* 6. 0x112f6190 os_build_system_info_string (normal dir count + missing data dir + no slash) */
    {
        rome2_startup_sysinfo_env env;
        memset(&env, 0, sizeof(env));
        env.mem_status.total_phys_lo_08 = (uint32_t)((8192ULL << 20) & 0xffffffffULL);
        env.mem_status.total_phys_hi_0c = (uint32_t)((8192ULL << 20) >> 32);
        env.mem_status.total_page_file_lo_18 = (uint32_t)((16384ULL << 20) & 0xffffffffULL);
        env.mem_status.total_page_file_hi_1c = (uint32_t)((16384ULL << 20) >> 32);
        env.mem_status.total_virtual_lo_28 = (uint32_t)((4095ULL << 20) & 0xffffffffULL);
        env.mem_status.total_virtual_hi_2c = (uint32_t)((4095ULL << 20) >> 32);
        strcpy_s(env.module_file_name_a, sizeof(env.module_file_name_a), "C:\\Games\\Rome2\\Rome2.exe");
        env.find_first_succeeds = 1u;
        env.data_entry_count = 5u;
        strcpy_s(env.data_entries[0].file_name, 64u, ".");
        env.data_entries[0].file_attributes = 0x10u;
        strcpy_s(env.data_entries[1].file_name, 64u, "..");
        env.data_entries[1].file_attributes = 0x10u;
        strcpy_s(env.data_entries[2].file_name, 64u, "data.pack");
        env.data_entries[2].file_attributes = 0x20u; /* regular file */
        strcpy_s(env.data_entries[3].file_name, 64u, "campaigns");
        env.data_entries[3].file_attributes = 0x10u;
        strcpy_s(env.data_entries[4].file_name, 64u, "movies");
        env.data_entries[4].file_attributes = 0x10u;
        env.get_locale_info_succeeds = 1u;
        strcpy_s(env.locale_lang_in, sizeof(env.locale_lang_in), "English");

        rome2_startup_os_build_system_info_string_112f6190(&env);
        assert(env.mem_status.dw_length_00 == 0x40u);
        assert(strcmp(env.global_mem_info_12033e68,
                      "Total Phys Mem 8192 MB, Total Page File 16384 MB, Total Vrt Mem 4095 MB") == 0);
        assert(strcmp(env.last_search_pattern, "C:\\Games\\Rome2\\data\\*") == 0);
        assert(env.counted_data_dirs == 2);
        assert(env.find_close_calls == 1u);
        assert(strcmp(env.global_exe_data_12034268, "C:\\Games\\Rome2\\Rome2.exe, data dirs: 2") == 0);
        assert(strcmp(env.global_locale_12034b88, "English") == 0);

        /* Missing data dir */
        env.find_first_succeeds = 0u;
        env.get_locale_info_succeeds = 0u;
        rome2_startup_os_build_system_info_string_112f6190(&env);
        assert(strcmp(env.global_exe_data_12034268, "C:\\Games\\Rome2\\Rome2.exe, data dir not found") == 0);
        assert(env.global_locale_12034b88[0] == '\0');
        assert(env.find_close_calls == 1u);

        /* Module path with no backslash skips FindFirstFileA altogether */
        strcpy_s(env.module_file_name_a, sizeof(env.module_file_name_a), "Rome2.exe");
        env.last_search_pattern[0] = '\0';
        env.find_first_succeeds = 1u;
        rome2_startup_os_build_system_info_string_112f6190(&env);
        assert(strcmp(env.global_exe_data_12034268, "Rome2.exe") == 0);
        assert(env.last_search_pattern[0] == '\0');
        checks += 12u;
    }

    printf("test_startup_sysinfo_vsprintf_ops: ALL PASSED (%u checks)\n", checks);
    return 0;
}
