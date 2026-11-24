#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "startup_vfprintf_read_ops.h"

int main(void)
{
    int checks = 0;

    /* 1. Validate Layer 64 guest32 fixed-width layouts. */
    assert(sizeof(rome2_startup_vfprintf_stream_adapter8_32) == 8);
    assert(sizeof(rome2_startup_vfprintf_lambda_ctx20_32) == 20);
    assert(sizeof(rome2_startup_crt_ioinfo_read56_32) == 56);
    checks += 3;

    /* 2. 0x116892d1 state transition table (0x1190ecd0). */
    assert(rome2_startup_fprintf_find_next_state_116892d1('A', 0u) == 0u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('%', 0u) == 1u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('%', 1u) == 0u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('+', 1u) == 2u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('*', 2u) == 3u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('.', 3u) == 4u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('2', 4u) == 5u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('l', 5u) == 6u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('d', 6u) == 7u);
    assert(rome2_startup_fprintf_find_next_state_116892d1(' ', 1u) == 2u);
    assert(rome2_startup_fprintf_find_next_state_116892d1('\x01', 1u) == 8u);
    checks += 11;

    /* 3. Stream flags/adapter/size validation & locked vfprintf/fprintf execution. */
    {
        char cap[128];
        memset(cap, 0, sizeof(cap));
        rome2_startup_fprintf_stream stream;
        memset(&stream, 0, sizeof(stream));
        stream.out_buf = cap;
        stream.out_cap = sizeof(cap) - 1u;

        int32_t err = 0;
        uint32_t inv = 0u;
        assert(rome2_startup_fprintf_validate_stream_flags_1168b8a6(&stream, &err, &inv) == 1u);

        stream.textmode = 1u;
        assert(rome2_startup_fprintf_validate_stream_flags_1168b8a6(&stream, &err, &inv) == 0u);
        assert(err == EINVAL && inv == 1u);

        stream.flags = ROME2_STARTUP_L64_IOSTRG;
        err = 0;
        assert(rome2_startup_fprintf_validate_stream_flags_1168b8a6(&stream, &err, &inv) == 1u);

        stream.flags = 0u;
        stream.textmode = 0u;
        stream.utf8_crlf_flags = 1u;
        assert(rome2_startup_fprintf_validate_stream_flags_1168b8a6(&stream, &err, &inv) == 0u);
        stream.utf8_crlf_flags = 0u;

        const char *tag = "mod";
        uintptr_t args1[3] = {
            (uintptr_t)42,
            (uintptr_t)tag,
            (uintptr_t)0x2aU,
        };
        err = 0;
        inv = 0u;
        int32_t n = rome2_startup_crt_fprintf_100edfb0(
            &stream, "id=%+04d name=%-5s hex=%#x", args1, 3u, &err, &inv);
        cap[stream.out_len < sizeof(cap) ? stream.out_len : sizeof(cap) - 1u] = '\0';
        assert(n == 27);
        assert(strcmp(cap, "id=+042 name=mod   hex=0x2a") == 0);
        assert(stream.lock_count == 1u && stream.unlock_count == 1u);
        assert(err == 0 && inv == 0u);
        checks += 8;

        /* Counting-only _IOSTRG stream with NULL ptr counts without buffering. */
        rome2_startup_fprintf_stream count_stream;
        memset(&count_stream, 0, sizeof(count_stream));
        count_stream.flags = ROME2_STARTUP_L64_IOSTRG;
        count_stream.has_buffer = 0u;
        int32_t cn = rome2_startup_common_vfprintf_char_1168bfab(
            0ull, &count_stream, "count:%d:%s", 0u, args1, 2u, &err, &inv);
        assert(cn == 12);
        assert(count_stream.out_len == 0u);
        assert(count_stream.lock_count == 1u && count_stream.unlock_count == 1u);
        checks += 3;

        /* Trailing dangling '%' rejects via 0x1168b884 with EINVAL. */
        err = 0;
        inv = 0u;
        assert(rome2_startup_crt_fprintf_100edfb0(&count_stream, "bad%", NULL, 0u, &err, &inv) == -1);
        assert(err == EINVAL && inv == 1u);

        /* 'N' length modifier without legacy bit 3 returns EINVAL; with bit 3 succeeds. */
        err = 0;
        inv = 0u;
        assert(rome2_startup_common_vfprintf_char_1168bfab(
                   0ull, &count_stream, "%Nd", 0u, args1, 1u, &err, &inv) == -1);
        assert(err == EINVAL && inv == 1u);
        err = 0;
        inv = 0u;
        assert(rome2_startup_common_vfprintf_char_1168bfab(
                   8ull, &count_stream, "%Nd", 0u, args1, 1u, &err, &inv) == 2);

        /* 'F' without legacy bit falls into state_case_type formatting uppercase %F float, then literal 'd'. */
        double fval = 1.5;
        uint64_t fbits = 0ull;
        memcpy(&fbits, &fval, sizeof(fbits));
        uintptr_t fargs[1] = { (uintptr_t)fbits };
        err = 0;
        inv = 0u;
        assert(rome2_startup_common_vfprintf_char_1168bfab(
                   0ull, &count_stream, "%.2Fd", 0u, fargs, 1u, &err, &inv) == 5);
        assert(rome2_startup_common_vfprintf_char_1168bfab(
                   8ull, &count_stream, "%Fd", 0u, args1, 1u, &err, &inv) == 2);

        /* write_string EILSEQ recovery writes '?' and preserves caller errno. */
        int32_t ws_written = 0;
        int32_t ws_err = EINVAL;
        stream.out_len = 0u;
        stream.fail_next_write = 1u;
        stream.simulated_write_errno = EILSEQ;
        rome2_startup_fprintf_write_string_dispatch_1168bc97(&stream, "A", 1, &ws_written, &ws_err);
        assert(ws_written == 1 && stream.out_buf[0] == '?');
        checks += 6;
    }

    /* 4. 0x116aa9e2..0x116aaffa: lowio _read ANSI/CR-LF/EOF/UTF-8/UTF-16LE/ConsoleW. */
    {
        /* 4a. Narrow text-mode ANSI CR-LF -> LF and Ctrl-Z sets FEOFLAG. */
        const uint8_t ansi_src[] = "line1\r\nline2\x1aignored";
        rome2_startup_lowio_read_device dev;
        memset(&dev, 0, sizeof(dev));
        dev.raw_bytes = ansi_src;
        dev.raw_len = sizeof(ansi_src) - 1u;
        dev.ioinfo.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN | ROME2_STARTUP_LOWIO_FTEXT;
        dev.ioinfo.textmode_29 = ROME2_STARTUP_LOWIO_TM_ANSI;
        memset(dev.ioinfo.pipech2_2a, 0x0au, 3u);

        uint8_t dst[64];
        memset(dst, 0, sizeof(dst));
        int32_t r = rome2_startup_crt_read_116aaee6(3, &dev, dst, 32u);
        assert(r == 11);
        assert(memcmp(dst, "line1\nline2", 11) == 0);
        assert((dev.ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FEOFLAG) != 0u);
        assert(dev.lock_count == 1u && dev.unlock_count == 1u);
        /* Subsequent read hits immediate FEOFLAG -> 0 bytes. */
        assert(rome2_startup_crt_read_116aaee6(3, &dev, dst, 8u) == 0);
        checks += 5;

        /* 4b. Narrow pipe lookahead splits '\r' then non-'\n' across pipech2_2a[0]. */
        const uint8_t pipe_src[] = "ab\rX";
        memset(&dev, 0, sizeof(dev));
        dev.raw_bytes = pipe_src;
        dev.raw_len = sizeof(pipe_src) - 1u;
        dev.ioinfo.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN | ROME2_STARTUP_LOWIO_FTEXT | ROME2_STARTUP_LOWIO_FPIPE;
        memset(dev.ioinfo.pipech2_2a, 0x0au, 3u);
        dev.raw_len = 3u;
        memset(dst, 0, sizeof(dst));
        r = rome2_startup_crt_read_116aaee6(4, &dev, dst, 3u);
        dev.raw_len = sizeof(pipe_src) - 1u;
        /* Now dev read 3 bytes ending in '\r' and peeked EOF before byte 3 'X' arrived; check pipe peek too. */
        assert(r == 3 && memcmp(dst, "ab\r", 3) == 0);

        const uint8_t pipe_split[] = {'a', '\r', 'Z'};
        memset(&dev, 0, sizeof(dev));
        dev.raw_bytes = pipe_split;
        dev.raw_len = sizeof(pipe_split);
        dev.ioinfo.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN | ROME2_STARTUP_LOWIO_FTEXT | ROME2_STARTUP_LOWIO_FPIPE;
        memset(dev.ioinfo.pipech2_2a, 0x0au, 3u);
        uint8_t two[2] = {0};
        assert(rome2_startup_crt_read_nolock_116aaffa(4, &dev, two, 2u) == 2);
        assert(two[0] == 'a' && two[1] == '\r');
        assert(dev.ioinfo.pipech2_2a[0] == 'Z');
        uint8_t tail_byte = 0u;
        assert(rome2_startup_crt_read_nolock_116aaffa(4, &dev, &tail_byte, 1u) == 1 && tail_byte == 'Z');
        checks += 5;

        /* 4c. UTF-8 text-mode -> UTF-16LE including split multi-byte sequence rewind. */
        const uint8_t utf8_src[] = {'A', '\r', '\n', 0xe2u, 0x82u, 0xacu}; /* A\r\n + U+20AC (Euro) */
        memset(&dev, 0, sizeof(dev));
        dev.raw_bytes = utf8_src;
        dev.raw_len = sizeof(utf8_src);
        dev.ioinfo.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN | ROME2_STARTUP_LOWIO_FTEXT;
        dev.ioinfo.textmode_29 = ROME2_STARTUP_LOWIO_TM_UTF8;
        memset(dev.ioinfo.pipech2_2a, 0x0au, 3u);
        uint16_t wout[8];
        memset(wout, 0, sizeof(wout));
        /* Request 8 output bytes (count/2 = 4 UTF-8 bytes read: 'A', '\r', '\n', 0xe2 truncated!). */
        int32_t u8n = rome2_startup_crt_read_116aaee6(5, &dev, wout, 8u);
        assert(u8n == 4); /* "A\n" in UTF-16LE = 2 code units = 4 bytes */
        assert(wout[0] == 'A' && wout[1] == '\n');
        assert(dev.raw_pos == 3u); /* 0xe2 was rewound */
        memset(wout, 0, sizeof(wout));
        int32_t u8n2 = rome2_startup_crt_read_116aaee6(5, &dev, wout, 8u);
        assert(u8n2 == 2 && wout[0] == 0x20acu);
        checks += 4;

        /* 4d. UTF-16LE console ReadConsoleW CR-LF -> LF and Ctrl-Z truncation. */
        const uint8_t u16_console[] = {
            'H', 0, 'i', 0, '\r', 0, '\n', 0, 0x1au, 0, '!', 0
        };
        memset(&dev, 0, sizeof(dev));
        dev.raw_bytes = u16_console;
        dev.raw_len = sizeof(u16_console);
        dev.ioinfo.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN | ROME2_STARTUP_LOWIO_FTEXT;
        dev.ioinfo.textmode_29 = ROME2_STARTUP_LOWIO_TM_UTF16LE;
        dev.is_tty = 1u;
        dev.is_console_handle = 1u;
        memset(wout, 0, sizeof(wout));
        int32_t con_n = rome2_startup_crt_read_116aaee6(0, &dev, wout, 12u);
        assert(con_n == 6 && wout[0] == 'H' && wout[1] == 'i' && wout[2] == '\n');
        assert((dev.ioinfo.osfile_28 & ROME2_STARTUP_LOWIO_FEOFLAG) != 0u);

        /* FEOFLAG short-circuits to 0 before checking odd byte count; clearing FEOFLAG restores EINVAL check. */
        assert(rome2_startup_crt_read_116aaee6(0, &dev, wout, 3u) == 0);
        dev.ioinfo.osfile_28 &= (uint8_t)(~ROME2_STARTUP_LOWIO_FEOFLAG & 0xffu);
        assert(rome2_startup_crt_read_116aaee6(0, &dev, wout, 3u) == -1 && dev.last_errno == EINVAL);
        assert(rome2_startup_crt_read_116aaee6(-2, &dev, wout, 4u) == -1 && dev.last_errno == EBADF);
        checks += 5;
    }

    printf("test_startup_vfprintf_read_ops: ALL PASSED (%d checks)\n", checks);
    return 0;
}
