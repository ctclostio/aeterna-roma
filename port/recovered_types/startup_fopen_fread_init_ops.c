#include "startup_fopen_fread_init_ops.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROME2_L66_EINVAL 22
#define ROME2_L66_EMFILE 24
#define ROME2_L66_EBADF  9
#define ROME2_L66_ERANGE 34

static rome2_startup_l65_vfs_file *l66_stream_file(rome2_startup_l66_env *env, const rome2_startup_l66_stream *stream)
{
    if (env == NULL || stream == NULL || stream->guest.file_10 < 0 ||
        (uint32_t)stream->guest.file_10 >= env->io.nhandle) {
        return NULL;
    }
    int32_t fh = stream->guest.file_10;
    rome2_startup_l65_ioinfo_slot *slot = &env->io.pages[(uint32_t)fh >> 6][(uint32_t)fh & 0x3fu];
    if (slot->backed_file_idx < 0 || (uint32_t)slot->backed_file_idx >= ROME2_STARTUP_L65_MAX_FILES) {
        return NULL;
    }
    return &env->io.files[slot->backed_file_idx];
}

static rome2_startup_l65_ioinfo_slot *l66_stream_ioinfo(rome2_startup_l66_env *env, const rome2_startup_l66_stream *stream)
{
    if (env == NULL || stream == NULL || stream->guest.file_10 < 0 ||
        (uint32_t)stream->guest.file_10 >= env->io.nhandle) {
        return NULL;
    }
    int32_t fh = stream->guest.file_10;
    return &env->io.pages[(uint32_t)fh >> 6][(uint32_t)fh & 0x3fu];
}

static void l66_sync_stream_buf_counts(rome2_startup_l66_stream *stream)
{
    if (stream == NULL) {
        return;
    }
    stream->guest.cnt_08 = (stream->cursor_off <= stream->valid_len)
        ? (int32_t)(stream->valid_len - stream->cursor_off)
        : 0;
    stream->guest.bufsiz_18 = (int32_t)stream->bufsiz;
}

static void l66_close_stream(rome2_startup_l66_env *env, rome2_startup_l66_stream *stream)
{
    if (stream == NULL) {
        return;
    }
    if (env != NULL && stream->guest.file_10 >= 0 && (uint32_t)stream->guest.file_10 < env->io.nhandle) {
        int32_t fh = stream->guest.file_10;
        rome2_startup_l65_ioinfo_slot *slot = &env->io.pages[(uint32_t)fh >> 6][(uint32_t)fh & 0x3fu];
        slot->guest.osfile_28 = 0u;
        slot->guest.osfhnd_18 = 0xffffffffu;
        slot->backed_file_idx = -1;
        slot->handle_allocated = 0u;
    }
    stream->guest.flag_0c = 0u;
    stream->guest.file_10 = -1;
    stream->cursor_off = 0u;
    stream->valid_len = 0u;
    l66_sync_stream_buf_counts(stream);
}

static void l66_set_invalid(rome2_startup_l66_env *env)
{
    if (env != NULL) {
        env->io.last_errno = ROME2_L66_EINVAL;
        env->io.invalid_param_calls += 1u;
    }
}

void rome2_startup_l66_env_init(rome2_startup_l66_env *env)
{
    if (env == NULL) {
        return;
    }
    memset(env, 0, sizeof(*env));
    rome2_startup_l65_env_init(&env->io);
    env->nstream = ROME2_STARTUP_L66_MAX_PIOB;
}

void rome2_startup_l66_env_destroy(rome2_startup_l66_env *env)
{
    if (env == NULL) {
        return;
    }
    for (size_t i = 0; i < ROME2_STARTUP_L66_MAX_PIOB; ++i) {
        free(env->piob[i]);
        env->piob[i] = NULL;
    }
    rome2_startup_l65_env_destroy(&env->io);
}

/* `0x11684670`: CRT __alldiv (signed 64-bit integer division). */
int64_t rome2_startup_crt_alldiv_11684670(int64_t numerator, int64_t denominator)
{
    if (denominator == 0 || (numerator == INT64_MIN && denominator == -1)) {
        return 0;
    }
    return numerator / denominator;
}

/* `0x11699fb7`: CRT LongLongSub overflow-checked subtraction. */
int32_t rome2_startup_crt_longlongsub_11699fb7(int64_t a, int64_t b, int64_t *out)
{
    if (out != NULL) {
        *out = 0;
    }
    if ((b < 0 && a > INT64_MAX + b) || (b > 0 && a < INT64_MIN + b)) {
        return (int32_t)ROME2_STARTUP_L66_INTSAFE_E_OVERFLOW;
    }
    if (out != NULL) {
        *out = a - b;
    }
    return 0;
}

/* `0x1168d37f`: CRT _exit. */
void rome2_startup_crt_exit_1168d37f(rome2_startup_l66_env *env, int32_t code)
{
    if (env != NULL) {
        env->exit_called = 1u;
        env->exit_code = code;
    }
}

/* `0x116aa25b`: find_or_allocate_unused_stream_nolock. */
rome2_startup_l66_stream *rome2_startup_crt_find_or_alloc_stream_nolock_116aa25b(rome2_startup_l66_env *env)
{
    if (env == NULL) {
        return NULL;
    }
    uint32_t limit = (env->nstream <= ROME2_STARTUP_L66_MAX_PIOB) ? env->nstream : ROME2_STARTUP_L66_MAX_PIOB;
    for (uint32_t i = 3u; i < limit; ++i) {
        rome2_startup_l66_stream *st = env->piob[i];
        if (st == NULL) {
            if (env->fail_stream_calloc != 0u) {
                return NULL;
            }
            st = (rome2_startup_l66_stream *)calloc(1, sizeof(*st));
            if (st == NULL) {
                return NULL;
            }
            env->piob[i] = st;
            st->guest.file_10 = -1;
            st->guest.flag_0c |= ROME2_STARTUP_L66_IOALLOCATED;
            st->lock_depth += 1u;
            st->bufsiz = 512u;
            st->guest.bufsiz_18 = 512;
            return st;
        }
        if ((st->guest.flag_0c & ROME2_STARTUP_L66_IOALLOCATED) == 0u) {
            st->lock_depth += 1u;
            if ((st->guest.flag_0c & ROME2_STARTUP_L66_IOALLOCATED) == 0u) {
                st->guest.flag_0c = ROME2_STARTUP_L66_IOALLOCATED;
                st->cursor_off = 0u;
                st->valid_len = 0u;
                st->bufsiz = 512u;
                st->guest.bufsiz_18 = 512;
                return st;
            }
            st->lock_depth -= 1u;
        }
    }
    return NULL;
}

/* `0x116aa217`: SEH4 unlock funclet for __acrt_stdio_allocate_stream. */
void rome2_startup_crt_stdio_alloc_unlock_116aa217(rome2_startup_l66_env *env)
{
    if (env != NULL) {
        env->stdio_table_unlock_count += 1u;
    }
}

/* `0x116aa1b7`: __acrt_stdio_allocate_stream. */
rome2_startup_l66_stream *rome2_startup_crt_stdio_allocate_stream_116aa1b7(rome2_startup_l66_env *env)
{
    if (env == NULL) {
        return NULL;
    }
    env->stdio_table_lock_count += 1u;
    rome2_startup_l66_stream *st = rome2_startup_crt_find_or_alloc_stream_nolock_116aa25b(env);
    if (st != NULL) {
        st->guest.cnt_08 = 0;
        st->guest.tmpfname_1c = 0u;
        st->guest.ptr_00 = 0u;
        st->guest.base_04 = 0u;
        st->guest.file_10 = -1;
        st->cursor_off = 0u;
        st->valid_len = 0u;
    }
    rome2_startup_crt_stdio_alloc_unlock_116aa217(env);
    return st;
}

/* `0x116aa9cc`: tail-jump thunk into common_openfile<char>. */
rome2_startup_l66_stream *rome2_startup_crt_common_openfile_char_thunk_116aa9cc(
    rome2_startup_l66_env *env,
    const char *filename,
    const char *mode,
    int32_t shflag,
    rome2_startup_l66_stream *stream)
{
    if (env == NULL || stream == NULL) {
        return NULL;
    }
    rome2_startup_l65_stdio_stream tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.flags = stream->guest.flag_0c;
    tmp.file_handle = stream->guest.file_10;
    if (rome2_startup_crt_common_openfile_char_116aa7b2(&env->io, filename, mode, shflag, &tmp) == NULL) {
        return NULL;
    }
    stream->guest.flag_0c = tmp.flags;
    stream->guest.file_10 = tmp.file_handle;
    stream->guest.ptr_00 = 0u;
    stream->guest.base_04 = 0u;
    stream->guest.cnt_08 = 0;
    stream->bufsiz = 512u;
    stream->guest.bufsiz_18 = 512;
    return stream;
}

/* `0x116aa9d7`: tail-jump thunk into common_openfile<wchar_t>. */
rome2_startup_l66_stream *rome2_startup_crt_common_openfile_wchar_thunk_116aa9d7(
    rome2_startup_l66_env *env,
    const uint16_t *filename,
    const uint16_t *mode,
    int32_t shflag,
    rome2_startup_l66_stream *stream)
{
    if (env == NULL || stream == NULL) {
        return NULL;
    }
    rome2_startup_l65_stdio_stream tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.flags = stream->guest.flag_0c;
    tmp.file_handle = stream->guest.file_10;
    if (rome2_startup_crt_common_openfile_wchar_116aa835(&env->io, filename, mode, shflag, &tmp) == NULL) {
        return NULL;
    }
    stream->guest.flag_0c = tmp.flags;
    stream->guest.file_10 = tmp.file_handle;
    stream->guest.ptr_00 = 0u;
    stream->guest.base_04 = 0u;
    stream->guest.cnt_08 = 0;
    stream->bufsiz = 512u;
    stream->guest.bufsiz_18 = 512;
    return stream;
}

/* `0x1168e877` & `0x1168e92d`: common_fsopen SEH4 cleanup funclets. */
void rome2_startup_crt_fsopen_cleanup_char_1168e877(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int32_t opened_ok)
{
    (void)env;
    if (stream != NULL) {
        if (opened_ok == 0) {
            stream->guest.flag_0c &= ~ROME2_STARTUP_L66_IOALLOCATED;
        }
        if (stream->lock_depth > 0u) {
            stream->lock_depth -= 1u;
        }
    }
}

void rome2_startup_crt_fsopen_cleanup_wchar_1168e92d(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int32_t opened_ok)
{
    rome2_startup_crt_fsopen_cleanup_char_1168e877(env, stream, opened_ok);
}

/* `0x1168e7d7`: common_fsopen<char>. */
rome2_startup_l66_stream *rome2_startup_crt_common_fsopen_char_1168e7d7(
    rome2_startup_l66_env *env,
    const char *filename,
    const char *mode,
    int32_t shflag)
{
    if (filename == NULL || mode == NULL || *mode == '\0') {
        l66_set_invalid(env);
        return NULL;
    }
    if (*filename == '\0') {
        if (env != NULL) {
            env->io.last_errno = ROME2_L66_EINVAL;
        }
        return NULL;
    }
    rome2_startup_l66_stream *st = rome2_startup_crt_stdio_allocate_stream_116aa1b7(env);
    if (st == NULL) {
        if (env != NULL) {
            env->io.last_errno = ROME2_L66_EMFILE;
        }
        return NULL;
    }
    rome2_startup_l66_stream *opened =
        rome2_startup_crt_common_openfile_char_thunk_116aa9cc(env, filename, mode, shflag, st);
    rome2_startup_crt_fsopen_cleanup_char_1168e877(env, st, opened != NULL ? 1 : 0);
    return opened;
}

/* `0x1168e88e`: common_fsopen<wchar_t>. */
rome2_startup_l66_stream *rome2_startup_crt_common_fsopen_wchar_1168e88e(
    rome2_startup_l66_env *env,
    const uint16_t *filename,
    const uint16_t *mode,
    int32_t shflag)
{
    if (filename == NULL || mode == NULL || *mode == 0u) {
        l66_set_invalid(env);
        return NULL;
    }
    if (*filename == 0u) {
        if (env != NULL) {
            env->io.last_errno = ROME2_L66_EINVAL;
        }
        return NULL;
    }
    rome2_startup_l66_stream *st = rome2_startup_crt_stdio_allocate_stream_116aa1b7(env);
    if (st == NULL) {
        if (env != NULL) {
            env->io.last_errno = ROME2_L66_EMFILE;
        }
        return NULL;
    }
    rome2_startup_l66_stream *opened =
        rome2_startup_crt_common_openfile_wchar_thunk_116aa9d7(env, filename, mode, shflag, st);
    rome2_startup_crt_fsopen_cleanup_wchar_1168e92d(env, st, opened != NULL ? 1 : 0);
    return opened;
}

/* `0x1168e9a2`: _fopen. */
rome2_startup_l66_stream *rome2_startup_crt_fopen_1168e9a2(
    rome2_startup_l66_env *env,
    const char *filename,
    const char *mode)
{
    return rome2_startup_crt_common_fsopen_char_1168e7d7(env, filename, mode, ROME2_STARTUP_SH_DENYNO);
}

/* `0x1168e9b9`: _fopen_s. */
int32_t rome2_startup_crt_fopen_s_1168e9b9(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream **out_stream,
    const char *filename,
    const char *mode)
{
    if (out_stream == NULL) {
        l66_set_invalid(env);
        return ROME2_L66_EINVAL;
    }
    *out_stream = rome2_startup_crt_common_fsopen_char_1168e7d7(env, filename, mode, ROME2_STARTUP_SH_SECURE);
    if (*out_stream != NULL) {
        return 0;
    }
    return (env != NULL && env->io.last_errno != 0) ? env->io.last_errno : ROME2_L66_EINVAL;
}

/* `0x1168e95b`: __wfopen_s. */
int32_t rome2_startup_crt_wfopen_s_1168e95b(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream **out_stream,
    const uint16_t *filename,
    const uint16_t *mode)
{
    if (out_stream == NULL) {
        l66_set_invalid(env);
        return ROME2_L66_EINVAL;
    }
    *out_stream = rome2_startup_crt_common_fsopen_wchar_1168e88e(env, filename, mode, ROME2_STARTUP_SH_SECURE);
    if (*out_stream != NULL) {
        return 0;
    }
    return (env != NULL && env->io.last_errno != 0) ? env->io.last_errno : ROME2_L66_EINVAL;
}

static int32_t l66_read_lowio_translated(
    rome2_startup_l66_env *env,
    const rome2_startup_l66_stream *stream,
    uint8_t *dst,
    uint32_t req)
{
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, stream);
    rome2_startup_l65_ioinfo_slot *slot = l66_stream_ioinfo(env, stream);
    if (vf == NULL || slot == NULL || dst == NULL) {
        return -1;
    }
    rome2_startup_lowio_read_device rdev;
    memset(&rdev, 0, sizeof(rdev));
    rdev.ioinfo = slot->guest;
    rdev.ioinfo.osfhnd_18 = 1u;
    rdev.raw_bytes = vf->data;
    rdev.raw_len = vf->len;
    rdev.raw_pos = (vf->cursor >= 0 && (size_t)vf->cursor <= vf->len) ? (size_t)vf->cursor : vf->len;
    int32_t nr = rome2_startup_crt_read_nolock_116aaffa(0, &rdev, dst, req);
    vf->cursor = (int64_t)rdev.raw_pos;
    slot->guest.osfile_28 = rdev.ioinfo.osfile_28;
    slot->guest.pipech2_2a[0] = rdev.ioinfo.pipech2_2a[0];
    slot->guest.pipech2_2a[1] = rdev.ioinfo.pipech2_2a[1];
    slot->guest.pipech2_2a[2] = rdev.ioinfo.pipech2_2a[2];
    return nr;
}

/* `0x116ab3aa`: common_refill_and_read_nolock<char>. */
int32_t rome2_startup_crt_refill_and_read_nolock_116ab3aa(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream)
{
    if (stream == NULL) {
        l66_set_invalid(env);
        return -1;
    }
    if ((stream->guest.flag_0c & ROME2_STARTUP_L66_IOALLOCATED) == 0u ||
        (stream->guest.flag_0c & ROME2_STARTUP_O_TEMPORARY) != 0u) {
        return -1;
    }
    if ((stream->guest.flag_0c & ROME2_STARTUP_IOWRT) != 0u) {
        stream->guest.flag_0c |= ROME2_STARTUP_L66_IOERR;
        return -1;
    }
    stream->guest.flag_0c |= ROME2_STARTUP_IOREAD;
    if ((stream->guest.flag_0c & (ROME2_STARTUP_L66_IOMYBUF | ROME2_STARTUP_L66_IOYOURBUF | 0x400u)) == 0u) {
        stream->guest.flag_0c |= ROME2_STARTUP_L66_IOMYBUF;
        stream->bufsiz = ROME2_STARTUP_L66_STREAM_BUF_CAP;
        stream->guest.bufsiz_18 = (int32_t)ROME2_STARTUP_L66_STREAM_BUF_CAP;
    }
    if (stream->bufsiz > ROME2_STARTUP_L66_STREAM_BUF_CAP) {
        stream->bufsiz = ROME2_STARTUP_L66_STREAM_BUF_CAP;
    }

    int32_t nr = l66_read_lowio_translated(env, stream, stream->buf, (uint32_t)stream->bufsiz);
    if (nr <= 0) {
        stream->guest.flag_0c |= (nr == 0) ? ROME2_STARTUP_L66_IOEOF : ROME2_STARTUP_L66_IOERR;
        stream->cursor_off = 0u;
        stream->valid_len = 0u;
        l66_sync_stream_buf_counts(stream);
        return -1;
    }
    rome2_startup_l65_ioinfo_slot *slot = l66_stream_ioinfo(env, stream);
    if ((stream->guest.flag_0c & (ROME2_STARTUP_IOWRT | ROME2_STARTUP_IORW)) == 0u &&
        slot != NULL && (slot->guest.osfile_28 & 0x82u) == 0x82u) {
        stream->guest.flag_0c |= 0x20u; /* _IOCTRLZ */
    }
    stream->cursor_off = 1u;
    stream->valid_len = (size_t)nr;
    l66_sync_stream_buf_counts(stream);
    return (int32_t)stream->buf[0];
}

/* `0x116ab534`: tail-jump thunk into common_refill_and_read_nolock<char>. */
int32_t rome2_startup_crt_refill_and_read_thunk_116ab534(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream)
{
    return rome2_startup_crt_refill_and_read_nolock_116ab3aa(env, stream);
}

/* `0x1168ea00`: __fread_nolock_s. */
size_t rome2_startup_crt_fread_nolock_s_1168ea00(
    rome2_startup_l66_env *env,
    void *dst_buf,
    size_t dst_size,
    size_t elem_size,
    size_t count,
    rome2_startup_l66_stream *stream)
{
    if (elem_size == 0u || count == 0u) {
        return 0u;
    }
    if (dst_buf == NULL || stream == NULL || count > (size_t)(0xffffffffu / elem_size)) {
        if (dst_buf != NULL && dst_size != (size_t)0xffffffffu) {
            memset(dst_buf, 0, dst_size);
        }
        l66_set_invalid(env);
        return 0u;
    }

    size_t bufsiz = ((stream->guest.flag_0c & 0x4c0u) != 0u && stream->bufsiz != 0u) ? stream->bufsiz : 4096u;
    size_t total = elem_size * count;
    size_t rem = total;
    size_t dst_rem = dst_size;
    uint8_t *out = (uint8_t *)dst_buf;

    while (rem > 0u) {
        size_t avail = (stream->valid_len > stream->cursor_off) ? (stream->valid_len - stream->cursor_off) : 0u;
        if ((stream->guest.flag_0c & 0x4c0u) != 0u && avail > 0u) {
            size_t take = (rem < avail) ? rem : avail;
            if (dst_rem < take) {
                if (dst_size != (size_t)0xffffffffu) {
                    memset(dst_buf, 0, dst_size);
                }
                if (env != NULL) {
                    env->io.last_errno = ROME2_L66_ERANGE;
                }
                l66_set_invalid(env);
                return 0u;
            }
            memcpy(out, stream->buf + stream->cursor_off, take);
            stream->cursor_off += take;
            l66_sync_stream_buf_counts(stream);
            out += take;
            rem -= take;
            dst_rem -= take;
        } else if (rem < bufsiz) {
            int32_t ch = rome2_startup_crt_refill_and_read_thunk_116ab534(env, stream);
            if (ch == -1) {
                return (total - rem) / elem_size;
            }
            if (dst_rem == 0u) {
                if (dst_size != (size_t)0xffffffffu) {
                    memset(dst_buf, 0, dst_size);
                }
                if (env != NULL) {
                    env->io.last_errno = ROME2_L66_ERANGE;
                }
                l66_set_invalid(env);
                return 0u;
            }
            *out++ = (uint8_t)ch;
            --rem;
            --dst_rem;
            bufsiz = (stream->bufsiz != 0u) ? stream->bufsiz : 4096u;
        } else {
            size_t bulk = rem;
            if (bulk > 0x7fffffffu) {
                bulk = 0x7fffffffu;
            }
            if (bufsiz != 0u) {
                bulk -= (bulk % bufsiz);
            }
            if (bulk == 0u) {
                bulk = rem;
            }
            if (dst_rem < bulk) {
                if (dst_size != (size_t)0xffffffffu) {
                    memset(dst_buf, 0, dst_size);
                }
                if (env != NULL) {
                    env->io.last_errno = ROME2_L66_ERANGE;
                }
                l66_set_invalid(env);
                return 0u;
            }
            stream->cursor_off = 0u;
            stream->valid_len = 0u;
            l66_sync_stream_buf_counts(stream);
            int32_t nr = l66_read_lowio_translated(env, stream, out, (uint32_t)bulk);
            if (nr == 0) {
                stream->guest.flag_0c |= ROME2_STARTUP_L66_IOEOF;
                return (total - rem) / elem_size;
            }
            if (nr < 0) {
                stream->guest.flag_0c |= ROME2_STARTUP_L66_IOERR;
                return (total - rem) / elem_size;
            }
            out += nr;
            rem -= (size_t)nr;
            dst_rem -= (size_t)nr;
        }
    }
    return count;
}

/* `0x1168ec98`: SEH4 unlock funclet for _fread_s. */
void rome2_startup_crt_fread_unlock_1168ec98(rome2_startup_l66_stream *stream)
{
    if (stream != NULL && stream->lock_depth > 0u) {
        stream->lock_depth -= 1u;
    }
}

/* `0x1168ec03`: _fread_s. */
size_t rome2_startup_crt_fread_s_1168ec03(
    rome2_startup_l66_env *env,
    void *dst_buf,
    size_t dst_size,
    size_t elem_size,
    size_t count,
    rome2_startup_l66_stream *stream)
{
    if (elem_size == 0u || count == 0u) {
        return 0u;
    }
    if (stream == NULL) {
        if (dst_buf != NULL && dst_size != (size_t)0xffffffffu) {
            memset(dst_buf, 0, dst_size);
        }
        l66_set_invalid(env);
        return 0u;
    }
    stream->lock_depth += 1u;
    size_t ret = rome2_startup_crt_fread_nolock_s_1168ea00(env, dst_buf, dst_size, elem_size, count, stream);
    rome2_startup_crt_fread_unlock_1168ec98(stream);
    return ret;
}

/* `0x1169a0bc`: common_fseek_binary_mode_read_only_fast_track_nolock. */
uint8_t rome2_startup_crt_fseek_fast_track_nolock_1169a0bc(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t offset,
    int32_t origin)
{
    if (env == NULL || stream == NULL || origin == 2 ||
        (stream->guest.flag_0c & 0x4c0u) == 0u ||
        (stream->guest.flag_0c & 6u) != 0u ||
        stream->guest.cnt_08 <= 0) {
        return 0u;
    }
    rome2_startup_l65_ioinfo_slot *slot = l66_stream_ioinfo(env, stream);
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, stream);
    if (slot == NULL || vf == NULL ||
        (slot->guest.osfile_28 & ROME2_STARTUP_LOWIO_FTEXT) != 0u ||
        slot->guest.textmode_29 != 0u) {
        return 0u;
    }
    int64_t rel = offset;
    if (origin == 0) {
        if (vf->cursor < 0) {
            return 0u;
        }
        int64_t delta = 0;
        if (rome2_startup_crt_longlongsub_11699fb7(offset, vf->cursor - stream->guest.cnt_08, &delta) < 0) {
            return 0u;
        }
        rel = delta;
    }
    int64_t min_back = -(int64_t)stream->cursor_off;
    int64_t max_fwd = (int64_t)stream->guest.cnt_08;
    if (rel >= min_back && rel <= max_fwd) {
        stream->cursor_off = (size_t)((int64_t)stream->cursor_off + rel);
        l66_sync_stream_buf_counts(stream);
        return 1u;
    }
    return 0u;
}

/* `0x1169a195`: common_fseek_nolock. */
int32_t rome2_startup_crt_common_fseek_nolock_1169a195(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t offset,
    int32_t origin)
{
    if (env == NULL || stream == NULL || (stream->guest.flag_0c & ROME2_STARTUP_L66_IOALLOCATED) == 0u) {
        if (env != NULL) {
            env->io.last_errno = ROME2_L66_EINVAL;
        }
        return -1;
    }
    stream->guest.flag_0c &= ~ROME2_STARTUP_L66_IOEOF;
    if (rome2_startup_crt_fseek_fast_track_nolock_1169a0bc(env, stream, offset, origin) != 0u) {
        return 0;
    }
    if (origin == 1) {
        int64_t cur = rome2_startup_crt_ftell_i32_thunk_1169a92a(env, stream);
        offset += cur;
        origin = 0;
    }
    stream->cursor_off = 0u;
    stream->valid_len = 0u;
    l66_sync_stream_buf_counts(stream);
    if ((stream->guest.flag_0c & ROME2_STARTUP_IORW) != 0u) {
        stream->guest.flag_0c &= ~(ROME2_STARTUP_IOREAD | ROME2_STARTUP_IOWRT);
    } else if ((stream->guest.flag_0c & 0x41u) == 0x41u &&
               (stream->guest.flag_0c & ROME2_STARTUP_L66_IOYOURBUF) == 0u) {
        stream->bufsiz = 512u;
        stream->guest.bufsiz_18 = 512;
    }
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, stream);
    if (vf == NULL) {
        env->io.last_errno = ROME2_L66_EBADF;
        return -1;
    }
    int64_t base = (origin == 2) ? (int64_t)vf->len : 0;
    int64_t target = base + offset;
    if (target < 0) {
        env->io.last_errno = ROME2_L66_EINVAL;
        return -1;
    }
    vf->cursor = target;
    return 0;
}

/* `0x1169a0b2`: SEH4 unlock funclet for common_fseek. */
void rome2_startup_crt_fseek_unlock_1169a0b2(rome2_startup_l66_stream *stream)
{
    if (stream != NULL && stream->lock_depth > 0u) {
        stream->lock_depth -= 1u;
    }
}

/* `0x1169a031`: common_fseek. */
int32_t rome2_startup_crt_common_fseek_1169a031(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t offset,
    int32_t origin)
{
    if (stream == NULL || (origin != 0 && origin != 1 && origin != 2)) {
        l66_set_invalid(env);
        return -1;
    }
    stream->lock_depth += 1u;
    int32_t ret = rome2_startup_crt_common_fseek_nolock_1169a195(env, stream, offset, origin);
    rome2_startup_crt_fseek_unlock_1169a0b2(stream);
    return ret;
}

/* `0x1169a28e`: _fseek. */
int32_t rome2_startup_crt_fseek_1169a28e(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int32_t offset,
    int32_t origin)
{
    return rome2_startup_crt_common_fseek_1169a031(env, stream, (int64_t)offset, origin);
}

/* `0x1169a8a1`: count_newline_bytes. */
int64_t rome2_startup_crt_count_newline_bytes_1169a8a1(
    const uint8_t *begin,
    const uint8_t *end,
    uint8_t textmode)
{
    if (begin == NULL || end == NULL || end <= begin) {
        return 0;
    }
    int64_t n = 0;
    if (textmode == ROME2_STARTUP_LOWIO_TM_UTF8 || textmode == ROME2_STARTUP_LOWIO_TM_UTF16LE) {
        size_t wcount = (size_t)(end - begin) / 2u;
        for (size_t i = 0; i < wcount; ++i) {
            uint16_t u = (uint16_t)begin[2u * i] | ((uint16_t)begin[2u * i + 1u] << 8);
            if (u == 10u) {
                n += 2;
            }
        }
    } else {
        size_t bcount = (size_t)(end - begin);
        for (size_t i = 0; i < bcount; ++i) {
            if (begin[i] == (uint8_t)'\n') {
                ++n;
            }
        }
    }
    return n;
}

/* `0x1169a708`: common_ftell_translated_utf8_nolock. */
int64_t rome2_startup_crt_ftell_utf8_nolock_1169a708(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t raw_pos)
{
    if (env == NULL || stream == NULL) {
        return -1;
    }
    if (stream->valid_len == 0u) {
        return raw_pos;
    }
    rome2_startup_l65_ioinfo_slot *slot = l66_stream_ioinfo(env, stream);
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, stream);
    if (slot == NULL || vf == NULL) {
        return -1;
    }
    int64_t wchar_off = rome2_startup_crt_alldiv_11684670((int64_t)stream->cursor_off, 2);
    size_t start_off = (size_t)slot->guest.startpos_lo_20;
    if (start_off > vf->len || wchar_off < 0) {
        return -1;
    }
    size_t pos = start_off;
    for (int64_t w = 0; w < wchar_off && pos < vf->len; ++w) {
        uint8_t b = vf->data[pos];
        if (b == '\r') {
            if (pos + 1u < vf->len && vf->data[pos + 1u] == '\n') {
                ++pos;
            }
            ++pos;
        } else if ((b & 0xe0u) == 0xc0u) {
            pos += 2u;
        } else if ((b & 0xf0u) == 0xe0u) {
            pos += 3u;
        } else {
            ++pos;
        }
    }
    return (int64_t)pos;
}

/* `0x1169a549`: common_ftell_read_mode_nolock. */
int64_t rome2_startup_crt_ftell_read_mode_nolock_1169a549(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream,
    int64_t file_pos,
    int64_t rd_off)
{
    if (env == NULL || stream == NULL || stream->valid_len == 0u) {
        return file_pos;
    }
    rome2_startup_l65_ioinfo_slot *slot = l66_stream_ioinfo(env, stream);
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, stream);
    if (slot == NULL || vf == NULL) {
        return -1;
    }
    int64_t div = (slot->guest.textmode_29 == ROME2_STARTUP_LOWIO_TM_UTF8) ? 2 : 1;
    int64_t total_len = (int64_t)stream->valid_len;
    if ((slot->guest.osfile_28 & ROME2_STARTUP_LOWIO_FTEXT) == 0u) {
        int64_t a = rome2_startup_crt_alldiv_11684670(rd_off, div);
        int64_t b = rome2_startup_crt_alldiv_11684670(total_len, div);
        return (a - b) + file_pos;
    }
    int64_t eof_pos = (int64_t)vf->len;
    int64_t span = 0;
    if (eof_pos == file_pos) {
        int64_t nl = rome2_startup_crt_count_newline_bytes_1169a8a1(
            stream->buf, stream->buf + stream->valid_len, slot->guest.textmode_29);
        span = total_len + nl;
        if ((stream->guest.flag_0c & 0x20u) != 0u) {
            span += (slot->guest.textmode_29 != 0u) ? 2 : 1;
        }
    } else {
        int64_t chunk = (total_len <= 512 && (stream->guest.flag_0c & ROME2_STARTUP_L66_IOMYBUF) != 0u &&
                         (stream->guest.flag_0c & ROME2_STARTUP_L66_IOYOURBUF) == 0u)
            ? 512
            : (int64_t)stream->bufsiz;
        if ((slot->guest.osfile_28 & ROME2_STARTUP_LOWIO_FCRLF) != 0u) {
            chunk += (slot->guest.textmode_29 != 0u) ? 2 : 1;
        }
        span = chunk;
    }
    return rome2_startup_crt_alldiv_11684670(rd_off, div) - rome2_startup_crt_alldiv_11684670(span, div) + file_pos;
}

/* `0x1169a3c5`: common_ftell_nolock<__int64>. */
int64_t rome2_startup_crt_ftell_i64_nolock_1169a3c5(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream)
{
    if (stream == NULL) {
        l66_set_invalid(env);
        return -1;
    }
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, stream);
    rome2_startup_l65_ioinfo_slot *slot = l66_stream_ioinfo(env, stream);
    if (vf == NULL || slot == NULL || vf->cursor < 0) {
        return -1;
    }
    int64_t file_pos = vf->cursor;
    if ((stream->guest.flag_0c & (ROME2_STARTUP_L66_IOMYBUF | 0x80u)) == 0u) {
        return file_pos - (int64_t)(stream->valid_len - stream->cursor_off);
    }
    int64_t rdoff = (int64_t)stream->cursor_off;
    if ((stream->guest.flag_0c & (ROME2_STARTUP_IOREAD | ROME2_STARTUP_IOWRT)) == 0u) {
        if ((stream->guest.flag_0c & ROME2_STARTUP_IORW) == 0u) {
            if (env != NULL) {
                env->io.last_errno = ROME2_L66_EINVAL;
            }
            return -1;
        }
    } else {
        if (slot->guest.textmode_29 == ROME2_STARTUP_LOWIO_TM_UTF8 &&
            (slot->guest.utf8_crlf_flags_2d & 2u) != 0u) {
            return rome2_startup_crt_ftell_utf8_nolock_1169a708(env, stream, file_pos);
        }
        if ((slot->guest.osfile_28 & ROME2_STARTUP_LOWIO_FTEXT) != 0u) {
            rdoff += rome2_startup_crt_count_newline_bytes_1169a8a1(
                stream->buf, stream->buf + stream->cursor_off, slot->guest.textmode_29);
        }
    }
    if (file_pos == 0) {
        return rdoff;
    }
    if ((stream->guest.flag_0c & ROME2_STARTUP_IOREAD) == 0u) {
        if (slot->guest.textmode_29 == ROME2_STARTUP_LOWIO_TM_UTF8) {
            rdoff = rome2_startup_crt_alldiv_11684670(rdoff, 2);
        }
        return file_pos + rdoff;
    }
    return rome2_startup_crt_ftell_read_mode_nolock_1169a549(env, stream, file_pos, rdoff);
}

/* `0x1169a92a`: tail-jump thunk into common_ftell_nolock<__int64>. */
int64_t rome2_startup_crt_ftell_i32_thunk_1169a92a(
    rome2_startup_l66_env *env,
    rome2_startup_l66_stream *stream)
{
    return rome2_startup_crt_ftell_i64_nolock_1169a3c5(env, stream);
}

/* `0x1011fee0`: engine_file_box_init. */
void rome2_startup_engine_file_box_init_1011fee0(rome2_startup_l66_file_box *box)
{
    if (box != NULL) {
        box->guest.fp_00 = 0u;
        box->guest.status_04 = 3u;
        box->stream = NULL;
    }
}

/* `0x100f21a0`: engine_file_box_close. */
void rome2_startup_engine_file_box_close_100f21a0(rome2_startup_l66_env *env, rome2_startup_l66_file_box *box)
{
    if (box != NULL) {
        l66_close_stream(env, box->stream);
        box->stream = NULL;
        box->guest.fp_00 = 0u;
        box->guest.status_04 = 6u;
    }
}

/* `0x10104a70`: engine_file_box_open. */
uint8_t rome2_startup_engine_file_box_open_10104a70(
    rome2_startup_l66_env *env,
    rome2_startup_l66_file_box *box,
    const char *path,
    uint8_t append_flag)
{
    if (box == NULL) {
        return 0u;
    }
    const char *mode = (append_flag != 0u) ? "abS" : "wbS";
    box->stream = rome2_startup_crt_fopen_1168e9a2(env, path, mode);
    if (box->stream == NULL) {
        box->guest.status_04 = (env != NULL && env->io.last_errno != 0) ? (uint32_t)env->io.last_errno : 13u;
        return 0u;
    }
    box->guest.fp_00 = 1u;
    box->guest.status_04 = 0u;
    return 1u;
}

/* `0x100edc70`: engine_file_box_write. */
size_t rome2_startup_engine_file_box_write_100edc70(
    rome2_startup_l66_env *env,
    rome2_startup_l66_file_box *box,
    const void *buf,
    size_t len)
{
    if (env == NULL || box == NULL || box->stream == NULL || buf == NULL) {
        return 0u;
    }
    rome2_startup_l65_vfs_file *vf = l66_stream_file(env, box->stream);
    if (vf == NULL || vf->is_readonly) {
        box->guest.status_04 = 13u;
        return 0u;
    }
    size_t room = (vf->cursor >= 0 && (size_t)vf->cursor < ROME2_STARTUP_L65_FILE_DATA_CAP)
        ? (ROME2_STARTUP_L65_FILE_DATA_CAP - (size_t)vf->cursor)
        : 0u;
    size_t put = (len < room) ? len : room;
    if (put > 0u) {
        memcpy(vf->data + (size_t)vf->cursor, buf, put);
        vf->cursor += (int64_t)put;
        if ((size_t)vf->cursor > vf->len) {
            vf->len = (size_t)vf->cursor;
        }
    }
    if (put != len) {
        box->guest.status_04 = 0x26u;
    }
    return put;
}

/* `0x100edcd0`: engine exit-code telemetry logger followed by _exit(0). */
void rome2_startup_engine_exit_with_telemetry_100edcd0(
    rome2_startup_l66_env *env,
    const char *log_path,
    int32_t exit_code)
{
    rome2_startup_l66_file_box box;
    rome2_startup_engine_file_box_init_1011fee0(&box);
    if (rome2_startup_engine_file_box_open_10104a70(env, &box, log_path != NULL ? log_path : "", 1u) != 0u) {
        char msg[32];
        int n = snprintf(msg, sizeof(msg), "%d", exit_code);
        if (n > 0) {
            rome2_startup_engine_file_box_write_100edc70(env, &box, msg, (size_t)n);
        }
    }
    rome2_startup_engine_file_box_close_100f21a0(env, &box);
    rome2_startup_crt_exit_1168d37f(env, 0);
}

/* `0x113471f0`: _Fiopen wide-string openmode lookup & seek-to-end helper. */
rome2_startup_l66_stream *rome2_startup_engine_fiopen_113471f0(
    rome2_startup_l66_env *env,
    const uint16_t *path,
    uint32_t ios_openmode)
{
    static const struct {
        uint32_t mode_bits;
        uint16_t wmode[4];
    } k_table[14] = {
        {0x01u, {'r', 0, 0, 0}},
        {0x02u, {'w', 0, 0, 0}},
        {0x12u, {'w', 0, 0, 0}},
        {0x0au, {'a', 0, 0, 0}},
        {0x21u, {'r', 'b', 0, 0}},
        {0x22u, {'w', 'b', 0, 0}},
        {0x32u, {'w', 'b', 0, 0}},
        {0x2au, {'a', 'b', 0, 0}},
        {0x03u, {'r', '+', 0, 0}},
        {0x13u, {'w', '+', 0, 0}},
        {0x0bu, {'a', '+', 0, 0}},
        {0x23u, {'r', '+', 'b', 0}},
        {0x33u, {'w', '+', 'b', 0}},
        {0x2bu, {'a', '+', 'b', 0}},
    };
    uint32_t eff = ((ios_openmode & 8u) != 0u) ? (ios_openmode | 2u) : ios_openmode;
    uint32_t key = eff & ~4u;
    const uint16_t *wmode = NULL;
    for (size_t i = 0; i < sizeof(k_table) / sizeof(k_table[0]); ++i) {
        if (k_table[i].mode_bits == key) {
            wmode = k_table[i].wmode;
            break;
        }
    }
    if (wmode == NULL) {
        return NULL;
    }
    rome2_startup_l66_stream *fp = NULL;
    if (rome2_startup_crt_wfopen_s_1168e95b(env, &fp, path, wmode) != 0 || fp == NULL) {
        return NULL;
    }
    if ((ios_openmode & 4u) != 0u && rome2_startup_crt_fseek_1169a28e(env, fp, 0, 2) != 0) {
        l66_close_stream(env, fp);
        return NULL;
    }
    return fp;
}

static void l66_append_log(char *out, size_t cap, size_t *pos, const char *line)
{
    if (out == NULL || cap == 0u || pos == NULL || line == NULL) {
        return;
    }
    size_t len = strlen(line);
    if (*pos + len >= cap) {
        len = (*pos + 1u < cap) ? (cap - 1u - *pos) : 0u;
    }
    if (len > 0u) {
        memcpy(out + *pos, line, len);
        *pos += len;
    }
    out[*pos] = '\0';
}

/* `0x100e2980`: manifest.txt vs data tree integrity check & modified.log writer. */
void rome2_startup_engine_verify_data_manifest_100e2980(
    rome2_startup_l66_env *env,
    const char *exe_path,
    const char *manifest_rel_path,
    const char *log_path,
    const rome2_startup_l66_disk_entry *disk_files,
    size_t disk_file_count,
    uint8_t user_script_exists,
    char *out_log,
    size_t out_log_cap)
{
    size_t log_pos = 0u;
    if (out_log != NULL && out_log_cap > 0u) {
        out_log[0] = '\0';
    }
    if (env == NULL || exe_path == NULL) {
        return;
    }
    const char *slash = strrchr(exe_path, '\\');
    if (slash == NULL) {
        return;
    }
    (void)log_path;

    rome2_startup_l66_stream *mf = rome2_startup_crt_fopen_1168e9a2(env, manifest_rel_path, "r");
    if (mf == NULL) {
        char line[192];
        snprintf(line, sizeof(line), "Failed to open %s for reading!\n", manifest_rel_path ? manifest_rel_path : "");
        l66_append_log(out_log, out_log_cap, &log_pos, line);
        env->manifest_mismatch_flag = 1u;
        return;
    }

    uint8_t matched[64];
    memset(matched, 0, sizeof(matched));
    size_t line_no = 1u;
    while (1) {
        char rel[128];
        size_t rpos = 0u;
        uint8_t ch = 0u;
        size_t n = rome2_startup_crt_fread_s_1168ec03(env, &ch, 1u, 1u, 1u, mf);
        if (n == 0u) {
            break;
        }
        while (n != 0u && ch != (uint8_t)'\t' && ch != 0u) {
            if (rpos + 1u < sizeof(rel)) {
                rel[rpos++] = (char)ch;
            }
            n = rome2_startup_crt_fread_s_1168ec03(env, &ch, 1u, 1u, 1u, mf);
        }
        rel[rpos] = '\0';
        if (n == 0u || ch == 0u) {
            if (rpos != 0u) {
                char msg[96];
                snprintf(msg, sizeof(msg), "Error while reading the manifest file (line: %u)\n", (unsigned)line_no);
                l66_append_log(out_log, out_log_cap, &log_pos, msg);
                env->manifest_mismatch_flag = 1u;
            }
            break;
        }
        uint64_t expected_sz = 0u;
        while ((n = rome2_startup_crt_fread_s_1168ec03(env, &ch, 1u, 1u, 1u, mf)) != 0u) {
            if (ch == (uint8_t)'\n' || ch == 0u) {
                break;
            }
            if (ch >= (uint8_t)'0' && ch <= (uint8_t)'9') {
                expected_sz = expected_sz * 10u + (uint64_t)(ch - (uint8_t)'0');
            }
        }

        int found = 0;
        for (size_t i = 0; i < disk_file_count && i < 64u; ++i) {
            if (disk_files[i].rel_path != NULL && strcmp(disk_files[i].rel_path, rel) == 0) {
                found = 1;
                matched[i] = 1u;
                if (disk_files[i].size_bytes != expected_sz) {
                    char msg[192];
                    snprintf(msg, sizeof(msg), "%s size mismatch\n", rel);
                    l66_append_log(out_log, out_log_cap, &log_pos, msg);
                    env->manifest_mismatch_flag = 1u;
                }
                break;
            }
        }
        if (!found) {
            char msg[192];
            snprintf(msg, sizeof(msg), "%s missing\n", rel);
            l66_append_log(out_log, out_log_cap, &log_pos, msg);
            env->manifest_mismatch_flag = 1u;
        }
        ++line_no;
    }

    for (size_t i = 0; i < disk_file_count && i < 64u; ++i) {
        if (matched[i] == 0u && disk_files[i].rel_path != NULL) {
            char msg[192];
            snprintf(msg, sizeof(msg), "%s unknown file\n", disk_files[i].rel_path);
            l66_append_log(out_log, out_log_cap, &log_pos, msg);
            env->manifest_mismatch_flag = 1u;
        }
    }

    if (user_script_exists != 0u) {
        l66_append_log(out_log, out_log_cap, &log_pos, "user.script.txt user script existing\n");
        env->manifest_mismatch_flag = 1u;
    }
    l66_close_stream(env, mf);
}
