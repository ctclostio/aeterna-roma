#include "startup_stdio_stream_ops.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define ROME2_L65_INVALID_HANDLE  0xffffffffu
#define ROME2_L65_EACCES          13
#define ROME2_L65_EINVAL          22
#define ROME2_L65_EMFILE          24
#define ROME2_L65_EBADF           9
#define ROME2_L65_ENOMEM          12

#define ROME2_L65_GEN_READ        0x80000000u
#define ROME2_L65_GEN_WRITE       0x40000000u
#define ROME2_L65_GEN_DELETE      0x00010000u

static void l65_set_invalid_param(rome2_startup_l65_crt_env *env, int32_t code)
{
    if (env != NULL) {
        env->last_errno = code;
        env->invalid_param_calls += 1u;
    }
}

static rome2_startup_l65_ioinfo_slot *l65_slot(rome2_startup_l65_crt_env *env, int32_t fh)
{
    if (env == NULL || fh < 0 || (uint32_t)fh >= env->nhandle) {
        return NULL;
    }
    uint32_t page = (uint32_t)fh >> 6;
    uint32_t idx = (uint32_t)fh & 0x3fu;
    if (page >= ROME2_STARTUP_L65_MAX_IO_PAGES || env->pages[page] == NULL) {
        return NULL;
    }
    return &env->pages[page][idx];
}

static int32_t l65_narrow_ci_cmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        uint8_t c1 = (uint8_t)s1[i];
        uint8_t c2 = (uint8_t)s2[i];
        if (c1 >= (uint8_t)'A' && c1 <= (uint8_t)'Z') {
            c1 = (uint8_t)(c1 + 32u);
        }
        if (c2 >= (uint8_t)'A' && c2 <= (uint8_t)'Z') {
            c2 = (uint8_t)(c2 + 32u);
        }
        if (c1 != c2 || c1 == 0u) {
            return (int32_t)c1 - (int32_t)c2;
        }
    }
    return 0;
}

static void l65_utf16_to_ascii_bounded(const uint16_t *wstr, char *out_buf, size_t cap)
{
    size_t i = 0;
    if (cap == 0) {
        return;
    }
    if (wstr != NULL) {
        while (i + 1 < cap && wstr[i] != 0u) {
            uint16_t ch = wstr[i];
            out_buf[i] = (ch <= 0x7fu) ? (char)ch : '?';
            ++i;
        }
    }
    out_buf[i] = '\0';
}

static int64_t l65_file_lseek_nolock(rome2_startup_l65_crt_env *env, int32_t fh, int64_t off, int origin)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot == NULL || slot->backed_file_idx < 0 ||
        (uint32_t)slot->backed_file_idx >= ROME2_STARTUP_L65_MAX_FILES) {
        if (env != NULL) {
            env->last_errno = ROME2_L65_EBADF;
        }
        return -1;
    }
    rome2_startup_l65_vfs_file *vf = &env->files[slot->backed_file_idx];
    if (!vf->exists || vf->file_type != 1u) {
        env->last_errno = ROME2_L65_EINVAL;
        env->last_doserrno = 131u; /* ERROR_NEGATIVE_SEEK */
        return -1;
    }
    int64_t base = 0;
    if (origin == 1) {
        base = vf->cursor;
    } else if (origin == 2) {
        base = (int64_t)vf->len;
    } else if (origin != 0) {
        env->last_errno = ROME2_L65_EINVAL;
        return -1;
    }
    int64_t target = base + off;
    if (target < 0) {
        env->last_errno = ROME2_L65_EINVAL;
        env->last_doserrno = 131u;
        return -1;
    }
    vf->cursor = target;
    return target;
}

static int32_t l65_file_read_raw_nolock(rome2_startup_l65_crt_env *env, int32_t fh, uint8_t *dst, uint32_t count)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot == NULL || slot->backed_file_idx < 0 ||
        (uint32_t)slot->backed_file_idx >= ROME2_STARTUP_L65_MAX_FILES || dst == NULL) {
        if (env != NULL) {
            env->last_errno = ROME2_L65_EBADF;
        }
        return -1;
    }
    rome2_startup_l65_vfs_file *vf = &env->files[slot->backed_file_idx];
    if (vf->cursor < 0 || (size_t)vf->cursor >= vf->len) {
        return 0;
    }
    size_t avail = vf->len - (size_t)vf->cursor;
    size_t take = ((size_t)count < avail) ? (size_t)count : avail;
    if (take > 0) {
        memcpy(dst, vf->data + (size_t)vf->cursor, take);
        vf->cursor += (int64_t)take;
    }
    return (int32_t)take;
}

static int32_t l65_file_write_raw_nolock(rome2_startup_l65_crt_env *env, int32_t fh, const uint8_t *src, uint32_t count)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot == NULL || slot->backed_file_idx < 0 ||
        (uint32_t)slot->backed_file_idx >= ROME2_STARTUP_L65_MAX_FILES || src == NULL) {
        if (env != NULL) {
            env->last_errno = ROME2_L65_EBADF;
        }
        return -1;
    }
    rome2_startup_l65_vfs_file *vf = &env->files[slot->backed_file_idx];
    if (vf->is_readonly) {
        env->last_errno = ROME2_L65_EACCES;
        env->last_doserrno = 5u;
        return -1;
    }
    if (vf->cursor < 0) {
        env->last_errno = ROME2_L65_EINVAL;
        return -1;
    }
    size_t pos = (size_t)vf->cursor;
    if (pos >= ROME2_STARTUP_L65_FILE_DATA_CAP) {
        env->last_errno = 28; /* ENOSPC */
        return -1;
    }
    size_t room = ROME2_STARTUP_L65_FILE_DATA_CAP - pos;
    size_t put = ((size_t)count < room) ? (size_t)count : room;
    if (put > 0) {
        memcpy(vf->data + pos, src, put);
        vf->cursor = (int64_t)(pos + put);
        if (pos + put > vf->len) {
            vf->len = pos + put;
        }
    }
    return (int32_t)put;
}

void rome2_startup_l65_env_init(rome2_startup_l65_crt_env *env)
{
    if (env == NULL) {
        return;
    }
    memset(env, 0, sizeof(*env));
    env->fmode = ROME2_STARTUP_O_TEXT;
    env->has_ex_cs_api = 1u;
}

void rome2_startup_l65_env_destroy(rome2_startup_l65_crt_env *env)
{
    if (env == NULL) {
        return;
    }
    for (size_t i = 0; i < ROME2_STARTUP_L65_MAX_IO_PAGES; ++i) {
        free(env->pages[i]);
        env->pages[i] = NULL;
    }
    env->nhandle = 0;
}

int32_t rome2_startup_l65_env_add_file(
    rome2_startup_l65_crt_env *env,
    const char *path,
    const uint8_t *data,
    size_t len,
    uint32_t file_type,
    uint8_t is_readonly)
{
    if (env == NULL || path == NULL || len > ROME2_STARTUP_L65_FILE_DATA_CAP) {
        return -1;
    }
    for (size_t i = 0; i < ROME2_STARTUP_L65_MAX_FILES; ++i) {
        if (!env->files[i].exists) {
            rome2_startup_l65_vfs_file *vf = &env->files[i];
            memset(vf, 0, sizeof(*vf));
            size_t plen = strlen(path);
            if (plen >= sizeof(vf->path)) {
                return -1;
            }
            memcpy(vf->path, path, plen + 1u);
            vf->exists = 1u;
            vf->is_readonly = is_readonly;
            vf->file_type = file_type;
            if (data != NULL && len > 0) {
                memcpy(vf->data, data, len);
            }
            vf->len = len;
            vf->cursor = 0;
            return (int32_t)i;
        }
    }
    return -1;
}

/* `0x1168d030`: CRT _strncmp (disjoint 2-range body). */
int32_t rome2_startup_crt_strncmp_1168d030(const char *s1, const char *s2, size_t max_count)
{
    if (max_count == 0u) {
        return 0;
    }
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;
    for (size_t i = 0; i < max_count; ++i) {
        uint8_t c1 = p1[i];
        uint8_t c2 = p2[i];
        if (c1 != c2) {
            return (c1 < c2) ? -1 : 1;
        }
        if (c1 == 0u) {
            return 0;
        }
    }
    return 0;
}

/* `0x116b849b`: CRT __wcsnicmp_l (UTF-16LE code units). */
int32_t rome2_startup_crt_wcsnicmp_l_116b849b(
    rome2_startup_l65_crt_env *env,
    const uint16_t *s1,
    const uint16_t *s2,
    size_t max_count,
    uint8_t has_locale)
{
    (void)has_locale;
    if (s1 == NULL || s2 == NULL) {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return 0x7fffffff;
    }
    if (max_count == 0u) {
        return 0;
    }
    for (size_t i = 0; i < max_count; ++i) {
        uint16_t c1 = s1[i];
        uint16_t c2 = s2[i];
        if (c1 >= (uint16_t)'A' && c1 <= (uint16_t)'Z') {
            c1 = (uint16_t)(c1 + 32u);
        }
        if (c2 >= (uint16_t)'A' && c2 <= (uint16_t)'Z') {
            c2 = (uint16_t)(c2 + 32u);
        }
        int32_t diff = (int32_t)c1 - (int32_t)c2;
        if (diff != 0 || c1 == 0u) {
            return diff;
        }
    }
    return 0;
}

/* `0x116b844f`: CRT __wcsnicmp. */
int32_t rome2_startup_crt_wcsnicmp_116b844f(
    rome2_startup_l65_crt_env *env,
    const uint16_t *s1,
    const uint16_t *s2,
    size_t max_count)
{
    if (env != NULL && env->has_custom_locale) {
        return rome2_startup_crt_wcsnicmp_l_116b849b(env, s1, s2, max_count, 1u);
    }
    return rome2_startup_crt_wcsnicmp_l_116b849b(env, s1, s2, max_count, 0u);
}

/* `0x116a896e`: ___acrt_InitializeCriticalSectionEx@12. */
uint8_t rome2_startup_crt_init_cs_ex_116a896e(
    const rome2_startup_l65_crt_env *env,
    rome2_startup_l65_critsec_state *cs,
    uint32_t spin_count,
    uint32_t flags)
{
    if (cs == NULL) {
        return 0u;
    }
    cs->spin_count = spin_count;
    cs->initialized = 1u;
    if (env != NULL && env->has_ex_cs_api) {
        cs->flags = flags;
        cs->used_ex_api = 1u;
    } else {
        cs->flags = 0u;
        cs->used_ex_api = 0u;
    }
    return 1u;
}

/* `0x116aa8b8`: __acrt_stdio_parse_mode_D. */
uint8_t rome2_startup_crt_parse_mode_D_116aa8b8(rome2_startup_crt_stdio_mode12_32 *mode)
{
    if (mode == NULL || (mode->lowio_mode_00 & ROME2_STARTUP_O_TEMPORARY) != 0u) {
        return 0u;
    }
    mode->lowio_mode_00 |= ROME2_STARTUP_O_TEMPORARY;
    return 1u;
}

/* `0x116aa8d3`: __acrt_stdio_parse_mode_T. */
uint8_t rome2_startup_crt_parse_mode_T_116aa8d3(rome2_startup_crt_stdio_mode12_32 *mode)
{
    if (mode == NULL || (mode->lowio_mode_00 & ROME2_STARTUP_O_SHORT_LIVED) != 0u) {
        return 0u;
    }
    mode->lowio_mode_00 |= ROME2_STARTUP_O_SHORT_LIVED;
    return 1u;
}

/* `0x116aa8f2`: __acrt_stdio_parse_mode_b. */
uint8_t rome2_startup_crt_parse_mode_b_116aa8f2(rome2_startup_crt_stdio_mode12_32 *mode)
{
    if (mode == NULL || (mode->lowio_mode_00 & (ROME2_STARTUP_O_TEXT | ROME2_STARTUP_O_BINARY)) != 0u) {
        return 0u;
    }
    mode->lowio_mode_00 |= ROME2_STARTUP_O_BINARY;
    return 1u;
}

/* `0x116aa98c`: __acrt_stdio_parse_mode_t. */
uint8_t rome2_startup_crt_parse_mode_t_116aa98c(rome2_startup_crt_stdio_mode12_32 *mode)
{
    if (mode == NULL || (mode->lowio_mode_00 & (ROME2_STARTUP_O_TEXT | ROME2_STARTUP_O_BINARY)) != 0u) {
        return 0u;
    }
    mode->lowio_mode_00 |= ROME2_STARTUP_O_TEXT;
    return 1u;
}

/* `0x116aa912`: __acrt_stdio_parse_mode_c. */
uint8_t rome2_startup_crt_parse_mode_c_116aa912(rome2_startup_crt_stdio_mode12_32 *mode, uint8_t *seen_commit)
{
    if (mode == NULL || seen_commit == NULL || *seen_commit != 0u) {
        return 0u;
    }
    *seen_commit = 1u;
    mode->stdio_mode_04 |= ROME2_STARTUP_IOCOMMIT;
    return 1u;
}

/* `0x116aa934`: __acrt_stdio_parse_mode_n. */
uint8_t rome2_startup_crt_parse_mode_n_116aa934(rome2_startup_crt_stdio_mode12_32 *mode, uint8_t *seen_commit)
{
    if (mode == NULL || seen_commit == NULL || *seen_commit != 0u) {
        return 0u;
    }
    *seen_commit = 1u;
    mode->stdio_mode_04 &= ~ROME2_STARTUP_IOCOMMIT;
    return 1u;
}

/* `0x116aa956`: __acrt_stdio_parse_mode_plus. */
uint8_t rome2_startup_crt_parse_mode_plus_116aa956(rome2_startup_crt_stdio_mode12_32 *mode, uint8_t *seen_plus)
{
    if (mode == NULL || seen_plus == NULL || *seen_plus != 0u) {
        return 0u;
    }
    *seen_plus = 1u;
    if ((mode->lowio_mode_00 & ROME2_STARTUP_O_RDWR) != 0u) {
        return 0u;
    }
    mode->lowio_mode_00 = (mode->lowio_mode_00 & ~ROME2_STARTUP_O_WRONLY) | ROME2_STARTUP_O_RDWR;
    mode->stdio_mode_04 = (mode->stdio_mode_04 & ~(ROME2_STARTUP_IOREAD | ROME2_STARTUP_IOWRT)) | ROME2_STARTUP_IORW;
    return 1u;
}

/* `0x116aa9ac`: __acrt_stdio_parse_mode_x. */
uint8_t rome2_startup_crt_parse_mode_x_116aa9ac(rome2_startup_crt_stdio_mode12_32 *mode)
{
    if (mode == NULL || (mode->lowio_mode_00 & ROME2_STARTUP_O_TRUNC) == 0u) {
        return 0u;
    }
    mode->lowio_mode_00 |= ROME2_STARTUP_O_EXCL;
    return 1u;
}

static uint8_t l65_parse_mode_flag_char(
    uint16_t ch,
    rome2_startup_crt_stdio_mode12_32 *out,
    uint8_t *seen_sr,
    uint8_t *seen_plus,
    uint8_t *seen_commit,
    uint8_t *seen_comma,
    uint8_t *valid_char)
{
    *valid_char = 1u;
    if (ch == (uint16_t)'S') {
        if (*seen_sr != 0u) {
            *valid_char = 0u;
            return 1u;
        }
        out->lowio_mode_00 |= ROME2_STARTUP_O_SEQUENTIAL;
        *seen_sr = 1u;
    } else if (ch == (uint16_t)'R') {
        if (*seen_sr != 0u) {
            *valid_char = 0u;
            return 1u;
        }
        out->lowio_mode_00 |= ROME2_STARTUP_O_RANDOM;
        *seen_sr = 1u;
    } else if (ch == (uint16_t)' ') {
        /* skipped */
    } else if (ch == (uint16_t)'+') {
        *valid_char = rome2_startup_crt_parse_mode_plus_116aa956(out, seen_plus);
    } else if (ch == (uint16_t)',') {
        *seen_comma = 1u;
        *valid_char = 0u;
    } else if (ch == (uint16_t)'D') {
        *valid_char = rome2_startup_crt_parse_mode_D_116aa8b8(out);
    } else if (ch == (uint16_t)'N') {
        out->lowio_mode_00 |= ROME2_STARTUP_O_NOINHERIT;
    } else if (ch == (uint16_t)'T') {
        *valid_char = rome2_startup_crt_parse_mode_T_116aa8d3(out);
    } else if (ch == (uint16_t)'b') {
        *valid_char = rome2_startup_crt_parse_mode_b_116aa8f2(out);
    } else if (ch == (uint16_t)'c') {
        *valid_char = rome2_startup_crt_parse_mode_c_116aa912(out, seen_commit);
    } else if (ch == (uint16_t)'n') {
        *valid_char = rome2_startup_crt_parse_mode_n_116aa934(out, seen_commit);
    } else if (ch == (uint16_t)'t') {
        *valid_char = rome2_startup_crt_parse_mode_t_116aa98c(out);
    } else if (ch == (uint16_t)'x') {
        *valid_char = rome2_startup_crt_parse_mode_x_116aa9ac(out);
    } else {
        return 0u;
    }
    return 1u;
}

static rome2_startup_crt_stdio_mode12_32 l65_parse_mode_common(
    rome2_startup_l65_crt_env *env,
    const char *narrow,
    const uint16_t *wide)
{
    rome2_startup_crt_stdio_mode12_32 out;
    memset(&out, 0, sizeof(out));
    out.stdio_mode_04 = (env != NULL) ? env->commode : 0u;
    if (narrow == NULL && wide == NULL) {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return out;
    }

    size_t pos = 0u;
    uint16_t first = 0u;
    while (1) {
        first = (narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos];
        if (first != (uint16_t)' ') {
            break;
        }
        ++pos;
    }

    if (first == (uint16_t)'a') {
        out.lowio_mode_00 = ROME2_STARTUP_O_WRONLY | ROME2_STARTUP_O_APPEND | ROME2_STARTUP_O_CREAT;
        out.stdio_mode_04 = ROME2_STARTUP_IOWRT;
    } else if (first == (uint16_t)'r') {
        out.stdio_mode_04 = ROME2_STARTUP_IOREAD;
    } else if (first == (uint16_t)'w') {
        out.lowio_mode_00 = ROME2_STARTUP_O_WRONLY | ROME2_STARTUP_O_CREAT | ROME2_STARTUP_O_TRUNC;
        out.stdio_mode_04 = ROME2_STARTUP_IOWRT;
    } else {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return out;
    }
    ++pos;

    uint8_t seen_sr = 0u, seen_plus = 0u, seen_commit = 0u, seen_comma = 0u, ok = 1u;
    while (ok != 0u) {
        uint16_t ch = (narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos];
        if (ch == 0u) {
            break;
        }
        uint8_t recognized = l65_parse_mode_flag_char(
            ch, &out, &seen_sr, &seen_plus, &seen_commit, &seen_comma, &ok);
        if (recognized == 0u) {
            l65_set_invalid_param(env, ROME2_L65_EINVAL);
            return out;
        }
        if (ok != 0u) {
            ++pos;
        }
    }

    if (seen_comma != 0u) {
        ++pos;
        while (((narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos]) == (uint16_t)' ') {
            ++pos;
        }
        static const char s_ccs[] = "ccs";
        static const uint16_t w_ccs[] = {'c', 'c', 's', 0};
        if ((narrow != NULL && rome2_startup_crt_strncmp_1168d030(narrow + pos, s_ccs, 3u) != 0) ||
            (wide != NULL && (wide[pos] != w_ccs[0] || wide[pos + 1] != w_ccs[1] || wide[pos + 2] != w_ccs[2]))) {
            l65_set_invalid_param(env, ROME2_L65_EINVAL);
            return out;
        }
        pos += 3u;
        while (((narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos]) == (uint16_t)' ') {
            ++pos;
        }
        if (((narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos]) != (uint16_t)'=') {
            l65_set_invalid_param(env, ROME2_L65_EINVAL);
            return out;
        }
        ++pos;
        while (((narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos]) == (uint16_t)' ') {
            ++pos;
        }

        static const uint16_t w_utf8[] = {'U', 'T', 'F', '-', '8', 0};
        static const uint16_t w_utf16le[] = {'U', 'T', 'F', '-', '1', '6', 'L', 'E', 0};
        static const uint16_t w_unicode[] = {'U', 'N', 'I', 'C', 'O', 'D', 'E', 0};
        size_t adv = 0u;
        if ((narrow != NULL && l65_narrow_ci_cmp(narrow + pos, "UTF-8", 5u) == 0) ||
            (wide != NULL && rome2_startup_crt_wcsnicmp_116b844f(env, wide + pos, w_utf8, 5u) == 0)) {
            out.lowio_mode_00 |= ROME2_STARTUP_O_U8TEXT;
            adv = 5u;
        } else if ((narrow != NULL && l65_narrow_ci_cmp(narrow + pos, "UTF-16LE", 8u) == 0) ||
                   (wide != NULL && rome2_startup_crt_wcsnicmp_116b844f(env, wide + pos, w_utf16le, 8u) == 0)) {
            out.lowio_mode_00 |= ROME2_STARTUP_O_U16TEXT;
            adv = 8u;
        } else if ((narrow != NULL && l65_narrow_ci_cmp(narrow + pos, "UNICODE", 7u) == 0) ||
                   (wide != NULL && rome2_startup_crt_wcsnicmp_116b844f(env, wide + pos, w_unicode, 7u) == 0)) {
            out.lowio_mode_00 |= ROME2_STARTUP_O_WTEXT;
            adv = 7u;
        } else {
            l65_set_invalid_param(env, ROME2_L65_EINVAL);
            return out;
        }
        pos += adv;
        while (((narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos]) == (uint16_t)' ') {
            ++pos;
        }
    }

    uint16_t tail = (narrow != NULL) ? (uint8_t)narrow[pos] : wide[pos];
    if (tail == 0u) {
        out.ok_08 = 1u;
        return out;
    }
    l65_set_invalid_param(env, ROME2_L65_EINVAL);
    return out;
}

/* `0x116aa31d`: __acrt_stdio_parse_mode<char>. */
rome2_startup_crt_stdio_mode12_32 rome2_startup_crt_parse_mode_char_116aa31d(
    rome2_startup_l65_crt_env *env,
    const char *mode_str)
{
    return l65_parse_mode_common(env, mode_str, NULL);
}

/* `0x116aa547`: __acrt_stdio_parse_mode<wchar_t>. */
rome2_startup_crt_stdio_mode12_32 rome2_startup_crt_parse_mode_wchar_116aa547(
    rome2_startup_l65_crt_env *env,
    const uint16_t *mode_wstr)
{
    return l65_parse_mode_common(env, NULL, mode_wstr);
}

/* `0x116aa7b2`: common_openfile<char>. */
rome2_startup_l65_stdio_stream *rome2_startup_crt_common_openfile_char_116aa7b2(
    rome2_startup_l65_crt_env *env,
    const char *filename,
    const char *mode_str,
    int32_t shflag,
    rome2_startup_l65_stdio_stream *stream)
{
    if (stream == NULL) {
        return NULL;
    }
    rome2_startup_crt_stdio_mode12_32 parsed = rome2_startup_crt_parse_mode_char_116aa31d(env, mode_str);
    if (parsed.ok_08 == 0u) {
        return NULL;
    }
    int32_t fh = -1;
    if (rome2_startup_crt_sopen_s_116af28b(env, &fh, filename, (int32_t)parsed.lowio_mode_00, shflag, 0x180) != 0) {
        return NULL;
    }
    if (env != NULL) {
        env->open_stream_count += 1u;
    }
    stream->flags |= parsed.stdio_mode_04;
    stream->base_val = 0u;
    stream->tmpfname_val = 0u;
    stream->cnt = 0;
    stream->ptr_val = 0u;
    stream->file_handle = fh;
    return stream;
}

/* `0x116aa835`: common_openfile<wchar_t>. */
rome2_startup_l65_stdio_stream *rome2_startup_crt_common_openfile_wchar_116aa835(
    rome2_startup_l65_crt_env *env,
    const uint16_t *filename,
    const uint16_t *mode_wstr,
    int32_t shflag,
    rome2_startup_l65_stdio_stream *stream)
{
    if (stream == NULL) {
        return NULL;
    }
    rome2_startup_crt_stdio_mode12_32 parsed = rome2_startup_crt_parse_mode_wchar_116aa547(env, mode_wstr);
    if (parsed.ok_08 == 0u) {
        return NULL;
    }
    int32_t fh = -1;
    if (rome2_startup_crt_wsopen_s_116af5d5(env, &fh, filename, (int32_t)parsed.lowio_mode_00, shflag, 0x180) != 0) {
        return NULL;
    }
    if (env != NULL) {
        env->open_stream_count += 1u;
    }
    stream->flags |= parsed.stdio_mode_04;
    stream->base_val = 0u;
    stream->tmpfname_val = 0u;
    stream->cnt = 0;
    stream->ptr_val = 0u;
    stream->file_handle = fh;
    return stream;
}

/* `0x116ae68f`: ___acrt_lowio_create_handle_array. */
rome2_startup_l65_ioinfo_slot *rome2_startup_crt_lowio_create_handle_array_116ae68f(
    rome2_startup_l65_crt_env *env)
{
    if (env != NULL && env->fail_alloc_array != 0u) {
        return NULL;
    }
    rome2_startup_l65_ioinfo_slot *arr =
        (rome2_startup_l65_ioinfo_slot *)calloc(ROME2_STARTUP_L65_IOINFO_ARRAY_LEN, sizeof(*arr));
    if (arr == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < ROME2_STARTUP_L65_IOINFO_ARRAY_LEN; ++i) {
        rome2_startup_crt_init_cs_ex_116a896e(env, &arr[i].cs, 4000u, 0u);
        arr[i].guest.osfhnd_18 = ROME2_L65_INVALID_HANDLE;
        arr[i].guest.startpos_lo_20 = 0u;
        arr[i].guest.startpos_hi_24 = 0u;
        arr[i].guest.osfile_28 = 0u;
        arr[i].guest.textmode_29 = 0u;
        arr[i].guest.pipech2_2a[0] = 0x0au;
        arr[i].guest.pipech2_2a[1] = 0x0au;
        arr[i].guest.pipech2_2a[2] = 0x0au;
        arr[i].guest.utf8_crlf_flags_2d &= (uint8_t)(~0x07u & 0xffu);
        arr[i].backed_file_idx = -1;
        arr[i].os_handle = ROME2_L65_INVALID_HANDLE;
    }
    return arr;
}

/* `0x116ae800`: ___acrt_lowio_set_os_handle. */
int32_t rome2_startup_crt_lowio_set_os_handle_116ae800(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    uint32_t osfhnd)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot != NULL && slot->guest.osfhnd_18 == ROME2_L65_INVALID_HANDLE) {
        if (env->is_gui_app != 0u && fh >= 0 && fh <= 2) {
            static const uint32_t std_ids[3] = {0xfffffff6u, 0xfffffff5u, 0xfffffff4u};
            env->set_std_handle_calls += 1u;
            env->last_std_handle_id = std_ids[fh];
            env->last_std_handle_val = osfhnd;
        }
        slot->guest.osfhnd_18 = osfhnd;
        slot->os_handle = osfhnd;
        return 0;
    }
    if (env != NULL) {
        env->last_errno = ROME2_L65_EBADF;
        env->last_doserrno = 0u;
    }
    return -1;
}

/* `0x116ae9bf`: SEH4 unlock funclet for __alloc_osfhnd. */
void rome2_startup_crt_alloc_osfhnd_seh_unlock_116ae9bf(rome2_startup_l65_crt_env *env)
{
    if (env != NULL) {
        env->lowio_unlock_count += 1u;
    }
}

/* `0x116ae8b5`: __alloc_osfhnd. */
int32_t rome2_startup_crt_alloc_osfhnd_116ae8b5(rome2_startup_l65_crt_env *env)
{
    if (env == NULL) {
        return -1;
    }
    env->lowio_lock_count += 1u;
    int32_t fh = -1;

    for (size_t p = 0; p < ROME2_STARTUP_L65_MAX_IO_PAGES; ++p) {
        if (env->pages[p] == NULL) {
            rome2_startup_l65_ioinfo_slot *arr = rome2_startup_crt_lowio_create_handle_array_116ae68f(env);
            env->pages[p] = arr;
            if (arr != NULL) {
                env->nhandle += ROME2_STARTUP_L65_IOINFO_ARRAY_LEN;
                fh = (int32_t)(p << 6);
                arr[0].lock_depth += 1u;
                arr[0].guest.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN;
                arr[0].handle_allocated = 1u;
            }
            break;
        }
        rome2_startup_l65_ioinfo_slot *page_slots = env->pages[p];
        for (size_t j = 0; j < ROME2_STARTUP_L65_IOINFO_ARRAY_LEN; ++j) {
            if ((page_slots[j].guest.osfile_28 & ROME2_STARTUP_LOWIO_FOPEN) == 0u) {
                page_slots[j].lock_depth += 1u;
                if ((page_slots[j].guest.osfile_28 & ROME2_STARTUP_LOWIO_FOPEN) == 0u) {
                    fh = (int32_t)(p * ROME2_STARTUP_L65_IOINFO_ARRAY_LEN + j);
                    page_slots[j].guest.osfile_28 = ROME2_STARTUP_LOWIO_FOPEN;
                    page_slots[j].guest.osfhnd_18 = ROME2_L65_INVALID_HANDLE;
                    page_slots[j].os_handle = ROME2_L65_INVALID_HANDLE;
                    page_slots[j].handle_allocated = 1u;
                    break;
                }
                page_slots[j].lock_depth -= 1u;
            }
        }
        if (fh != -1) {
            break;
        }
    }

    rome2_startup_crt_alloc_osfhnd_seh_unlock_116ae9bf(env);
    return fh;
}

/* `0x116bc6de`: _get_fmode. */
int32_t rome2_startup_crt_get_fmode_116bc6de(rome2_startup_l65_crt_env *env, uint32_t *out_fmode)
{
    if (out_fmode == NULL) {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return ROME2_L65_EINVAL;
    }
    *out_fmode = (env != NULL) ? env->fmode : ROME2_STARTUP_O_TEXT;
    return 0;
}

/* `0x116bc70b`: __setmode_nolock. */
int32_t rome2_startup_crt_setmode_nolock_116bc70b(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    int32_t mode)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot == NULL) {
        return -1;
    }
    uint8_t old_osfile = slot->guest.osfile_28;
    uint8_t old_tm = slot->guest.textmode_29;
    if ((uint32_t)mode == ROME2_STARTUP_O_TEXT) {
        slot->guest.osfile_28 = (uint8_t)(old_osfile | ROME2_STARTUP_LOWIO_FTEXT);
        slot->guest.textmode_29 = ROME2_STARTUP_LOWIO_TM_ANSI;
    } else if ((uint32_t)mode == ROME2_STARTUP_O_BINARY) {
        slot->guest.osfile_28 = (uint8_t)(old_osfile & (uint8_t)(~ROME2_STARTUP_LOWIO_FTEXT & 0xffu));
    } else if ((uint32_t)mode == ROME2_STARTUP_O_WTEXT || (uint32_t)mode == ROME2_STARTUP_O_U16TEXT) {
        slot->guest.osfile_28 = (uint8_t)(old_osfile | ROME2_STARTUP_LOWIO_FTEXT);
        slot->guest.textmode_29 = ROME2_STARTUP_LOWIO_TM_UTF16LE;
    } else if ((uint32_t)mode == ROME2_STARTUP_O_U8TEXT) {
        slot->guest.osfile_28 = (uint8_t)(old_osfile | ROME2_STARTUP_LOWIO_FTEXT);
        slot->guest.textmode_29 = ROME2_STARTUP_LOWIO_TM_UTF8;
    }

    if ((old_osfile & ROME2_STARTUP_LOWIO_FTEXT) == 0u) {
        return (int32_t)ROME2_STARTUP_O_BINARY;
    }
    if (old_tm == ROME2_STARTUP_LOWIO_TM_ANSI) {
        return (int32_t)ROME2_STARTUP_O_TEXT;
    }
    return (old_tm == ROME2_STARTUP_LOWIO_TM_UTF8) ? (int32_t)ROME2_STARTUP_O_U8TEXT : (int32_t)ROME2_STARTUP_O_WTEXT;
}

static int64_t l65_join_i64(uint32_t lo, int32_t hi)
{
    return (int64_t)(((uint64_t)(uint32_t)hi << 32) | (uint64_t)lo);
}

static void l65_split_i64(int64_t val, uint32_t *out_lo, int32_t *out_hi)
{
    uint64_t u = (uint64_t)val;
    *out_lo = (uint32_t)(u & 0xffffffffu);
    *out_hi = (int32_t)(u >> 32);
}

/* `0x116bc7da`: __crt_seek_guard::__crt_seek_guard. */
void rome2_startup_crt_seek_guard_init_116bc7da(
    rome2_startup_l65_crt_env *env,
    rome2_startup_crt_seek_guard28_32 *guard,
    int32_t fh,
    int64_t target_size)
{
    if (guard == NULL) {
        return;
    }
    int64_t saved_pos = l65_file_lseek_nolock(env, fh, 0, 1);
    int64_t end_pos = l65_file_lseek_nolock(env, fh, 0, 2);
    int64_t delta = target_size - end_pos;
    l65_split_i64(saved_pos, &guard->saved_pos_lo_00, &guard->saved_pos_hi_04);
    l65_split_i64(end_pos, &guard->end_pos_lo_08, &guard->end_pos_hi_0c);
    l65_split_i64(delta, &guard->extend_delta_lo_10, &guard->extend_delta_hi_14);
    guard->fh_18 = fh;
}

/* `0x116bc827`: __chsize_nolock. */
int32_t rome2_startup_crt_chsize_nolock_116bc827(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    int64_t new_size)
{
    rome2_startup_crt_seek_guard28_32 guard;
    rome2_startup_crt_seek_guard_init_116bc7da(env, &guard, fh, new_size);
    int64_t saved_pos = l65_join_i64(guard.saved_pos_lo_00, guard.saved_pos_hi_04);
    int64_t end_pos = l65_join_i64(guard.end_pos_lo_08, guard.end_pos_hi_0c);
    int64_t extend_delta = l65_join_i64(guard.extend_delta_lo_10, guard.extend_delta_hi_14);
    if (saved_pos == -1 || end_pos == -1 || new_size < 0) {
        l65_file_lseek_nolock(env, fh, saved_pos, 0);
        return (env != NULL && env->last_errno != 0) ? env->last_errno : ROME2_L65_EINVAL;
    }

    int32_t ret = 0;
    if (extend_delta > 0) {
        uint8_t zero_buf[256];
        memset(zero_buf, 0, sizeof(zero_buf));
        int32_t old_mode = rome2_startup_crt_setmode_nolock_116bc70b(env, fh, (int32_t)ROME2_STARTUP_O_BINARY);
        int64_t rem = extend_delta;
        while (rem > 0) {
            uint32_t chunk = (rem > (int64_t)sizeof(zero_buf)) ? (uint32_t)sizeof(zero_buf) : (uint32_t)rem;
            int32_t wrote = l65_file_write_raw_nolock(env, fh, zero_buf, chunk);
            if (wrote == -1 || wrote == 0) {
                ret = (env != NULL) ? env->last_errno : ROME2_L65_EACCES;
                break;
            }
            rem -= wrote;
        }
        rome2_startup_crt_setmode_nolock_116bc70b(env, fh, old_mode);
    } else {
        rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
        if (slot == NULL || slot->backed_file_idx < 0) {
            ret = ROME2_L65_EBADF;
        } else if (l65_file_lseek_nolock(env, fh, new_size, 0) == -1) {
            ret = (env != NULL) ? env->last_errno : ROME2_L65_EINVAL;
        } else {
            rome2_startup_l65_vfs_file *vf = &env->files[slot->backed_file_idx];
            if (vf->is_readonly) {
                if (env != NULL) {
                    env->last_errno = ROME2_L65_EACCES;
                    env->last_doserrno = 5u;
                }
                ret = ROME2_L65_EACCES;
            } else {
                vf->len = (size_t)new_size;
            }
        }
    }

    l65_file_lseek_nolock(env, guard.fh_18, saved_pos, 0);
    return ret;
}

/* `0x116aef71`: decode_open_create_flags. */
uint32_t rome2_startup_crt_decode_open_create_flags_116aef71(
    rome2_startup_l65_crt_env *env,
    int32_t oflag)
{
    uint32_t bits = (uint32_t)oflag & 0x700u;
    switch (bits) {
    case 0x000u:
    case 0x400u:
        return 3u; /* OPEN_EXISTING */
    case 0x100u:
        return 4u; /* OPEN_ALWAYS */
    case 0x200u:
    case 0x600u:
        return 5u; /* TRUNCATE_EXISTING */
    case 0x300u:
        return 2u; /* CREATE_ALWAYS */
    case 0x500u:
    case 0x700u:
        return 1u; /* CREATE_NEW */
    default:
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return 0xffffffffu;
    }
}

/* `0x116aefe1`: decode_options (produces 24B file_options). */
rome2_startup_crt_file_options24_32 *rome2_startup_crt_decode_options_116aefe1(
    rome2_startup_l65_crt_env *env,
    rome2_startup_crt_file_options24_32 *out_opts,
    uint32_t oflag,
    int32_t shflag,
    uint8_t pmode)
{
    if (out_opts == NULL) {
        return NULL;
    }
    memset(out_opts, 0, sizeof(*out_opts));

    uint32_t rw = oflag & 3u;
    if (rw == 0u) {
        out_opts->access_04 = ROME2_L65_GEN_READ;
    } else if (rw == 1u) {
        uint32_t read_bit = ((oflag & 0x70000u) != 0u && (oflag & ROME2_STARTUP_O_APPEND) != 0u) ? ROME2_L65_GEN_READ : 0u;
        out_opts->access_04 = ROME2_L65_GEN_WRITE | read_bit;
    } else if (rw == 2u) {
        out_opts->access_04 = ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE;
    } else {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        out_opts->access_04 = 0xffffffffu;
    }

    out_opts->disposition_08 = rome2_startup_crt_decode_open_create_flags_116aef71(env, (int32_t)oflag);

    if (shflag == (int32_t)ROME2_STARTUP_SH_DENYRW) {
        out_opts->share_0c = 0u;
    } else if (shflag == (int32_t)ROME2_STARTUP_SH_DENYWR) {
        out_opts->share_0c = 1u;
    } else if (shflag == (int32_t)ROME2_STARTUP_SH_DENYRD) {
        out_opts->share_0c = 2u;
    } else if (shflag == (int32_t)ROME2_STARTUP_SH_DENYNO) {
        out_opts->share_0c = 3u;
    } else if (shflag == (int32_t)ROME2_STARTUP_SH_SECURE) {
        out_opts->share_0c = (out_opts->access_04 == ROME2_L65_GEN_READ) ? 1u : 0u;
    } else {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        out_opts->share_0c = 0xffffffffu;
    }

    out_opts->attributes_10 = 0x80u; /* FILE_ATTRIBUTE_NORMAL */
    if ((oflag & ROME2_STARTUP_O_NOINHERIT) != 0u) {
        out_opts->osfile_flags_00 |= ROME2_STARTUP_LOWIO_FNOINHERIT;
    }
    if ((oflag & ROME2_STARTUP_O_BINARY) == 0u) {
        uint8_t set_ftext = 1u;
        if ((oflag & 0x74000u) == 0u) {
            uint32_t fmode = 0u;
            if (rome2_startup_crt_get_fmode_116bc6de(env, &fmode) != 0) {
                if (env != NULL) {
                    env->watson_calls += 1u;
                }
                set_ftext = 0u;
            } else if (fmode == ROME2_STARTUP_O_BINARY) {
                set_ftext = 0u;
            }
        }
        if (set_ftext != 0u) {
            out_opts->osfile_flags_00 |= ROME2_STARTUP_LOWIO_FTEXT;
        }
    }

    uint8_t umask_val = (env != NULL) ? (uint8_t)env->umask : 0u;
    if ((oflag & ROME2_STARTUP_O_CREAT) != 0u && (((uint8_t)~umask_val & pmode) & 0x80u) == 0u) {
        out_opts->attributes_10 = 1u; /* FILE_ATTRIBUTE_READONLY */
    }
    if ((oflag & ROME2_STARTUP_O_TEMPORARY) != 0u) {
        out_opts->flags_14 |= 0x4000000u; /* FILE_FLAG_DELETE_ON_CLOSE */
        out_opts->access_04 |= ROME2_L65_GEN_DELETE;
        out_opts->share_0c |= 4u;
    }
    if ((oflag & ROME2_STARTUP_O_SHORT_LIVED) != 0u) {
        out_opts->attributes_10 |= 0x100u; /* FILE_ATTRIBUTE_TEMPORARY */
    }
    if ((oflag & ROME2_STARTUP_O_OBTAIN_DIR) != 0u) {
        out_opts->flags_14 |= 0x2000000u; /* FILE_FLAG_BACKUP_SEMANTICS */
    }
    if ((oflag & ROME2_STARTUP_O_SEQUENTIAL) != 0u) {
        out_opts->flags_14 |= 0x8000000u;
    } else if ((oflag & ROME2_STARTUP_O_RANDOM) != 0u) {
        out_opts->flags_14 |= 0x10000000u;
    }
    return out_opts;
}

/* `0x116aef4c`: create_file (simulated synthetic CreateFileW against env->files). */
int32_t rome2_startup_crt_create_file_116aef4c(
    rome2_startup_l65_crt_env *env,
    const uint16_t *filename,
    const rome2_startup_crt_file_options24_32 *opts)
{
    if (env == NULL || filename == NULL || opts == NULL ||
        opts->share_0c == 0xffffffffu || opts->disposition_08 == 0xffffffffu) {
        return -1;
    }
    if (env->force_first_open_rw_denied != 0u &&
        (opts->access_04 & (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE)) == (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE)) {
        env->last_doserrno = 5u;
        return -1;
    }
    char path_ascii[128];
    l65_utf16_to_ascii_bounded(filename, path_ascii, sizeof(path_ascii));

    int32_t idx = -1;
    for (size_t i = 0; i < ROME2_STARTUP_L65_MAX_FILES; ++i) {
        if (env->files[i].exists && strcmp(env->files[i].path, path_ascii) == 0) {
            idx = (int32_t)i;
            break;
        }
    }

    uint32_t disp = opts->disposition_08;
    if (idx >= 0) {
        rome2_startup_l65_vfs_file *vf = &env->files[idx];
        if (disp == 1u) { /* CREATE_NEW -> exists */
            env->last_doserrno = 80u;
            return -1;
        }
        if (vf->is_readonly && (opts->access_04 & ROME2_L65_GEN_WRITE) != 0u) {
            env->last_doserrno = 5u;
            return -1;
        }
        if (disp == 2u || disp == 5u) { /* CREATE_ALWAYS or TRUNCATE_EXISTING */
            vf->len = 0u;
        }
        vf->cursor = 0;
        return idx;
    }

    if (disp == 3u || disp == 5u) { /* OPEN_EXISTING or TRUNCATE_EXISTING */
        env->last_doserrno = 2u;
        return -1;
    }
    uint8_t ro = (uint8_t)((opts->attributes_10 & 1u) != 0u);
    return rome2_startup_l65_env_add_file(env, path_ascii, NULL, 0u, 1u, ro);
}

/* `0x116af15b`: truncate_ctrl_z_if_present. */
int32_t rome2_startup_crt_truncate_ctrl_z_116af15b(
    rome2_startup_l65_crt_env *env,
    int32_t fh)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot == NULL) {
        return ROME2_L65_EBADF;
    }
    uint8_t osfile = slot->guest.osfile_28;
    if ((osfile & (ROME2_STARTUP_LOWIO_FDEV | ROME2_STARTUP_LOWIO_FPIPE)) == 0u &&
        (osfile & ROME2_STARTUP_LOWIO_FTEXT) != 0u) {
        int64_t end_minus_one = l65_file_lseek_nolock(env, fh, -1, 2);
        if (end_minus_one == -1) {
            if (env->last_doserrno == 131u) {
                return 0;
            }
            return env->last_errno;
        }
        uint8_t ch = 0u;
        int32_t nr = l65_file_read_raw_nolock(env, fh, &ch, 1u);
        if (nr == 1 && ch == 0x1au) {
            if (rome2_startup_crt_chsize_nolock_116bc827(env, fh, end_minus_one) != 0) {
                return env->last_errno;
            }
        }
        if (l65_file_lseek_nolock(env, fh, 0, 0) == -1) {
            return env->last_errno;
        }
    }
    return 0;
}

/* `0x116aecf9`: configure_text_mode (BOM detection & BOM write for UTF-8 / UTF-16LE). */
int32_t rome2_startup_crt_configure_text_mode_116aecf9(
    rome2_startup_l65_crt_env *env,
    int32_t fh,
    const rome2_startup_crt_file_options24_32 *opts,
    uint32_t oflag,
    uint8_t *out_textmode)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (out_textmode == NULL || slot == NULL || opts == NULL) {
        return ROME2_L65_EINVAL;
    }
    *out_textmode = 0u;
    if ((slot->guest.osfile_28 & ROME2_STARTUP_LOWIO_FTEXT) == 0u) {
        return 0;
    }

    if ((oflag & 0x74000u) == 0u) {
        uint32_t fmode = 0u;
        if (rome2_startup_crt_get_fmode_116bc6de(env, &fmode) != 0) {
            if (env != NULL) {
                env->watson_calls += 1u;
            }
            return ROME2_L65_EINVAL;
        }
        oflag |= ((fmode & 0x74000u) != 0u) ? (fmode & 0x74000u) : ROME2_STARTUP_O_TEXT;
    }

    uint32_t tm_bits = oflag & 0x74000u;
    if (tm_bits == ROME2_STARTUP_O_TEXT) {
        *out_textmode = ROME2_STARTUP_LOWIO_TM_ANSI;
    } else if (tm_bits == ROME2_STARTUP_O_WTEXT || tm_bits == (ROME2_STARTUP_O_WTEXT | ROME2_STARTUP_O_TEXT)) {
        if ((oflag & 0x301u) == 0x301u) {
            *out_textmode = ROME2_STARTUP_LOWIO_TM_UTF16LE;
        }
    } else if (tm_bits == ROME2_STARTUP_O_U16TEXT || tm_bits == (ROME2_STARTUP_O_U16TEXT | ROME2_STARTUP_O_TEXT)) {
        *out_textmode = ROME2_STARTUP_LOWIO_TM_UTF16LE;
    } else if (tm_bits == ROME2_STARTUP_O_U8TEXT || tm_bits == (ROME2_STARTUP_O_U8TEXT | ROME2_STARTUP_O_TEXT)) {
        *out_textmode = ROME2_STARTUP_LOWIO_TM_UTF8;
    }

    if ((oflag & 0x70000u) == 0u || (opts->osfile_flags_00 & ROME2_STARTUP_LOWIO_FDEV) != 0u) {
        return 0;
    }

    uint32_t access_rw = opts->access_04 & (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE);
    uint8_t write_bom = 0u;
    uint8_t need_read_bom = 0u;
    if (access_rw == ROME2_L65_GEN_WRITE || access_rw == (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE)) {
        uint32_t d = opts->disposition_08;
        if (d == 0u) {
            return 0;
        }
        if (d <= 2u || d == 5u) {
            write_bom = 1u;
        } else if (d <= 4u) {
            int64_t eof_pos = l65_file_lseek_nolock(env, fh, 0, 2);
            if (eof_pos == 0) {
                write_bom = 1u;
            } else {
                if (l65_file_lseek_nolock(env, fh, 0, 0) == -1) {
                    return env->last_errno;
                }
                need_read_bom = (opts->access_04 & ROME2_L65_GEN_READ) ? 1u : 0u;
            }
        } else {
            return 0;
        }
    } else if (access_rw == ROME2_L65_GEN_READ) {
        need_read_bom = 1u;
    } else {
        return 0;
    }

    if (need_read_bom != 0u) {
        uint8_t bom[4] = {0, 0, 0, 0};
        int32_t nr = l65_file_read_raw_nolock(env, fh, bom, 3u);
        if (nr < 0) {
            return env->last_errno;
        }
        if (nr > 0) {
            write_bom = 0u;
        }
        uint16_t bom16 = (uint16_t)bom[0] | ((uint16_t)bom[1] << 8);
        if (nr == 3 && bom[0] == 0xefu && bom[1] == 0xbbu && bom[2] == 0xbfu) {
            *out_textmode = ROME2_STARTUP_LOWIO_TM_UTF8;
        } else if ((nr == 2 || nr == 3) && bom16 == 0xfffeu) {
            env->last_errno = ROME2_L65_EINVAL;
            return ROME2_L65_EINVAL;
        } else if ((nr == 2 || nr == 3) && bom16 == 0xfeffu) {
            if (l65_file_lseek_nolock(env, fh, 2, 0) == -1) {
                return env->last_errno;
            }
            *out_textmode = ROME2_STARTUP_LOWIO_TM_UTF16LE;
        } else {
            if (l65_file_lseek_nolock(env, fh, 0, 0) == -1) {
                return env->last_errno;
            }
        }
    }

    if (write_bom != 0u) {
        uint8_t bom_out[3] = {0, 0, 0};
        uint32_t bom_len = 0u;
        if (*out_textmode == ROME2_STARTUP_LOWIO_TM_UTF8) {
            bom_out[0] = 0xefu;
            bom_out[1] = 0xbbu;
            bom_out[2] = 0xbfu;
            bom_len = 3u;
        } else if (*out_textmode == ROME2_STARTUP_LOWIO_TM_UTF16LE) {
            bom_out[0] = 0xffu;
            bom_out[1] = 0xfeu;
            bom_len = 2u;
        }
        if (bom_len > 0u) {
            int32_t nw = l65_file_write_raw_nolock(env, fh, bom_out, bom_len);
            if (nw != (int32_t)bom_len) {
                return (env->last_errno != 0) ? env->last_errno : ROME2_L65_EACCES;
            }
        }
    }
    return 0;
}

static void l65_release_slot_on_fail(rome2_startup_l65_crt_env *env, int32_t fh)
{
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot != NULL) {
        slot->guest.osfile_28 &= (uint8_t)(~ROME2_STARTUP_LOWIO_FOPEN & 0xffu);
        slot->guest.osfhnd_18 = ROME2_L65_INVALID_HANDLE;
        slot->backed_file_idx = -1;
    }
}

/* `0x116aec0c` / `0x116aeccd`: common_sopen_dispatch SEH cleanup funclets. */
void rome2_startup_crt_sopen_cleanup_char_116aec0c(
    rome2_startup_l65_crt_env *env,
    int32_t err,
    int32_t unlock_flag,
    const int32_t *pfh)
{
    if (unlock_flag != 0 && pfh != NULL) {
        rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, *pfh);
        if (err != 0 && slot != NULL) {
            slot->guest.osfile_28 &= (uint8_t)(~ROME2_STARTUP_LOWIO_FOPEN & 0xffu);
        }
        if (slot != NULL && slot->lock_depth > 0u) {
            slot->lock_depth -= 1u;
        }
    }
}

void rome2_startup_crt_sopen_cleanup_wchar_116aeccd(
    rome2_startup_l65_crt_env *env,
    int32_t err,
    int32_t unlock_flag,
    const int32_t *pfh)
{
    rome2_startup_crt_sopen_cleanup_char_116aec0c(env, err, unlock_flag, pfh);
}

/* `0x116af2ab`: __wsopen_nolock. */
int32_t rome2_startup_crt_wsopen_nolock_116af2ab(
    rome2_startup_l65_crt_env *env,
    int32_t *unlock_flag,
    int32_t *out_fh,
    const uint16_t *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t secure)
{
    (void)secure;
    if (env == NULL || unlock_flag == NULL || out_fh == NULL) {
        return ROME2_L65_EINVAL;
    }
    rome2_startup_crt_file_options24_32 opts;
    rome2_startup_crt_decode_options_116aefe1(env, &opts, (uint32_t)oflag, shflag, (uint8_t)pmode);
    if (opts.share_0c == 0xffffffffu) {
        env->last_doserrno = 0u;
        *out_fh = -1;
        return env->last_errno;
    }
    int32_t fh = rome2_startup_crt_alloc_osfhnd_116ae8b5(env);
    *out_fh = fh;
    if (fh == -1) {
        env->last_doserrno = 0u;
        env->last_errno = ROME2_L65_EMFILE;
        return ROME2_L65_EMFILE;
    }
    *unlock_flag = 1;

    int32_t file_idx = rome2_startup_crt_create_file_116aef4c(env, filename, &opts);
    if (file_idx == -1 &&
        (opts.access_04 & (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE)) == (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE) &&
        ((uint32_t)oflag & ROME2_STARTUP_O_WRONLY) != 0u) {
        opts.access_04 &= ~ROME2_L65_GEN_READ;
        file_idx = rome2_startup_crt_create_file_116aef4c(env, filename, &opts);
    }
    if (file_idx == -1) {
        l65_release_slot_on_fail(env, fh);
        env->last_errno = (env->last_doserrno == 2u) ? 2 : ROME2_L65_EACCES;
        return env->last_errno;
    }

    rome2_startup_l65_vfs_file *vf = &env->files[file_idx];
    if (vf->file_type == 0u) {
        l65_release_slot_on_fail(env, fh);
        env->last_errno = ROME2_L65_EACCES;
        return ROME2_L65_EACCES;
    }
    if (vf->file_type == 2u) {
        opts.osfile_flags_00 |= ROME2_STARTUP_LOWIO_FDEV;
    } else if (vf->file_type == 3u) {
        opts.osfile_flags_00 |= ROME2_STARTUP_LOWIO_FPIPE;
    }

    rome2_startup_crt_lowio_set_os_handle_116ae800(env, fh, (uint32_t)(0x1000 + file_idx));
    rome2_startup_l65_ioinfo_slot *slot = l65_slot(env, fh);
    if (slot == NULL) {
        return ROME2_L65_EBADF;
    }
    slot->backed_file_idx = file_idx;
    opts.osfile_flags_00 |= ROME2_STARTUP_LOWIO_FOPEN;
    slot->guest.osfile_28 = opts.osfile_flags_00;
    slot->guest.textmode_29 = 0u;

    if (((uint32_t)oflag & ROME2_STARTUP_O_RDWR) != 0u) {
        int32_t terr = rome2_startup_crt_truncate_ctrl_z_116af15b(env, fh);
        if (terr != 0) {
            l65_release_slot_on_fail(env, fh);
            return terr;
        }
    }

    uint8_t tm = 0u;
    int32_t cerr = rome2_startup_crt_configure_text_mode_116aecf9(env, fh, &opts, (uint32_t)oflag, &tm);
    if (cerr != 0) {
        l65_release_slot_on_fail(env, fh);
        return cerr;
    }
    slot->guest.textmode_29 = tm;
    uint8_t ubit = (uint8_t)(((uint32_t)oflag >> 16) & 1u);
    slot->guest.utf8_crlf_flags_2d = (uint8_t)((slot->guest.utf8_crlf_flags_2d & 0xfeu) | ubit);

    if ((opts.osfile_flags_00 & (ROME2_STARTUP_LOWIO_FDEV | ROME2_STARTUP_LOWIO_FPIPE)) == 0u &&
        ((uint32_t)oflag & ROME2_STARTUP_O_APPEND) != 0u) {
        slot->guest.osfile_28 |= ROME2_STARTUP_LOWIO_FAPPEND;
    }

    if ((opts.access_04 & (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE)) == (ROME2_L65_GEN_READ | ROME2_L65_GEN_WRITE) &&
        ((uint32_t)oflag & ROME2_STARTUP_O_WRONLY) != 0u) {
        opts.access_04 &= ~ROME2_L65_GEN_READ;
        int32_t ro_idx = rome2_startup_crt_create_file_116aef4c(env, filename, &opts);
        if (ro_idx == -1) {
            l65_release_slot_on_fail(env, fh);
            env->last_errno = ROME2_L65_EACCES;
            return ROME2_L65_EACCES;
        }
    }
    return 0;
}

/* `0x116af21d`: __sopen_nolock. */
int32_t rome2_startup_crt_sopen_nolock_116af21d(
    rome2_startup_l65_crt_env *env,
    int32_t *unlock_flag,
    int32_t *out_fh,
    const char *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t secure)
{
    if (filename == NULL) {
        return -1;
    }
    uint16_t wname[128];
    size_t i = 0;
    while (i + 1u < 128u && filename[i] != '\0') {
        wname[i] = (uint8_t)filename[i];
        ++i;
    }
    wname[i] = 0u;
    return rome2_startup_crt_wsopen_nolock_116af2ab(
        env, unlock_flag, out_fh, wname, oflag, shflag, pmode, secure);
}

/* `0x116aeb77`: common_sopen_dispatch<char>. */
int32_t rome2_startup_crt_common_sopen_dispatch_char_116aeb77(
    rome2_startup_l65_crt_env *env,
    const char *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t *out_fh,
    int32_t secure)
{
    if (out_fh == NULL || (*out_fh = -1, filename == NULL) ||
        (secure != 0 && ((uint32_t)pmode & 0xfffffe7fu) != 0u)) {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return ROME2_L65_EINVAL;
    }
    int32_t unlock_flag = 0;
    int32_t err = rome2_startup_crt_sopen_nolock_116af21d(
        env, &unlock_flag, out_fh, filename, oflag, shflag, pmode, secure);
    rome2_startup_crt_sopen_cleanup_char_116aec0c(env, err, unlock_flag, out_fh);
    if (err != 0) {
        *out_fh = -1;
    }
    return err;
}

/* `0x116aec38`: common_sopen_dispatch<wchar_t>. */
int32_t rome2_startup_crt_common_sopen_dispatch_wchar_116aec38(
    rome2_startup_l65_crt_env *env,
    const uint16_t *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode,
    int32_t *out_fh,
    int32_t secure)
{
    if (out_fh == NULL || (*out_fh = -1, filename == NULL) ||
        (secure != 0 && ((uint32_t)pmode & 0xfffffe7fu) != 0u)) {
        l65_set_invalid_param(env, ROME2_L65_EINVAL);
        return ROME2_L65_EINVAL;
    }
    int32_t unlock_flag = 0;
    int32_t err = rome2_startup_crt_wsopen_nolock_116af2ab(
        env, &unlock_flag, out_fh, filename, oflag, shflag, pmode, secure);
    rome2_startup_crt_sopen_cleanup_wchar_116aeccd(env, err, unlock_flag, out_fh);
    if (err != 0) {
        *out_fh = -1;
    }
    return err;
}

/* `0x116af28b`: __sopen_s. */
int32_t rome2_startup_crt_sopen_s_116af28b(
    rome2_startup_l65_crt_env *env,
    int32_t *out_fh,
    const char *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode)
{
    return rome2_startup_crt_common_sopen_dispatch_char_116aeb77(
        env, filename, oflag, shflag, pmode, out_fh, 1);
}

/* `0x116af5d5`: __wsopen_s. */
int32_t rome2_startup_crt_wsopen_s_116af5d5(
    rome2_startup_l65_crt_env *env,
    int32_t *out_fh,
    const uint16_t *filename,
    int32_t oflag,
    int32_t shflag,
    int32_t pmode)
{
    return rome2_startup_crt_common_sopen_dispatch_wchar_116aec38(
        env, filename, oflag, shflag, pmode, out_fh, 1);
}
