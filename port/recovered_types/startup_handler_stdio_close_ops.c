#include "startup_handler_stdio_close_ops.h"

#include <string.h>

static void set_crt_einval(rome2_startup_crt_stdio_env *env) {
    if (env) {
        env->last_errno = ROME2_STARTUP_CRT_EINVAL;
        env->invalid_param_calls += 1u;
    }
}

static void set_crt_ebadf(rome2_startup_crt_stdio_env *env, uint8_t invoke_invalid_param) {
    if (env) {
        env->last_doserrno = 0u;
        env->last_errno = ROME2_STARTUP_CRT_EBADF;
        if (invoke_invalid_param != 0u) {
            env->invalid_param_calls += 1u;
        }
    }
}

static void record_freed_va(rome2_startup_crt_stdio_env *env, uint32_t va) {
    if (env && va != 0u) {
        if (env->freed_va_count < ROME2_STARTUP_CRT_MAX_FREED) {
            env->freed_vas[env->freed_va_count] = va;
        }
        env->freed_va_count += 1u;
    }
}

static int is_fh_open(const rome2_startup_crt_stdio_env *env, int32_t fh) {
    if (!env || fh < 0 || (uint32_t)fh >= env->nhandle || (uint32_t)fh >= ROME2_STARTUP_CRT_MAX_FDS) {
        return 0;
    }
    return (env->io_slots[fh].osfile_28 & ROME2_STARTUP_IOFILE_FOPEN) != 0u;
}

static int flush_stream_model(rome2_startup_crt_stream_model *stream) {
    if (!stream) {
        return -1;
    }
    if (stream->fail_flush != 0u) {
        stream->guest.flags_0c |= ROME2_STARTUP_IOERR;
        return -1;
    }
    if (stream->buffer_cursor > 0u) {
        size_t copy_len = stream->buffer_cursor;
        if (stream->sink_len < sizeof(stream->sink)) {
            size_t avail = sizeof(stream->sink) - stream->sink_len;
            if (copy_len > avail) {
                copy_len = avail;
            }
            if (copy_len > 0u) {
                memcpy(stream->sink + stream->sink_len, stream->buffer, copy_len);
                stream->sink_len += copy_len;
            }
        }
        stream->buffer_cursor = 0u;
    }
    stream->guest.cnt_08 = (stream->guest.bufsiz_18 > 0 && (stream->guest.flags_0c & ROME2_STARTUP_IOBUFFER_CRT) != 0u)
                               ? stream->guest.bufsiz_18
                               : (int32_t)sizeof(stream->buffer);
    return 0;
}

static void push_vtable_trace(rome2_startup_handler_dispatch_env *env, uint32_t vt) {
    if (env) {
        if (env->vtable_trace_count < 8u) {
            env->vtable_trace[env->vtable_trace_count] = vt;
        }
        env->vtable_trace_count += 1u;
    }
}

static void destroy_and_clear_slot(rome2_startup_handler_dispatch_env *env, uint32_t *slot_va) {
    if (env && slot_va && *slot_va != 0u) {
        if (env->destroyed_count < 8u) {
            env->destroyed_targets[env->destroyed_count] = *slot_va;
        }
        env->destroyed_count += 1u;
        *slot_va = 0u;
    }
}

static rome2_startup_handler_slot4_32 *finalize_handler_scalar_dtor(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env) {
    if (!self) {
        return NULL;
    }
    self->vtable_00 = ROME2_STARTUP_VTABLE_BASE_ADAPTER;
    push_vtable_trace(env, ROME2_STARTUP_VTABLE_BASE_ADAPTER);
    if ((flags & 1u) != 0u && env) {
        if (env->freed_handler_count < 8u) {
            env->freed_handler_vas[env->freed_handler_count] = self_va;
        }
        env->freed_handler_count += 1u;
    }
    return self;
}

/* `0x116bc6d8` */
uint32_t rome2_startup_crt_get_std_handle_policy_116bc6d8(
    const rome2_startup_crt_stdio_env *env) {
    return env ? env->std_handle_free_policy : 0u;
}

/* `0x116ae9c8` */
int32_t rome2_startup_crt_free_osfhnd_116ae9c8(
    rome2_startup_crt_stdio_env *env,
    int32_t fh) {
    rome2_startup_crt_ioinfo56_32 *slot = NULL;
    if (!is_fh_open(env, fh)) {
        set_crt_ebadf(env, 0u);
        return -1;
    }
    slot = &env->io_slots[fh];
    if (slot->osfhnd_18 == ROME2_STARTUP_CRT_INVALID_HANDLE) {
        set_crt_ebadf(env, 0u);
        return -1;
    }
    if (rome2_startup_crt_get_std_handle_policy_116bc6d8(env) == 1u) {
        if (fh == 0 || fh == 1 || fh == 2) {
            static const uint32_t std_ids[3] = {
                ROME2_STARTUP_STD_INPUT_HANDLE,
                ROME2_STARTUP_STD_OUTPUT_HANDLE,
                ROME2_STARTUP_STD_ERROR_HANDLE,
            };
            env->set_std_handle_calls += 1u;
            env->last_std_handle_id = std_ids[fh];
            env->last_std_handle_value = 0u;
        }
    }
    slot->osfhnd_18 = ROME2_STARTUP_CRT_INVALID_HANDLE;
    return 0;
}

/* `0x116ab658` */
int32_t rome2_startup_crt_close_nolock_116ab658(
    rome2_startup_crt_stdio_env *env,
    int32_t fh) {
    uint32_t os_err = 0u;
    uint32_t h = ROME2_STARTUP_CRT_INVALID_HANDLE;

    if (!env || fh < 0 || (uint32_t)fh >= env->nhandle || (uint32_t)fh >= ROME2_STARTUP_CRT_MAX_FDS) {
        set_crt_ebadf(env, 1u);
        return -1;
    }

    h = is_fh_open(env, fh) ? env->io_slots[fh].osfhnd_18 : ROME2_STARTUP_CRT_INVALID_HANDLE;
    if (h != ROME2_STARTUP_CRT_INVALID_HANDLE) {
        uint8_t alias_skip = 0u;
        if ((fh == 1 && (env->io_slots[2].osfile_28 & ROME2_STARTUP_IOFILE_FOPEN) != 0u) ||
            (fh == 2 && (env->io_slots[1].osfile_28 & ROME2_STARTUP_IOFILE_FOPEN) != 0u)) {
            uint32_t h1 = (env->io_slots[1].osfile_28 & ROME2_STARTUP_IOFILE_FOPEN) != 0u
                              ? env->io_slots[1].osfhnd_18
                              : ROME2_STARTUP_CRT_INVALID_HANDLE;
            uint32_t h2 = (env->io_slots[2].osfile_28 & ROME2_STARTUP_IOFILE_FOPEN) != 0u
                              ? env->io_slots[2].osfhnd_18
                              : ROME2_STARTUP_CRT_INVALID_HANDLE;
            if (h1 == h2) {
                alias_skip = 1u;
            }
        }
        if (alias_skip == 0u) {
            env->close_handle_calls += 1u;
            if (env->fail_close_os_handle != 0u && h == env->fail_close_os_handle) {
                os_err = env->simulated_last_error != 0u ? env->simulated_last_error : 6u;
            } else if (env->closed_handle_count < ROME2_STARTUP_CRT_MAX_CLOSED_HANDLES) {
                env->closed_handles[env->closed_handle_count] = h;
                env->closed_handle_count += 1u;
            } else {
                env->closed_handle_count += 1u;
            }
        }
    }

    (void)rome2_startup_crt_free_osfhnd_116ae9c8(env, fh);
    env->io_slots[fh].osfile_28 = 0u;
    if (os_err == 0u) {
        return 0;
    }
    env->last_doserrno = os_err;
    env->last_errno = ROME2_STARTUP_CRT_EBADF;
    return -1;
}

/* `0x116ab5bf` */
void rome2_startup_crt_seh_close_unlock_116ab5bf(
    rome2_startup_crt_stdio_env *env,
    int32_t fh) {
    (void)fh;
    if (env) {
        env->unlock_fhandle_calls += 1u;
    }
}

/* `0x116ab53f` */
int32_t rome2_startup_crt_seh_guarded_call_close_116ab53f(
    rome2_startup_crt_stdio_env *env,
    int32_t fh) {
    int32_t rc = -1;
    if (!env) {
        return -1;
    }
    env->lock_fhandle_calls += 1u;
    if (is_fh_open(env, fh)) {
        rc = rome2_startup_crt_close_nolock_116ab658(env, fh);
    } else {
        env->last_errno = ROME2_STARTUP_CRT_EBADF;
        rc = -1;
    }
    rome2_startup_crt_seh_close_unlock_116ab5bf(env, fh);
    return rc;
}

/* `0x116ab5cb` */
int32_t rome2_startup_crt_close_116ab5cb(
    rome2_startup_crt_stdio_env *env,
    int32_t fh) {
    if (fh == -2) {
        set_crt_ebadf(env, 0u);
        return -1;
    }
    if (!is_fh_open(env, fh)) {
        set_crt_ebadf(env, 1u);
        return -1;
    }
    return rome2_startup_crt_seh_guarded_call_close_116ab53f(env, fh);
}

/* `0x116aa220` */
void rome2_startup_crt_stdio_free_stream_116aa220(
    rome2_startup_crt_stream_model *stream) {
    if (!stream) {
        return;
    }
    stream->guest.ptr_00 = 0u;
    stream->guest.base_04 = 0u;
    stream->guest.cnt_08 = 0;
    stream->guest.file_10 = -1;
    stream->guest.charbuf_14 = 0u;
    stream->guest.bufsiz_18 = 0;
    stream->guest.tmpfname_1c = 0u;
    stream->guest.flags_0c = 0u;
    stream->buffer_cursor = 0u;
}

/* `0x116ab6f4` */
void rome2_startup_crt_stdio_free_buffer_nolock_116ab6f4(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream) {
    if (!stream) {
        return;
    }
    if ((stream->guest.flags_0c & ROME2_STARTUP_IOALLOCATED) != 0u &&
        (stream->guest.flags_0c & ROME2_STARTUP_IOBUFFER_CRT) != 0u) {
        record_freed_va(env, stream->guest.base_04);
        stream->guest.flags_0c &= ~(ROME2_STARTUP_IOBUFFER_CRT | 0x100u);
        stream->guest.base_04 = 0u;
        stream->guest.ptr_00 = 0u;
        stream->guest.cnt_08 = 0;
        stream->buffer_cursor = 0u;
    }
}

/* `0x1168ed21` */
int32_t rome2_startup_crt_fclose_nolock_1168ed21(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream) {
    int32_t result = -1;
    if (!stream) {
        set_crt_einval(env);
        return -1;
    }
    if ((stream->guest.flags_0c & ROME2_STARTUP_IOALLOCATED) != 0u) {
        int32_t flush_rc = flush_stream_model(stream);
        result = flush_rc;
        rome2_startup_crt_stdio_free_buffer_nolock_116ab6f4(env, stream);
        if (rome2_startup_crt_close_116ab5cb(env, stream->guest.file_10) < 0) {
            result = -1;
        } else if (stream->guest.tmpfname_1c != 0u) {
            record_freed_va(env, stream->guest.tmpfname_1c);
            stream->guest.tmpfname_1c = 0u;
        }
    }
    rome2_startup_crt_stdio_free_stream_116aa220(stream);
    return result;
}

/* `0x1168ee12` */
void rome2_startup_crt_seh_fclose_unlock_1168ee12(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream) {
    (void)stream;
    if (env) {
        env->unlock_file_calls += 1u;
    }
}

/* `0x1168ed98` */
int32_t rome2_startup_crt_fclose_1168ed98(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream) {
    int32_t result = -1;
    if (!stream) {
        set_crt_einval(env);
        return -1;
    }
    if ((stream->guest.flags_0c & ROME2_STARTUP_IOSTRG) != 0u) {
        rome2_startup_crt_stdio_free_stream_116aa220(stream);
        return -1;
    }
    if (env) {
        env->lock_file_calls += 1u;
    }
    result = rome2_startup_crt_fclose_nolock_1168ed21(env, stream);
    rome2_startup_crt_seh_fclose_unlock_1168ee12(env, stream);
    return result;
}

/* `0x11687a7a` */
int32_t rome2_startup_crt_feof_11687a7a(
    rome2_startup_crt_stdio_env *env,
    const rome2_startup_crt_stream_model *stream) {
    if (!stream) {
        set_crt_einval(env);
        return 0;
    }
    return (int32_t)((stream->guest.flags_0c >> 3) & 1u);
}

/* `0x11687eb8` */
size_t rome2_startup_crt_fwrite_nolock_11687eb8(
    rome2_startup_crt_stdio_env *env,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream) {
    const uint8_t *src = (const uint8_t *)buf;
    size_t buf_chunk = 0u;
    size_t total_bytes = 0u;
    size_t remaining = 0u;

    if (elem_size == 0u || elem_count == 0u) {
        return 0u;
    }
    if (!stream || !buf || elem_count > (UINT32_MAX / elem_size)) {
        set_crt_einval(env);
        return 0u;
    }
    if ((stream->guest.flags_0c & (ROME2_STARTUP_IOBUFFER_CRT | ROME2_STARTUP_IOBUFFER_USER | ROME2_STARTUP_IOBUFFER_NONE)) != 0u) {
        buf_chunk = (stream->guest.bufsiz_18 > 0) ? (size_t)stream->guest.bufsiz_18 : 0u;
    } else {
        buf_chunk = 0x1000u;
    }

    total_bytes = elem_size * elem_count;
    remaining = total_bytes;
    while (remaining > 0u) {
        size_t step = 0u;
        if ((stream->guest.flags_0c & (ROME2_STARTUP_IOBUFFER_CRT | ROME2_STARTUP_IOBUFFER_USER)) != 0u &&
            stream->guest.cnt_08 != 0) {
            size_t avail = 0u;
            if (stream->guest.cnt_08 < 0) {
                stream->guest.flags_0c |= ROME2_STARTUP_IOERR;
                break;
            }
            if ((stream->guest.flags_0c & ROME2_STARTUP_IOREAD) != 0u) {
                break;
            }
            avail = (size_t)stream->guest.cnt_08;
            step = (remaining < avail) ? remaining : avail;
            if (stream->buffer_cursor + step <= sizeof(stream->buffer)) {
                memcpy(stream->buffer + stream->buffer_cursor, src, step);
                stream->buffer_cursor += step;
            }
            stream->guest.cnt_08 -= (int32_t)step;
            stream->guest.ptr_00 += (uint32_t)step;
            remaining -= step;
            src += step;
            continue;
        }

        if (buf_chunk > 0u && remaining >= buf_chunk) {
            size_t aligned = remaining - (remaining % buf_chunk);
            if ((stream->guest.flags_0c & (ROME2_STARTUP_IOBUFFER_CRT | ROME2_STARTUP_IOBUFFER_USER)) != 0u &&
                flush_stream_model(stream) != 0) {
                break;
            }
            if (stream->fail_write != 0u) {
                if (stream->simulate_eof_on_error != 0u) {
                    stream->guest.flags_0c |= ROME2_STARTUP_IOEOF;
                }
                stream->guest.flags_0c |= ROME2_STARTUP_IOERR;
                break;
            }
            if (stream->sink_len + aligned > sizeof(stream->sink)) {
                size_t wrote = sizeof(stream->sink) - stream->sink_len;
                if (wrote > 0u) {
                    memcpy(stream->sink + stream->sink_len, src, wrote);
                    stream->sink_len += wrote;
                }
                remaining -= wrote;
                stream->guest.flags_0c |= ROME2_STARTUP_IOERR;
                break;
            }
            memcpy(stream->sink + stream->sink_len, src, aligned);
            stream->sink_len += aligned;
            remaining -= aligned;
            src += aligned;
            continue;
        }

        /* Single-byte _flsbuf path when buffer empty and remaining < buf_chunk */
        if (stream->fail_write != 0u) {
            if (stream->simulate_eof_on_error != 0u) {
                stream->guest.flags_0c |= ROME2_STARTUP_IOEOF;
            }
            stream->guest.flags_0c |= ROME2_STARTUP_IOERR;
            break;
        }
        if ((stream->guest.flags_0c & ROME2_STARTUP_IOBUFFER_NONE) != 0u) {
            if (stream->sink_len < sizeof(stream->sink)) {
                stream->sink[stream->sink_len] = *src;
                stream->sink_len += 1u;
            } else {
                stream->guest.flags_0c |= ROME2_STARTUP_IOERR;
                break;
            }
        } else {
            size_t cap = (stream->guest.bufsiz_18 > 0 && (size_t)stream->guest.bufsiz_18 <= sizeof(stream->buffer))
                             ? (size_t)stream->guest.bufsiz_18
                             : sizeof(stream->buffer);
            if (stream->buffer_cursor > 0u && flush_stream_model(stream) != 0) {
                break;
            }
            stream->guest.flags_0c |= ROME2_STARTUP_IOBUFFER_CRT;
            stream->buffer[0] = *src;
            stream->buffer_cursor = 1u;
            stream->guest.ptr_00 = stream->guest.base_04 + 1u;
            stream->guest.cnt_08 = (int32_t)(cap - 1u);
            buf_chunk = cap;
        }
        remaining -= 1u;
        src += 1u;
    }

    return (total_bytes - remaining) / elem_size;
}

/* `0x11687e75` */
size_t rome2_startup_crt_fwrite_lambda_11687e75(
    rome2_startup_crt_stdio_env *env,
    const rome2_startup_fwrite_capture16_32 *capture_layout,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream) {
    size_t written = 0u;
    (void)capture_layout;
    if (env) {
        env->flock_lock_calls += 1u;
    }
    written = rome2_startup_crt_fwrite_nolock_11687eb8(env, buf, elem_size, elem_count, stream);
    if (env) {
        env->flock_unlock_calls += 1u;
    }
    return written;
}

/* `0x11687e69` */
void rome2_startup_crt_seh_fwrite_unlock_11687e69(
    rome2_startup_crt_stdio_env *env,
    rome2_startup_crt_stream_model *stream) {
    (void)stream;
    if (env) {
        env->unlock_file_calls += 1u;
    }
}

/* `0x11687e1a` */
size_t rome2_startup_crt_seh_guarded_call_fwrite_11687e1a(
    rome2_startup_crt_stdio_env *env,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream) {
    rome2_startup_fwrite_capture16_32 cap = { 0u, 0u, 0u, 0u };
    size_t written = 0u;
    if (env) {
        env->lock_file_calls += 1u;
    }
    written = rome2_startup_crt_fwrite_lambda_11687e75(
        env, &cap, buf, elem_size, elem_count, stream);
    rome2_startup_crt_seh_fwrite_unlock_11687e69(env, stream);
    return written;
}

/* `0x11688039` */
size_t rome2_startup_crt_fwrite_11688039(
    rome2_startup_crt_stdio_env *env,
    const void *buf,
    size_t elem_size,
    size_t elem_count,
    rome2_startup_crt_stream_model *stream) {
    if (elem_size == 0u || elem_count == 0u) {
        return 0u;
    }
    if (!stream) {
        set_crt_einval(env);
        return 0u;
    }
    return rome2_startup_crt_seh_guarded_call_fwrite_11687e1a(
        env, buf, elem_size, elem_count, stream);
}

/* `0x100d3620` */
void rome2_startup_app_cleanup_five_buffers_100d3620(
    rome2_startup_app_teardown_buffers *buffers) {
    uint32_t *fields[5];
    size_t i = 0u;
    if (!buffers) {
        return;
    }
    fields[0] = &buffers->ptr_0e0;
    fields[1] = &buffers->ptr_0d4;
    fields[2] = &buffers->ptr_0a0;
    fields[3] = &buffers->ptr_094;
    fields[4] = &buffers->ptr_088;
    for (i = 0u; i < 5u; ++i) {
        if (*fields[i] != 0u) {
            if (buffers->freed_count < 8u) {
                buffers->freed_vas[buffers->freed_count] = *fields[i];
            }
            buffers->freed_count += 1u;
            *fields[i] = 0u;
        }
    }
}

/* `0x100e7690` */
void rome2_startup_app_destroy_observer_slots_100e7690(
    rome2_startup_app_observer_array *arr) {
    uint32_t count = 0u;
    uint32_t i = 0u;
    if (!arr) {
        return;
    }
    count = arr->active_count;
    if (count > ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS) {
        count = ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS;
    }
    for (i = count; i > 0u && i <= ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS; --i) {
        uint32_t slot = arr->slot_vas[i - 1u];
        if (slot != 0u) {
            if (arr->destroyed_count < ROME2_STARTUP_MAX_OBS_DESTROY_SLOTS) {
                arr->destroyed_vas[arr->destroyed_count] = slot;
                arr->destroyed_flags[arr->destroyed_count] = 1u;
            }
            arr->destroyed_count += 1u;
            arr->slot_vas[i - 1u] = 0u;
        }
    }
    arr->active_count = 0u;
}

/* `0x10121170` */
uint8_t rome2_startup_log_file_box_close_10121170(
    rome2_startup_app_log_state *log_state,
    rome2_startup_crt_stdio_env *crt_env) {
    int32_t rc = 0;
    int32_t err = 0;
    if (!log_state || log_state->box.stdio_file_00 == 0u || !log_state->open_stream) {
        return 0u;
    }
    rc = rome2_startup_crt_fclose_1168ed98(crt_env, log_state->open_stream);
    if (rc != 0) {
        err = crt_env ? crt_env->last_errno : 0;
    }
    log_state->box.last_errno_04 = err;
    log_state->box.stdio_file_00 = 0u;
    return (err == 0) ? 1u : 0u;
}

/* `0x100e32e0` */
uint8_t rome2_startup_app_close_log_100e32e0(
    rome2_startup_app_log_state *log_state,
    rome2_startup_crt_stdio_env *crt_env) {
    size_t wrote = 0u;
    uint8_t ok = 0u;

    if (!log_state || log_state->box_va == 0u) {
        return 0u;
    }
    if (log_state->box.stdio_file_00 != 0u && log_state->open_stream != NULL) {
        wrote = rome2_startup_crt_fwrite_11688039(
            crt_env,
            ROME2_STARTUP_LOG_END_LITERAL,
            1u,
            ROME2_STARTUP_LOG_END_LEN,
            log_state->open_stream);
        if (wrote != ROME2_STARTUP_LOG_END_LEN) {
            if (rome2_startup_crt_feof_11687a7a(crt_env, log_state->open_stream) != 0) {
                log_state->box.last_errno_04 = ROME2_STARTUP_LOG_EOF_SENTINEL;
            } else {
                log_state->box.last_errno_04 =
                    ((log_state->open_stream->guest.flags_0c >> 4) & 1u) != 0u ? 1 : 0;
            }
        }
    }
    ok = rome2_startup_log_file_box_close_10121170(log_state, crt_env);
    if (log_state->freed_box_count < 4u) {
        log_state->freed_box_vas[log_state->freed_box_count] = log_state->box_va;
    }
    log_state->freed_box_count += 1u;
    log_state->box_va = 0u;
    return ok;
}

/* `0x100d38b0` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_scalar_dtor_base_100d38b0(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env) {
    return finalize_handler_scalar_dtor(self, self_va, flags, env);
}

/* `0x100e14d0` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_singleton_dtor_100e14d0(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env) {
    if (!self) {
        return NULL;
    }
    self->vtable_00 = ROME2_STARTUP_VTABLE_SINGLETON_385C;
    push_vtable_trace(env, ROME2_STARTUP_VTABLE_SINGLETON_385C);
    if (env) {
        destroy_and_clear_slot(env, &env->singleton_119f385c);
    }
    return finalize_handler_scalar_dtor(self, self_va, flags, env);
}

/* `0x100e16a0` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_crash_slot04_dtor_100e16a0(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env) {
    if (!self) {
        return NULL;
    }
    self->vtable_00 = ROME2_STARTUP_VTABLE_CRASH_SLOT04;
    push_vtable_trace(env, ROME2_STARTUP_VTABLE_CRASH_SLOT04);
    if (env) {
        destroy_and_clear_slot(env, &env->crash_slot04);
    }
    return finalize_handler_scalar_dtor(self, self_va, flags, env);
}

/* `0x100e1820` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_vfs_slot50_dtor_100e1820(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env) {
    if (!self) {
        return NULL;
    }
    self->vtable_00 = ROME2_STARTUP_VTABLE_VFS_SLOT50;
    push_vtable_trace(env, ROME2_STARTUP_VTABLE_VFS_SLOT50);
    if (env) {
        env->vfs_slot50_calls += 1u;
    }
    return finalize_handler_scalar_dtor(self, self_va, flags, env);
}

/* `0x100e1a70` */
rome2_startup_handler_slot4_32 *rome2_startup_handler_crash_slots_2c_28_24_dtor_100e1a70(
    rome2_startup_handler_slot4_32 *self,
    uint32_t self_va,
    uint8_t flags,
    rome2_startup_handler_dispatch_env *env) {
    if (!self) {
        return NULL;
    }
    self->vtable_00 = ROME2_STARTUP_VTABLE_CRASH_SLOTS_2C;
    push_vtable_trace(env, ROME2_STARTUP_VTABLE_CRASH_SLOTS_2C);
    if (env) {
        destroy_and_clear_slot(env, &env->crash_slot2c);
        destroy_and_clear_slot(env, &env->crash_slot28);
        destroy_and_clear_slot(env, &env->crash_slot24);
    }
    return finalize_handler_scalar_dtor(self, self_va, flags, env);
}

/* `0x100e85d0` */
uint8_t rome2_startup_handler_clear_flag_100e85d0(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va) {
    (void)ctx_va;
    if (env) {
        env->flag_100d6560_last_arg = 0u;
        env->flag_100d6560_calls += 1u;
    }
    return 1u;
}

/* `0x100e8be0` */
uint8_t rome2_startup_handler_crash_vslot104_vslot68_100e8be0(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va) {
    (void)ctx_va;
    if (env) {
        env->crash_vslot104_calls += 1u;
        if (env->crash_vslot104_obj != 0u) {
            env->crash_vslot68_calls += 1u;
        }
    }
    return 1u;
}

/* `0x100e8e50` */
uint8_t rome2_startup_handler_vfs_load_release_100e8e50(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va) {
    (void)ctx_va;
    if (!env) {
        return 0u;
    }
    env->vfs_slot08_calls += 1u;
    if (env->vfs_slot08_ready == 0u) {
        return 0u;
    }
    (void)rome2_startup_report_section_timing_done_112dcaf0(
        env->timing_env, "Finished VFS load_release", 0, NULL);
    return 1u;
}

/* `0x100e9230` */
uint8_t rome2_startup_handler_vfs_start_100e9230(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va) {
    (void)ctx_va;
    if (!env) {
        return 0u;
    }
    env->vfs_slot58_calls += 1u;
    if (env->vfs_slot58_ready == 0u) {
        return 0u;
    }
    env->vfs_slot54_calls += 1u;
    env->vfs_slot54_arg = 1u;
    (void)rome2_startup_report_section_timing_done_112dcaf0(
        env->timing_env, "VFS started", 0, NULL);
    return 1u;
}

/* `0x100ea040` */
uint8_t rome2_startup_handler_crash_vslot344_100ea040(
    rome2_startup_handler_dispatch_env *env,
    uint32_t ctx_va) {
    (void)ctx_va;
    if (env) {
        env->crash_vslot344_calls += 1u;
    }
    return 1u;
}
