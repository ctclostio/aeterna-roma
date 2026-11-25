#include "facefx_alloc_singleton_log_ops.h"

#include <stdio.h>
#include <string.h>

void rome2_l80_ctx_init(
    rome2_l80_fx_ctx *ctx,
    uint8_t *arena_bytes,
    uint32_t base_va,
    uint32_t arena_size,
    uint32_t heap_start_va) {
    uint32_t i;
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->arena_bytes = arena_bytes;
    ctx->arena_base_va = base_va;
    ctx->arena_size = arena_size;
    ctx->heap_cursor = heap_start_va;
    for (i = 0u; i < 16u; ++i) {
        ctx->slabs[i].block_size = (i + 1u) * 8u;
    }
}

void *rome2_l80_mut_ptr(const rome2_l80_fx_ctx *ctx, uint32_t va, uint32_t bytes) {
    uint32_t off;
    if (ctx == NULL || ctx->arena_bytes == NULL || bytes == 0u) {
        return NULL;
    }
    if (va < ctx->arena_base_va) {
        return NULL;
    }
    off = va - ctx->arena_base_va;
    if (off >= ctx->arena_size || bytes > ctx->arena_size - off) {
        return NULL;
    }
    return ctx->arena_bytes + off;
}

const void *rome2_l80_const_ptr(const rome2_l80_fx_ctx *ctx, uint32_t va, uint32_t bytes) {
    return rome2_l80_mut_ptr(ctx, va, bytes);
}

/* 0x10ed3d90 */
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_ctor_default(
    rome2_fx_memory_allocation_policy_32 *self) {
    if (self == NULL) {
        return NULL;
    }
    memset(self, 0, sizeof(*self));
    return self;
}

/* 0x10ed3d60 */
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_ctor_full(
    rome2_fx_memory_allocation_policy_32 *self,
    int32_t alloc_type,
    uint8_t use_default_hooks,
    uint32_t alloc_fn_va,
    uint32_t alloc_dbg_fn_va,
    uint32_t free_fn_va) {
    if (self == NULL) {
        return NULL;
    }
    self->alloc_type = alloc_type;
    self->use_default_hooks = use_default_hooks;
    self->pad05[0] = 0u;
    self->pad05[1] = 0u;
    self->pad05[2] = 0u;
    self->alloc_fn_va = alloc_fn_va;
    self->alloc_dbg_fn_va = alloc_dbg_fn_va;
    self->free_fn_va = free_fn_va;
    return self;
}

/* 0x10ed3d30 */
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_ctor_copy(
    rome2_fx_memory_allocation_policy_32 *self,
    const rome2_fx_memory_allocation_policy_32 *other) {
    if (self == NULL || other == NULL) {
        return self;
    }
    *self = *other;
    return self;
}

/* 0x10ed3e20 */
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_assign(
    rome2_fx_memory_allocation_policy_32 *self,
    const rome2_fx_memory_allocation_policy_32 *other) {
    if (self != NULL && other != NULL && self != other) {
        *self = *other;
    }
    return self;
}

/* 0x10ed3f40 */
uint32_t rome2_l80_fx_allocate(rome2_l80_fx_ctx *ctx, uint32_t bytes) {
    uint32_t aligned;
    uint32_t i;
    uint32_t va;
    if (ctx == NULL || bytes == 0u) {
        return 0u;
    }
    ++ctx->alloc_calls;
    if (ctx->slab_enabled != 0u) {
        for (i = 0u; i < 16u; ++i) {
            rome2_l80_fx_slab_bucket *sb = &ctx->slabs[i];
            if (bytes <= sb->block_size && sb->slab_base_va != 0u && sb->free_count > 0u) {
                uint32_t blk_va = sb->slab_base_va + (uint32_t)sb->next_free_idx * sb->block_size;
                const uint8_t *blk = (const uint8_t *)rome2_l80_const_ptr(ctx, blk_va, 1u);
                if (blk != NULL) {
                    sb->next_free_idx = *blk;
                    --sb->free_count;
                    return blk_va;
                }
            }
        }
    }
    if (ctx->custom_alloc != NULL) {
        return ctx->custom_alloc(ctx, bytes);
    }
    aligned = (bytes + 7u) & ~7u;
    if (ctx->heap_cursor < ctx->arena_base_va) {
        return 0u;
    }
    {
        uint32_t off = ctx->heap_cursor - ctx->arena_base_va;
        if (off > ctx->arena_size || aligned > ctx->arena_size - off) {
            return 0u;
        }
    }
    va = ctx->heap_cursor;
    ctx->heap_cursor += aligned;
    return va;
}

/* 0x10ed4030 */
void rome2_l80_fx_free(rome2_l80_fx_ctx *ctx, uint32_t ptr_va, uint32_t bytes) {
    uint32_t i;
    if (ctx == NULL || ptr_va == 0u) {
        return;
    }
    ++ctx->free_calls;
    if (ctx->slab_enabled != 0u) {
        for (i = 0u; i < 16u; ++i) {
            rome2_l80_fx_slab_bucket *sb = &ctx->slabs[i];
            if (bytes <= sb->block_size && sb->slab_base_va != 0u && sb->capacity > 0u) {
                uint32_t span = (uint32_t)sb->capacity * sb->block_size;
                if (ptr_va >= sb->slab_base_va && ptr_va < sb->slab_base_va + span) {
                    uint8_t *blk = (uint8_t *)rome2_l80_mut_ptr(ctx, ptr_va, 1u);
                    if (blk != NULL) {
                        *blk = sb->next_free_idx;
                        sb->next_free_idx = (uint8_t)((ptr_va - sb->slab_base_va) / sb->block_size);
                        ++sb->free_count;
                        return;
                    }
                }
            }
        }
    }
    if (ctx->custom_free != NULL) {
        ctx->custom_free(ctx, ptr_va, bytes);
    }
}

/* 0x10ed3ce0, 0x10ed3cd0, 0x10ed3dc0, 0x10ed48c0 */
uint32_t rome2_l80_singleton_log_mgr_ctor(rome2_l80_fx_ctx *ctx, uint32_t self_va) {
    uint32_t *vt = (uint32_t *)rome2_l80_mut_ptr(ctx, self_va, 4u);
    if (vt != NULL) {
        *vt = ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER;
    }
    if (ctx != NULL) {
        ctx->log_manager_singleton_va = self_va;
    }
    return self_va;
}

uint32_t rome2_l80_singleton_log_mgr_copy(uint32_t *vtable_slot, uint32_t self_va) {
    if (vtable_slot != NULL) {
        *vtable_slot = ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER;
    }
    return self_va;
}

void rome2_l80_singleton_log_mgr_dtor(rome2_l80_fx_ctx *ctx, uint32_t self_va) {
    uint32_t *vt = (uint32_t *)rome2_l80_mut_ptr(ctx, self_va, 4u);
    if (vt != NULL) {
        *vt = ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER;
    }
    if (ctx != NULL) {
        ctx->log_manager_singleton_va = 0u;
    }
}

uint32_t rome2_l80_singleton_log_mgr_get(const rome2_l80_fx_ctx *ctx) {
    return (ctx != NULL) ? ctx->log_manager_singleton_va : 0u;
}

/* 0x10ed5670, 0x10ed5660, 0x10ed57d0, 0x10ed7890 */
uint32_t rome2_l80_singleton_res_mgr_ctor(rome2_l80_fx_ctx *ctx, uint32_t self_va) {
    uint32_t *vt = (uint32_t *)rome2_l80_mut_ptr(ctx, self_va, 4u);
    if (vt != NULL) {
        *vt = ROME2_FX_VTABLE_SINGLETON_RESOURCE_MANAGER;
    }
    if (ctx != NULL) {
        ctx->resource_manager_singleton_va = self_va;
    }
    return self_va;
}

uint32_t rome2_l80_singleton_res_mgr_copy(uint32_t *vtable_slot, uint32_t self_va) {
    if (vtable_slot != NULL) {
        *vtable_slot = ROME2_FX_VTABLE_SINGLETON_RESOURCE_MANAGER;
    }
    return self_va;
}

void rome2_l80_singleton_res_mgr_dtor(rome2_l80_fx_ctx *ctx, uint32_t self_va) {
    uint32_t *vt = (uint32_t *)rome2_l80_mut_ptr(ctx, self_va, 4u);
    if (vt != NULL) {
        *vt = ROME2_FX_VTABLE_SINGLETON_RESOURCE_MANAGER;
    }
    if (ctx != NULL) {
        ctx->resource_manager_singleton_va = 0u;
    }
}

uint32_t rome2_l80_singleton_res_mgr_get(const rome2_l80_fx_ctx *ctx) {
    return (ctx != NULL) ? ctx->resource_manager_singleton_va : 0u;
}

/* 0x107e7830 */
void *rome2_l80_fx_nobase_assign(void *self, const void *other) {
    (void)other;
    return self;
}

/* 0x1039a190, 0x10ed7be0, 0x10ed6120, 0x10ed6130, 0x10ed6150 */
rome2_fx_mount_result_32 *rome2_l80_mount_result_ctor(rome2_fx_mount_result_32 *self, int32_t err) {
    if (self != NULL) {
        self->error_code = err;
    }
    return self;
}

int32_t rome2_l80_mount_result_bool(const rome2_fx_mount_result_32 *self) {
    return (self != NULL && self->error_code == 0) ? 1 : 0;
}

uint32_t rome2_l80_safe_bool_mount_result(const rome2_fx_mount_result_32 *self) {
    return (self != NULL && self->error_code != 0) ? 0xffffffffu : 0u;
}

uint32_t rome2_l80_safe_bool_mount_unmount(const rome2_fx_mount_unmount_result_32 *self) {
    if (self != NULL && self->mount_err == 0 && self->unmount_err == 0) {
        return 0u;
    }
    return 0xffffffffu;
}

uint32_t rome2_l80_safe_bool_play_result(const int32_t *play_status) {
    return (play_status != NULL && *play_status == -1) ? 0xffffffffu : 0u;
}

/* 0x10ed5680, 0x10ed5810, 0x10ed5830, 0x10ed7bc0, 0x10ed6100 */
rome2_fx_actor_load_result_32 *rome2_l80_actor_load_result_ctor(rome2_fx_actor_load_result_32 *self) {
    if (self != NULL) {
        memset(self, 0, sizeof(*self));
    }
    return self;
}

rome2_fx_actor_load_result_32 *rome2_l80_actor_load_result_assign_move(
    rome2_fx_actor_load_result_32 *self,
    const rome2_fx_actor_load_result_32 *other) {
    if (self != NULL && other != NULL) {
        *self = *other;
    }
    return self;
}

rome2_fx_actor_load_result_32 *rome2_l80_actor_load_result_assign_copy(
    rome2_fx_actor_load_result_32 *self,
    const rome2_fx_actor_load_result_32 *other) {
    if (self != NULL && other != NULL) {
        *self = *other;
    }
    return self;
}

int32_t rome2_l80_actor_load_result_bool(const rome2_fx_actor_load_result_32 *self) {
    if (self != NULL && self->actor_va != 0u && self->secondary_error == 0 && self->error_code == 0) {
        return 1;
    }
    return 0;
}

uint32_t rome2_l80_safe_bool_actor_load_result(const rome2_fx_actor_load_result_32 *self) {
    return rome2_l80_actor_load_result_bool(self) != 0 ? 0u : 0xffffffffu;
}

/* 0x10ed3d10, 0x10ed3d20, 0x100e07a0 */
uint32_t rome2_l80_log_listener_ctor(uint32_t *vtable_slot, uint32_t self_va) {
    if (vtable_slot != NULL) {
        *vtable_slot = ROME2_FX_VTABLE_LOG_LISTENER;
    }
    return self_va;
}

void rome2_l80_log_listener_dtor(uint32_t *vtable_slot) {
    if (vtable_slot != NULL) {
        *vtable_slot = ROME2_FX_VTABLE_LOG_LISTENER;
    }
}

/* 0x10ed49b0, 0x10ed4a50, 0x10ed3e00, 0x100e81a0, 0x10ed4d60, 0x10ed4b80, 0x10ed4a70, 0x10ed4af0, 0x10ed4be0 */
rome2_fx_log_stream_32 *rome2_l80_log_stream_ctor(rome2_fx_log_stream_32 *self) {
    if (self != NULL) {
        self->cursor = 0u;
        memset(self->buf, 0, sizeof(self->buf));
    }
    return self;
}

void rome2_l80_log_stream_dtor(rome2_fx_log_stream_32 *self) {
    if (self != NULL) {
        self->cursor = 0u;
        memset(self->buf, 0, sizeof(self->buf));
    }
}

rome2_fx_log_stream_32 *rome2_l80_log_stream_assign(
    rome2_fx_log_stream_32 *self,
    const rome2_fx_log_stream_32 *other) {
    if (self != NULL && other != NULL) {
        *self = *other;
    }
    return self;
}

const char *rome2_l80_log_stream_get_cstr(const rome2_fx_log_stream_32 *self) {
    return (self != NULL) ? self->buf : NULL;
}

void rome2_l80_log_stream_append_len(rome2_fx_log_stream_32 *self, const char *s, uint32_t len) {
    uint32_t cur;
    uint32_t avail;
    if (self == NULL || s == NULL || len == 0u) {
        return;
    }
    cur = self->cursor;
    if (cur < 0x3ffu) {
        avail = 0x3ffu - cur;
        if (len > avail) {
            len = avail;
        }
        memcpy(self->buf + cur, s, len);
        self->cursor = cur + len;
        self->buf[self->cursor] = '\0';
    }
}

rome2_fx_log_stream_32 *rome2_l80_log_stream_push_cstr(rome2_fx_log_stream_32 *self, const char *s) {
    if (self != NULL && s != NULL) {
        rome2_l80_log_stream_append_len(self, s, (uint32_t)strlen(s));
    }
    return self;
}

rome2_fx_log_stream_32 *rome2_l80_log_stream_push_int(rome2_fx_log_stream_32 *self, int32_t v) {
    char tmp[64];
    if (self != NULL) {
        (void)snprintf(tmp, sizeof(tmp), "%d", v);
        rome2_l80_log_stream_push_cstr(self, tmp);
    }
    return self;
}

rome2_fx_log_stream_32 *rome2_l80_log_stream_push_float(rome2_fx_log_stream_32 *self, float v) {
    char tmp[64];
    if (self != NULL) {
        (void)snprintf(tmp, sizeof(tmp), "%f", (double)v);
        rome2_l80_log_stream_push_cstr(self, tmp);
    }
    return self;
}

rome2_fx_log_stream_32 *rome2_l80_log_stream_push_ptr(rome2_fx_log_stream_32 *self, uint32_t ptr_va) {
    char tmp[64];
    if (self != NULL) {
        (void)snprintf(tmp, sizeof(tmp), "%08X", ptr_va);
        rome2_l80_log_stream_push_cstr(self, tmp);
    }
    return self;
}

/* 0x10ed4950, 0x10ed49d0, 0x10ed4c60, 0x10ed4d30, 0x10ed4db0 */
rome2_fx_log_32 *rome2_l80_fx_log_ctor(rome2_fx_log_32 *self) {
    if (self != NULL) {
        memset(self, 0, sizeof(*self));
    }
    return self;
}

void rome2_l80_fx_log_dtor(rome2_fx_log_32 *self) {
    if (self != NULL) {
        memset(self, 0, sizeof(*self));
    }
}

void rome2_l80_fx_log_add_listener(rome2_fx_log_32 *self, uint32_t listener_va) {
    uint32_t i;
    if (self == NULL || listener_va == 0u) {
        return;
    }
    for (i = 0u; i < 32u; ++i) {
        if (self->listeners_va[i] == 0u) {
            self->listeners_va[i] = listener_va;
            return;
        }
    }
}

void rome2_l80_fx_log_remove_listener(rome2_fx_log_32 *self, uint32_t listener_va) {
    uint32_t i;
    if (self == NULL || listener_va == 0u) {
        return;
    }
    for (i = 0u; i < 32u; ++i) {
        if (self->listeners_va[i] == listener_va) {
            self->listeners_va[i] = 0u;
        }
    }
}

void rome2_l80_fx_log_message(
    rome2_l80_fx_ctx *ctx,
    const rome2_fx_log_32 *self,
    const char *msg,
    int32_t level) {
    uint32_t i;
    if (self == NULL) {
        return;
    }
    for (i = 0u; i < 32u; ++i) {
        if (self->listeners_va[i] != 0u) {
            if (ctx != NULL) {
                ++ctx->log_dispatches;
                if (ctx->on_log_message != NULL) {
                    ctx->on_log_message(ctx, self->listeners_va[i], msg != NULL ? msg : "", level);
                }
            }
        }
    }
}

/* 0x10ed4970, 0x10ed4c90, 0x10ed49f0, 0x10ed3de0, 0x10ed4cd0 */
rome2_fx_log_entry_32 *rome2_l80_log_entry_ctor(
    rome2_fx_log_entry_32 *self,
    uint32_t log_va,
    int32_t level) {
    if (self != NULL) {
        (void)rome2_l80_log_stream_ctor(&self->stream);
        self->log_va = log_va;
        self->level = level;
    }
    return self;
}

rome2_fx_log_entry_32 *rome2_l80_log_entry_create(
    rome2_fx_log_entry_32 *out_entry,
    uint32_t log_va,
    int32_t level) {
    return rome2_l80_log_entry_ctor(out_entry, log_va, level);
}

void rome2_l80_log_entry_dtor(rome2_l80_fx_ctx *ctx, rome2_fx_log_entry_32 *self) {
    const rome2_fx_log_32 *logp;
    if (self == NULL) {
        return;
    }
    logp = (const rome2_fx_log_32 *)rome2_l80_const_ptr(ctx, self->log_va, sizeof(*logp));
    if (logp != NULL) {
        rome2_l80_fx_log_message(ctx, logp, self->stream.buf, self->level);
    }
    rome2_l80_log_stream_dtor(&self->stream);
}

rome2_fx_log_entry_32 *rome2_l80_log_entry_assign(
    rome2_fx_log_entry_32 *self,
    const rome2_fx_log_entry_32 *other) {
    if (self != NULL && other != NULL) {
        *self = *other;
    }
    return self;
}

rome2_fx_log_stream_32 *rome2_l80_log_entry_get_stream(
    rome2_fx_log_entry_32 *self,
    uint32_t tabs) {
    uint32_t i;
    if (self == NULL) {
        return NULL;
    }
    for (i = 0u; i < tabs; ++i) {
        rome2_l80_log_stream_append_len(&self->stream, "    ", 4u);
    }
    return &self->stream;
}

/* 0x10eec0a0, 0x10eec0d0, 0x10a2a680, 0x10eec190, 0x10a2a440, 0x10aab590 */
uint32_t rome2_l80_log_manager_ctor(rome2_l80_fx_ctx *ctx, uint32_t self_va) {
    rome2_fx_log_manager_32 *mgr = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        ctx, self_va, sizeof(*mgr));
    if (mgr != NULL) {
        mgr->vtable_va = ROME2_FX_VTABLE_LOG_MANAGER;
        (void)rome2_l80_fx_log_ctor(&mgr->log);
        mgr->max_log_level = 6;
        mgr->tab_level = 0u;
    }
    if (ctx != NULL) {
        ctx->log_manager_singleton_va = self_va;
    }
    return self_va;
}

void rome2_l80_log_manager_dtor(rome2_l80_fx_ctx *ctx, uint32_t self_va) {
    rome2_fx_log_manager_32 *mgr = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        ctx, self_va, sizeof(*mgr));
    if (mgr != NULL) {
        mgr->vtable_va = ROME2_FX_VTABLE_LOG_MANAGER;
        rome2_l80_fx_log_dtor(&mgr->log);
        mgr->vtable_va = ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER;
    }
    if (ctx != NULL) {
        ctx->log_manager_singleton_va = 0u;
    }
}

int32_t rome2_l80_log_manager_get_max_level(const rome2_fx_log_manager_32 *self) {
    return (self != NULL) ? self->max_log_level : 0;
}

void rome2_l80_log_manager_set_max_level(rome2_fx_log_manager_32 *self, int32_t level) {
    if (self != NULL) {
        self->max_log_level = level;
    }
}

uint32_t rome2_l80_log_manager_get_tab_level(const rome2_fx_log_manager_32 *self) {
    return (self != NULL) ? self->tab_level : 0u;
}

void rome2_l80_log_manager_set_tab_level(rome2_fx_log_manager_32 *self, uint32_t tabs) {
    if (self != NULL) {
        self->tab_level = tabs;
    }
}

/* 0x11688295, 0x1168974d, 0x1168889f, 0x1168c0fc, 0x100de0e0 */
int32_t rome2_l80_common_vsprintf(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    va_list ap) {
    int n;
    if (fmt == NULL || (cap != 0u && dst == NULL)) {
        if (ctx != NULL) {
            ctx->last_errno = 0x16;
        }
        return -1;
    }
#pragma warning(push)
#pragma warning(disable:4774)
    n = vsnprintf(dst, (size_t)cap, fmt, ap);
#pragma warning(pop)
    if (n < 0) {
        return -1;
    }
    if (cap != 0u && (uint32_t)n >= cap) {
        return -2;
    }
    return n;
}

int32_t rome2_l80_common_vsprintf_s(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    va_list ap) {
    int32_t rc;
    if (fmt == NULL || dst == NULL || cap == 0u) {
        if (ctx != NULL) {
            ctx->last_errno = 0x16;
        }
        return -1;
    }
    rc = rome2_l80_common_vsprintf(ctx, dst, cap, fmt, ap);
    if (rc < 0) {
        dst[0] = '\0';
        if (rc == -2 && ctx != NULL) {
            ctx->last_errno = 0x22;
        }
        return -1;
    }
    return rc;
}

int32_t rome2_l80_stdio_common_vsprintf_s(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    va_list ap) {
    return rome2_l80_common_vsprintf_s(ctx, dst, cap, fmt, ap);
}

int32_t rome2_l80_crt_sprintf_s(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    ...) {
    va_list ap;
    int32_t rc;
    va_start(ap, fmt);
    rc = rome2_l80_stdio_common_vsprintf_s(ctx, dst, cap, fmt, ap);
    va_end(ap);
    return (rc < 0) ? -1 : rc;
}
