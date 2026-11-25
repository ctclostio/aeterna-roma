#ifndef ROME2_FACEFX_ALLOC_SINGLETON_LOG_OPS_H
#define ROME2_FACEFX_ALLOC_SINGLETON_LOG_OPS_H

#include "guest32_layouts.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

enum rome2_fx_vtable_va {
    ROME2_FX_VTABLE_LOG_LISTENER = 0x1173fb24u,
    ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER = 0x1183a4d0u,
    ROME2_FX_VTABLE_SINGLETON_RESOURCE_MANAGER = 0x1183a794u,
    ROME2_FX_VTABLE_LOG_MANAGER = 0x1183c7a0u
};

typedef struct rome2_fx_mount_unmount_result_32 {
    int32_t mount_err;
    int32_t unmount_err;
} rome2_fx_mount_unmount_result_32;

typedef struct rome2_l80_fx_slab_bucket {
    uint32_t block_size;
    uint32_t slab_base_va;
    uint8_t next_free_idx;
    uint8_t free_count;
    uint8_t capacity;
} rome2_l80_fx_slab_bucket;

typedef struct rome2_l80_fx_ctx {
    uint8_t *arena_bytes;
    uint32_t arena_base_va;
    uint32_t arena_size;
    uint32_t heap_cursor;

    uint8_t slab_enabled; /* 0x11fadb54 */
    rome2_l80_fx_slab_bucket slabs[16]; /* 0x11fada90 */
    uint32_t (*custom_alloc)(struct rome2_l80_fx_ctx *ctx, uint32_t bytes);
    void (*custom_free)(struct rome2_l80_fx_ctx *ctx, uint32_t ptr_va, uint32_t bytes);

    uint32_t log_manager_singleton_va;      /* 0x119f3890 */
    uint32_t resource_manager_singleton_va; /* 0x11bd14ac */

    void (*on_log_message)(
        struct rome2_l80_fx_ctx *ctx,
        uint32_t listener_va,
        const char *msg,
        int32_t level);
    int32_t last_errno;
    uint32_t alloc_calls;
    uint32_t free_calls;
    uint32_t log_dispatches;
} rome2_l80_fx_ctx;

void rome2_l80_ctx_init(
    rome2_l80_fx_ctx *ctx,
    uint8_t *arena_bytes,
    uint32_t base_va,
    uint32_t arena_size,
    uint32_t heap_start_va);
void *rome2_l80_mut_ptr(const rome2_l80_fx_ctx *ctx, uint32_t va, uint32_t bytes);
const void *rome2_l80_const_ptr(const rome2_l80_fx_ctx *ctx, uint32_t va, uint32_t bytes);

/* Memory allocation & policy (0x10ed3d30, 0x10ed3d60, 0x10ed3d90, 0x10ed3e20, 0x10ed3f40, 0x10ed4030) */
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_ctor_default(
    rome2_fx_memory_allocation_policy_32 *self);
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_ctor_full(
    rome2_fx_memory_allocation_policy_32 *self,
    int32_t alloc_type,
    uint8_t use_default_hooks,
    uint32_t alloc_fn_va,
    uint32_t alloc_dbg_fn_va,
    uint32_t free_fn_va);
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_ctor_copy(
    rome2_fx_memory_allocation_policy_32 *self,
    const rome2_fx_memory_allocation_policy_32 *other);
rome2_fx_memory_allocation_policy_32 *rome2_l80_alloc_policy_assign(
    rome2_fx_memory_allocation_policy_32 *self,
    const rome2_fx_memory_allocation_policy_32 *other);
uint32_t rome2_l80_fx_allocate(rome2_l80_fx_ctx *ctx, uint32_t bytes);
void rome2_l80_fx_free(rome2_l80_fx_ctx *ctx, uint32_t ptr_va, uint32_t bytes);

/* Singletons (0x10ed3cd0, 0x10ed3ce0, 0x10ed3dc0, 0x10ed48c0, 0x10ed5660, 0x10ed5670, 0x10ed57d0, 0x10ed7890) */
uint32_t rome2_l80_singleton_log_mgr_ctor(rome2_l80_fx_ctx *ctx, uint32_t self_va);
uint32_t rome2_l80_singleton_log_mgr_copy(uint32_t *vtable_slot, uint32_t self_va);
void rome2_l80_singleton_log_mgr_dtor(rome2_l80_fx_ctx *ctx, uint32_t self_va);
uint32_t rome2_l80_singleton_log_mgr_get(const rome2_l80_fx_ctx *ctx);
uint32_t rome2_l80_singleton_res_mgr_ctor(rome2_l80_fx_ctx *ctx, uint32_t self_va);
uint32_t rome2_l80_singleton_res_mgr_copy(uint32_t *vtable_slot, uint32_t self_va);
void rome2_l80_singleton_res_mgr_dtor(rome2_l80_fx_ctx *ctx, uint32_t self_va);
uint32_t rome2_l80_singleton_res_mgr_get(const rome2_l80_fx_ctx *ctx);

/* Result types, FxNoBase, FxSafeBool (0x1039a190, 0x107e7830, 0x10ed5680, 0x10ed5810, 0x10ed5830, 0x10ed6100..0x10ed6150, 0x10ed7bc0, 0x10ed7be0) */
void *rome2_l80_fx_nobase_assign(void *self, const void *other);
rome2_fx_mount_result_32 *rome2_l80_mount_result_ctor(rome2_fx_mount_result_32 *self, int32_t err);
int32_t rome2_l80_mount_result_bool(const rome2_fx_mount_result_32 *self);
uint32_t rome2_l80_safe_bool_mount_result(const rome2_fx_mount_result_32 *self);
uint32_t rome2_l80_safe_bool_mount_unmount(const rome2_fx_mount_unmount_result_32 *self);
uint32_t rome2_l80_safe_bool_play_result(const int32_t *play_status);
rome2_fx_actor_load_result_32 *rome2_l80_actor_load_result_ctor(rome2_fx_actor_load_result_32 *self);
rome2_fx_actor_load_result_32 *rome2_l80_actor_load_result_assign_move(
    rome2_fx_actor_load_result_32 *self,
    const rome2_fx_actor_load_result_32 *other);
rome2_fx_actor_load_result_32 *rome2_l80_actor_load_result_assign_copy(
    rome2_fx_actor_load_result_32 *self,
    const rome2_fx_actor_load_result_32 *other);
int32_t rome2_l80_actor_load_result_bool(const rome2_fx_actor_load_result_32 *self);
uint32_t rome2_l80_safe_bool_actor_load_result(const rome2_fx_actor_load_result_32 *self);

/* Logging (0x100e07a0, 0x100e81a0, 0x10a2a440, 0x10a2a680, 0x10aab590, 0x10ed3d10, 0x10ed3d20, 0x10ed3de0, 0x10ed3e00, 0x10ed4950..0x10ed4db0, 0x10eec0a0..0x10eec190) */
uint32_t rome2_l80_log_listener_ctor(uint32_t *vtable_slot, uint32_t self_va);
void rome2_l80_log_listener_dtor(uint32_t *vtable_slot);
rome2_fx_log_stream_32 *rome2_l80_log_stream_ctor(rome2_fx_log_stream_32 *self);
void rome2_l80_log_stream_dtor(rome2_fx_log_stream_32 *self);
rome2_fx_log_stream_32 *rome2_l80_log_stream_assign(
    rome2_fx_log_stream_32 *self,
    const rome2_fx_log_stream_32 *other);
const char *rome2_l80_log_stream_get_cstr(const rome2_fx_log_stream_32 *self);
void rome2_l80_log_stream_append_len(rome2_fx_log_stream_32 *self, const char *s, uint32_t len);
rome2_fx_log_stream_32 *rome2_l80_log_stream_push_cstr(rome2_fx_log_stream_32 *self, const char *s);
rome2_fx_log_stream_32 *rome2_l80_log_stream_push_int(rome2_fx_log_stream_32 *self, int32_t v);
rome2_fx_log_stream_32 *rome2_l80_log_stream_push_float(rome2_fx_log_stream_32 *self, float v);
rome2_fx_log_stream_32 *rome2_l80_log_stream_push_ptr(rome2_fx_log_stream_32 *self, uint32_t ptr_va);

rome2_fx_log_32 *rome2_l80_fx_log_ctor(rome2_fx_log_32 *self);
void rome2_l80_fx_log_dtor(rome2_fx_log_32 *self);
void rome2_l80_fx_log_add_listener(rome2_fx_log_32 *self, uint32_t listener_va);
void rome2_l80_fx_log_remove_listener(rome2_fx_log_32 *self, uint32_t listener_va);
void rome2_l80_fx_log_message(
    rome2_l80_fx_ctx *ctx,
    const rome2_fx_log_32 *self,
    const char *msg,
    int32_t level);

rome2_fx_log_entry_32 *rome2_l80_log_entry_ctor(
    rome2_fx_log_entry_32 *self,
    uint32_t log_va,
    int32_t level);
rome2_fx_log_entry_32 *rome2_l80_log_entry_create(
    rome2_fx_log_entry_32 *out_entry,
    uint32_t log_va,
    int32_t level);
void rome2_l80_log_entry_dtor(rome2_l80_fx_ctx *ctx, rome2_fx_log_entry_32 *self);
rome2_fx_log_entry_32 *rome2_l80_log_entry_assign(
    rome2_fx_log_entry_32 *self,
    const rome2_fx_log_entry_32 *other);
rome2_fx_log_stream_32 *rome2_l80_log_entry_get_stream(
    rome2_fx_log_entry_32 *self,
    uint32_t tabs);

uint32_t rome2_l80_log_manager_ctor(rome2_l80_fx_ctx *ctx, uint32_t self_va);
void rome2_l80_log_manager_dtor(rome2_l80_fx_ctx *ctx, uint32_t self_va);
int32_t rome2_l80_log_manager_get_max_level(const rome2_fx_log_manager_32 *self);
void rome2_l80_log_manager_set_max_level(rome2_fx_log_manager_32 *self, int32_t level);
uint32_t rome2_l80_log_manager_get_tab_level(const rome2_fx_log_manager_32 *self);
void rome2_l80_log_manager_set_tab_level(rome2_fx_log_manager_32 *self, uint32_t tabs);

/* CRT vsprintf_s helpers (0x100de0e0, 0x11688295, 0x1168889f, 0x1168974d, 0x1168c0fc) */
int32_t rome2_l80_common_vsprintf(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    va_list ap);
int32_t rome2_l80_common_vsprintf_s(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    va_list ap);
int32_t rome2_l80_stdio_common_vsprintf_s(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    va_list ap);
int32_t rome2_l80_crt_sprintf_s(
    rome2_l80_fx_ctx *ctx,
    char *dst,
    uint32_t cap,
    const char *fmt,
    ...);

#endif
