#ifndef ROME2_FACEFX_NAME_AVL_TABLE_OPS_H
#define ROME2_FACEFX_NAME_AVL_TABLE_OPS_H

#include "facefx_alloc_singleton_log_ops.h"
#include "guest32_layouts.h"

#include <stdint.h>

enum rome2_l81_vtable_va {
    ROME2_FX_VTABLE_NAME_ENTRY = 0x1183b970u,
    ROME2_FX_VTABLE_AVL_STRING_NODE = 0x1183b99cu,
    ROME2_FX_VTABLE_AVL_BUCKET = 0x1183b9c0u,
    ROME2_FX_VTABLE_OBJECT_HELPER = 0x1183ce20u,
    ROME2_FX_VTABLE_REF_OBJECT = 0x1183de70u
};

enum rome2_l81_table_const {
    ROME2_FX_NAME_BUCKET_COUNT = 0x1000u,
    ROME2_FX_NAME_TABLE_HEADER_BYTES = 0x14u,
    ROME2_FX_NAME_TABLE_BYTES = 0xc014u,
    ROME2_FX_NAME_MAX_LEN = 0x200u
};

typedef struct rome2_l81_name_iter {
    uint32_t table_va;
    uint32_t bucket_count;
    int32_t bucket_index;
    uint32_t bucket_va;
    uint32_t node_va;
} rome2_l81_name_iter;

typedef struct rome2_l81_name_stats {
    uint32_t num_names;
    uint32_t num_collisions;
    uint32_t num_added;
    uint32_t num_probes;
    uint32_t bucket_count;
    uint32_t non_empty_buckets;
    uint32_t min_bucket_len;
    uint32_t max_bucket_len;
    uint32_t avg_bucket_len;
    uint32_t mem_bytes;
} rome2_l81_name_stats;

typedef struct rome2_l81_fx_name_ctx {
    rome2_l80_fx_ctx *fx;
    uint32_t name_table_va;         /* 0x11fadb78 */
    uint32_t null_name_entry_va;    /* 0x11fadb7c */
    uint32_t class_desc_array_va;   /* 0x11fadba0 */
    uint32_t fx_object_class_va;    /* 0x11fadba4 */
    uint32_t fx_ref_object_class_va;/* 0x11fb5920 */
    uint32_t fx_name_entry_class_va;/* 0x11fadb74 */
} rome2_l81_fx_name_ctx;

void rome2_l81_ctx_init(rome2_l81_fx_name_ctx *ctx, rome2_l80_fx_ctx *fx_ctx);

/* FxString helpers (0x10411670, 0x10eddab0, 0x10eddb40) */
uint32_t rome2_l81_fx_string_ctor_slice(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *src,
    int32_t len);
const char *rome2_l81_fx_string_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    uint8_t mut_materialize);
void rome2_l81_fx_string_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t self_va);
uint8_t rome2_l81_fx_string_equals_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *rhs);
uint8_t rome2_l81_fx_string_not_equals_cstr(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *rhs);

/* AVL bucket & string node ops (0x10eddc90, 0x10eddfb0, 0x10ede150, 0x10edfb00, 0x10edfc40, 0x10edff50, 0x10ee19c0, 0x10ee1a20) */
uint32_t rome2_l81_avl_string_node_ctor(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    uint32_t parent_va,
    uint32_t key_str_va,
    uint32_t value_va);
uint32_t rome2_l81_avl_bucket_ctor(rome2_l81_fx_name_ctx *ctx, uint32_t bucket_va);
void rome2_l81_avl_bucket_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t bucket_va);
void rome2_l81_avl_rotate_left(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    uint32_t parent_slot_node_va,
    uint32_t is_right_child);
void rome2_l81_avl_rotate_right(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    uint32_t parent_slot_node_va,
    uint32_t is_right_child);
uint32_t rome2_l81_avl_find(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    const char *key);
uint32_t rome2_l81_avl_insert(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    const char *key,
    uint32_t value_va,
    uint8_t *inserted_out);
uint8_t rome2_l81_avl_remove_key(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t bucket_va,
    const char *key);

/* Hash name table ops (0x10eddfd0, 0x10edea00, 0x10edf5f0, 0x10edf9f0, 0x10ee0140) */
uint32_t rome2_l81_djb2_hash(const char *s);
void rome2_l81_name_table_dtor(rome2_l81_fx_name_ctx *ctx, uint32_t table_va);
rome2_l81_name_iter *rome2_l81_name_table_find(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *out_iter,
    const char *key);
rome2_l81_name_iter *rome2_l81_name_table_insert(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *out_iter,
    const char *key,
    uint32_t entry_va);
uint8_t rome2_l81_name_table_remove(rome2_l81_fx_name_ctx *ctx, const char *key);
rome2_l81_name_iter *rome2_l81_name_iter_advance(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_iter *iter);

/* FxName lifecycle & ops (0x10ed5dd0, 0x10ed60d0, 0x10edde70..0x10ee1a80) */
void rome2_l81_fx_name_startup(rome2_l81_fx_name_ctx *ctx);
void rome2_l81_fx_name_shutdown(rome2_l81_fx_name_ctx *ctx);
void rome2_l81_fx_name_dump_to_log(rome2_l81_fx_name_ctx *ctx);
void rome2_l81_fx_name_get_stats(
    rome2_l81_fx_name_ctx *ctx,
    rome2_l81_name_stats *out_stats);
uint8_t rome2_l81_fx_name_exists(rome2_l81_fx_name_ctx *ctx, const char *name);

rome2_fx_name_32 *rome2_l81_fx_name_ctor_default(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self);
rome2_fx_name_32 *rome2_l81_fx_name_ctor_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *name);
rome2_fx_name_32 *rome2_l81_fx_name_ctor_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other);
void rome2_l81_fx_name_dtor(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self);
void rome2_l81_fx_name_safe_remove_ref(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self);
void rome2_l81_fx_name_add_to_table(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name);
void rome2_l81_fx_name_set_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *raw_name);
rome2_fx_name_32 *rome2_l81_fx_name_assign_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other);
rome2_fx_name_32 *rome2_l81_fx_name_assign_move(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other);

uint8_t rome2_l81_fx_name_eq_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other);
uint8_t rome2_l81_fx_name_ne_name(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const rome2_fx_name_32 *other);
uint8_t rome2_l81_fx_name_eq_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *rhs);
uint8_t rome2_l81_fx_name_ne_cstr(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    const char *rhs);
uint8_t rome2_l81_fx_name_lt(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other);
uint8_t rome2_l81_fx_name_gt(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_name_32 *self,
    rome2_fx_name_32 *other);
const char *rome2_l81_fx_name_get_cstr(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self);
uint32_t rome2_l81_fx_name_get_string_va(rome2_l81_fx_name_ctx *ctx, rome2_fx_name_32 *self);

/* FxClientEvent ops (0x10ed56a0, 0x10ed57f0, 0x10ed5840, 0x10ed7d70) */
rome2_fx_client_event_32 *rome2_l81_fx_client_event_ctor_full(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_name_32 *group_name,
    const rome2_fx_name_32 *anim_name,
    float start_time_offset,
    float magnitude_scale,
    float blend_in_time,
    float blend_out_time,
    float duration_scale,
    uint8_t should_persist_values,
    uint32_t event_id,
    const rome2_fx_name_32 *custom_payload);
rome2_fx_client_event_32 *rome2_l81_fx_client_event_ctor_copy(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other);
rome2_fx_client_event_32 *rome2_l81_fx_client_event_assign(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self,
    const rome2_fx_client_event_32 *other);
void rome2_l81_fx_client_event_dtor(
    rome2_l81_fx_name_ctx *ctx,
    rome2_fx_client_event_32 *self);

/* FxClass & FxObject / FxRefObject static class init (0x10ef2a10, 0x10ef3160, 0x10ef31c0, 0x10f06ad0, 0x10f06b40) */
uint32_t rome2_l81_fx_object_helper_bind(uint32_t *vtable_slot, uint32_t self_va);
uint32_t rome2_l81_fx_ref_object_ctor(rome2_l81_fx_name_ctx *ctx, uint32_t self_va);
uint32_t rome2_l81_fx_class_ctor(
    rome2_l81_fx_name_ctx *ctx,
    uint32_t self_va,
    const char *name,
    uint16_t version,
    uint32_t base_class_va,
    uint32_t size,
    uint32_t ctor_fn_va);
uint32_t rome2_l81_fx_object_static_class_init(rome2_l81_fx_name_ctx *ctx);
uint32_t rome2_l81_fx_ref_object_static_class_init(rome2_l81_fx_name_ctx *ctx);

#endif
