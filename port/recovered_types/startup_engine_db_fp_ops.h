#ifndef ROME2_STARTUP_ENGINE_DB_FP_OPS_H
#define ROME2_STARTUP_ENGINE_DB_FP_OPS_H

#include <stdint.h>

#include "guest32_layouts.h"
#include "startup_fopen_fread_init_ops.h"

/*
 * Layer 67 Partition 8 recovery:
 * 24 engine DB / EMPIRE_APP teardown / Warscape open_handler / la_gioconda UI /
 * CRT x87+SSE2 floating-point control-word functions (0x100d2c80..0x116adaed).
 */

#define ROME2_L67_OPEN_HANDLER_MAX_LOG 16u
#define ROME2_L67_HASH_SALT 0x4a545eedu
#define ROME2_L67_FP_INVALID_BITS 0xfcf0fce0u

typedef struct rome2_l67_fp_env {
    int32_t has_sse2_1212564c;
    uint32_t sse2_enabled_12126c3c;
    uint32_t dazflush_119ec140;
    uint16_t x87_cw;
    uint32_t mxcsr;
    int32_t crt_errno;
    int invalid_param_calls;
} rome2_l67_fp_env;

typedef struct rome2_l67_db_node54 {
    uint32_t id;
    struct rome2_l67_db_node54 *prev;
    struct rome2_l67_db_node54 *next;
    uint32_t pool_tag;
    uint32_t aux;
    int cleaned_ref;
    int released_slab;
} rome2_l67_db_node54;

typedef struct rome2_l67_db_pool_bucket {
    uint32_t head_id;
    rome2_l67_db_node54 *free_head;
} rome2_l67_db_pool_bucket;

typedef struct rome2_l67_db_hash_table {
    uint32_t init_flags_119e1254;
    uint32_t reserved_119e1258;
    uint32_t bucket_count_119e125c;
    rome2_l67_db_pool_bucket *buckets;
    int tls_initialized;
    int list_cleared;
    int atexit_registered;
} rome2_l67_db_hash_table;

typedef struct rome2_l67_manager_state {
    uint32_t vptr;
    void *controller_ctx;
    uint32_t ui_slot_08;
    uint32_t ui_slot_0c;
    uint32_t ui_slot_10;
    uint32_t gio_14;
    uint32_t gio_1c;
    uint32_t gio_20;
    uint32_t gio_24;
    uint32_t gio_28;
    uint32_t gio_2c;
    uint8_t flag_c9;
    uint8_t flag_ca;
    uint8_t flag_1b8;
    int32_t spin_1b0;
    uint32_t field_1b4;
    uint32_t desc_count_18;
    rome2_startup_db_desc_entry28_32 *desc_vec_1c;
    uint32_t desc_cap;
    rome2_l67_db_node54 *list_head;
    rome2_l67_db_node54 *sub_list_head;
    uint32_t *ctrl_vec_44;
    uint32_t ctrl_count_40;
    uint32_t obj_68;
    uint32_t obj_6c;
    uint32_t opt_14_target;
    uint32_t warscape_ready;
    uint32_t warscape_arg;
    float progress_marks[4];
    size_t progress_count;
    char trace_log[ROME2_L67_OPEN_HANDLER_MAX_LOG][40];
    size_t trace_count;
    int controllers_created;
    int views_created;
    int uis_created;
    int opened_ok;
    int sub_destructor_calls;
} rome2_l67_manager_state;

typedef struct rome2_l67_empire_teardown_env {
    uint32_t vptr_00;
    int32_t d2c80_cold_flag;
    uint32_t d2c80_vptr;
    int cold_branch_calls;
    uint32_t crash_rep_slot04;
    uint32_t crash_rep_slot08;
    int log_closed;
    int stats_closed;
    int handler_destroy_calls;
    uint32_t vec_217_count;
    uint32_t buf_218_ptr;
    uint32_t buf_21c_ptr;
    int freed_218;
    int freed_21c;
    uint32_t global_119f3140;
    uint32_t spi_param_119f3854;
    int spi_restored;
    uint32_t handle_202;
    int handle_closed;
    int sym_released_count;
} rome2_l67_empire_teardown_env;

/* 0x100d2c80 */
int rome2_l67_d2c80_teardown(rome2_l67_empire_teardown_env *env);

/* 0x100e0650 */
void rome2_l67_empire_app_dtor_core(rome2_l67_empire_teardown_env *env);

/* 0x11698a7c */
void rome2_l67_set_sse2_enable(rome2_l67_fp_env *env, int32_t enable);

/* 0x1169b349 */
uint32_t rome2_l67_hw_cw(uint32_t abstract_cw);

/* 0x1169aec3 */
uint32_t rome2_l67_hw_cw_sse2(uint32_t abstract_cw);

/* 0x116adaed */
void rome2_l67_set_fpsr_sse2(rome2_l67_fp_env *env, uint32_t raw_mxcsr);

/* 0x1169b048 */
uint32_t rome2_l67_control87(rome2_l67_fp_env *env, uint32_t new_val, uint32_t mask);

/* 0x1169b482 */
int32_t rome2_l67_controlfp_s(
    rome2_l67_fp_env *env, uint32_t *current_state, uint32_t new_val, uint32_t mask);

/* 0x101150a0 */
uint32_t rome2_l67_init_fp_precision_control(rome2_l67_fp_env *env);

/* 0x112bb3f0 */
rome2_l67_db_hash_table *rome2_l67_db_bucket_singleton_get(rome2_l67_db_hash_table *tbl);

/* 0x106d1a90 */
void rome2_l67_refcounted_slab_list_clear(rome2_l67_db_node54 **head_slot);

/* 0x106d2e80 */
void rome2_l67_hash_map_end(
    const rome2_l67_db_hash_table *tbl, rome2_startup_db_hash_iter12_32 *out_iter);

/* 0x106d2f20 */
int rome2_l67_hash_map_find(
    const rome2_l67_db_hash_table *tbl, uint32_t key, rome2_startup_db_hash_iter12_32 *out_iter);

/* 0x106d2a40 */
void rome2_l67_hash_bucket_unlink_push(
    const rome2_l67_db_hash_table *tbl, rome2_l67_db_node54 *node, uint32_t key);

/* 0x10cad6e0 */
int rome2_l67_desc_vec_push_back(
    rome2_startup_db_desc_entry28_32 **vec_ptr, uint32_t *count, uint32_t *cap,
    const rome2_startup_db_desc_entry28_32 *elem);

/* 0x10ca3740 */
void rome2_l67_desc_list_clear(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl);

/* 0x10ca37d0 */
void rome2_l67_sub_desc_list_clear(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl);

/* 0x10ca3810 */
void rome2_l67_open_handler_sub_reset(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl);

/* 0x10c84e40 */
void rome2_l67_optional_controller_reset(rome2_l67_manager_state *mgr);

/* 0x10c8f760 */
void rome2_l67_init_gioconda_cursor_a(rome2_l67_manager_state *mgr);

/* 0x10c8f8c0 */
void rome2_l67_init_gioconda_cursor_b(rome2_l67_manager_state *mgr);

/* 0x10cb8f90 */
void rome2_l67_query_gioconda_slots(rome2_l67_manager_state *mgr);

/* 0x100d6db0 */
void rome2_l67_manager_teardown(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl);

/* 0x100d81c0 */
void rome2_l67_warscape_open_handler(rome2_l67_manager_state *mgr, rome2_l67_fp_env *fp_env);

#endif
