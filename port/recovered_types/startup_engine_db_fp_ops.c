#include "startup_engine_db_fp_ops.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t l67_x87_cw_to_abstract(uint16_t cw) {
    uint32_t res = ((uint32_t)(cw & 1u)) << 4u;
    uint16_t rc = (uint16_t)(cw & 0x0c00u);
    uint16_t pc = (uint16_t)(cw & 0x0300u);

    if ((cw & 4u) != 0u) {
        res |= 8u;
    }
    if ((cw & 8u) != 0u) {
        res |= 4u;
    }
    if ((cw & 0x10u) != 0u) {
        res |= 2u;
    }
    if ((cw & 0x20u) != 0u) {
        res |= 1u;
    }
    if ((cw & 2u) != 0u) {
        res |= 0x80000u;
    }
    if (rc == 0x400u) {
        res |= 0x100u;
    } else if (rc == 0x800u) {
        res |= 0x200u;
    } else if (rc == 0x0c00u) {
        res |= 0x300u;
    }
    if (pc == 0u) {
        res |= 0x20000u;
    } else if (pc == 0x200u) {
        res |= 0x10000u;
    }
    if ((cw & 0x1000u) != 0u) {
        res |= 0x40000u;
    }
    return res;
}

static uint32_t l67_mxcsr_to_abstract(uint32_t mxcsr) {
    uint32_t res = (mxcsr >> 3u) & 0x10u;
    uint32_t rc = mxcsr & 0x6000u;
    uint32_t daz_ftz = mxcsr & 0x8040u;

    if ((mxcsr & 0x200u) != 0u) {
        res |= 8u;
    }
    if ((mxcsr & 0x400u) != 0u) {
        res |= 4u;
    }
    if ((mxcsr & 0x800u) != 0u) {
        res |= 2u;
    }
    if ((mxcsr & 0x1000u) != 0u) {
        res |= 1u;
    }
    if ((mxcsr & 0x100u) != 0u) {
        res |= 0x80000u;
    }
    if (rc == 0x2000u) {
        res |= 0x100u;
    } else if (rc == 0x4000u) {
        res |= 0x200u;
    } else if (rc == 0x6000u) {
        res |= 0x300u;
    }
    if (daz_ftz == 0x40u) {
        res |= 0x2000000u;
    } else if (daz_ftz == 0x8000u) {
        res |= 0x3000000u;
    } else if (daz_ftz == 0x8040u) {
        res |= 0x1000000u;
    }
    return res;
}

static void l67_record_trace(rome2_l67_manager_state *mgr, const char *msg) {
    if (mgr != NULL && msg != NULL && mgr->trace_count < ROME2_L67_OPEN_HANDLER_MAX_LOG) {
        snprintf(mgr->trace_log[mgr->trace_count], sizeof(mgr->trace_log[0]), "%s", msg);
        mgr->trace_count++;
    }
}

int rome2_l67_d2c80_teardown(rome2_l67_empire_teardown_env *env) {
    if (env == NULL) {
        return 0;
    }
    env->d2c80_vptr = 0x1173dc18u;
    if (env->d2c80_cold_flag == 0) {
        return 0;
    }
    env->cold_branch_calls++;
    return 1;
}

void rome2_l67_empire_app_dtor_core(rome2_l67_empire_teardown_env *env) {
    if (env == NULL) {
        return;
    }
    env->vptr_00 = 0x1173f2f4u;
    env->sym_released_count++;
    if (env->crash_rep_slot04 != 0u) {
        env->crash_rep_slot04 = 0u;
    }
    if (env->crash_rep_slot08 != 0u) {
        env->crash_rep_slot08 = 0u;
    }
    env->log_closed = 1;
    env->stats_closed = 1;
    env->handler_destroy_calls += (int)env->vec_217_count;
    env->vec_217_count = 0u;
    env->global_119f3140 = 0u;
    (void)rome2_l67_d2c80_teardown(env);
    if (env->buf_21c_ptr != 0u) {
        env->freed_21c = 1;
    }
    if (env->buf_218_ptr != 0u) {
        env->freed_218 = 1;
    }
    env->vptr_00 = 0x1173f208u;
    env->spi_restored = 1;
    if (env->handle_202 != 0u) {
        env->handle_closed = 1;
    }
    env->vptr_00 = 0x1173f200u;
}

void rome2_l67_set_sse2_enable(rome2_l67_fp_env *env, int32_t enable) {
    if (env == NULL) {
        return;
    }
    env->sse2_enabled_12126c3c = (enable != 0 && env->has_sse2_1212564c > 0) ? 1u : 0u;
}

uint32_t rome2_l67_hw_cw(uint32_t abstract_cw) {
    uint32_t hw = (abstract_cw >> 4u) & 1u;
    uint32_t rc = abstract_cw & 0x300u;
    uint32_t pc = abstract_cw & 0x30000u;

    if ((abstract_cw & 8u) != 0u) {
        hw |= 4u;
    }
    if ((abstract_cw & 4u) != 0u) {
        hw |= 8u;
    }
    if ((abstract_cw & 2u) != 0u) {
        hw |= 0x10u;
    }
    if ((abstract_cw & 1u) != 0u) {
        hw |= 0x20u;
    }
    if ((abstract_cw & 0x80000u) != 0u) {
        hw |= 2u;
    }
    if (rc == 0x100u) {
        hw |= 0x400u;
    } else if (rc == 0x200u) {
        hw |= 0x800u;
    } else if (rc == 0x300u) {
        hw |= 0x0c00u;
    }
    if (pc == 0u) {
        hw |= 0x300u;
    } else if (pc == 0x10000u) {
        hw |= 0x200u;
    }
    if ((abstract_cw & 0x40000u) != 0u) {
        hw |= 0x1000u;
    }
    return hw;
}

uint32_t rome2_l67_hw_cw_sse2(uint32_t abstract_cw) {
    uint32_t mx = (abstract_cw & 0x10u) << 3u;
    uint32_t rc = abstract_cw & 0x300u;
    uint32_t ftz = abstract_cw & 0x3000000u;

    if ((abstract_cw & 8u) != 0u) {
        mx |= 0x200u;
    }
    if ((abstract_cw & 4u) != 0u) {
        mx |= 0x400u;
    }
    if ((abstract_cw & 2u) != 0u) {
        mx |= 0x800u;
    }
    if ((abstract_cw & 1u) != 0u) {
        mx |= 0x1000u;
    }
    if ((abstract_cw & 0x80000u) != 0u) {
        mx |= 0x100u;
    }
    if (rc == 0x100u) {
        mx |= 0x2000u;
    } else if (rc == 0x200u) {
        mx |= 0x4000u;
    } else if (rc == 0x300u) {
        mx |= 0x6000u;
    }
    if (ftz == 0x1000000u) {
        mx |= 0x8040u;
    } else if (ftz == 0x2000000u) {
        mx |= 0x40u;
    } else if (ftz == 0x3000000u) {
        mx |= 0x8000u;
    }
    return mx;
}

void rome2_l67_set_fpsr_sse2(rome2_l67_fp_env *env, uint32_t raw_mxcsr) {
    if (env == NULL || env->has_sse2_1212564c <= 0) {
        return;
    }
    if ((raw_mxcsr & 0x40u) == 0u || env->dazflush_119ec140 == 0u) {
        env->mxcsr = raw_mxcsr & 0xffffffbfu;
    } else {
        env->mxcsr = raw_mxcsr;
    }
}

uint32_t rome2_l67_control87(rome2_l67_fp_env *env, uint32_t new_val, uint32_t mask) {
    uint32_t old_x87;
    uint32_t target_x87;
    uint32_t final_x87;
    uint32_t sse_mask;
    uint32_t old_sse;
    uint32_t target_sse;
    uint32_t final_sse;
    uint32_t combined;

    if (env == NULL) {
        return 0u;
    }
    old_x87 = l67_x87_cw_to_abstract(env->x87_cw);
    target_x87 = ((~mask) & old_x87) | (new_val & mask);
    if (target_x87 != old_x87) {
        env->x87_cw = (uint16_t)(rome2_l67_hw_cw(target_x87) & 0xffffu);
        final_x87 = l67_x87_cw_to_abstract(env->x87_cw);
    } else {
        final_x87 = target_x87;
    }
    if (env->sse2_enabled_12126c3c == 0u) {
        return final_x87;
    }
    old_sse = l67_mxcsr_to_abstract(env->mxcsr);
    sse_mask = mask & 0x308031fu;
    target_sse = ((~sse_mask) & old_sse) | (new_val & sse_mask);
    if (target_sse != old_sse) {
        uint32_t hw_mxcsr = rome2_l67_hw_cw_sse2(target_sse);
        rome2_l67_set_fpsr_sse2(env, hw_mxcsr);
        final_sse = l67_mxcsr_to_abstract(env->mxcsr);
    } else {
        final_sse = target_sse;
    }
    combined = final_sse | final_x87;
    if (((final_sse ^ final_x87) & 0x8031fu) != 0u) {
        combined |= 0x80000000u;
    }
    return combined;
}

int32_t rome2_l67_controlfp_s(
    rome2_l67_fp_env *env, uint32_t *current_state, uint32_t new_val, uint32_t mask) {
    uint32_t effective_mask = mask & 0xfff7ffffu;

    if (env == NULL) {
        return EINVAL;
    }
    if ((new_val & effective_mask & ROME2_L67_FP_INVALID_BITS) == 0u) {
        uint32_t state = rome2_l67_control87(env, new_val, effective_mask);
        if (current_state != NULL) {
            *current_state = state;
        }
        return 0;
    }
    if (current_state != NULL) {
        *current_state = rome2_l67_control87(env, 0u, 0u);
    }
    env->crt_errno = EINVAL;
    env->invalid_param_calls++;
    return EINVAL;
}

uint32_t rome2_l67_init_fp_precision_control(rome2_l67_fp_env *env) {
    uint32_t current = 0u;
    rome2_l67_set_sse2_enable(env, 0);
    if (env != NULL) {
        env->x87_cw = (uint16_t)(env->x87_cw & 0xffc0u);
    }
    (void)rome2_l67_controlfp_s(env, &current, 0xa001fu, 0x30f031fu);
    return 1u;
}

rome2_l67_db_hash_table *rome2_l67_db_bucket_singleton_get(rome2_l67_db_hash_table *tbl) {
    uint32_t i;

    if (tbl == NULL) {
        return NULL;
    }
    if (tbl->tls_initialized == 0) {
        uint32_t count = tbl->bucket_count_119e125c;
        if (count != 0u && tbl->buckets != NULL) {
            for (i = 0u; i < count; ++i) {
                tbl->buckets[i].head_id = i + 1u;
                tbl->buckets[i].free_head = NULL;
            }
        }
        tbl->list_cleared = 1;
        tbl->atexit_registered = 1;
        tbl->tls_initialized = 1;
    }
    return tbl;
}

void rome2_l67_refcounted_slab_list_clear(rome2_l67_db_node54 **head_slot) {
    rome2_l67_db_node54 *cur;

    if (head_slot == NULL) {
        return;
    }
    cur = *head_slot;
    while (cur != NULL) {
        rome2_l67_db_node54 *next = cur->next;
        cur->cleaned_ref--;
        if (cur->cleaned_ref <= 0) {
            cur->released_slab = 1;
        }
        cur = next;
    }
    *head_slot = NULL;
}

void rome2_l67_hash_map_end(
    const rome2_l67_db_hash_table *tbl, rome2_startup_db_hash_iter12_32 *out_iter) {
    if (out_iter == NULL) {
        return;
    }
    out_iter->table_ptr_00 = (tbl != NULL) ? 1u : 0u;
    out_iter->bucket_ptr_04 = (tbl != NULL) ? tbl->bucket_count_119e125c : 0u;
    out_iter->node_ptr_08 = 0u;
}

int rome2_l67_hash_map_find(
    const rome2_l67_db_hash_table *tbl, uint32_t key, rome2_startup_db_hash_iter12_32 *out_iter) {
    uint32_t bucket_idx;
    rome2_l67_db_node54 *node;

    if (tbl == NULL || out_iter == NULL || tbl->bucket_count_119e125c == 0u || tbl->buckets == NULL) {
        rome2_l67_hash_map_end(tbl, out_iter);
        return 0;
    }
    bucket_idx = (key ^ ROME2_L67_HASH_SALT) % tbl->bucket_count_119e125c;
    node = tbl->buckets[bucket_idx].free_head;
    while (node != NULL) {
        if (node->id == key) {
            out_iter->table_ptr_00 = 1u;
            out_iter->bucket_ptr_04 = bucket_idx;
            out_iter->node_ptr_08 = node->id;
            return 1;
        }
        node = node->next;
    }
    rome2_l67_hash_map_end(tbl, out_iter);
    return 0;
}

void rome2_l67_hash_bucket_unlink_push(
    const rome2_l67_db_hash_table *tbl, rome2_l67_db_node54 *node, uint32_t key) {
    rome2_startup_db_hash_iter12_32 it;

    if (tbl == NULL || node == NULL || tbl->buckets == NULL || tbl->bucket_count_119e125c == 0u) {
        return;
    }
    if (rome2_l67_hash_map_find(tbl, key, &it) != 0 && it.bucket_ptr_04 < tbl->bucket_count_119e125c) {
        rome2_l67_db_pool_bucket *bucket = &tbl->buckets[it.bucket_ptr_04];
        node->next = bucket->free_head;
        bucket->free_head = node;
    }
}

int rome2_l67_desc_vec_push_back(
    rome2_startup_db_desc_entry28_32 **vec_ptr, uint32_t *count, uint32_t *cap,
    const rome2_startup_db_desc_entry28_32 *elem) {
    uint32_t cur_count;
    uint32_t cur_cap;

    if (vec_ptr == NULL || count == NULL || cap == NULL || elem == NULL) {
        return 0;
    }
    cur_count = *count;
    cur_cap = *cap;
    if (cur_count >= cur_cap) {
        uint32_t new_cap = (cur_cap == 0u) ? 1u : (cur_cap <= UINT32_MAX / 2u ? cur_cap * 2u : 0u);
        rome2_startup_db_desc_entry28_32 *grown;
        rome2_startup_db_desc_entry28_32 elem_copy = *elem;
        if (new_cap == 0u || new_cap > SIZE_MAX / sizeof(rome2_startup_db_desc_entry28_32)) {
            return 0;
        }
        grown = (rome2_startup_db_desc_entry28_32 *)calloc(
            new_cap, sizeof(rome2_startup_db_desc_entry28_32));
        if (grown == NULL) {
            return 0;
        }
        if (*vec_ptr != NULL && cur_count > 0u) {
            memcpy(grown, *vec_ptr, (size_t)cur_count * sizeof(rome2_startup_db_desc_entry28_32));
        }
        free(*vec_ptr);
        *vec_ptr = grown;
        *cap = new_cap;
        (*vec_ptr)[cur_count] = elem_copy;
        *count = cur_count + 1u;
        return 1;
    }
    (*vec_ptr)[cur_count] = *elem;
    *count = cur_count + 1u;
    return 1;
}

void rome2_l67_desc_list_clear(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl) {
    rome2_l67_db_node54 *cur;

    if (mgr == NULL) {
        return;
    }
    cur = mgr->list_head;
    while (cur != NULL) {
        rome2_l67_db_node54 *next = cur->next;
        (void)rome2_l67_db_bucket_singleton_get(tbl);
        rome2_l67_hash_bucket_unlink_push(tbl, cur, 0x54u);
        cur = next;
    }
    mgr->list_head = NULL;
}

void rome2_l67_sub_desc_list_clear(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl) {
    rome2_l67_db_node54 *cur;

    if (mgr == NULL) {
        return;
    }
    cur = mgr->sub_list_head;
    while (cur != NULL) {
        rome2_l67_db_node54 *next = cur->next;
        rome2_l67_hash_bucket_unlink_push(tbl, cur, 0x58u);
        cur = next;
    }
    mgr->sub_list_head = NULL;
}

void rome2_l67_open_handler_sub_reset(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl) {
    rome2_startup_db_desc_entry28_32 entry;

    if (mgr == NULL) {
        return;
    }
    mgr->desc_count_18 = 0u;
    memset(&entry, 0, sizeof(entry));
    entry.col0_0c = 1u;
    entry.col1_10 = 0xffffffffu;
    (void)rome2_l67_desc_vec_push_back(&mgr->desc_vec_1c, &mgr->desc_count_18, &mgr->desc_cap, &entry);
    rome2_l67_desc_list_clear(mgr, tbl);
}

void rome2_l67_optional_controller_reset(rome2_l67_manager_state *mgr) {
    if (mgr != NULL && mgr->opt_14_target != 0u) {
        mgr->opt_14_target = 0u;
    }
}

void rome2_l67_init_gioconda_cursor_a(rome2_l67_manager_state *mgr) {
    if (mgr == NULL) {
        return;
    }
    mgr->gio_1c = 0u;
    mgr->gio_20 = 0x14u;
    mgr->gio_24 = 2u;
    mgr->gio_28 = 0xffffffffu;
    mgr->gio_2c = 0x16u;
}

void rome2_l67_init_gioconda_cursor_b(rome2_l67_manager_state *mgr) {
    if (mgr == NULL) {
        return;
    }
    mgr->gio_1c = 0u;
    mgr->gio_20 = 0x14u;
    mgr->gio_24 = 2u;
    mgr->gio_28 = 0xffffffffu;
    mgr->gio_2c = 0x16u;
}

void rome2_l67_query_gioconda_slots(rome2_l67_manager_state *mgr) {
    if (mgr == NULL) {
        return;
    }
    mgr->ui_slot_08 = 10u;
    mgr->ui_slot_0c = 0x0eu;
    mgr->ui_slot_10 = 0x12u;
}

void rome2_l67_manager_teardown(rome2_l67_manager_state *mgr, rome2_l67_db_hash_table *tbl) {
    uint32_t i;

    if (mgr == NULL) {
        return;
    }
    rome2_l67_open_handler_sub_reset(mgr, tbl);
    rome2_l67_sub_desc_list_clear(mgr, tbl);
    if (mgr->ctrl_vec_44 != NULL) {
        for (i = 0u; i < mgr->ctrl_count_40; ++i) {
            if (mgr->ctrl_vec_44[i] != 0u) {
                mgr->sub_destructor_calls++;
                mgr->ctrl_vec_44[i] = 0u;
            }
        }
    }
    mgr->ctrl_count_40 = 0u;
    if (mgr->obj_6c != 0u) {
        mgr->sub_destructor_calls++;
        mgr->obj_6c = 0u;
    }
    if (mgr->obj_68 != 0u) {
        mgr->sub_destructor_calls++;
        mgr->obj_68 = 0u;
    }
}

void rome2_l67_warscape_open_handler(rome2_l67_manager_state *mgr, rome2_l67_fp_env *fp_env) {
    static const float marks[4] = {0.2f, 0.4f, 0.6f, 0.8f};

    if (mgr == NULL) {
        return;
    }
    l67_record_trace(mgr, "At start of open_handler");
    l67_record_trace(mgr, "About to create controllers");
    mgr->controllers_created = 1;
    l67_record_trace(mgr, "After creating controllers");
    l67_record_trace(mgr, "About to create views");
    mgr->views_created = 1;
    l67_record_trace(mgr, "After creating views");
    l67_record_trace(mgr, "About to create UIs");
    rome2_l67_optional_controller_reset(mgr);
    rome2_l67_init_gioconda_cursor_b(mgr);
    rome2_l67_init_gioconda_cursor_a(mgr);
    mgr->uis_created = 1;
    l67_record_trace(mgr, "After creating UIs");

    mgr->progress_count = 4u;
    memcpy(mgr->progress_marks, marks, sizeof(marks));

    if (mgr->flag_c9 != 0u || mgr->warscape_ready != 0u) {
        rome2_l67_query_gioconda_slots(mgr);
        (void)rome2_l67_init_fp_precision_control(fp_env);
        mgr->warscape_arg = 1u;
        (void)rome2_l67_init_fp_precision_control(fp_env);
        l67_record_trace(mgr, "After Warscape registration end");
    }
    mgr->flag_c9 = 0u;
    mgr->flag_ca = 1u;
    mgr->spin_1b0 = 0;
    mgr->field_1b4 = 0u;
    mgr->opened_ok = 1;
    l67_record_trace(mgr, "After open_handler");
}
