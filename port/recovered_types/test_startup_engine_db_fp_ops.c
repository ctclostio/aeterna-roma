#include "startup_engine_db_fp_ops.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_checks = 0;
#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAILED at line %d: %s\n", __LINE__, #cond); \
        return 1; \
    } \
    g_checks++; \
} while (0)

int main(void) {
    /* 1. Layer 67 guest32 layout assertions & field verification */
    rome2_startup_db_hash_bucket12_32 b12;
    rome2_startup_db_hash_iter12_32 it12;
    rome2_startup_db_desc_entry28_32 de28;
    CHECK(sizeof(b12) == 12u);
    CHECK(sizeof(it12) == 12u);
    CHECK(sizeof(de28) == 28u);

    /* 2. Teardown 0x100d2c80 & EMPIRE_APP dtor 0x100e0650 */
    rome2_l67_empire_teardown_env *env = (rome2_l67_empire_teardown_env *)calloc(
        1u, sizeof(rome2_l67_empire_teardown_env));
    CHECK(env != NULL);
    env->d2c80_cold_flag = 0;
    CHECK(rome2_l67_d2c80_teardown(env) == 0);
    CHECK(env->d2c80_vptr == 0x1173dc18u);
    env->crash_rep_slot04 = 0x1000u;
    env->crash_rep_slot08 = 0x2000u;
    env->vec_217_count = 3u;
    env->buf_218_ptr = 0x3000u;
    env->buf_21c_ptr = 0x4000u;
    env->global_119f3140 = 9u;
    env->handle_202 = 0x55u;
    env->d2c80_cold_flag = 1;
    rome2_l67_empire_app_dtor_core(env);
    CHECK(env->vptr_00 == 0x1173f200u);
    CHECK(env->cold_branch_calls == 1);
    CHECK(env->handler_destroy_calls == 3);
    CHECK(env->freed_218 == 1 && env->freed_21c == 1 && env->handle_closed == 1 && env->spi_restored == 1);
    CHECK(env->global_119f3140 == 0u);
    free(env);

    /* 3. CRT FP x87 / SSE2 control word suite */
    rome2_l67_fp_env fp;
    memset(&fp, 0, sizeof(fp));
    fp.has_sse2_1212564c = 1;
    fp.dazflush_119ec140 = 1u;
    fp.x87_cw = 0x037fu;
    fp.mxcsr = 0x1f80u;
    rome2_l67_set_sse2_enable(&fp, 1);
    CHECK(fp.sse2_enabled_12126c3c == 1u);
    CHECK(rome2_l67_hw_cw(0x0300u) == 0x0f00u);
    CHECK(rome2_l67_hw_cw_sse2(0x01080300u) == 0xe140u);
    uint32_t cur = 0u;
    CHECK(rome2_l67_controlfp_s(&fp, &cur, 0x1000000u, 0x3000000u) == 0);
    CHECK((fp.mxcsr & 0x8040u) == 0x8040u);
    CHECK(rome2_l67_controlfp_s(&fp, &cur, 0xf0000000u, 0xf0000000u) == EINVAL);
    CHECK(fp.crt_errno == EINVAL && fp.invalid_param_calls == 1);
    fp.dazflush_119ec140 = 0u;
    rome2_l67_set_fpsr_sse2(&fp, 0x8040u);
    CHECK(fp.mxcsr == 0x8000u);
    CHECK(rome2_l67_init_fp_precision_control(&fp) == 1u);
    CHECK(fp.sse2_enabled_12126c3c == 0u);

    /* 4. DB hash buckets, refcounted slab list, and Warscape open_handler */
    rome2_l67_db_pool_bucket buckets[4];
    rome2_l67_db_hash_table tbl;
    memset(&tbl, 0, sizeof(tbl));
    tbl.bucket_count_119e125c = 4u;
    tbl.buckets = buckets;
    CHECK(rome2_l67_db_bucket_singleton_get(&tbl) == &tbl);
    CHECK(tbl.tls_initialized == 1 && tbl.list_cleared == 1 && tbl.atexit_registered == 1);

    rome2_l67_db_node54 n1, n2, s1, s2, m1, m2;
    memset(&n1, 0, sizeof(n1));
    memset(&n2, 0, sizeof(n2));
    memset(&s1, 0, sizeof(s1));
    memset(&s2, 0, sizeof(s2));
    memset(&m1, 0, sizeof(m1));
    memset(&m2, 0, sizeof(m2));
    n1.id = 0x54u;
    n1.next = &n2;
    n2.id = 0x58u;
    uint32_t b54 = (0x54u ^ ROME2_L67_HASH_SALT) % 4u;
    buckets[b54].free_head = &n1;
    CHECK(rome2_l67_hash_map_find(&tbl, 0x54u, &it12) == 1 && it12.node_ptr_08 == 0x54u);
    CHECK(rome2_l67_hash_map_find(&tbl, 0x58u, &it12) == 1 && it12.node_ptr_08 == 0x58u);
    CHECK(rome2_l67_hash_map_find(&tbl, 0x9999u, &it12) == 0 && it12.node_ptr_08 == 0u);

    s1.id = 0x54u;
    s1.cleaned_ref = 1;
    s1.next = &s2;
    s2.id = 0x58u;
    s2.cleaned_ref = 2;
    rome2_l67_db_node54 *slab_head = &s1;
    rome2_l67_refcounted_slab_list_clear(&slab_head);
    CHECK(slab_head == NULL && s1.released_slab == 1 && s2.released_slab == 0);

    rome2_l67_manager_state *mgr = (rome2_l67_manager_state *)calloc(1u, sizeof(rome2_l67_manager_state));
    CHECK(mgr != NULL);
    uint32_t ctrls[2] = {10u, 20u};
    mgr->ctrl_vec_44 = ctrls;
    mgr->ctrl_count_40 = 2u;
    mgr->obj_68 = 1u;
    mgr->obj_6c = 1u;
    mgr->opt_14_target = 7u;
    mgr->flag_c9 = 1u;
    rome2_l67_warscape_open_handler(mgr, &fp);
    CHECK(mgr->opened_ok == 1 && mgr->controllers_created == 1 && mgr->views_created == 1 && mgr->uis_created == 1);
    CHECK(mgr->opt_14_target == 0u && mgr->gio_20 == 0x14u && mgr->ui_slot_10 == 0x12u);
    CHECK(mgr->trace_count == 9u && strcmp(mgr->trace_log[0], "At start of open_handler") == 0);
    CHECK(strcmp(mgr->trace_log[8], "After open_handler") == 0);
    m1.id = 1u;
    m2.id = 2u;
    mgr->list_head = &m1;
    mgr->sub_list_head = &m2;
    rome2_l67_manager_teardown(mgr, &tbl);
    CHECK(mgr->sub_destructor_calls == 4 && mgr->ctrl_count_40 == 0u && mgr->desc_count_18 == 1u);
    free(mgr->desc_vec_1c);
    free(mgr);

    printf("test_startup_engine_db_fp_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
