#include "facefx_name_avl_table_ops.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t s_l81_arena[256u * 1024u];
static char s_l81_last_log[256];
static int s_l81_log_count = 0;

static void test_on_log(
    rome2_l80_fx_ctx *ctx,
    uint32_t listener_va,
    const char *msg,
    int32_t level) {
    (void)ctx;
    (void)listener_va;
    (void)level;
    s_l81_log_count++;
    if (msg) {
        size_t len = strlen(msg);
        if (len >= sizeof(s_l81_last_log)) {
            len = sizeof(s_l81_last_log) - 1u;
        }
        memcpy(s_l81_last_log, msg, len);
        s_l81_last_log[len] = '\0';
    }
}

static void setup_ctx(rome2_l80_fx_ctx *fx, rome2_l81_fx_name_ctx *nctx) {
    memset(s_l81_arena, 0, sizeof(s_l81_arena));
    memset(s_l81_last_log, 0, sizeof(s_l81_last_log));
    s_l81_log_count = 0;

    rome2_l80_ctx_init(fx, s_l81_arena, 0x30000000u, (uint32_t)sizeof(s_l81_arena), 0x30001000u);
    fx->on_log_message = test_on_log;

    uint32_t mgr_va = 0x30000200u;
    (void)rome2_l80_log_manager_ctor(fx, mgr_va);
    fx->log_manager_singleton_va = mgr_va;
    rome2_fx_log_manager_32 *mgr = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(
        fx, mgr_va, (uint32_t)sizeof(*mgr));
    assert(mgr != NULL);
    rome2_l80_log_manager_set_max_level(mgr, 6);
    rome2_l80_fx_log_add_listener(&mgr->log, 0x30000400u);

    rome2_l81_ctx_init(nctx, fx);
}

static void test_l81_avl_tree_and_fxname_table(void) {
    rome2_l80_fx_ctx fx;
    rome2_l81_fx_name_ctx nctx;
    setup_ctx(&fx, &nctx);

    rome2_l81_fx_name_startup(&nctx);
    assert(nctx.name_table_va != 0u);
    assert(nctx.null_name_entry_va != 0u);
    assert(rome2_l81_fx_name_exists(&nctx, "NullName") == 1u);
    assert(rome2_l81_fx_name_exists(&nctx, "Missing") == 0u);

    /* Sanitize '|' -> '_' and '"' -> '\'' while interning & deduplicating. */
    rome2_fx_name_32 def_name;
    rome2_fx_name_32 a_name;
    rome2_fx_name_32 b_name;
    rome2_fx_name_32 c_name;
    assert(rome2_l81_fx_name_ctor_default(&nctx, &def_name) == &def_name);
    assert(rome2_l81_fx_name_eq_cstr(&nctx, &def_name, "NullName") == 1u);

    assert(rome2_l81_fx_name_ctor_cstr(&nctx, &a_name, "Rome|Legate\"Alpha\"") == &a_name);
    assert(strcmp(rome2_l81_fx_name_get_cstr(&nctx, &a_name), "Rome_Legate'Alpha'") == 0);
    assert(rome2_l81_fx_name_ctor_cstr(&nctx, &b_name, "Rome_Legate'Alpha'") == &b_name);
    assert(rome2_l81_fx_name_eq_name(&nctx, &a_name, &b_name) == 1u);
    assert(rome2_l81_fx_name_ne_name(&nctx, &a_name, &def_name) == 1u);

    /* Exercise AVL rotation/insert/remove on same bucket or arbitrary keys cleanly. */
    rome2_fx_name_32 pool[12];
    static const char *const keys[12] = {
        "k_01", "k_02", "k_03", "k_04", "k_05", "k_06",
        "k_07", "k_08", "k_09", "k_10", "k_11", "k_12"
    };
    for (int i = 0; i < 12; ++i) {
        rome2_l81_fx_name_ctor_cstr(&nctx, &pool[i], keys[i]);
    }
    /* Direct single-bucket AVL rotations + delete check. */
    uint32_t test_bucket = 0x30000800u;
    (void)rome2_l81_avl_bucket_ctor(&nctx, test_bucket);
    static const char *const asc[6] = {"aa", "bb", "cc", "dd", "ee", "ff"};
    for (int i = 0; i < 6; ++i) {
        uint8_t ins = 0u;
        assert(rome2_l81_avl_insert(&nctx, test_bucket, asc[i], (uint32_t)(0x100 + i), &ins) != 0u);
        assert(ins == 1u);
    }
    const rome2_fx_avl_bucket_32 *tb = (const rome2_fx_avl_bucket_32 *)rome2_l80_const_ptr(
        &fx, test_bucket, (uint32_t)sizeof(*tb));
    assert(tb != NULL && tb->node_count == 6u);
    assert(rome2_l81_avl_find(&nctx, test_bucket, "dd") != 0u);
    assert(rome2_l81_avl_remove_key(&nctx, test_bucket, "cc") == 1u);
    assert(rome2_l81_avl_find(&nctx, test_bucket, "cc") == 0u);
    rome2_l81_avl_bucket_dtor(&nctx, test_bucket);

    assert(rome2_l81_fx_name_ctor_copy(&nctx, &c_name, &a_name) == &c_name);
    rome2_l81_fx_name_set_name(&nctx, &c_name, "Zeta");
    assert(rome2_l81_fx_name_lt(&nctx, &a_name, &c_name) == 1u);
    assert(rome2_l81_fx_name_gt(&nctx, &c_name, &a_name) == 1u);

    rome2_l81_name_stats stats;
    rome2_l81_fx_name_get_stats(&nctx, &stats);
    assert(stats.bucket_count == 4096u);
    assert(stats.num_names == 15u); /* NullName + Rome_Legate'Alpha' + 12 pool + Zeta */
    assert(stats.mem_bytes > 0xc000u);

    rome2_l81_fx_name_dump_to_log(&nctx);
    assert(s_l81_log_count > 3);

    for (int i = 0; i < 12; ++i) {
        rome2_l81_fx_name_dtor(&nctx, &pool[i]);
    }
    rome2_l81_fx_name_dtor(&nctx, &c_name);
    rome2_l81_fx_name_dtor(&nctx, &b_name);
    rome2_l81_fx_name_dtor(&nctx, &a_name);
    rome2_l81_fx_name_dtor(&nctx, &def_name);
    assert(rome2_l81_fx_name_exists(&nctx, "Zeta") == 0u);

    rome2_l81_fx_name_shutdown(&nctx);
    assert(nctx.name_table_va == 0u);
}

static void test_l81_client_event_and_fxclass_init(void) {
    rome2_l80_fx_ctx fx;
    rome2_l81_fx_name_ctx nctx;
    setup_ctx(&fx, &nctx);
    rome2_l81_fx_name_startup(&nctx);

    rome2_fx_name_32 grp;
    rome2_fx_name_32 anim;
    rome2_fx_name_32 payload;
    rome2_l81_fx_name_ctor_cstr(&nctx, &grp, "Speech");
    rome2_l81_fx_name_ctor_cstr(&nctx, &anim, "Centurion_Rally");
    rome2_l81_fx_name_ctor_cstr(&nctx, &payload, "event_tag");

    rome2_fx_client_event_32 ev1;
    rome2_fx_client_event_32 ev2;
    rome2_fx_client_event_32 ev3;
    (void)rome2_l81_fx_client_event_ctor_full(
        &nctx, &ev1, &grp, &anim, 0.25f, 1.0f, 0.1f, 0.2f, 1.5f, 1u, 42u, &payload);
    (void)rome2_l81_fx_client_event_ctor_copy(&nctx, &ev2, &ev1);
    (void)rome2_l81_fx_client_event_ctor_full(
        &nctx, &ev3, &grp, &grp, 0.0f, 0.5f, 0.0f, 0.0f, 1.0f, 0u, 7u, &grp);
    (void)rome2_l81_fx_client_event_assign(&nctx, &ev3, &ev2);
    assert(ev3.event_id == 42u);
    assert(ev3.should_persist_values == 1u);
    assert(rome2_l81_fx_name_eq_cstr(&nctx, &ev3.animation_name, "Centurion_Rally") == 1u);

    uint32_t obj_va = rome2_l80_fx_allocate(&fx, 8u);
    assert(rome2_l81_fx_ref_object_ctor(&nctx, obj_va) == obj_va);
    const uint32_t *obj_words = (const uint32_t *)rome2_l80_const_ptr(&fx, obj_va, 8u);
    assert(obj_words != NULL && obj_words[0] == ROME2_FX_VTABLE_REF_OBJECT && obj_words[1] == 0u);

    /* Ensure FxClass::Startup warning path + FxObject -> FxRefObject hierarchy counts work. */
    nctx.fx_ref_object_class_va = rome2_l81_fx_ref_object_static_class_init(&nctx);
    assert(nctx.fx_object_class_va != 0u);
    assert(nctx.fx_ref_object_class_va != 0u);
    const rome2_fx_class_32 *obj_cls = (const rome2_fx_class_32 *)rome2_l80_const_ptr(
        &fx, nctx.fx_object_class_va, (uint32_t)sizeof(*obj_cls));
    const rome2_fx_class_32 *ref_cls = (const rome2_fx_class_32 *)rome2_l80_const_ptr(
        &fx, nctx.fx_ref_object_class_va, (uint32_t)sizeof(*ref_cls));
    assert(obj_cls != NULL && obj_cls->num_children == 1u && obj_cls->size == 4u);
    assert(ref_cls != NULL && ref_cls->base_class_va == nctx.fx_object_class_va && ref_cls->size == 8u);

    rome2_l81_fx_client_event_dtor(&nctx, &ev3);
    rome2_l81_fx_client_event_dtor(&nctx, &ev2);
    rome2_l81_fx_client_event_dtor(&nctx, &ev1);
    rome2_l81_fx_name_dtor(&nctx, &payload);
    rome2_l81_fx_name_dtor(&nctx, &anim);
    rome2_l81_fx_name_dtor(&nctx, &grp);

    rome2_l81_fx_name_shutdown(&nctx);
}

int main(void) {
    test_l81_avl_tree_and_fxname_table();
    test_l81_client_event_and_fxclass_init();
    printf("facefx_name_avl_table_ops tests passed\n");
    return 0;
}
