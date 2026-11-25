#include "facefx_alloc_singleton_log_ops.h"

#include <assert.h>
#include <string.h>

static uint8_t g_l80_arena[16384];
static rome2_fx_log_entry_32 g_l80_entry;
static char g_l80_last_msg[1024];
static int32_t g_l80_last_level = -1;
static uint32_t g_l80_last_listener = 0u;

static void on_l80_log(
    rome2_l80_fx_ctx *ctx,
    uint32_t listener_va,
    const char *msg,
    int32_t level) {
    (void)ctx;
    g_l80_last_listener = listener_va;
    g_l80_last_level = level;
    strncpy_s(g_l80_last_msg, sizeof(g_l80_last_msg), msg != NULL ? msg : "", _TRUNCATE);
}

static void test_l80_alloc_policy_singletons_and_results(void) {
    rome2_l80_fx_ctx ctx;
    uint32_t base = 0x55000000u;
    uint32_t slab_va, p1, p2, p3;
    rome2_fx_memory_allocation_policy_32 pol1, pol2;
    rome2_fx_mount_result_32 mr;
    rome2_fx_mount_unmount_result_32 mur;
    rome2_fx_actor_load_result_32 lr1, lr2;
    int32_t play_err = -1;
    uint32_t mgr_va = base + 0x100u;
    uint32_t res_va = base + 0x200u;

    memset(g_l80_arena, 0, sizeof(g_l80_arena));
    rome2_l80_ctx_init(&ctx, g_l80_arena, base, sizeof(g_l80_arena), base + 0x1000u);

    /* Configure 16B slab bucket */
    slab_va = base + 0x400u;
    ctx.slab_enabled = 1u;
    ctx.slabs[1].slab_base_va = slab_va;
    ctx.slabs[1].capacity = 4u;
    ctx.slabs[1].free_count = 4u;
    ctx.slabs[1].next_free_idx = 0u;
    {
        uint8_t *s = (uint8_t *)rome2_l80_mut_ptr(&ctx, slab_va, 64u);
        s[0] = 1u; s[16] = 2u; s[32] = 3u; s[48] = 0xffu;
    }

    p1 = rome2_l80_fx_allocate(&ctx, 12u);
    p2 = rome2_l80_fx_allocate(&ctx, 16u);
    assert(p1 == slab_va && p2 == slab_va + 16u && ctx.slabs[1].free_count == 2u);
    rome2_l80_fx_free(&ctx, p1, 12u);
    p3 = rome2_l80_fx_allocate(&ctx, 12u);
    assert(p3 == p1 && ctx.slabs[1].free_count == 2u);
    rome2_l80_fx_free(&ctx, p2, 16u);
    rome2_l80_fx_free(&ctx, p3, 12u);

    /* Policy copy/assign */
    (void)rome2_l80_alloc_policy_ctor_default(&pol1);
    assert(pol1.alloc_type == 0 && pol1.alloc_fn_va == 0u);
    (void)rome2_l80_alloc_policy_ctor_full(&pol1, 2, 1u, 0x1111u, 0x2222u, 0x3333u);
    (void)rome2_l80_alloc_policy_ctor_copy(&pol2, &pol1);
    assert(pol2.alloc_type == 2 && pol2.free_fn_va == 0x3333u);
    pol1.alloc_type = 5;
    (void)rome2_l80_alloc_policy_assign(&pol2, &pol1);
    assert(pol2.alloc_type == 5);

    /* Singletons */
    assert(rome2_l80_singleton_log_mgr_ctor(&ctx, mgr_va) == mgr_va);
    assert(rome2_l80_singleton_log_mgr_get(&ctx) == mgr_va);
    rome2_l80_singleton_log_mgr_dtor(&ctx, mgr_va);
    assert(rome2_l80_singleton_log_mgr_get(&ctx) == 0u);

    assert(rome2_l80_singleton_res_mgr_ctor(&ctx, res_va) == res_va);
    assert(rome2_l80_singleton_res_mgr_get(&ctx) == res_va);
    rome2_l80_singleton_res_mgr_dtor(&ctx, res_va);
    assert(rome2_l80_singleton_res_mgr_get(&ctx) == 0u);

    /* Result / SafeBool checks */
    (void)rome2_l80_mount_result_ctor(&mr, 0);
    assert(rome2_l80_mount_result_bool(&mr) == 1 && rome2_l80_safe_bool_mount_result(&mr) == 0u);
    mr.error_code = 7;
    assert(rome2_l80_mount_result_bool(&mr) == 0 && rome2_l80_safe_bool_mount_result(&mr) == 0xffffffffu);

    mur.mount_err = 0; mur.unmount_err = 0;
    assert(rome2_l80_safe_bool_mount_unmount(&mur) == 0u);
    mur.unmount_err = 1;
    assert(rome2_l80_safe_bool_mount_unmount(&mur) == 0xffffffffu);
    assert(rome2_l80_safe_bool_play_result(&play_err) == 0xffffffffu);
    play_err = 0;
    assert(rome2_l80_safe_bool_play_result(&play_err) == 0u);

    (void)rome2_l80_actor_load_result_ctor(&lr1);
    assert(rome2_l80_actor_load_result_bool(&lr1) == 0);
    lr1.actor_va = 0xfeedbeefu;
    (void)rome2_l80_actor_load_result_assign_copy(&lr2, &lr1);
    assert(rome2_l80_actor_load_result_bool(&lr2) == 1 && rome2_l80_safe_bool_actor_load_result(&lr2) == 0u);
}

static void test_l80_logging_stream_manager_and_sprintf(void) {
    rome2_l80_fx_ctx ctx;
    uint32_t base = 0x56000000u;
    uint32_t mgr_va = base + 0x100u;
    uint32_t listener_va = base + 0x300u;
    rome2_fx_log_manager_32 *mgr;
    rome2_fx_log_stream_32 *st;
    char sbuf[64];

    g_l80_last_msg[0] = '\0';
    g_l80_last_level = -1;
    g_l80_last_listener = 0u;
    memset(g_l80_arena, 0, sizeof(g_l80_arena));
    rome2_l80_ctx_init(&ctx, g_l80_arena, base, sizeof(g_l80_arena), base + 0x1000u);
    ctx.on_log_message = on_l80_log;

    (void)rome2_l80_log_manager_ctor(&ctx, mgr_va);
    mgr = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(&ctx, mgr_va, sizeof(*mgr));
    assert(mgr != NULL && mgr->max_log_level == 6 && mgr->tab_level == 0u);
    rome2_l80_log_manager_set_max_level(mgr, 3);
    rome2_l80_log_manager_set_tab_level(mgr, 2u);
    assert(rome2_l80_log_manager_get_max_level(mgr) == 3);
    assert(rome2_l80_log_manager_get_tab_level(mgr) == 2u);

    (void)rome2_l80_log_listener_ctor((uint32_t *)rome2_l80_mut_ptr(&ctx, listener_va, 4u), listener_va);
    rome2_l80_fx_log_add_listener(&mgr->log, listener_va);

    (void)rome2_l80_log_entry_create(&g_l80_entry, mgr_va + 0x04u, 2);
    st = rome2_l80_log_entry_get_stream(&g_l80_entry, rome2_l80_log_manager_get_tab_level(mgr));
    (void)rome2_l80_log_stream_push_cstr(st, "FX:");
    (void)rome2_l80_log_stream_push_int(st, 42);
    (void)rome2_l80_log_stream_push_cstr(st, "@");
    (void)rome2_l80_log_stream_push_ptr(st, 0x10ed4a70u);
    assert(strcmp(rome2_l80_log_stream_get_cstr(st), "        FX:42@10ED4A70") == 0);

    rome2_l80_log_entry_dtor(&ctx, &g_l80_entry);
    assert(ctx.log_dispatches == 1u && g_l80_last_listener == listener_va && g_l80_last_level == 2);
    assert(strcmp(g_l80_last_msg, "        FX:42@10ED4A70") == 0);

    rome2_l80_fx_log_remove_listener(&mgr->log, listener_va);
    rome2_l80_log_manager_dtor(&ctx, mgr_va);

    assert(rome2_l80_crt_sprintf_s(&ctx, sbuf, sizeof(sbuf), "%s-%d", "fx", 80) == 5);
    assert(strcmp(sbuf, "fx-80") == 0);
    assert(rome2_l80_crt_sprintf_s(&ctx, sbuf, 3u, "too-long") == -1 && sbuf[0] == '\0');
}

int main(void) {
    test_l80_alloc_policy_singletons_and_results();
    test_l80_logging_stream_manager_and_sprintf();
    return 0;
}
