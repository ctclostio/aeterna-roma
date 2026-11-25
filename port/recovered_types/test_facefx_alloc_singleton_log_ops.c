#include "facefx_alloc_singleton_log_ops.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define L80_BASE 0x55000000u
#define L80_HEAP_START 0x55001000u
#define L80_CALL_CAPACITY 40u
#define L80_LOG_CAPACITY 40u

typedef struct l80_call {
    uint32_t va;
    uint32_t bytes;
} l80_call;

typedef struct l80_log_call {
    uint32_t listener_va;
    int32_t level;
    char text[48];
} l80_log_call;

static uint8_t s_arena[256u * 1024u];
static rome2_fx_log_entry_32 s_entry;
static rome2_fx_log_entry_32 s_entry_copy;
static l80_call s_allocs[L80_CALL_CAPACITY];
static uint32_t s_alloc_count;
static l80_call s_frees[L80_CALL_CAPACITY];
static uint32_t s_free_count;
static l80_log_call s_logs[L80_LOG_CAPACITY];
static uint32_t s_log_count;

/* Stand-in for the policy's allocate pointer: an 8-byte aligned bump through the arena. */
static uint32_t test_system_alloc(rome2_l80_fx_ctx *ctx, uint32_t bytes) {
    uint32_t va = ctx->heap_cursor;
    ctx->heap_cursor += (bytes + 7u) & ~7u;
    assert(ctx->heap_cursor - ctx->arena_base_va <= ctx->arena_size);
    if (s_alloc_count < L80_CALL_CAPACITY) {
        s_allocs[s_alloc_count].va = va;
        s_allocs[s_alloc_count].bytes = bytes;
    }
    ++s_alloc_count;
    return va;
}

static void test_system_free(rome2_l80_fx_ctx *ctx, uint32_t ptr_va, uint32_t bytes) {
    (void)ctx;
    if (s_free_count < L80_CALL_CAPACITY) {
        s_frees[s_free_count].va = ptr_va;
        s_frees[s_free_count].bytes = bytes;
    }
    ++s_free_count;
}

static void test_on_log(rome2_l80_fx_ctx *ctx, uint32_t listener_va, const char *msg, int32_t level) {
    (void)ctx;
    assert(msg != NULL);
    if (s_log_count < L80_LOG_CAPACITY) {
        s_logs[s_log_count].listener_va = listener_va;
        s_logs[s_log_count].level = level;
        (void)snprintf(s_logs[s_log_count].text, sizeof(s_logs[s_log_count].text), "%s", msg);
    }
    ++s_log_count;
}

static void setup(rome2_l80_fx_ctx *ctx) {
    memset(s_arena, 0, sizeof(s_arena));
    s_alloc_count = 0u;
    s_free_count = 0u;
    s_log_count = 0u;
    rome2_l80_ctx_init(ctx, s_arena, L80_BASE, (uint32_t)sizeof(s_arena), L80_HEAP_START);
    ctx->custom_alloc = test_system_alloc;
    ctx->custom_free = test_system_free;
    ctx->on_log_message = test_on_log;
}

static rome2_fx_memory_pool_chunk_32 *chunk_at(const rome2_l80_fx_ctx *ctx, uint32_t va) {
    rome2_fx_memory_pool_chunk_32 *chunk = (rome2_fx_memory_pool_chunk_32 *)rome2_l80_mut_ptr(
        ctx, va, (uint32_t)sizeof(*chunk));
    assert(chunk != NULL);
    return chunk;
}

static uint8_t byte_at(const rome2_l80_fx_ctx *ctx, uint32_t va) {
    const uint8_t *p = (const uint8_t *)rome2_l80_const_ptr(ctx, va, 1u);
    assert(p != NULL);
    return *p;
}

static void test_allocation_policy(void) {
    rome2_fx_memory_allocation_policy_32 a;
    rome2_fx_memory_allocation_policy_32 b;

    /* the constructors and the assignment write the flag byte at +4 and leave +5..+7 alone */
    memset(&a, 0xcc, sizeof(a));
    assert(rome2_l80_alloc_policy_ctor_default(&a) == &a);
    assert(a.alloc_type == 0 && a.use_memory_pools == 0u);
    assert(a.alloc_fn_va == 0u && a.alloc_dbg_fn_va == 0u && a.free_fn_va == 0u);
    assert(a.pad05[0] == 0xccu && a.pad05[1] == 0xccu && a.pad05[2] == 0xccu);

    assert(rome2_l80_alloc_policy_ctor_full(&a, 2, 1u, 0x1111u, 0x2222u, 0x3333u) == &a);
    assert(a.alloc_type == 2 && a.use_memory_pools == 1u);
    assert(a.alloc_fn_va == 0x1111u && a.alloc_dbg_fn_va == 0x2222u && a.free_fn_va == 0x3333u);
    assert(a.pad05[0] == 0xccu && a.pad05[2] == 0xccu);

    memset(&b, 0x11, sizeof(b));
    assert(rome2_l80_alloc_policy_ctor_copy(&b, &a) == &b);
    assert(b.alloc_type == 2 && b.use_memory_pools == 1u);
    assert(b.alloc_fn_va == 0x1111u && b.alloc_dbg_fn_va == 0x2222u && b.free_fn_va == 0x3333u);
    assert(b.pad05[0] == 0x11u && b.pad05[1] == 0x11u && b.pad05[2] == 0x11u);

    a.alloc_type = 5;
    a.use_memory_pools = 0u;
    a.free_fn_va = 0x4444u;
    assert(rome2_l80_alloc_policy_assign(&b, &a) == &b);
    assert(b.alloc_type == 5 && b.use_memory_pools == 0u && b.free_fn_va == 0x4444u);
    assert(b.pad05[0] == 0x11u);
    assert(rome2_l80_alloc_policy_assign(&b, &b) == &b && b.alloc_type == 5);
}

static void test_fx_allocate_without_pools(void) {
    rome2_l80_fx_ctx ctx;
    uint32_t p;
    setup(&ctx);

    /* every request goes straight to the policy's allocate pointer, every free to its free pointer */
    p = rome2_l80_fx_allocate(&ctx, 12u);
    assert(p == L80_HEAP_START && ctx.alloc_calls == 1u);
    assert(s_alloc_count == 1u && s_allocs[0].bytes == 12u);
    assert(rome2_l80_fx_allocate(&ctx, 0x2000u) == L80_HEAP_START + 16u);
    assert(s_alloc_count == 2u && s_allocs[1].bytes == 0x2000u);

    rome2_l80_fx_free(&ctx, p, 12u);
    assert(ctx.free_calls == 1u && s_free_count == 1u);
    assert(s_frees[0].va == p && s_frees[0].bytes == 12u);
    rome2_l80_fx_free(&ctx, 0u, 12u); /* a NULL pointer returns at once */
    assert(ctx.free_calls == 1u && s_free_count == 1u);

    /* without hooks the arena bump serves the request and a free releases nothing */
    ctx.custom_alloc = NULL;
    ctx.custom_free = NULL;
    p = rome2_l80_fx_allocate(&ctx, 5u);
    assert(p != 0u && rome2_l80_fx_allocate(&ctx, 5u) == p + 8u);
    rome2_l80_fx_free(&ctx, p, 5u);
    assert(ctx.free_calls == 2u && s_free_count == 1u);
}

static void test_fx_allocate_with_pools(void) {
    static const uint8_t blocks_per_chunk[16] = {255, 255, 170, 128, 102, 85, 73, 64, 56, 51, 46, 42, 39, 36, 34, 32};
    rome2_l80_fx_ctx ctx;
    const rome2_fx_memory_pool_32 *pool;
    rome2_fx_memory_pool_chunk_32 *chunk;
    rome2_fx_memory_pool_chunk_32 *grown;
    uint32_t blocks[33];
    uint32_t p1;
    uint32_t p2;
    uint32_t p3;
    uint32_t big;
    uint32_t i;
    setup(&ctx);

    /* pooling off: startup builds nothing */
    rome2_l80_memory_pools_startup(&ctx);
    assert(s_alloc_count == 0u && ctx.pools[0].block_size == 0u);

    /* 16 pools of 8 .. 0x80 bytes, 0x1000 / size blocks per chunk capped at 0xff, one chunk each */
    ctx.pooling_enabled = 1u;
    rome2_l80_memory_pools_startup(&ctx);
    assert(s_alloc_count == 32u);
    for (i = 0u; i < 16u; ++i) {
        uint32_t k;
        pool = &ctx.pools[i];
        assert(pool->block_size == (i + 1u) * 8u && pool->blocks_per_chunk == blocks_per_chunk[i]);
        chunk = chunk_at(&ctx, pool->first_chunk_va);
        assert(chunk->bytes == pool->block_size * pool->blocks_per_chunk);
        assert(chunk->next_free == 0u && chunk->free_count == pool->blocks_per_chunk && chunk->next_va == 0u);
        for (k = 0u; k < pool->blocks_per_chunk; ++k) {
            assert(byte_at(&ctx, chunk->blocks_va + k * pool->block_size) == (uint8_t)(k + 1u));
        }
    }
    assert(s_allocs[0].bytes == 0x10u && s_allocs[1].bytes == 255u * 8u);
    assert(s_allocs[30].bytes == 0x10u && s_allocs[31].bytes == 0x1000u);

    /* the first pool whose block size covers the request serves it, lowest block first */
    pool = &ctx.pools[1];
    chunk = chunk_at(&ctx, pool->first_chunk_va);
    p1 = rome2_l80_fx_allocate(&ctx, 12u);
    p2 = rome2_l80_fx_allocate(&ctx, 16u);
    p3 = rome2_l80_fx_allocate(&ctx, 9u);
    assert(p1 == chunk->blocks_va && p2 == p1 + 16u && p3 == p1 + 32u);
    assert(chunk->next_free == 3u && chunk->free_count == 252u);
    assert(ctx.alloc_calls == 3u && s_alloc_count == 32u);
    assert(rome2_l80_fx_allocate(&ctx, 8u) == chunk_at(&ctx, ctx.pools[0].first_chunk_va)->blocks_va);
    assert(rome2_l80_fx_allocate(&ctx, 0u) == chunk_at(&ctx, ctx.pools[0].first_chunk_va)->blocks_va + 8u);

    /* a freed block stores the old list head in its first byte and becomes the head */
    rome2_l80_fx_free(&ctx, p2, 16u);
    assert(byte_at(&ctx, p2) == 3u && chunk->next_free == 1u && chunk->free_count == 253u);
    rome2_l80_fx_free(&ctx, p1, 12u);
    assert(byte_at(&ctx, p1) == 1u && chunk->next_free == 0u && chunk->free_count == 254u);
    assert(s_free_count == 0u);
    assert(rome2_l80_fx_allocate(&ctx, 16u) == p1);
    assert(rome2_l80_fx_allocate(&ctx, 16u) == p2);
    assert(rome2_l80_fx_allocate(&ctx, 16u) == p1 + 48u);

    /* a request above the largest block size uses the policy pointers even with pooling on */
    big = rome2_l80_fx_allocate(&ctx, 0x81u);
    assert(s_alloc_count == 33u && s_allocs[32].bytes == 0x81u && s_allocs[32].va == big);
    rome2_l80_fx_free(&ctx, big, 0x81u);
    assert(s_free_count == 1u && s_frees[0].va == big && s_frees[0].bytes == 0x81u);

    /* a full pool grows by one chunk linked at the tail of its list */
    pool = &ctx.pools[15];
    chunk = chunk_at(&ctx, pool->first_chunk_va);
    for (i = 0u; i < 32u; ++i) {
        blocks[i] = rome2_l80_fx_allocate(&ctx, 0x80u);
        assert(blocks[i] == chunk->blocks_va + i * 0x80u);
    }
    assert(chunk->free_count == 0u && chunk->next_va == 0u && s_alloc_count == 33u);
    blocks[32] = rome2_l80_fx_allocate(&ctx, 0x79u);
    assert(s_alloc_count == 35u && s_allocs[33].bytes == 0x10u && s_allocs[34].bytes == 0x1000u);
    assert(chunk->next_va == s_allocs[33].va);
    grown = chunk_at(&ctx, chunk->next_va);
    assert(grown->blocks_va == s_allocs[34].va && grown->bytes == 0x1000u && grown->next_va == 0u);
    assert(blocks[32] == grown->blocks_va && grown->next_free == 1u && grown->free_count == 31u);
    assert(byte_at(&ctx, grown->blocks_va + 31u * 0x80u) == 32u);

    /* the address picks the chunk on free; allocation scans chunks from the head */
    rome2_l80_fx_free(&ctx, blocks[32], 0x80u);
    assert(grown->free_count == 32u && grown->next_free == 0u && byte_at(&ctx, blocks[32]) == 1u);
    rome2_l80_fx_free(&ctx, blocks[5], 0x80u);
    assert(chunk->free_count == 1u && chunk->next_free == 5u && byte_at(&ctx, blocks[5]) == 32u);
    assert(rome2_l80_fx_allocate(&ctx, 0x80u) == blocks[5]);
    assert(rome2_l80_fx_allocate(&ctx, 0x80u) == blocks[32]);
    assert(s_free_count == 1u && s_alloc_count == 35u);

    /* 0x10ed48d0 outside the startup sizes: a size above 0x1000 gives the low byte of size * 8 */
    setup(&ctx);
    assert(rome2_l80_memory_pool_init(&ctx, 0u, 0x1001u) == L80_HEAP_START);
    assert(ctx.pools[0].block_size == 0x1001u && ctx.pools[0].blocks_per_chunk == 8u);
    assert(chunk_at(&ctx, L80_HEAP_START)->bytes == 8u * 0x1001u);
    assert(byte_at(&ctx, chunk_at(&ctx, L80_HEAP_START)->blocks_va + 7u * 0x1001u) == 8u);
    assert(rome2_l80_memory_pool_init(&ctx, 1u, 0x1000u) != 0u && ctx.pools[1].blocks_per_chunk == 1u);
    assert(rome2_l80_memory_pool_init(&ctx, 16u, 8u) == 0u);
}

static void test_singletons_and_results(void) {
    rome2_l80_fx_ctx ctx;
    rome2_fx_mount_result_32 mount;
    rome2_fx_mount_unmount_result_32 both;
    rome2_fx_actor_load_result_32 loaded;
    rome2_fx_actor_load_result_32 other;
    uint32_t *words;
    int32_t play;
    uint32_t manager_va = L80_BASE + 0x100u;
    uint32_t resource_va = L80_BASE + 0x200u;
    uint32_t listener_va = L80_BASE + 0x300u;
    setup(&ctx);

    /* FxSingleton<T>: the default constructor publishes the instance, the copy constructor does not */
    words = (uint32_t *)rome2_l80_mut_ptr(&ctx, manager_va, 4u);
    assert(words != NULL);
    assert(rome2_l80_singleton_log_mgr_ctor(&ctx, manager_va) == manager_va);
    assert(words[0] == ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER);
    assert(rome2_l80_singleton_log_mgr_get(&ctx) == manager_va);
    words[0] = 0u;
    assert(rome2_l80_singleton_log_mgr_copy(words, manager_va + 0x40u) == manager_va + 0x40u);
    assert(words[0] == ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER);
    assert(rome2_l80_singleton_log_mgr_get(&ctx) == manager_va);
    rome2_l80_singleton_log_mgr_dtor(&ctx, manager_va);
    assert(rome2_l80_singleton_log_mgr_get(&ctx) == 0u);

    words = (uint32_t *)rome2_l80_mut_ptr(&ctx, resource_va, 4u);
    assert(words != NULL);
    assert(rome2_l80_singleton_res_mgr_ctor(&ctx, resource_va) == resource_va);
    assert(words[0] == ROME2_FX_VTABLE_SINGLETON_RESOURCE_MANAGER);
    assert(rome2_l80_singleton_res_mgr_get(&ctx) == resource_va);
    assert(rome2_l80_singleton_res_mgr_copy(words, resource_va) == resource_va);
    rome2_l80_singleton_res_mgr_dtor(&ctx, resource_va);
    assert(rome2_l80_singleton_res_mgr_get(&ctx) == 0u);

    words = (uint32_t *)rome2_l80_mut_ptr(&ctx, listener_va, 4u);
    assert(words != NULL);
    assert(rome2_l80_log_listener_ctor(words, listener_va) == listener_va);
    assert(words[0] == ROME2_FX_VTABLE_LOG_LISTENER);
    words[0] = 0u;
    rome2_l80_log_listener_dtor(words);
    assert(words[0] == ROME2_FX_VTABLE_LOG_LISTENER);
    assert(rome2_l80_fx_nobase_assign(&mount, &both) == &mount);

    /* FxSafeBool returns a member pointer: 0 is true, the NULL member pointer -1 is false */
    assert(rome2_l80_mount_result_ctor(&mount, 0) == &mount);
    assert(rome2_l80_mount_result_bool(&mount) == 1 && rome2_l80_safe_bool_mount_result(&mount) == 0u);
    (void)rome2_l80_mount_result_ctor(&mount, 7);
    assert(mount.error_code == 7);
    assert(rome2_l80_mount_result_bool(&mount) == 0 && rome2_l80_safe_bool_mount_result(&mount) == 0xffffffffu);

    both.mount_err = 0;
    both.unmount_err = 0;
    assert(rome2_l80_safe_bool_mount_unmount(&both) == 0u);
    both.unmount_err = 1;
    assert(rome2_l80_safe_bool_mount_unmount(&both) == 0xffffffffu);
    both.unmount_err = 0;
    both.mount_err = -3;
    assert(rome2_l80_safe_bool_mount_unmount(&both) == 0xffffffffu);

    /* FxPlayResult is false only for the status -1 */
    play = -1;
    assert(rome2_l80_safe_bool_play_result(&play) == 0xffffffffu);
    play = 0;
    assert(rome2_l80_safe_bool_play_result(&play) == 0u);
    play = 9;
    assert(rome2_l80_safe_bool_play_result(&play) == 0u);

    /* FxActorLoadResult: the constructor and the move assignment skip +9..+0xb, the copy assignment does not */
    memset(&loaded, 0xcc, sizeof(loaded));
    assert(rome2_l80_actor_load_result_ctor(&loaded) == &loaded);
    assert(loaded.error_code == 0 && loaded.secondary_error == 0 && loaded.flags08 == 0u && loaded.actor_va == 0u);
    assert(loaded.pad09[0] == 0xccu && loaded.pad09[1] == 0xccu && loaded.pad09[2] == 0xccu);
    assert(rome2_l80_actor_load_result_bool(&loaded) == 0);
    assert(rome2_l80_safe_bool_actor_load_result(&loaded) == 0xffffffffu);
    loaded.actor_va = 0x7eedbeefu;
    loaded.flags08 = 1u;
    assert(rome2_l80_actor_load_result_bool(&loaded) == 1 && rome2_l80_safe_bool_actor_load_result(&loaded) == 0u);
    loaded.secondary_error = 2;
    assert(rome2_l80_actor_load_result_bool(&loaded) == 0);
    loaded.secondary_error = 0;
    loaded.error_code = 1;
    assert(rome2_l80_actor_load_result_bool(&loaded) == 0);
    assert(rome2_l80_safe_bool_actor_load_result(&loaded) == 0xffffffffu);

    memset(&other, 0x11, sizeof(other));
    assert(rome2_l80_actor_load_result_assign_move(&other, &loaded) == &other);
    assert(other.error_code == 1 && other.secondary_error == 0 && other.flags08 == 1u);
    assert(other.actor_va == 0x7eedbeefu && other.pad09[0] == 0x11u && other.pad09[2] == 0x11u);
    assert(rome2_l80_actor_load_result_assign_copy(&other, &loaded) == &other);
    assert(memcmp(&other, &loaded, sizeof(other)) == 0);
}

static void test_log_stream(void) {
    static char filler[0x400];
    rome2_fx_log_stream_32 stream;
    rome2_fx_log_stream_32 copy;

    memset(&stream, 0xcc, sizeof(stream));
    assert(rome2_l80_log_stream_ctor(&stream) == &stream);
    assert(stream.cursor == 0u && stream.buf[0] == '\0' && stream.buf[0x3ff] == '\0');
    assert(rome2_l80_log_stream_get_cstr(&stream) == stream.buf);

    /* "%d", "%f" and "%p" through a 64-byte sprintf_s buffer */
    assert(rome2_l80_log_stream_push_cstr(&stream, "n=") == &stream);
    assert(rome2_l80_log_stream_push_int(&stream, -7) == &stream);
    assert(rome2_l80_log_stream_push_cstr(&stream, " f=") == &stream);
    assert(rome2_l80_log_stream_push_float(&stream, 1.5f) == &stream);
    assert(rome2_l80_log_stream_push_cstr(&stream, " p=") == &stream);
    assert(rome2_l80_log_stream_push_ptr(&stream, 0xabcu) == &stream);
    assert(strcmp(stream.buf, "n=-7 f=1.500000 p=00000ABC") == 0);
    assert(stream.cursor == 26u);
    rome2_l80_log_stream_append_len(&stream, "wxyz", 2u);
    assert(strcmp(stream.buf + 26, "wx") == 0 && stream.cursor == 28u);

    assert(rome2_l80_log_stream_assign(&copy, &stream) == &copy);
    assert(memcmp(&copy, &stream, sizeof(stream)) == 0);

    /* the text stops at 0x3ff characters; a stream that is full ignores further output */
    rome2_l80_log_stream_dtor(&stream);
    assert(stream.cursor == 0u && stream.buf[0] == '\0' && stream.buf[27] == '\0');
    memset(filler, 'a', 0x3fdu);
    filler[0x3fd] = '\0';
    (void)rome2_l80_log_stream_push_cstr(&stream, filler);
    assert(stream.cursor == 0x3fdu);
    (void)rome2_l80_log_stream_push_cstr(&stream, "bcdef");
    assert(stream.cursor == 0x3ffu && stream.buf[0x3fd] == 'b' && stream.buf[0x3fe] == 'c');
    assert(stream.buf[0x3ff] == '\0');
    (void)rome2_l80_log_stream_push_int(&stream, 5);
    rome2_l80_log_stream_append_len(&stream, "zz", 2u);
    assert(stream.cursor == 0x3ffu && stream.buf[0x3fe] == 'c' && stream.buf[0x3ff] == '\0');
}

static void test_log_listeners_and_entries(void) {
    rome2_l80_fx_ctx ctx;
    rome2_fx_log_manager_32 *manager;
    rome2_fx_log_stream_32 *stream;
    const uint32_t *words;
    uint32_t manager_va = L80_BASE + 0x100u;
    uint32_t i;
    setup(&ctx);

    /* 0x10eec0a0: singleton published, 32 empty listener slots, maximum level 6, no indentation */
    manager = (rome2_fx_log_manager_32 *)rome2_l80_mut_ptr(&ctx, manager_va, (uint32_t)sizeof(*manager));
    assert(manager != NULL);
    memset(manager, 0xcc, sizeof(*manager));
    assert(rome2_l80_log_manager_ctor(&ctx, manager_va) == manager_va);
    assert(manager->vtable_va == ROME2_FX_VTABLE_LOG_MANAGER && ctx.log_manager_singleton_va == manager_va);
    assert(manager->max_log_level == 6 && manager->tab_level == 0u);
    for (i = 0u; i < 32u; ++i) {
        assert(manager->log.listeners_va[i] == 0u);
    }
    rome2_l80_log_manager_set_max_level(manager, 3);
    rome2_l80_log_manager_set_tab_level(manager, 2u);
    assert(rome2_l80_log_manager_get_max_level(manager) == 3 && manager->max_log_level == 3);
    assert(rome2_l80_log_manager_get_tab_level(manager) == 2u && manager->tab_level == 2u);

    /* AddListener takes the first empty slot and drops the listener when all 32 are taken */
    rome2_l80_fx_log_add_listener(&manager->log, 0u);
    assert(manager->log.listeners_va[0] == 0u);
    for (i = 0u; i < 32u; ++i) {
        rome2_l80_fx_log_add_listener(&manager->log, 0x1000u + i);
    }
    rome2_l80_fx_log_add_listener(&manager->log, 0x2000u);
    for (i = 0u; i < 32u; ++i) {
        assert(manager->log.listeners_va[i] == 0x1000u + i);
    }
    /* RemoveListener clears every slot holding the pointer */
    manager->log.listeners_va[7] = 0x1003u;
    rome2_l80_fx_log_remove_listener(&manager->log, 0x1003u);
    assert(manager->log.listeners_va[3] == 0u && manager->log.listeners_va[7] == 0u);
    rome2_l80_fx_log_remove_listener(&manager->log, 0u);
    assert(manager->log.listeners_va[2] == 0x1002u);
    rome2_l80_fx_log_add_listener(&manager->log, 0x2000u);
    assert(manager->log.listeners_va[3] == 0x2000u && manager->log.listeners_va[7] == 0u);

    /* _logMessage visits the occupied slots in order */
    rome2_l80_fx_log_message(&ctx, &manager->log, "direct", 4);
    assert(s_log_count == 31u && ctx.log_dispatches == 31u);
    assert(s_logs[0].listener_va == 0x1000u && s_logs[3].listener_va == 0x2000u);
    assert(s_logs[7].listener_va == 0x1008u && s_logs[30].listener_va == 0x101fu);
    assert(s_logs[30].level == 4 && strcmp(s_logs[30].text, "direct") == 0);

    /* CreateNewEntry + GetStream(tab level): four spaces per tab ahead of the text */
    for (i = 1u; i < 32u; ++i) {
        manager->log.listeners_va[i] = 0u;
    }
    s_log_count = 0u;
    memset(&s_entry, 0xcc, sizeof(s_entry));
    assert(rome2_l80_log_entry_create(&s_entry, manager_va + 4u, 2) == &s_entry);
    assert(s_entry.stream.cursor == 0u && s_entry.stream.buf[0] == '\0');
    assert(s_entry.log_va == manager_va + 4u && s_entry.level == 2);
    stream = rome2_l80_log_entry_get_stream(&s_entry, rome2_l80_log_manager_get_tab_level(manager));
    assert(stream == &s_entry.stream && stream->cursor == 8u);
    (void)rome2_l80_log_stream_push_cstr(stream, "FX:");
    (void)rome2_l80_log_stream_push_int(stream, 42);
    (void)rome2_l80_log_stream_push_cstr(stream, "@");
    (void)rome2_l80_log_stream_push_ptr(stream, 0x10ed4a70u);
    assert(strcmp(rome2_l80_log_stream_get_cstr(stream), "        FX:42@10ED4A70") == 0);

    assert(rome2_l80_log_entry_assign(&s_entry_copy, &s_entry) == &s_entry_copy);
    assert(memcmp(&s_entry_copy, &s_entry, sizeof(s_entry)) == 0);

    /* ~FxLogEntry hands the text and level to each listener, then empties the stream */
    rome2_l80_log_entry_dtor(&ctx, &s_entry);
    assert(s_log_count == 1u && s_logs[0].listener_va == 0x1000u && s_logs[0].level == 2);
    assert(strcmp(s_logs[0].text, "        FX:42@10ED4A70") == 0);
    assert(s_entry.stream.cursor == 0u && s_entry.stream.buf[0] == '\0' && s_entry.stream.buf[21] == '\0');
    assert(s_entry.log_va == manager_va + 4u && s_entry.level == 2);

    /* the plain constructor 0x10ed4970 builds the same state */
    assert(rome2_l80_log_entry_ctor(&s_entry_copy, manager_va + 4u, 5) == &s_entry_copy);
    assert(s_entry_copy.stream.cursor == 0u && s_entry_copy.level == 5);
    assert(rome2_l80_log_entry_get_stream(&s_entry_copy, 0u)->cursor == 0u);

    /* ~FxLogManager: listeners cleared, base vtable restored, singleton withdrawn */
    words = (const uint32_t *)manager;
    rome2_l80_log_manager_dtor(&ctx, manager_va);
    assert(words[0] == ROME2_FX_VTABLE_SINGLETON_LOG_MANAGER && manager->log.listeners_va[0] == 0u);
    assert(ctx.log_manager_singleton_va == 0u);
    assert(manager->max_log_level == 3 && manager->tab_level == 2u);
}

static int32_t call_common_vsprintf(rome2_l80_fx_ctx *ctx, char *dst, uint32_t cap, const char *fmt, ...) {
    va_list ap;
    int32_t rc;
    va_start(ap, fmt);
    rc = rome2_l80_common_vsprintf(ctx, dst, cap, fmt, ap);
    va_end(ap);
    return rc;
}

static void test_crt_sprintf_s(void) {
    rome2_l80_fx_ctx ctx;
    char text[16];
    setup(&ctx);

    assert(rome2_l80_crt_sprintf_s(&ctx, text, (uint32_t)sizeof(text), "%s-%d", "fx", 80) == 5);
    assert(strcmp(text, "fx-80") == 0 && ctx.last_errno == 0);
    assert(rome2_l80_crt_sprintf_s(&ctx, text, 6u, "%s-%d", "fx", 80) == 5);

    /* output that leaves no room for the terminator: empty string, ERANGE, -1 */
    memset(text, 'x', sizeof(text));
    assert(rome2_l80_crt_sprintf_s(&ctx, text, 5u, "%s-%d", "fx", 80) == -1);
    assert(text[0] == '\0' && ctx.last_errno == 0x22);

    /* missing format, missing buffer or zero capacity: EINVAL, -1 */
    ctx.last_errno = 0;
    assert(rome2_l80_crt_sprintf_s(&ctx, text, (uint32_t)sizeof(text), NULL) == -1 && ctx.last_errno == 0x16);
    ctx.last_errno = 0;
    assert(rome2_l80_crt_sprintf_s(&ctx, NULL, 4u, "x") == -1 && ctx.last_errno == 0x16);
    ctx.last_errno = 0;
    assert(rome2_l80_crt_sprintf_s(&ctx, text, 0u, "x") == -1 && ctx.last_errno == 0x16);

    /* common_vsprintf itself reports the overflow as -2 and counts without a buffer */
    ctx.last_errno = 0;
    assert(call_common_vsprintf(&ctx, text, 4u, "%s", "abc") == 3);
    assert(call_common_vsprintf(&ctx, text, 3u, "%s", "abc") == -2 && ctx.last_errno == 0);
    assert(text[0] == 'a' && text[1] == 'b' && text[2] == '\0');
    assert(call_common_vsprintf(&ctx, text, 0u, "%s", "abc") == -1 && ctx.last_errno == 0);
    assert(call_common_vsprintf(&ctx, NULL, 0u, "%s", "abcdef") == 6);
    assert(call_common_vsprintf(&ctx, NULL, 4u, "%s", "abc") == -1 && ctx.last_errno == 0x16);
}

int main(void) {
    test_allocation_policy();
    test_fx_allocate_without_pools();
    test_fx_allocate_with_pools();
    test_singletons_and_results();
    test_log_stream();
    test_log_listeners_and_entries();
    test_crt_sprintf_s();
    printf("facefx_alloc_singleton_log_ops tests passed\n");
    return 0;
}
