#include "startup_entry_frame_loop_ops.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "startup_input_msg_console_ops.h"
#include "vfs_fs_engine_crt_ops.h"

#define L71_SOUND_EVENT 0x814a7e77u

static void l71_hook(const rome2_l71_env *env, uint32_t id, uint32_t arg, const void *data) {
    if (env->hook != NULL) {
        env->hook(env->user, id, arg, data);
    }
}

static uint8_t l71_query(const rome2_l71_env *env, uint32_t id) {
    return (env->query != NULL) ? env->query(env->user, id) : 0u;
}

static uint64_t l71_now(const rome2_l71_env *env) {
    return (env->now_us != NULL) ? env->now_us(env->user) : 0u;
}

static uint64_t l71_pair_value(const rome2_startup_u64_pair8_32 *pair) {
    return ((uint64_t)pair->hi_04 << 32) | pair->lo_00;
}

/* ---- 0x104274b0 / 0x112ac410 / 0x112e2bf0 ---- */

rome2_startup_u64_pair8_32 *rome2_l71_u64_pair_ctor(rome2_startup_u64_pair8_32 *self, uint32_t lo, uint32_t hi) {
    if (self != NULL) {
        self->lo_00 = lo;
        self->hi_04 = hi;
    }
    return self;
}

rome2_startup_u64_pair8_32 *rome2_l71_u64_add(
    rome2_startup_u64_pair8_32 *out, const rome2_startup_u64_pair8_32 *lhs, const rome2_startup_u64_pair8_32 *rhs) {
    if (out != NULL && lhs != NULL && rhs != NULL) {
        uint64_t sum = l71_pair_value(lhs) + l71_pair_value(rhs);

        out->lo_00 = (uint32_t)sum;
        out->hi_04 = (uint32_t)(sum >> 32);
    }
    return out;
}

uint32_t rome2_l71_us_to_scaled_ms(const rome2_startup_u64_pair8_32 *us, float scale) {
    float value;

    if (us == NULL) {
        return 0u;
    }
    value = (float)rome2_startup_crt_ultod3_11683d60(us->lo_00, us->hi_04);
    value *= scale;
    value *= 0.001f;                             /* 0x1173e2b8 */
    return rome2_vfs_crt_ftoui3(value);
}

/* ---- 0x10cb8420 / 0x10cb8450 / 0x10cb8480 ---- */

static void l71_time_accum(void *object, size_t last_offset, float value, float scale) {
    uint8_t *base = (uint8_t *)object;
    float last;
    float accum;

    if (base == NULL) {
        return;
    }
    memcpy(&last, base + last_offset, sizeof(last));
    memcpy(&accum, base + last_offset + 4u, sizeof(accum));
    accum = accum + (value - last) * scale;
    memcpy(base + last_offset, &value, sizeof(value));
    memcpy(base + last_offset + 4u, &accum, sizeof(accum));
}

void rome2_l71_time_accum_0c(void *object, float value, float scale) {
    l71_time_accum(object, 0x0cu, value, scale);
}

void rome2_l71_time_accum_28(void *object, float value, float scale) {
    l71_time_accum(object, 0x28u, value, scale);
}

void rome2_l71_time_accum_2c(void *object, float value, float scale) {
    l71_time_accum(object, 0x2cu, value, scale);
}

/* ---- 0x100f6940 / 0x10114ee0 ---- */

int rome2_l71_fp_control_is_engine_default(uint32_t control_word) {
    return (control_word & ROME2_L71_FP_CONTROL_MASK) == ROME2_L71_FP_CONTROL_DEFAULT;
}

void rome2_l71_set_wait_params(rome2_l71_globals *globals, uint32_t value, float seconds) {
    if (globals != NULL) {
        globals->wait_value = value;
        globals->wait_seconds = seconds;
    }
}

/* ---- 0x100d9d90 (also inlined for the handler stack in 0x100dbf80) ---- */

int rome2_l71_ptr_vec_push_back(rome2_l71_ptr_vec *vec, void *value) {
    if (vec == NULL) {
        return 0;
    }
    if (vec->capacity == 0u) {
        void **fresh;

        if (vec->count != 0u) {
            return 0;                            /* the original writes at data + count * 4 */
        }
        fresh = (void **)malloc(sizeof(*fresh));
        if (fresh == NULL) {
            return 0;
        }
        vec->capacity = 1u;
        vec->data = fresh;
    } else if (vec->count >= vec->capacity) {
        uint32_t doubled = vec->capacity * 2u;
        void **fresh;

        /* The original allocates nothing for a zero or sign-bit capacity. */
        if (doubled == 0u || (doubled & 0x80000000u) != 0u || vec->count >= doubled) {
            return 0;
        }
        fresh = (void **)malloc((size_t)doubled * sizeof(*fresh));
        if (fresh == NULL) {
            return 0;
        }
        if (vec->count != 0u && vec->data != NULL) {
            memcpy(fresh, vec->data, (size_t)vec->count * sizeof(*fresh));
        }
        free(vec->data);
        vec->capacity = doubled;
        vec->data = fresh;
    }
    if (vec->data == NULL) {
        return 0;
    }
    vec->data[vec->count] = value;
    vec->count++;
    return 1;
}

void rome2_l71_ptr_vec_free(rome2_l71_ptr_vec *vec) {
    if (vec != NULL) {
        free(vec->data);
        vec->data = NULL;
        vec->count = 0u;
        vec->capacity = 0u;
    }
}

/* ---- 0x10c8fff0 / 0x10c914d0 / 0x10cb0440 ---- */

void rome2_l71_iface_call_slot14_if_slot28(const rome2_l71_iface_holder *holder) {
    const rome2_l71_iface *iface = (holder != NULL) ? holder->iface_14 : NULL;

    if (iface != NULL && iface->slot28 != NULL && iface->slot28(iface->user) != 0u && iface->slot14 != NULL) {
        iface->slot14(iface->user);              /* JMP [eax+0x14] */
    }
}

void rome2_l71_iface_call_slot08_if_present(const rome2_l71_iface_holder *holder) {
    const rome2_l71_iface *iface = (holder != NULL) ? holder->iface_14 : NULL;

    if (iface != NULL && iface->slot08 != NULL) {
        iface->slot08(iface->user);              /* JMP [eax+0x8] */
    }
}

int rome2_l71_advice_set_enabled(rome2_l71_advice_state *state, uint8_t enabled) {
    uint8_t previous;

    if (state == NULL) {
        return 0;
    }
    previous = state->enabled;
    state->enabled = enabled;
    if (enabled != 0u && previous == 0u && state->pending_count != 0u) {
        if (state->issue_pending != NULL) {
            state->issue_pending(state->user);   /* JNZ 0x10cb6520 */
        }
        return 1;
    }
    return 0;
}

/* ---- 0x100d6cc0 ---- */

uint32_t rome2_l71_remove_ui_entries(rome2_l71_ptr_vec *entries, const char *prefix_or_null) {
    uint32_t removed = 0u;
    uint32_t i = 0u;

    if (entries == NULL || entries->data == NULL) {
        return 0u;
    }
    while (i < entries->count) {
        rome2_l71_ui_entry *entry = (rome2_l71_ui_entry *)entries->data[i];
        int matched = 1;

        if (prefix_or_null != NULL) {
            /* 0x100ff8f0 searches from position 0; only a hit at offset 0 matches. */
            const char *name = (entry != NULL && entry->owner_name != NULL) ? entry->owner_name : "";

            matched = (strncmp(name, prefix_or_null, strlen(prefix_or_null)) == 0);
        }
        if (!matched) {
            i++;
            continue;
        }
        if (entry != NULL && entry->destroy_owner != NULL) {
            entry->destroy_owner(entry->user);   /* the 12B entry block itself stays caller-owned here */
        }
        memmove(&entries->data[i], &entries->data[i + 1u], (size_t)(entries->count - i - 1u) * sizeof(*entries->data));
        entries->count--;
        removed++;
    }
    return removed;
}

/* ---- pieces of 0x100dbf80 ---- */

uint32_t rome2_l71_scale_frame_ms(uint32_t ms, float time_scale) {
    float value;
    double floored;

    if (time_scale == 1.0f) {                    /* UCOMISS/LAHF/TEST AH,0x44: NaN takes the scaled path */
        return ms;
    }
    value = (float)(double)ms;
    value = value * time_scale;
    value = value + 0.5f;                        /* 0x1173e2c4 */
    /* FISTP dword under RC |= 0x400 (round down from the engine default word). */
    floored = floor((double)value);
    if (!(floored >= -2147483648.0 && floored <= 2147483647.0)) {
        return 0x80000000u;
    }
    return (uint32_t)(int32_t)floored;
}

void rome2_l71_frame_ring_push(rome2_l71_screen_mgr *mgr, uint32_t ms) {
    uint32_t slot;

    if (mgr == NULL) {
        return;
    }
    if (mgr->frame_index_1b4 < mgr->frame_count_1b0) {
        slot = mgr->frame_index_1b4;
    } else {
        slot = mgr->frame_count_1b0;
        mgr->frame_count_1b0 = slot + 1u;
    }
    if (slot < ROME2_L71_FRAME_RING) {           /* the original stores without a bound */
        mgr->frame_ms_e8[slot] = ms;
    }
    mgr->frame_index_1b4 = (mgr->frame_index_1b4 + 1u) % ROME2_L71_FRAME_RING;
}

int rome2_l71_u64_vec_push(rome2_l71_u64_vec *vec, uint64_t value) {
    if (vec == NULL) {
        return 0;
    }
    if (vec->count >= vec->capacity) {
        uint32_t wanted = (vec->capacity == 0u) ? 1u : vec->capacity * 2u;
        uint64_t *fresh;

        if (wanted == 0u || (wanted & 0x80000000u) != 0u || vec->count >= wanted) {
            return 0;
        }
        fresh = (uint64_t *)malloc((size_t)wanted * sizeof(*fresh));
        if (fresh == NULL) {
            return 0;
        }
        if (vec->count != 0u && vec->data != NULL) {
            memcpy(fresh, vec->data, (size_t)vec->count * sizeof(*fresh));
        }
        free(vec->data);
        vec->capacity = wanted;
        vec->data = fresh;
    }
    if (vec->data == NULL) {
        /* Initial image state: capacity 0x10000 with a null buffer. */
        return 0;
    }
    vec->data[vec->count] = value;
    vec->count++;
    return 1;
}

/* ---- 0x100dbf80 ---- */

static void l71_notify(rome2_l71_handler *handler, uint32_t slot, const void *arg) {
    if (handler != NULL && handler->notify != NULL) {
        handler->notify(handler, slot, arg);
    }
}

static rome2_l71_handler *l71_top(const rome2_l71_screen_mgr *mgr) {
    if (mgr->handlers_2c.count == 0u || mgr->handlers_2c.data == NULL) {
        return NULL;                             /* the original reads data[-1] */
    }
    return (rome2_l71_handler *)mgr->handlers_2c.data[mgr->handlers_2c.count - 1u];
}

static void l71_listeners_notify(const rome2_l71_ptr_vec *list, uint32_t slot, const void *arg, int enabled_only) {
    uint32_t i;

    for (i = 0u; list->data != NULL && i < list->count; i++) {
        rome2_l71_listener *listener = (rome2_l71_listener *)list->data[i];

        if (listener == NULL || listener->notify == NULL || (enabled_only && listener->enabled_10 == 0u)) {
            continue;
        }
        listener->notify(listener, slot, arg);
    }
}

/* Slot +0x08 with argument 1 on every non-null element, then count = 0. */
static void l71_listeners_delete(rome2_l71_ptr_vec *list) {
    l71_listeners_notify(list, 0x08u, NULL, 0);
    list->count = 0u;
}

static uint32_t l71_frame_ms(const rome2_startup_u64_pair8_32 *delta, float scale, const rome2_l71_globals *globals) {
    uint32_t ms = rome2_l71_us_to_scaled_ms(delta, scale);

    if (globals->fixed_fps == 0u && ms > ROME2_L71_FRAME_MS_CAP) {
        ms = ROME2_L71_FRAME_MS_CAP;
    }
    return rome2_l71_scale_frame_ms(ms, globals->time_scale);
}

static void l71_begin_transition(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env, uint8_t reload, int movie_allowed) {
    uint32_t i;

    rome2_l71_set_wait_params(globals, ROME2_L71_WAIT_BUSY, 0.0f);
    l71_hook(env, ROME2_L71_HOOK_CLOCK_MODE, 1u, NULL);
    mgr->loading_c8 = 1u;
    mgr->reload_c9 = reload;
    (void)rome2_l71_remove_ui_entries(&mgr->ui_entries_20, NULL);
    l71_hook(env, ROME2_L71_HOOK_TEARDOWN, 0u, NULL);
    l71_listeners_delete(&mgr->primary_50);
    if (mgr->movie != NULL && movie_allowed) {
        rome2_l71_iface_call_slot08_if_present(mgr->movie);
    }
    l71_listeners_delete(&mgr->secondary_60);
    for (i = 0u; mgr->handlers_2c.data != NULL && i < mgr->handlers_2c.count; i++) {
        l71_notify((rome2_l71_handler *)mgr->handlers_2c.data[i], 0x60u, NULL);
    }
    if (mgr->has_sound != 0u) {
        l71_hook(env, ROME2_L71_HOOK_SOUND_EVENT, L71_SOUND_EVENT, NULL);
    }
}

static void l71_end_transition(rome2_l71_globals *globals, const rome2_l71_env *env) {
    l71_hook(env, ROME2_L71_HOOK_CLOCK_MODE, 0u, NULL);
    rome2_l71_set_wait_params(globals, 0u, ROME2_L71_WAIT_IDLE_SECONDS);
}

static void l71_pop_top(rome2_l71_screen_mgr *mgr) {
    l71_notify(l71_top(mgr), 0x04u, NULL);       /* slot +0x04 with argument 1 */
    if (mgr->handlers_2c.count != 0u) {
        mgr->handlers_2c.count--;
    }
}

static void l71_create_handler(
    rome2_l71_screen_mgr *mgr, const rome2_l71_env *env, rome2_l71_factory *factory, int with_name) {
    rome2_l71_handler *created = NULL;

    if (factory == NULL) {
        return;                                  /* the original dereferences the factory unguarded */
    }
    if (with_name && factory->notify != NULL) {
        factory->notify(factory, 0x0cu);         /* the returned name string is destroyed unread */
    }
    if (factory->create != NULL) {
        created = factory->create(factory, mgr->reload_c9);
    }
    if (with_name) {
        l71_hook(env, ROME2_L71_HOOK_LOG, 0u, "Created new handler");
    }
    if (created != NULL && !rome2_l71_ptr_vec_push_back(&mgr->handlers_2c, created)) {
        mgr->alloc_failures++;
    }
    if (factory->notify != NULL) {
        factory->notify(factory, 0x00u);         /* slot +0x00 with argument 1 */
    }
}

/* Transition requests raised through the flag bytes [mgr+0xcb..0xce] and [mgr+0xd0]. */
static void l71_handle_requests(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env, rome2_l71_handler *top) {
    uint8_t cb = mgr->request_cb[0];
    uint8_t cc = mgr->request_cb[1];
    uint8_t cd = mgr->request_cb[2];
    uint8_t ce = mgr->request_cb[3];
    uint8_t d0 = mgr->request_d0;
    rome2_l71_factory *factory = NULL;

    if (cb == 0u && cc == 0u && cd == 0u && ce == 0u && d0 == 0u) {
        return;
    }
    if (top != NULL && top->request != NULL) {
        if (cd != 0u) {
            factory = top->request(top, 0x40u, 1u);
        } else if (cb != 0u || cc != 0u) {
            factory = top->request(top, 0x40u, 0u);
        } else if (ce != 0u) {
            factory = top->request(top, 0x44u, 0u);
        } else {
            factory = top->request(top, 0x48u, 0u);
        }
    }
    memset(mgr->request_cb, 0, sizeof(mgr->request_cb));
    mgr->request_d0 = 0u;
    if (factory == NULL) {
        return;
    }
    l71_begin_transition(mgr, globals, env, (uint8_t)(d0 != 0u || cc != 0u), cb == 0u);
    l71_pop_top(mgr);
    l71_hook(env, ROME2_L71_HOOK_FP_PRECISION, 1u, NULL);
    l71_create_handler(mgr, env, factory, 0);
    l71_hook(env, ROME2_L71_HOOK_LOG, 0u, "After create_new_handler");
    l71_end_transition(globals, env);
}

/* The transition taken on a nonzero step code, the pop request or the quit-all flag. */
static void l71_step_transition(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env,
    int32_t code, rome2_l71_factory *factory) {
    uint32_t i;

    l71_begin_transition(mgr, globals, env, (uint8_t)(code != ROME2_L71_CODE_REPLACE_NO_RESET), 1);
    if (mgr->reload_c9 != 0u) {
        l71_hook(env, ROME2_L71_HOOK_DEVICE_SLOT94, 0u, NULL);
    }
    if (mgr->pop_request_cf != 0u || code == ROME2_L71_CODE_POP || code == ROME2_L71_CODE_REPLACE ||
        code == ROME2_L71_CODE_REPLACE_NO_RESET) {
        l71_pop_top(mgr);
    }
    if (globals->quit_all != 0u || code == ROME2_L71_CODE_CLEAR) {
        for (i = mgr->handlers_2c.count; mgr->handlers_2c.data != NULL && i > 0u; i--) {
            l71_notify((rome2_l71_handler *)mgr->handlers_2c.data[i - 1u], 0x04u, NULL);
        }
        mgr->handlers_2c.count = 0u;
    }
    if (code == ROME2_L71_CODE_KEEP_BOTTOM) {
        for (i = mgr->handlers_2c.count; mgr->handlers_2c.data != NULL && i > 1u; i--) {
            l71_notify((rome2_l71_handler *)mgr->handlers_2c.data[i - 1u], 0x04u, NULL);
        }
        if (mgr->handlers_2c.count > 1u) {
            mgr->handlers_2c.count = 1u;
        }
    }
    (void)rome2_l71_advice_set_enabled(mgr->advice, 0u);
    if (mgr->pop_request_cf == 0u && (code == ROME2_L71_CODE_PUSH || code == ROME2_L71_CODE_REPLACE ||
                                      code == ROME2_L71_CODE_REPLACE_NO_RESET)) {
        l71_hook(env, ROME2_L71_HOOK_FP_PRECISION, 1u, NULL);
        l71_hook(env, ROME2_L71_HOOK_LOG, 0u, "About to create new handler");
        l71_create_handler(mgr, env, factory, 1);
    }
    l71_end_transition(globals, env);
}

/* Up to 1000 steps of the top handler. */
static void l71_step_loop(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env, rome2_l71_handler *top) {
    uint8_t again = 1u;
    uint32_t iteration;

    for (iteration = 0u; iteration < ROME2_L71_STEP_LIMIT; iteration++) {
        rome2_l71_step_result res;

        l71_hook(env, ROME2_L71_HOOK_FP_PRECISION, 1u, NULL);
        memset(&res, 0, sizeof(res));
        if (mgr->pop_request_cf == 0u) {
            if (top == NULL || top->step == NULL) {
                return;                          /* the original dereferences the top handler unguarded */
            }
            top->step(top, &res);
            if (res.advanced != 0u) {
                top->elapsed_ms_04 += res.ms;
            }
            /* 0x100f6940 is called here and its result discarded. */
            if (res.leave_ui != 0u) {
                (void)rome2_l71_remove_ui_entries(&mgr->ui_entries_20, "UIs/");
                mgr->secondary_60.count = 0u;
                l71_notify(top, 0x10u, mgr);     /* argument is mgr + 8 in the original */
                if (again == 0u) {
                    return;
                }
                continue;
            }
        }
        if (mgr->pop_request_cf != 0u || globals->quit_all != 0u || res.code != ROME2_L71_CODE_NONE) {
            l71_step_transition(mgr, globals, env, res.code, res.factory);
            return;
        }
        if (res.advanced != 0u) {
            if (res.notify != 0u) {
                rome2_startup_frame_time16_32 frame;

                frame.total_ms_00 = top->elapsed_ms_04;
                frame.dt_ms_04 = res.ms;
                frame.total_s_08 = (float)(double)top->elapsed_ms_04 * 0.001f;
                frame.dt_s_0c = (float)(double)res.ms * 0.001f;
                l71_listeners_notify(&mgr->primary_50, 0x0cu, NULL, 0);
                l71_listeners_notify(&mgr->listeners_40, 0x0cu, &frame, 0);
                l71_listeners_notify(&mgr->secondary_60, 0x10u, &frame, 0);
                l71_notify(top, 0x64u, NULL);
            } else {
                l71_notify(top, 0x68u, NULL);
            }
            l71_notify(top, 0x74u, NULL);
        }
        again = res.again;
        if (again == 0u) {
            return;
        }
    }
}

static void l71_render(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env,
    rome2_l71_handler *stale_top, const rome2_startup_frame_time16_32 *frame, uint32_t render_ms) {
    rome2_l71_render_args args;
    rome2_l71_handler *top;
    int32_t delay;

    l71_hook(env, ROME2_L71_HOOK_FP_PRECISION, 0u, NULL);
    l71_hook(env, ROME2_L71_HOOK_DEVICE_FRAME, 1u, NULL);
    args.top = stale_top;
    args.frame = frame;
    args.render_ms = render_ms;
    l71_listeners_notify(&mgr->renderers_b4, 0x04u, &args, 0);
    top = l71_top(mgr);
    if (globals->capture_request != 0u) {
        l71_notify(top, 0x7cu, NULL);
        globals->capture_name_length = 0u;       /* 0x100f6ea0 on 0x119f06ac */
        globals->flag_cd = 0u;
        globals->flag_ce = 0u;
        globals->capture_request = 0u;
        globals->flag_8d0 = 0u;
    }
    if (globals->capture_name_length != 0u) {
        l71_notify(top, 0x78u, NULL);            /* (name, 1, 1) in the original */
        globals->capture_name_length = 0u;
        globals->flag_cd = 0u;
        globals->flag_ce = 0u;
    }
    l71_notify(top, 0x80u, NULL);
    l71_hook(env, ROME2_L71_HOOK_FP_PRECISION, 0u, NULL);
    delay = mgr->present_delay_d4;
    if (delay > 0) {
        delay--;
        mgr->present_delay_d4 = delay;
    }
    if (delay == 0) {
        l71_hook(env, ROME2_L71_HOOK_DEVICE_PRESENT, 0u, NULL);
    }
    l71_hook(env, ROME2_L71_HOOK_DEVICE_FRAME, 0u, NULL);
    l71_hook(env, ROME2_L71_HOOK_FP_PRECISION, 1u, NULL);
}

uint8_t rome2_l71_screen_mgr_frame_update(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env) {
    rome2_startup_u64_pair8_32 delta;
    rome2_startup_frame_time12_32 frame;
    rome2_l71_handler *top;
    uint64_t now;
    uint64_t elapsed;
    uint32_t dt_ms;
    uint32_t i;
    float sub_scale = 1.0f;
    float now_s;

    if (mgr == NULL || globals == NULL || env == NULL) {
        return 1u;
    }
    if (globals->sample_counter != 0u) {
        uint64_t ticks = (env->counter != NULL) ? env->counter(env->user) : 0u;

        if (!rome2_l71_u64_vec_push(&globals->samples, ticks - globals->counter_base)) {
            mgr->alloc_failures++;
        }
    }
    /* Enable-state sync of the by-name entries. */
    for (i = 0u; mgr->ui_entries_20.data != NULL && i < mgr->ui_entries_20.count; i++) {
        rome2_l71_ui_entry *entry = (rome2_l71_ui_entry *)mgr->ui_entries_20.data[i];
        rome2_l71_toggle *toggle = (entry != NULL) ? entry->handler_04 : NULL;

        if (toggle == NULL || toggle->set == NULL || entry->wanted_00 == toggle->enabled_10) {
            continue;
        }
        if (entry->wanted_00 != 0u) {
            if (toggle->set(toggle, 1u) != 0u) {
                toggle->enabled_10 = 1u;
            }
        } else if (toggle->set(toggle, 0u) != 0u) {
            toggle->enabled_10 = 0u;
        }
    }
    if (globals->last_us_valid == 0u) {          /* thread-safe static init of 0x119f3080 */
        globals->last_us = l71_now(env);
        globals->last_us_valid = 1u;
    }
    if (globals->fixed_fps != 0u) {
        now = globals->last_us + (uint64_t)((1000u / globals->fixed_fps) * 1000u);
    } else {
        now = l71_now(env);
    }
    elapsed = now - globals->last_us;
    (void)rome2_l71_u64_pair_ctor(&delta, (uint32_t)elapsed, (uint32_t)(elapsed >> 32));
    globals->last_us = now;
    l71_hook(env, ROME2_L71_HOOK_REMOTE_POLL, 0u, NULL);
    if (mgr->loading_c8 != 0u) {
        mgr->loading_c8 = 0u;
        rome2_l71_set_wait_params(globals, ROME2_L71_WAIT_BUSY, 0.0f);
        l71_hook(env, ROME2_L71_HOOK_CLOCK_MODE, 1u, NULL);
        l71_hook(env, ROME2_L71_HOOK_OPEN_HANDLER, 0u, NULL);
        l71_hook(env, ROME2_L71_HOOK_CLOCK_MODE, 0u, NULL);
        rome2_l71_set_wait_params(globals, 0u, ROME2_L71_WAIT_IDLE_SECONDS);
        mgr->present_delay_d4 = 2;
    }
    top = l71_top(mgr);
    dt_ms = l71_frame_ms(&delta, 1.0f, globals);
    mgr->total_ms_c0 += dt_ms;
    if (top != NULL && top->time_scale != NULL && !top->time_scale(top, &sub_scale)) {
        sub_scale = 1.0f;
    }
    mgr->scaled_total_ms_c4 += l71_frame_ms(&delta, sub_scale, globals);
    rome2_l71_frame_ring_push(mgr, dt_ms);
    now_s = rome2_startup_u64_us_to_seconds_112e2b00(now);
    rome2_l71_time_accum_2c(globals->accum_2c, now_s, sub_scale);
    rome2_l71_time_accum_0c(globals->accum_0c, now_s, sub_scale);
    rome2_l71_time_accum_28(globals->accum_28, now_s, sub_scale);
    if (mgr->notify_d1 != 0u) {
        l71_notify(top, 0x58u, NULL);
        mgr->notify_d1 = 0u;
    }
    frame.total_ms_00 = mgr->total_ms_c0;
    frame.dt_ms_04 = dt_ms;
    frame.dt_s_08 = (float)(double)dt_ms * 0.001f;
    l71_hook(env, ROME2_L71_HOOK_INPUT_UPDATE, 0u, &frame);
    if (mgr->overlay_1b8 == 0u) {
        uint32_t before = mgr->handlers_2c.count;

        l71_handle_requests(mgr, globals, env, top);
        if (mgr->loading_c8 != 0u || mgr->handlers_2c.count != before) {
            top = NULL;                          /* ebx is zeroed after the top handler is destroyed */
        }
    }
    if (mgr->loading_c8 == 0u) {
        if (mgr->overlay_1b8 != 0u) {
            l71_hook(env, ROME2_L71_HOOK_OVERLAY_POP, 0u, NULL);
        }
        if (mgr->overlay_1b8 == 0u) {
            frame.total_ms_00 = mgr->total_ms_c0;
            l71_notify(top, 0x30u, &frame);
            l71_hook(env, ROME2_L71_HOOK_INPUT_PRIMARY, 0u, &frame);
            l71_listeners_notify(&mgr->secondary_60, 0x2cu, &mgr->total_ms_c0, 1);
            l71_hook(env, ROME2_L71_HOOK_INPUT_SECONDARY, 0u, &frame);
            l71_notify(top, 0x20u, &frame.dt_s_08);
            l71_step_loop(mgr, globals, env, top);
            mgr->pop_request_cf = 0u;
        }
    }
    if (mgr->loading_c8 == 0u) {
        rome2_startup_frame_time16_32 render_frame;
        uint64_t render_elapsed;
        uint32_t render_ms;

        if (mgr->overlay_1b8 != 0u && globals->movie_skip_enabled != 0u && mgr->records_7c != NULL) {
            for (i = 0u; i < mgr->records_count_78; i++) {
                if (mgr->records_7c[i][0] == 0u && mgr->records_7c[i][1] == 0u && mgr->movie != NULL) {
                    rome2_l71_iface_call_slot14_if_slot28(mgr->movie);
                }
            }
        }
        mgr->records_count_78 = 0u;
        mgr->events_count_84 = 0u;
        mgr->events_count_90 = 0u;
        mgr->records_count_a8 = 0u;
        render_elapsed = l71_now(env);
        render_elapsed = (globals->fixed_fps != 0u) ? 0u : render_elapsed - globals->last_us;
        render_ms = rome2_startup_u64_us_to_ms_112e2c20(render_elapsed);
        if (render_ms > ROME2_L71_FRAME_MS_CAP) {
            render_ms = ROME2_L71_FRAME_MS_CAP;
        }
        render_ms = rome2_l71_scale_frame_ms(render_ms, globals->time_scale);
        render_frame.total_ms_00 = mgr->total_ms_c0;
        render_frame.dt_ms_04 = dt_ms;
        render_frame.total_s_08 = (float)(double)mgr->total_ms_c0 * 0.001f;
        render_frame.dt_s_0c = frame.dt_s_08;
        if (mgr->pop_request_cf == 0u && mgr->handlers_2c.count != 0u && mgr->render_blocked_d3 == 0u) {
            l71_render(mgr, globals, env, top, &render_frame, render_ms);
        }
    }
    if (l71_query(env, ROME2_L71_QUERY_DEVICE_IDLE) != 0u) {
        l71_hook(env, ROME2_L71_HOOK_SLEEP, 5u, NULL);
    }
    return (uint8_t)(mgr->handlers_2c.count == 0u);
}

/* ---- 0x100ec5c0 ---- */

size_t rome2_l71_format_fps_line(char *out, size_t out_size, uint32_t frames, uint32_t seconds) {
    float inverse;
    float value;
    int written;

    if (out == NULL || out_size == 0u) {
        return 0u;
    }
    out[0] = '\0';
    if (seconds == 0u) {
        return 0u;                               /* the original writes no line for a zero count */
    }
    inverse = 1.0f / (float)(double)seconds;
    value = (float)(double)frames * inverse;
    /* The original lays out three fraction digits by hand from the CRT digit
     * string of 0x1168e713; host snprintf is not claimed digit-identical on ties. */
    written = snprintf(out, out_size, "%.3f\r\n", (double)value);
    if (written < 0 || (size_t)written >= out_size) {
        out[0] = '\0';
        return 0u;
    }
    return (size_t)written;
}

uint32_t rome2_l71_app_frame_step(
    rome2_l71_app *app, rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env) {
    if (app == NULL || mgr == NULL || globals == NULL || env == NULL) {
        return 2u;
    }
    if (l71_query(env, ROME2_L71_QUERY_QUIT_PUMP) != 0u) {
        return 2u;
    }
    for (;;) {
        uint32_t cap = 0u;

        if (l71_query(env, ROME2_L71_QUERY_WINDOW_ALIVE) == 0u) {
            return 2u;
        }
        if (l71_query(env, ROME2_L71_QUERY_POWER_SAVE) != 0u) {
            cap = ROME2_L71_POWER_SAVE_CAP;
        }
        if (mgr->overlay_1b8 != 0u || l71_query(env, ROME2_L71_QUERY_DEVICE_SLOT3FC) != 0u) {
            cap = app->overlay_cap;
        }
        if (app->forced_cap != 0u) {
            cap = app->forced_cap;
        }
        if (cap == 0u ||
            rome2_startup_u64_us_to_ms_112e2c20(l71_now(env) - app->last_frame_us_8a0) >= 1000u / cap) {
            break;
        }
        if (l71_query(env, ROME2_L71_QUERY_QUIT_PUMP) != 0u) {
            return 2u;
        }
    }
    app->last_frame_us_8a0 = l71_now(env);
    l71_hook(env, ROME2_L71_HOOK_POLL_INPUT, 0u, NULL);
    if (rome2_l71_screen_mgr_frame_update(mgr, globals, env) != 0u) {
        return 2u;
    }
    if (app->fps_log_open_89c != 0u) {
        float start;
        float now_s;

        if (app->fps_frames_898 == -1) {
            app->fps_window_start_894 = rome2_startup_u64_us_to_seconds_112e2b00(l71_now(env));
            app->fps_frames_898 = 0;
        } else {
            app->fps_frames_898++;
        }
        now_s = rome2_startup_u64_us_to_seconds_112e2b00(l71_now(env));
        start = app->fps_window_start_894;
        if (now_s - start >= 1.0f) {
            uint32_t seconds = rome2_vfs_crt_ftoui3(now_s - start);
            uint32_t line;

            for (line = 0u; line < seconds; line++) {
                char text[72];

                if (rome2_l71_format_fps_line(text, sizeof(text), (uint32_t)app->fps_frames_898, seconds) != 0u) {
                    l71_hook(env, ROME2_L71_HOOK_FPS_LINE, 0u, text);
                }
            }
            app->fps_frames_898 = 0;
            app->fps_window_start_894 = (float)(double)seconds + start;
            if (l71_query(env, ROME2_L71_QUERY_TOP_SLOT50) != 0u && l71_query(env, ROME2_L71_QUERY_TOP_SLOT54) != 0u) {
                return 2u;
            }
            if (l71_query(env, ROME2_L71_QUERY_TOP_SLOT4C) != 0u) {
                return 2u;
            }
        }
    }
    if (app->first_frame_pending != 0u) {
        float seconds_f;
        uint32_t whole;

        app->first_frame_pending = 0u;
        seconds_f = rome2_startup_u64_us_to_seconds_112e2b00(l71_now(env));
        whole = (seconds_f >= 0.0f && seconds_f < 4294967296.0f) ? (uint32_t)seconds_f : 0u;
        if (l71_query(env, ROME2_L71_QUERY_BENCHMARK_NAME_SET) != 0u) {
            /* 0x100edcd0 does not return; an INT3 follows the call. */
            l71_hook(env, ROME2_L71_HOOK_BENCHMARK_EXIT, whole, NULL);
            return 2u;
        } else {
            char text[192];

            (void)snprintf(
                text, sizeof(text),
                "\n\n*******************************************\n***  TIME TO FIRST FRAME: %u"
                "seconds\n*******************************************\n\n\n",
                (unsigned)whole);
            l71_hook(env, ROME2_L71_HOOK_LOG, 0u, text);
        }
    }
    return (l71_query(env, ROME2_L71_QUERY_VFS_QUIT_FLAG) != 0u) ? 2u : 0u;
}

/* ---- 0x100ed3c0 ---- */

void rome2_l71_app_run(
    rome2_l71_app *app, const rome2_l71_env *env, uint32_t (*frame_step)(void *user), void *step_user) {
    if (app == NULL || env == NULL || frame_step == NULL) {
        return;
    }
    app->started_flags[0] = 1u;
    app->started_flags[1] = 1u;
    l71_hook(env, ROME2_L71_HOOK_APP_CONSTRUCT, 0u, NULL);
    for (;;) {
        uint32_t result;

        l71_hook(env, ROME2_L71_HOOK_APP_INIT, 0u, NULL);
        l71_hook(env, ROME2_L71_HOOK_LOG, 0u, "Init completed");
        l71_hook(env, ROME2_L71_HOOK_CLOCK_MODE, 0u, NULL);
        app->last_frame_us_8a0 = l71_now(env);
        do {
            result = frame_step(step_user);
        } while (result != 1u && result != 2u);
        if (result == 2u) {
            break;
        }
        l71_hook(env, ROME2_L71_HOOK_APP_RESTART, 0u, NULL);
    }
    l71_hook(env, ROME2_L71_HOOK_APP_DESTROY, 0u, NULL);
}

/* ---- 0x100edd70 ---- */

int rome2_l71_command_line_disables_exception_handler(const uint16_t *command_line) {
    static const char expected[] = "-no_exception_handler";
    size_t i;

    if (command_line == NULL) {
        return 0;
    }
    for (i = 0u; i < sizeof(expected); i++) {    /* includes the terminator */
        if (command_line[i] != (uint16_t)(unsigned char)expected[i]) {
            return 0;
        }
    }
    return 1;
}

uint8_t rome2_l71_entry_point(
    const rome2_l71_entry_env *env, rome2_l71_crash_ctx *ctx, const uint16_t *command_line,
    uint32_t arg4, uintptr_t *reserve_slot, uint32_t arg6, uint32_t arg7, const uint8_t *exit_flag_119f3144) {
    int guarded;

    if (env == NULL || ctx == NULL) {
        return 0u;
    }
    l71_hook(&env->base, ROME2_L71_HOOK_STARTUP_INFO, 0u, NULL);
    l71_hook(&env->base, ROME2_L71_HOOK_COM, 1u, NULL);
    ctx->arg4_60 = arg4;
    ctx->reserve_slot_64 = reserve_slot;
    ctx->arg6_58 = arg6;
    ctx->arg7_5c = arg7;
    if (ctx->reserve_slot_64 != NULL && *ctx->reserve_slot_64 != 0u) {
        l71_hook(&env->base, ROME2_L71_HOOK_RELEASE_RESERVE, 0u, ctx->reserve_slot_64);
        *ctx->reserve_slot_64 = 0u;
    }
    if (env->game_explorer_create != NULL && env->game_explorer_create(env->base.user) >= 0) {
        int32_t allowed = 0;

        if (env->game_explorer_verify == NULL || env->game_explorer_verify(env->base.user, &allowed) < 0) {
            l71_hook(&env->base, ROME2_L71_HOOK_ACCESS_DENIED_DIALOG, 0x67u, NULL);
        }
        if (allowed == 0) {
            l71_hook(&env->base, ROME2_L71_HOOK_COM, 0u, NULL);
            return 0u;
        }
    }
    guarded = !rome2_l71_command_line_disables_exception_handler(command_line);
    if (guarded) {
        l71_hook(&env->base, ROME2_L71_HOOK_INVALID_PARAMETER_HANDLER, 0u, NULL);
    }
    if (env->run != NULL) {
        env->run(env->base.user, guarded);
    }
    l71_hook(&env->base, ROME2_L71_HOOK_KEEPER, 1u, NULL);
    l71_hook(&env->base, ROME2_L71_HOOK_COM, 0u, NULL);
    return (exit_flag_119f3144 != NULL) ? *exit_flag_119f3144 : 0u;
}
