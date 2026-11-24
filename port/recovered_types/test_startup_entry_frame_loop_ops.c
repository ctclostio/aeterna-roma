#include "startup_entry_frame_loop_ops.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "startup_input_msg_console_ops.h"

static int g_checks = 0;
#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAILED at line %d: %s\n", __LINE__, #cond); \
        return 1; \
    } \
    g_checks++; \
} while (0)

#define H(name) ROME2_L71_HOOK_##name
#define Q(name) ROME2_L71_QUERY_##name
#define LOG_CAP 64u
#define QUERY_CAP 12u

/* ---- environment double ---- */

typedef struct test_env {
    uint32_t ids[LOG_CAP];
    uint32_t args[LOG_CAP];
    uint32_t n;
    uint64_t now;
    uint64_t now_step;
    uint64_t counter;
    uint8_t answers[QUERY_CAP];
    uint32_t asked[QUERY_CAP];
    char last_log[224];
    char fps_text[32];
    uint32_t fps_lines;
    rome2_startup_frame_time12_32 input_frame;
    rome2_l71_screen_mgr *overlay_mgr;
    uintptr_t released;
    int32_t create_hr;
    int32_t verify_hr;
    int32_t allowed;
    uint32_t verify_calls;
    uint32_t run_calls;
    int run_guarded;
} test_env;

static uint64_t env_now(void *user) {
    test_env *te = (test_env *)user;
    uint64_t value = te->now;

    te->now += te->now_step;
    return value;
}

static uint64_t env_counter(void *user) {
    return ((test_env *)user)->counter;
}

static void env_hook(void *user, uint32_t id, uint32_t arg, const void *data) {
    test_env *te = (test_env *)user;

    if (te->n < LOG_CAP) {
        te->ids[te->n] = id;
        te->args[te->n] = arg;
        te->n++;
    }
    if (id == H(LOG) && data != NULL) {
        (void)snprintf(te->last_log, sizeof(te->last_log), "%s", (const char *)data);
    } else if (id == H(FPS_LINE) && data != NULL) {
        te->fps_lines++;
        (void)snprintf(te->fps_text, sizeof(te->fps_text), "%s", (const char *)data);
    } else if (id == H(INPUT_UPDATE) && data != NULL) {
        te->input_frame = *(const rome2_startup_frame_time12_32 *)data;
    } else if (id == H(OVERLAY_POP) && te->overlay_mgr != NULL) {
        te->overlay_mgr->overlay_1b8 = 0u;
    } else if (id == H(RELEASE_RESERVE) && data != NULL) {
        te->released = *(const uintptr_t *)data;
    }
}

static uint8_t env_query(void *user, uint32_t id) {
    test_env *te = (test_env *)user;

    if (id >= QUERY_CAP) {
        return 0u;
    }
    te->asked[id]++;
    return te->answers[id];
}

static void env_init(rome2_l71_env *env, test_env *te) {
    memset(te, 0, sizeof(*te));
    env->user = te;
    env->now_us = env_now;
    env->counter = env_counter;
    env->hook = env_hook;
    env->query = env_query;
}

static int hooks_are(const test_env *te, const uint32_t *want, uint32_t n) {
    return te->n == n && memcmp(te->ids, want, (size_t)n * sizeof(*want)) == 0;
}

static uint32_t hook_count(const test_env *te, uint32_t id) {
    uint32_t i;
    uint32_t count = 0u;

    for (i = 0u; i < te->n && i < LOG_CAP; i++) {
        if (te->ids[i] == id) {
            count++;
        }
    }
    return count;
}

static uint32_t hook_arg(const test_env *te, uint32_t id) {
    uint32_t i;

    for (i = 0u; i < te->n && i < LOG_CAP; i++) {
        if (te->ids[i] == id) {
            return te->args[i];
        }
    }
    return 0xffffffffu;
}

static int slots_are(const uint32_t *slots, uint32_t n_slots, const uint32_t *want, uint32_t n) {
    return n_slots == n && memcmp(slots, want, (size_t)n * sizeof(*want)) == 0;
}

/* ---- handler / factory / listener doubles ---- */

#define SLOT_CAP 24u

typedef struct test_handler {
    rome2_l71_handler base;
    rome2_l71_step_result script[2];
    uint32_t script_len;
    uint32_t script_pos;
    uint32_t step_calls;
    uint32_t slots[SLOT_CAP];
    uint32_t n_slots;
    rome2_l71_factory *request_factory;
    uint32_t request_slot;
    uint32_t request_arg;
    int has_scale;
    float scale;
} test_handler;

static void h_step(rome2_l71_handler *self, rome2_l71_step_result *out) {
    test_handler *h = (test_handler *)self->user;

    h->step_calls++;
    if (h->script_len != 0u && h->script_pos < 2u) {
        *out = h->script[h->script_pos];
        if (h->script_pos + 1u < h->script_len) {
            h->script_pos++;
        }
    }
}

static rome2_l71_factory *h_request(rome2_l71_handler *self, uint32_t slot, uint32_t arg) {
    test_handler *h = (test_handler *)self->user;

    h->request_slot = slot;
    h->request_arg = arg;
    return h->request_factory;
}

static int h_time_scale(rome2_l71_handler *self, float *out) {
    test_handler *h = (test_handler *)self->user;

    if (!h->has_scale) {
        return 0;
    }
    *out = h->scale;
    return 1;
}

static void h_notify(rome2_l71_handler *self, uint32_t slot, const void *arg) {
    test_handler *h = (test_handler *)self->user;

    (void)arg;
    if (h->n_slots < SLOT_CAP) {
        h->slots[h->n_slots++] = slot;
    }
}

static void handler_init(test_handler *h) {
    memset(h, 0, sizeof(*h));
    h->base.step = h_step;
    h->base.request = h_request;
    h->base.time_scale = h_time_scale;
    h->base.notify = h_notify;
    h->base.user = h;
}

typedef struct test_factory {
    rome2_l71_factory base;
    rome2_l71_handler *product;
    uint8_t create_flag;
    uint32_t create_calls;
    uint32_t slots[4];
    uint32_t n_slots;
} test_factory;

static rome2_l71_handler *f_create(rome2_l71_factory *self, uint8_t flag) {
    test_factory *f = (test_factory *)self->user;

    f->create_flag = flag;
    f->create_calls++;
    return f->product;
}

static void f_notify(rome2_l71_factory *self, uint32_t slot) {
    test_factory *f = (test_factory *)self->user;

    if (f->n_slots < 4u) {
        f->slots[f->n_slots++] = slot;
    }
}

static void factory_init(test_factory *f, rome2_l71_handler *product) {
    memset(f, 0, sizeof(*f));
    f->base.create = f_create;
    f->base.notify = f_notify;
    f->base.user = f;
    f->product = product;
}

typedef struct test_listener {
    rome2_l71_listener base;
    uint32_t slots[8];
    uint32_t n_slots;
    rome2_startup_frame_time16_32 frame;
    uint32_t total_ms;
    uint32_t render_ms;
    rome2_l71_handler *render_top;
} test_listener;

static void li_notify(rome2_l71_listener *self, uint32_t slot, const void *arg) {
    test_listener *l = (test_listener *)self->user;

    if (l->n_slots < 8u) {
        l->slots[l->n_slots++] = slot;
    }
    if (arg == NULL) {
        return;
    }
    if (slot == 0x0cu || slot == 0x10u) {
        l->frame = *(const rome2_startup_frame_time16_32 *)arg;
    } else if (slot == 0x2cu) {
        l->total_ms = *(const uint32_t *)arg;
    } else if (slot == 0x04u) {
        const rome2_l71_render_args *render = (const rome2_l71_render_args *)arg;

        l->render_ms = render->render_ms;
        l->render_top = render->top;
        l->frame = *render->frame;
    }
}

static void listener_init(test_listener *l, uint8_t enabled) {
    memset(l, 0, sizeof(*l));
    l->base.enabled_10 = enabled;
    l->base.notify = li_notify;
    l->base.user = l;
}

typedef struct iface_log {
    uint32_t slot28_calls;
    uint32_t slot14_calls;
    uint32_t slot08_calls;
    uint8_t slot28_result;
} iface_log;

static uint8_t iface_slot28(void *user) {
    iface_log *log = (iface_log *)user;

    log->slot28_calls++;
    return log->slot28_result;
}

static void iface_slot14(void *user) {
    ((iface_log *)user)->slot14_calls++;
}

static void iface_slot08(void *user) {
    ((iface_log *)user)->slot08_calls++;
}

static void iface_init(rome2_l71_iface *iface, rome2_l71_iface_holder *holder, iface_log *log) {
    memset(log, 0, sizeof(*log));
    iface->slot28 = iface_slot28;
    iface->slot14 = iface_slot14;
    iface->slot08 = iface_slot08;
    iface->user = log;
    holder->iface_14 = iface;
}

static void count_call(void *user) {
    (*(uint32_t *)user)++;
}

typedef struct toggle_log {
    uint32_t calls;
    uint8_t last;
    uint8_t result;
} toggle_log;

static uint8_t toggle_set(rome2_l71_toggle *self, uint8_t enable) {
    toggle_log *log = (toggle_log *)self->user;

    log->calls++;
    log->last = enable;
    return log->result;
}

static void entry_init(rome2_l71_ui_entry *entry, const char *name, uint32_t *destroyed) {
    memset(entry, 0, sizeof(*entry));
    entry->owner_name = name;
    entry->destroy_owner = count_call;
    entry->user = destroyed;
}

static float read_f(const uint8_t *object, size_t offset) {
    float value;

    memcpy(&value, object + offset, sizeof(value));
    return value;
}

static void write_f(uint8_t *object, size_t offset, float value) {
    memcpy(object + offset, &value, sizeof(value));
}

static void globals_init(rome2_l71_globals *globals, uint32_t fixed_fps) {
    memset(globals, 0, sizeof(*globals));
    globals->fixed_fps = fixed_fps;
    globals->time_scale = 1.0f;
}

/* ---- 0x104274b0 / 0x112ac410 / 0x112e2bf0 / 0x10cb84x0 / 0x100f6940 / 0x10114ee0 ---- */

static int test_scalar_helpers(void) {
    rome2_startup_u64_pair8_32 a;
    rome2_startup_u64_pair8_32 b;
    rome2_startup_u64_pair8_32 sum;
    rome2_l71_globals globals;
    uint8_t obj[0x34];

    CHECK(rome2_l71_u64_pair_ctor(&a, 0xfffffff0u, 1u) == &a && a.lo_00 == 0xfffffff0u && a.hi_04 == 1u);
    (void)rome2_l71_u64_pair_ctor(&b, 0x20u, 2u);
    CHECK(rome2_l71_u64_add(&sum, &a, &b) == &sum && sum.lo_00 == 0x10u && sum.hi_04 == 4u);

    (void)rome2_l71_u64_pair_ctor(&a, 1000000u, 0u);
    CHECK(rome2_l71_us_to_scaled_ms(&a, 1.0f) == 1000u && rome2_l71_us_to_scaled_ms(&a, 0.0f) == 0u);
    (void)rome2_l71_u64_pair_ctor(&a, 1500000u, 0u);
    CHECK(rome2_l71_us_to_scaled_ms(&a, 2.0f) == 3000u);
    (void)rome2_l71_u64_pair_ctor(&a, 999999u, 0u);
    CHECK(rome2_l71_us_to_scaled_ms(&a, 1.0f) == 999u);
    (void)rome2_l71_u64_pair_ctor(&a, 0u, 1u);
    CHECK(rome2_l71_us_to_scaled_ms(&a, 1.0f) == 4294967u && rome2_l71_us_to_scaled_ms(NULL, 1.0f) == 0u);

    memset(obj, 0, sizeof(obj));
    write_f(obj, 0x0cu, 2.0f);
    write_f(obj, 0x10u, 10.0f);
    rome2_l71_time_accum_0c(obj, 5.0f, 0.5f);
    CHECK(read_f(obj, 0x0cu) == 5.0f && read_f(obj, 0x10u) == 11.5f && read_f(obj, 0x14u) == 0.0f);
    memset(obj, 0, sizeof(obj));
    write_f(obj, 0x28u, 1.0f);
    rome2_l71_time_accum_28(obj, 3.0f, 2.0f);
    CHECK(read_f(obj, 0x28u) == 3.0f && read_f(obj, 0x2cu) == 4.0f && read_f(obj, 0x30u) == 0.0f);
    memset(obj, 0, sizeof(obj));
    write_f(obj, 0x30u, -1.0f);
    rome2_l71_time_accum_2c(obj, 4.0f, 0.25f);
    CHECK(read_f(obj, 0x2cu) == 4.0f && read_f(obj, 0x30u) == 0.0f && read_f(obj, 0x28u) == 0.0f);

    CHECK(rome2_l71_fp_control_is_engine_default(0x000a001fu) &&
          rome2_l71_fp_control_is_engine_default(0x100a003fu));
    CHECK(!rome2_l71_fp_control_is_engine_default(0x0009001fu) &&
          !rome2_l71_fp_control_is_engine_default(0x000a011fu));

    globals_init(&globals, 0u);
    rome2_l71_set_wait_params(&globals, ROME2_L71_WAIT_BUSY, 0.0f);
    CHECK(globals.wait_value == 10000u && globals.wait_seconds == 0.0f);
    rome2_l71_set_wait_params(&globals, 0u, ROME2_L71_WAIT_IDLE_SECONDS);
    CHECK(globals.wait_value == 0u && globals.wait_seconds == 8.0f);

    CHECK(rome2_l71_scale_frame_ms(16u, 1.0f) == 16u && rome2_l71_scale_frame_ms(16u, 2.0f) == 32u);
    CHECK(rome2_l71_scale_frame_ms(33u, 0.5f) == 17u && rome2_l71_scale_frame_ms(16u, 0.5f) == 8u);
    CHECK(rome2_l71_scale_frame_ms(16u, 0.0f) == 0u && rome2_l71_scale_frame_ms(16u, nanf("")) == 0x80000000u);
    return 0;
}

/* ---- 0x100d9d90 / 0x10c8fff0 / 0x10c914d0 / 0x10cb0440 / 0x100d6cc0 ---- */

static int test_container_helpers(void) {
    rome2_l71_ptr_vec vec;
    rome2_l71_ptr_vec big;
    rome2_l71_u64_vec samples;
    rome2_l71_screen_mgr mgr;
    rome2_l71_iface iface;
    rome2_l71_iface_holder holder;
    rome2_l71_iface_holder empty_holder;
    rome2_l71_advice_state advice;
    rome2_l71_ui_entry entries[4];
    rome2_l71_ptr_vec list;
    iface_log ilog;
    uint32_t issued = 0u;
    uint32_t destroyed = 0u;
    int values[5];
    uint32_t i;

    memset(&vec, 0, sizeof(vec));
    memset(values, 0, sizeof(values));
    for (i = 0u; i < 5u; i++) {
        CHECK(rome2_l71_ptr_vec_push_back(&vec, &values[i]) == 1);
    }
    CHECK(vec.capacity == 8u && vec.count == 5u && vec.data[0] == &values[0] && vec.data[4] == &values[4]);
    big.capacity = 0x40000000u;
    big.count = 0x40000000u;
    big.data = vec.data;
    CHECK(rome2_l71_ptr_vec_push_back(&big, &values[0]) == 0 && big.capacity == 0x40000000u &&
          big.data == vec.data && rome2_l71_ptr_vec_push_back(NULL, &values[0]) == 0);
    rome2_l71_ptr_vec_free(&vec);
    CHECK(vec.data == NULL && vec.count == 0u && vec.capacity == 0u);

    memset(&samples, 0, sizeof(samples));
    for (i = 0u; i < 3u; i++) {
        CHECK(rome2_l71_u64_vec_push(&samples, 0x100000000ull + i) == 1);
    }
    CHECK(samples.capacity == 4u && samples.count == 3u && samples.data[2] == 0x100000002ull);
    free(samples.data);
    samples.capacity = 0x00010000u;              /* initial image state with no buffer yet */
    samples.count = 0u;
    samples.data = NULL;
    CHECK(rome2_l71_u64_vec_push(&samples, 1u) == 0 && samples.count == 0u);

    memset(&mgr, 0, sizeof(mgr));
    for (i = 0u; i < 51u; i++) {
        rome2_l71_frame_ring_push(&mgr, 100u + i);
    }
    CHECK(mgr.frame_count_1b0 == 50u && mgr.frame_index_1b4 == 1u && mgr.frame_ms_e8[0] == 150u &&
          mgr.frame_ms_e8[49] == 149u);

    iface_init(&iface, &holder, &ilog);
    empty_holder.iface_14 = NULL;
    rome2_l71_iface_call_slot14_if_slot28(&holder);
    rome2_l71_iface_call_slot14_if_slot28(&empty_holder);
    CHECK(ilog.slot28_calls == 1u && ilog.slot14_calls == 0u);
    ilog.slot28_result = 1u;
    rome2_l71_iface_call_slot14_if_slot28(&holder);
    rome2_l71_iface_call_slot08_if_present(&holder);
    rome2_l71_iface_call_slot08_if_present(&empty_holder);
    CHECK(ilog.slot28_calls == 2u && ilog.slot14_calls == 1u && ilog.slot08_calls == 1u);

    memset(&advice, 0, sizeof(advice));
    advice.issue_pending = count_call;
    advice.user = &issued;
    CHECK(rome2_l71_advice_set_enabled(&advice, 1u) == 0 && advice.enabled == 1u && issued == 0u);
    advice.enabled = 0u;
    advice.pending_count = 3u;
    CHECK(rome2_l71_advice_set_enabled(&advice, 1u) == 1 && issued == 1u);
    CHECK(rome2_l71_advice_set_enabled(&advice, 1u) == 0 && issued == 1u);
    CHECK(rome2_l71_advice_set_enabled(&advice, 0u) == 0 && advice.enabled == 0u && issued == 1u &&
          rome2_l71_advice_set_enabled(NULL, 1u) == 0);

    entry_init(&entries[0], "UIs/menu", &destroyed);
    entry_init(&entries[1], "data/UIs/x", &destroyed);
    entry_init(&entries[2], "UIs/hud", &destroyed);
    entry_init(&entries[3], NULL, &destroyed);
    memset(&list, 0, sizeof(list));
    for (i = 0u; i < 4u; i++) {
        CHECK(rome2_l71_ptr_vec_push_back(&list, &entries[i]) == 1);
    }
    CHECK(rome2_l71_remove_ui_entries(&list, "UIs/") == 2u && list.count == 2u && destroyed == 2u &&
          list.data[0] == &entries[1] && list.data[1] == &entries[3]);
    CHECK(rome2_l71_remove_ui_entries(&list, NULL) == 2u && list.count == 0u && destroyed == 4u);
    rome2_l71_ptr_vec_free(&list);
    return 0;
}

/* ---- 0x100dbf80: empty stack, counter samples and enable-state sync ---- */

static int test_frame_empty(void) {
    static const uint32_t want[6] = {
        H(REMOTE_POLL), H(INPUT_UPDATE), H(INPUT_PRIMARY), H(INPUT_SECONDARY), H(FP_PRECISION), H(SLEEP)};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    rome2_l71_toggle toggles[3];
    rome2_l71_ui_entry entries[3];
    toggle_log logs[3];
    uint32_t destroyed = 0u;
    uint32_t i;

    env_init(&env, &te);
    te.now = 1000000u;
    te.counter = 1000u;
    te.answers[Q(DEVICE_IDLE)] = 1u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 0u);
    globals.sample_counter = 1u;
    globals.counter_base = 400u;
    memset(logs, 0, sizeof(logs));
    memset(toggles, 0, sizeof(toggles));
    for (i = 0u; i < 3u; i++) {
        entry_init(&entries[i], "x", &destroyed);
        toggles[i].set = toggle_set;
        toggles[i].user = &logs[i];
        entries[i].handler_04 = &toggles[i];
        CHECK(rome2_l71_ptr_vec_push_back(&mgr.ui_entries_20, &entries[i]) == 1);
    }
    entries[0].wanted_00 = 1u;                   /* off -> on, accepted */
    logs[0].result = 1u;
    toggles[1].enabled_10 = 1u;                  /* on -> off, refused */
    entries[2].wanted_00 = 1u;                   /* already on */
    toggles[2].enabled_10 = 1u;

    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 1u);
    CHECK(hooks_are(&te, want, 6u) && te.args[5] == 5u);
    CHECK(toggles[0].enabled_10 == 1u && logs[0].calls == 1u && logs[0].last == 1u);
    CHECK(toggles[1].enabled_10 == 1u && logs[1].calls == 1u && logs[1].last == 0u && logs[2].calls == 0u);
    CHECK(globals.samples.count == 1u && globals.samples.capacity == 1u && globals.samples.data[0] == 600u);
    CHECK(globals.last_us_valid == 1u && globals.last_us == 1000000u && mgr.frame_count_1b0 == 1u &&
          mgr.frame_index_1b4 == 1u && mgr.total_ms_c0 == 0u);
    CHECK(rome2_l71_screen_mgr_frame_update(NULL, &globals, &env) == 1u);
    free(globals.samples.data);
    rome2_l71_ptr_vec_free(&mgr.ui_entries_20);
    return 0;
}

/* ---- 0x100dbf80: fixed-step frame, listener notification, time scale and accumulators ---- */

static int test_frame_notify(void) {
    static const uint32_t want[11] = {
        H(REMOTE_POLL), H(INPUT_UPDATE), H(INPUT_PRIMARY), H(INPUT_SECONDARY), H(FP_PRECISION), H(FP_PRECISION),
        H(DEVICE_FRAME), H(FP_PRECISION), H(DEVICE_PRESENT), H(DEVICE_FRAME), H(FP_PRECISION)};
    static const uint32_t want_h[5] = {0x30u, 0x20u, 0x64u, 0x74u, 0x80u};
    static const uint32_t want_secondary[2] = {0x2cu, 0x10u};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    test_handler h1;
    test_listener primary;
    test_listener listener;
    test_listener secondary;
    test_listener renderer;
    uint8_t a2c[0x34];
    uint8_t a0c[0x34];
    uint8_t a28[0x34];
    float s1;
    float s2;

    env_init(&env, &te);
    te.now = 5000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    memset(a2c, 0, sizeof(a2c));
    memset(a0c, 0, sizeof(a0c));
    memset(a28, 0, sizeof(a28));
    globals.accum_2c = a2c;
    globals.accum_0c = a0c;
    globals.accum_28 = a28;
    handler_init(&h1);
    h1.script_len = 1u;
    h1.script[0].advanced = 1u;
    h1.script[0].ms = 20u;
    h1.script[0].notify = 1u;
    listener_init(&primary, 0u);
    listener_init(&listener, 0u);
    listener_init(&secondary, 1u);
    listener_init(&renderer, 0u);
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &h1.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.primary_50, &primary.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.listeners_40, &listener.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.secondary_60, &secondary.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.renderers_b4, &renderer.base) == 1);

    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(hooks_are(&te, want, 11u) && te.args[4] == 1u && te.args[5] == 0u && te.args[6] == 1u &&
          te.args[7] == 0u && te.args[9] == 0u && te.args[10] == 1u);
    CHECK(mgr.total_ms_c0 == 20u && mgr.scaled_total_ms_c4 == 20u && mgr.frame_ms_e8[0] == 20u &&
          globals.last_us == 5020000u);
    CHECK(te.input_frame.total_ms_00 == 20u && te.input_frame.dt_ms_04 == 20u &&
          fabsf(te.input_frame.dt_s_08 - 0.02f) < 1.0e-6f);
    CHECK(slots_are(h1.slots, h1.n_slots, want_h, 5u) && h1.base.elapsed_ms_04 == 20u);
    CHECK(primary.n_slots == 1u && primary.slots[0] == 0x0cu && listener.n_slots == 1u &&
          listener.slots[0] == 0x0cu && listener.frame.total_ms_00 == 20u && listener.frame.dt_ms_04 == 20u);
    CHECK(slots_are(secondary.slots, secondary.n_slots, want_secondary, 2u) && secondary.total_ms == 20u);
    CHECK(renderer.n_slots == 1u && renderer.slots[0] == 0x04u && renderer.render_top == &h1.base &&
          renderer.render_ms == 0u && renderer.frame.total_ms_00 == 20u);
    s1 = rome2_startup_u64_us_to_seconds_112e2b00(5020000u);
    CHECK(read_f(a2c, 0x2cu) == s1 && read_f(a2c, 0x30u) == s1 && read_f(a0c, 0x0cu) == s1 &&
          read_f(a0c, 0x10u) == s1 && read_f(a28, 0x28u) == s1 && read_f(a28, 0x2cu) == s1);

    /* Second frame: engine time scale 2.0, handler scale 0.5 and the pending slot +0x58 notification. */
    te.n = 0u;
    globals.time_scale = 2.0f;
    h1.has_scale = 1;
    h1.scale = 0.5f;
    mgr.notify_d1 = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.total_ms_c0 == 60u && mgr.scaled_total_ms_c4 == 40u && mgr.frame_ms_e8[1] == 40u &&
          mgr.frame_count_1b0 == 2u && mgr.frame_index_1b4 == 2u);
    CHECK(mgr.notify_d1 == 0u && h1.n_slots == 11u && h1.slots[5] == 0x58u && h1.base.elapsed_ms_04 == 40u);
    CHECK(listener.frame.total_ms_00 == 40u && listener.frame.dt_ms_04 == 20u && secondary.total_ms == 60u &&
          te.input_frame.dt_ms_04 == 40u);
    s2 = rome2_startup_u64_us_to_seconds_112e2b00(5040000u);
    CHECK(read_f(a0c, 0x0cu) == s2 && fabsf(read_f(a0c, 0x10u) - (s1 + (s2 - s1) * 0.5f)) < 1.0e-5f);

    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    rome2_l71_ptr_vec_free(&mgr.primary_50);
    rome2_l71_ptr_vec_free(&mgr.listeners_40);
    rome2_l71_ptr_vec_free(&mgr.secondary_60);
    rome2_l71_ptr_vec_free(&mgr.renderers_b4);
    return 0;
}

/* ---- 0x100dbf80: 300 ms clamp, render interval and the capture flags ---- */

static int test_frame_clamp_render(void) {
    static const uint32_t want_first[4] = {0x30u, 0x20u, 0x7cu, 0x80u};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    test_handler hd;
    test_listener renderer;

    env_init(&env, &te);
    te.now = 2000000u;
    te.now_step = 7000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 0u);
    globals.last_us_valid = 1u;
    globals.last_us = 1000000u;
    globals.capture_request = 1u;
    globals.capture_name_length = 4u;
    globals.flag_cd = 1u;
    globals.flag_ce = 1u;
    globals.flag_8d0 = 1u;
    handler_init(&hd);
    listener_init(&renderer, 0u);
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &hd.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.renderers_b4, &renderer.base) == 1);

    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.total_ms_c0 == 300u && te.input_frame.dt_ms_04 == 300u && renderer.render_ms == 7u &&
          renderer.frame.dt_ms_04 == 300u && fabsf(renderer.frame.total_s_08 - 0.3f) < 1.0e-6f);
    CHECK(slots_are(hd.slots, hd.n_slots, want_first, 4u) && globals.capture_request == 0u &&
          globals.capture_name_length == 0u && globals.flag_cd == 0u && globals.flag_ce == 0u &&
          globals.flag_8d0 == 0u);

    te.n = 0u;
    globals.capture_name_length = 3u;
    globals.flag_cd = 1u;
    globals.flag_8d0 = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.total_ms_c0 == 314u && renderer.render_ms == 7u && hd.n_slots == 8u && hd.slots[6] == 0x78u &&
          globals.capture_name_length == 0u && globals.flag_cd == 0u && globals.flag_8d0 == 1u);
    CHECK(hook_count(&te, H(DEVICE_FRAME)) == 2u && hook_count(&te, H(DEVICE_PRESENT)) == 1u);

    te.n = 0u;
    mgr.render_blocked_d3 = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u &&
          hook_count(&te, H(DEVICE_FRAME)) == 0u && renderer.n_slots == 2u);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    rome2_l71_ptr_vec_free(&mgr.renderers_b4);
    return 0;
}

/* ---- 0x100dbf80: step code 1 pushes a handler; the load completes on the next frames ---- */

static int test_frame_push_transition(void) {
    static const uint32_t want[13] = {
        H(REMOTE_POLL), H(INPUT_UPDATE), H(INPUT_PRIMARY), H(INPUT_SECONDARY), H(FP_PRECISION), H(CLOCK_MODE),
        H(TEARDOWN), H(SOUND_EVENT), H(DEVICE_SLOT94), H(FP_PRECISION), H(LOG), H(LOG), H(CLOCK_MODE)};
    static const uint32_t want_h1[3] = {0x30u, 0x20u, 0x60u};
    static const uint32_t want_h2[3] = {0x30u, 0x20u, 0x80u};
    static const uint32_t want_factory[2] = {0x0cu, 0x00u};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    test_handler h1;
    test_handler h2;
    test_factory factory;
    test_listener primary;
    test_listener secondary;
    rome2_l71_ui_entry entries[2];
    rome2_l71_iface iface;
    rome2_l71_iface_holder movie;
    rome2_l71_advice_state advice;
    iface_log ilog;
    uint32_t destroyed = 0u;
    uint32_t issued = 0u;

    env_init(&env, &te);
    te.now = 1000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    handler_init(&h1);
    handler_init(&h2);
    factory_init(&factory, &h2.base);
    h1.script_len = 1u;
    h1.script[0].advanced = 1u;
    h1.script[0].ms = 5u;
    h1.script[0].again = 1u;
    h1.script[0].factory = &factory.base;
    h1.script[0].code = ROME2_L71_CODE_PUSH;
    listener_init(&primary, 0u);
    listener_init(&secondary, 0u);
    entry_init(&entries[0], "a", &destroyed);
    entry_init(&entries[1], "b", &destroyed);
    iface_init(&iface, &movie, &ilog);
    memset(&advice, 0, sizeof(advice));
    advice.enabled = 1u;
    advice.pending_count = 3u;
    advice.issue_pending = count_call;
    advice.user = &issued;
    mgr.movie = &movie;
    mgr.advice = &advice;
    mgr.has_sound = 1u;
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &h1.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.primary_50, &primary.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.secondary_60, &secondary.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.ui_entries_20, &entries[0]) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.ui_entries_20, &entries[1]) == 1);

    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(hooks_are(&te, want, 13u) && te.args[5] == 1u && te.args[7] == 0x814a7e77u && te.args[12] == 0u);
    CHECK(mgr.loading_c8 == 1u && mgr.reload_c9 == 1u && mgr.handlers_2c.count == 2u &&
          mgr.handlers_2c.data[1] == &h2.base && mgr.alloc_failures == 0u);
    CHECK(mgr.ui_entries_20.count == 0u && destroyed == 2u && mgr.primary_50.count == 0u &&
          mgr.secondary_60.count == 0u && ilog.slot08_calls == 1u);
    CHECK(primary.n_slots == 1u && primary.slots[0] == 0x08u && secondary.n_slots == 1u &&
          secondary.slots[0] == 0x08u);
    CHECK(slots_are(h1.slots, h1.n_slots, want_h1, 3u) && h1.base.elapsed_ms_04 == 5u && h1.step_calls == 1u);
    CHECK(slots_are(factory.slots, factory.n_slots, want_factory, 2u) && factory.create_flag == 1u &&
          factory.create_calls == 1u);
    CHECK(advice.enabled == 0u && issued == 0u && globals.wait_value == 0u && globals.wait_seconds == 8.0f &&
          strcmp(te.last_log, "Created new handler") == 0);

    te.n = 0u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.loading_c8 == 0u && hook_count(&te, H(OPEN_HANDLER)) == 1u && hook_count(&te, H(CLOCK_MODE)) == 2u &&
          hook_count(&te, H(DEVICE_PRESENT)) == 0u && mgr.present_delay_d4 == 1);
    CHECK(slots_are(h2.slots, h2.n_slots, want_h2, 3u) && h2.step_calls == 1u && h1.step_calls == 1u);
    te.n = 0u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u &&
          hook_count(&te, H(DEVICE_PRESENT)) == 1u && hook_count(&te, H(OPEN_HANDLER)) == 0u &&
          mgr.present_delay_d4 == 0);

    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    rome2_l71_ptr_vec_free(&mgr.primary_50);
    rome2_l71_ptr_vec_free(&mgr.secondary_60);
    rome2_l71_ptr_vec_free(&mgr.ui_entries_20);
    return 0;
}

/* ---- 0x100dbf80: step codes 5, 6 and 4, the pop request and the quit-all flag ---- */

static int test_frame_codes(void) {
    static const uint32_t want_top[4] = {0x30u, 0x20u, 0x60u, 0x04u};
    static const uint32_t want_mid[2] = {0x60u, 0x04u};
    static const uint32_t want_bottom[5] = {0x60u, 0x30u, 0x20u, 0x60u, 0x04u};
    static const uint32_t want_factory[2] = {0x0cu, 0x00u};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    test_handler a;
    test_handler b;
    test_handler c;
    test_handler z;
    test_factory factory;

    env_init(&env, &te);
    te.now = 1000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    handler_init(&a);
    handler_init(&b);
    handler_init(&c);
    c.script_len = 1u;
    c.script[0].code = ROME2_L71_CODE_KEEP_BOTTOM;
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &a.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &b.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &c.base) == 1);
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.handlers_2c.count == 1u && mgr.handlers_2c.data[0] == &a.base && mgr.reload_c9 == 1u &&
          hook_count(&te, H(DEVICE_SLOT94)) == 1u);
    CHECK(slots_are(c.slots, c.n_slots, want_top, 4u) && slots_are(b.slots, b.n_slots, want_mid, 2u) &&
          a.n_slots == 1u && a.slots[0] == 0x60u);

    te.n = 0u;
    a.script_len = 1u;
    a.script[0].code = ROME2_L71_CODE_CLEAR;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 1u);
    CHECK(mgr.handlers_2c.count == 0u && slots_are(a.slots, a.n_slots, want_bottom, 5u) &&
          hook_count(&te, H(DEVICE_FRAME)) == 0u);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);

    /* Code 4 replaces the top handler without the device reset. */
    env_init(&env, &te);
    te.now = 1000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    handler_init(&a);
    handler_init(&b);
    handler_init(&z);
    factory_init(&factory, &z.base);
    b.script_len = 1u;
    b.script[0].code = ROME2_L71_CODE_REPLACE_NO_RESET;
    b.script[0].factory = &factory.base;
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &a.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &b.base) == 1);
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.reload_c9 == 0u && hook_count(&te, H(DEVICE_SLOT94)) == 0u && mgr.handlers_2c.count == 2u &&
          mgr.handlers_2c.data[0] == &a.base && mgr.handlers_2c.data[1] == &z.base);
    CHECK(slots_are(b.slots, b.n_slots, want_top, 4u) && factory.create_flag == 0u &&
          slots_are(factory.slots, factory.n_slots, want_factory, 2u));

    /* The pop request skips the step call and pops the top handler. */
    te.n = 0u;
    mgr.pop_request_cf = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(z.step_calls == 0u && slots_are(z.slots, z.n_slots, want_top, 4u) && mgr.handlers_2c.count == 1u &&
          mgr.pop_request_cf == 0u && mgr.reload_c9 == 1u && factory.create_calls == 1u);

    /* The quit-all flag destroys every handler after one more step. */
    te.n = 0u;
    globals.quit_all = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 1u);
    CHECK(a.step_calls == 1u && mgr.handlers_2c.count == 0u && a.n_slots == 6u && a.slots[5] == 0x04u);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    return 0;
}

/* ---- 0x100dbf80: transition requests raised through the flag bytes ---- */

static int test_frame_requests(void) {
    static const uint32_t want[7] = {
        H(REMOTE_POLL), H(INPUT_UPDATE), H(CLOCK_MODE), H(TEARDOWN), H(FP_PRECISION), H(LOG), H(CLOCK_MODE)};
    static const uint32_t want_h[2] = {0x60u, 0x04u};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    test_handler h;
    test_handler n;
    test_handler m;
    test_factory f3;
    test_factory f4;
    rome2_l71_iface iface;
    rome2_l71_iface_holder movie;
    iface_log ilog;

    env_init(&env, &te);
    te.now = 1000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    handler_init(&h);
    handler_init(&n);
    handler_init(&m);
    factory_init(&f3, &n.base);
    factory_init(&f4, &m.base);
    iface_init(&iface, &movie, &ilog);
    mgr.movie = &movie;
    h.request_factory = &f3.base;
    mgr.request_cb[0] = 1u;
    mgr.request_cb[2] = 1u;
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &h.base) == 1);

    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(hooks_are(&te, want, 7u) && strcmp(te.last_log, "After create_new_handler") == 0);
    CHECK(h.request_slot == 0x40u && h.request_arg == 1u && ilog.slot08_calls == 0u && mgr.loading_c8 == 1u &&
          mgr.reload_c9 == 0u);
    CHECK(mgr.handlers_2c.count == 1u && mgr.handlers_2c.data[0] == &n.base && f3.create_flag == 0u &&
          f3.n_slots == 1u && f3.slots[0] == 0x00u && slots_are(h.slots, h.n_slots, want_h, 2u));
    CHECK(mgr.request_cb[0] == 0u && mgr.request_cb[2] == 0u && mgr.request_d0 == 0u);

    /* A request the top handler answers with no factory only clears the flags. */
    mgr.request_d0 = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(n.request_slot == 0x48u && mgr.request_d0 == 0u && mgr.loading_c8 == 0u && n.step_calls == 1u);
    mgr.request_cb[3] = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(n.request_slot == 0x44u && mgr.request_cb[3] == 0u && mgr.handlers_2c.count == 1u);

    /* Flag +0xcc keeps the reload flag and, with +0xcb clear, stops the movie interface. */
    n.request_factory = &f4.base;
    mgr.request_cb[1] = 1u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(n.request_slot == 0x40u && n.request_arg == 0u && f4.create_flag == 1u && ilog.slot08_calls == 1u &&
          mgr.handlers_2c.count == 1u && mgr.handlers_2c.data[0] == &m.base);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    return 0;
}

/* ---- 0x100dbf80: the 'UIs/' leave step and the video overlay path ---- */

static int test_frame_leave_ui_overlay(void) {
    static const uint32_t want_u[6] = {0x30u, 0x20u, 0x10u, 0x68u, 0x74u, 0x80u};
    static const uint32_t want_overlay[9] = {
        H(REMOTE_POLL), H(INPUT_UPDATE), H(OVERLAY_POP), H(FP_PRECISION), H(DEVICE_FRAME), H(FP_PRECISION),
        H(DEVICE_PRESENT), H(DEVICE_FRAME), H(FP_PRECISION)};
    static const uint32_t records[3][12] = {{0u, 0u, 9u}, {1u, 0u}, {0u, 0u}};
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    test_handler u;
    test_handler v;
    test_listener secondary;
    rome2_l71_ui_entry entries[3];
    rome2_l71_iface iface;
    rome2_l71_iface_holder movie;
    iface_log ilog;
    uint32_t destroyed = 0u;
    uint32_t i;

    env_init(&env, &te);
    te.now = 1000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    handler_init(&u);
    u.script_len = 2u;
    u.script[0].leave_ui = 1u;
    u.script[1].advanced = 1u;
    u.script[1].ms = 3u;
    listener_init(&secondary, 1u);
    entry_init(&entries[0], "UIs/menu", &destroyed);
    entry_init(&entries[1], "data/UIs/x", &destroyed);
    entry_init(&entries[2], "UIs/hud", &destroyed);
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &u.base) == 1 &&
          rome2_l71_ptr_vec_push_back(&mgr.secondary_60, &secondary.base) == 1);
    for (i = 0u; i < 3u; i++) {
        CHECK(rome2_l71_ptr_vec_push_back(&mgr.ui_entries_20, &entries[i]) == 1);
    }
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(slots_are(u.slots, u.n_slots, want_u, 6u) && u.step_calls == 2u && u.base.elapsed_ms_04 == 3u);
    CHECK(mgr.ui_entries_20.count == 1u && mgr.ui_entries_20.data[0] == &entries[1] && destroyed == 2u &&
          mgr.secondary_60.count == 0u && secondary.n_slots == 1u && secondary.slots[0] == 0x2cu);
    CHECK(hook_count(&te, H(FP_PRECISION)) == 5u && mgr.loading_c8 == 0u);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    rome2_l71_ptr_vec_free(&mgr.secondary_60);
    rome2_l71_ptr_vec_free(&mgr.ui_entries_20);

    env_init(&env, &te);
    te.now = 1000000u;
    memset(&mgr, 0, sizeof(mgr));
    globals_init(&globals, 50u);
    globals.movie_skip_enabled = 1u;
    handler_init(&v);
    iface_init(&iface, &movie, &ilog);
    ilog.slot28_result = 1u;
    mgr.movie = &movie;
    mgr.overlay_1b8 = 1u;
    mgr.records_7c = records;
    mgr.records_count_78 = 3u;
    mgr.events_count_84 = 5u;
    mgr.events_count_90 = 6u;
    mgr.records_count_a8 = 7u;
    mgr.request_cb[0] = 1u;
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &v.base) == 1);
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(hooks_are(&te, want_overlay, 9u) && v.step_calls == 0u && v.n_slots == 1u && v.slots[0] == 0x80u);
    CHECK(ilog.slot28_calls == 2u && ilog.slot14_calls == 2u && mgr.records_count_78 == 0u &&
          mgr.events_count_84 == 0u && mgr.events_count_90 == 0u && mgr.records_count_a8 == 0u &&
          mgr.request_cb[0] == 1u);

    /* Once 0x100dd4c0 drops the overlay the same frame steps the handler again. */
    te.overlay_mgr = &mgr;
    mgr.records_count_78 = 3u;
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u);
    CHECK(mgr.overlay_1b8 == 0u && v.step_calls == 1u && ilog.slot14_calls == 2u && mgr.request_cb[0] == 1u);
    CHECK(rome2_l71_screen_mgr_frame_update(&mgr, &globals, &env) == 0u && v.request_slot == 0x40u &&
          v.request_arg == 0u && mgr.request_cb[0] == 0u);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    return 0;
}

/* ---- 0x100ec5c0 ---- */

static int test_app_frame_step(void) {
    rome2_l71_env env;
    test_env te;
    rome2_l71_screen_mgr mgr;
    rome2_l71_globals globals;
    rome2_l71_app app;
    test_handler w;
    char line[16];

    CHECK(rome2_l71_format_fps_line(line, sizeof(line), 60u, 1u) == 8u && strcmp(line, "60.000\r\n") == 0);
    CHECK(rome2_l71_format_fps_line(line, sizeof(line), 90u, 2u) == 7u + 1u && strcmp(line, "45.000\r\n") == 0);
    CHECK(rome2_l71_format_fps_line(line, sizeof(line), 1u, 3u) == 7u && strcmp(line, "0.333\r\n") == 0);
    CHECK(rome2_l71_format_fps_line(line, sizeof(line), 60u, 0u) == 0u && line[0] == '\0' &&
          rome2_l71_format_fps_line(line, 4u, 60u, 1u) == 0u && rome2_l71_format_fps_line(NULL, 0u, 1u, 1u) == 0u);

    env_init(&env, &te);
    memset(&mgr, 0, sizeof(mgr));
    memset(&app, 0, sizeof(app));
    globals_init(&globals, 0u);
    handler_init(&w);
    CHECK(rome2_l71_ptr_vec_push_back(&mgr.handlers_2c, &w.base) == 1);

    te.answers[Q(QUIT_PUMP)] = 1u;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 2u && te.n == 0u);
    te.answers[Q(QUIT_PUMP)] = 0u;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 2u && te.n == 0u &&
          te.asked[Q(WINDOW_ALIVE)] == 1u);

    /* A forced 10 fps cap waits for 100 ms; the first presented frame logs the start-up time. */
    memset(te.asked, 0, sizeof(te.asked));
    te.answers[Q(WINDOW_ALIVE)] = 1u;
    te.now = 1030000u;
    te.now_step = 30000u;
    app.forced_cap = 10u;
    app.last_frame_us_8a0 = 1000000u;
    app.first_frame_pending = 1u;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 0u);
    CHECK(te.asked[Q(WINDOW_ALIVE)] == 4u && te.asked[Q(QUIT_PUMP)] == 4u && app.last_frame_us_8a0 == 1150000u &&
          hook_count(&te, H(POLL_INPUT)) == 1u);
    CHECK(app.first_frame_pending == 0u && strstr(te.last_log, "TIME TO FIRST FRAME: 1seconds\n") != NULL &&
          w.step_calls == 1u);

    /* Power-save cap of 30 fps is already satisfied; the VFS flag ends the loop. */
    te.n = 0u;
    te.answers[Q(VFS_QUIT_FLAG)] = 1u;
    te.answers[Q(POWER_SAVE)] = 1u;
    app.forced_cap = 0u;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 2u && te.asked[Q(WINDOW_ALIVE)] == 5u &&
          hook_count(&te, H(LOG)) == 0u && w.step_calls == 2u);

    /* With a benchmark name set the first frame leaves through the noreturn exit. */
    te.n = 0u;
    te.answers[Q(VFS_QUIT_FLAG)] = 0u;
    te.answers[Q(POWER_SAVE)] = 0u;
    te.answers[Q(BENCHMARK_NAME_SET)] = 1u;
    app.first_frame_pending = 1u;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 2u &&
          hook_count(&te, H(BENCHMARK_EXIT)) == 1u && hook_arg(&te, H(BENCHMARK_EXIT)) >= 1u &&
          hook_arg(&te, H(BENCHMARK_EXIT)) < 10u);

    /* FPS log: one line per elapsed whole second, then the top-handler quit queries. */
    te.n = 0u;
    te.answers[Q(BENCHMARK_NAME_SET)] = 0u;
    te.now = 10000000u;
    te.now_step = 0u;
    app.fps_log_open_89c = 1u;
    app.fps_frames_898 = -1;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 0u && app.fps_frames_898 == 0 &&
          te.fps_lines == 0u && fabsf(app.fps_window_start_894 - 10.0f) < 1.0e-4f);
    memset(te.asked, 0, sizeof(te.asked));
    te.now = 12500000u;
    te.answers[Q(TOP_SLOT50)] = 1u;
    te.answers[Q(TOP_SLOT4C)] = 1u;
    app.fps_frames_898 = 59;
    CHECK(rome2_l71_app_frame_step(&app, &mgr, &globals, &env) == 2u);
    CHECK(te.fps_lines == 2u && strcmp(te.fps_text, "30.000\r\n") == 0 && app.fps_frames_898 == 0 &&
          fabsf(app.fps_window_start_894 - 12.0f) < 1.0e-4f);
    CHECK(te.asked[Q(TOP_SLOT50)] == 1u && te.asked[Q(TOP_SLOT54)] == 1u && te.asked[Q(TOP_SLOT4C)] == 1u &&
          rome2_l71_app_frame_step(NULL, &mgr, &globals, &env) == 2u);
    rome2_l71_ptr_vec_free(&mgr.handlers_2c);
    return 0;
}

/* ---- 0x100ed3c0 ---- */

typedef struct step_script {
    uint32_t results[5];
    uint32_t pos;
} step_script;

static uint32_t scripted_step(void *user) {
    step_script *script = (step_script *)user;

    if (script->pos >= 5u) {
        return 2u;
    }
    return script->results[script->pos++];
}

static int test_app_run(void) {
    static const uint32_t want[9] = {
        H(APP_CONSTRUCT), H(APP_INIT), H(LOG), H(CLOCK_MODE), H(APP_RESTART), H(APP_INIT), H(LOG), H(CLOCK_MODE),
        H(APP_DESTROY)};
    rome2_l71_env env;
    test_env te;
    rome2_l71_app app;
    step_script script;

    env_init(&env, &te);
    te.now = 777u;
    memset(&app, 0, sizeof(app));
    memset(&script, 0, sizeof(script));
    script.results[2] = 1u;                      /* restart */
    script.results[4] = 2u;                      /* quit */
    rome2_l71_app_run(&app, &env, scripted_step, &script);
    CHECK(hooks_are(&te, want, 9u) && script.pos == 5u && strcmp(te.last_log, "Init completed") == 0);
    CHECK(app.started_flags[0] == 1u && app.started_flags[1] == 1u && app.last_frame_us_8a0 == 777u);
    te.n = 0u;
    rome2_l71_app_run(&app, &env, NULL, NULL);
    CHECK(te.n == 0u);
    return 0;
}

/* ---- 0x100edd70 ---- */

static int32_t ge_create(void *user) {
    return ((test_env *)user)->create_hr;
}

static int32_t ge_verify(void *user, int32_t *allowed) {
    test_env *te = (test_env *)user;

    te->verify_calls++;
    *allowed = te->allowed;
    return te->verify_hr;
}

static void ge_run(void *user, int guarded) {
    test_env *te = (test_env *)user;

    te->run_calls++;
    te->run_guarded = guarded;
}

static void widen(const char *text, uint16_t *out, size_t capacity) {
    size_t i;

    for (i = 0u; i + 1u < capacity && text[i] != '\0'; i++) {
        out[i] = (uint16_t)(unsigned char)text[i];
    }
    out[i] = 0u;
}

static int test_entry_point(void) {
    static const uint32_t want_guarded[6] = {
        H(STARTUP_INFO), H(COM), H(RELEASE_RESERVE), H(INVALID_PARAMETER_HANDLER), H(KEEPER), H(COM)};
    static const uint32_t want_denied[3] = {H(STARTUP_INFO), H(COM), H(COM)};
    static const uint32_t want_unguarded[5] = {
        H(STARTUP_INFO), H(COM), H(ACCESS_DENIED_DIALOG), H(KEEPER), H(COM)};
    rome2_l71_entry_env env;
    test_env te;
    rome2_l71_crash_ctx ctx;
    uint16_t command_line[40];
    uintptr_t reserve = (uintptr_t)0x12345000u;
    uint8_t exit_flag = 7u;

    widen("-no_exception_handler", command_line, 40u);
    CHECK(rome2_l71_command_line_disables_exception_handler(command_line) == 1);
    widen("-no_exception_handler ", command_line, 40u);
    CHECK(rome2_l71_command_line_disables_exception_handler(command_line) == 0);
    widen("-no_exception_handle", command_line, 40u);
    CHECK(rome2_l71_command_line_disables_exception_handler(command_line) == 0 &&
          rome2_l71_command_line_disables_exception_handler(NULL) == 0);
    widen("", command_line, 40u);
    CHECK(rome2_l71_command_line_disables_exception_handler(command_line) == 0);

    env_init(&env.base, &te);
    env.game_explorer_create = ge_create;
    env.game_explorer_verify = ge_verify;
    env.run = ge_run;
    memset(&ctx, 0, sizeof(ctx));

    /* CoCreateInstance failure skips the access check; the default command line installs the handler. */
    te.create_hr = -2147221164;                  /* REGDB_E_CLASSNOTREG */
    CHECK(rome2_l71_entry_point(&env, &ctx, command_line, 4u, &reserve, 6u, 7u, &exit_flag) == 7u);
    CHECK(hooks_are(&te, want_guarded, 6u) && te.args[1] == 1u && te.args[5] == 0u && te.args[4] == 1u);
    CHECK(te.released == (uintptr_t)0x12345000u && reserve == 0u && te.verify_calls == 0u && te.run_calls == 1u &&
          te.run_guarded == 1);
    CHECK(ctx.arg4_60 == 4u && ctx.arg6_58 == 6u && ctx.arg7_5c == 7u && ctx.reserve_slot_64 == &reserve);

    /* A successful check that reports no access leaves before the run loop. */
    te.n = 0u;
    te.create_hr = 0;
    te.verify_hr = 0;
    te.allowed = 0;
    CHECK(rome2_l71_entry_point(&env, &ctx, command_line, 4u, &reserve, 6u, 7u, &exit_flag) == 0u);
    CHECK(hooks_are(&te, want_denied, 3u) && te.args[2] == 0u && te.verify_calls == 1u && te.run_calls == 1u);

    /* A failed check shows the dialog; -no_exception_handler runs without the handler install. */
    te.n = 0u;
    te.verify_hr = -1;
    te.allowed = 1;
    widen("-no_exception_handler", command_line, 40u);
    CHECK(rome2_l71_entry_point(&env, &ctx, command_line, 4u, &reserve, 6u, 7u, NULL) == 0u);
    CHECK(hooks_are(&te, want_unguarded, 5u) && te.args[2] == 0x67u && te.run_calls == 2u &&
          te.run_guarded == 0 && te.verify_calls == 2u);
    CHECK(rome2_l71_entry_point(NULL, &ctx, command_line, 4u, &reserve, 6u, 7u, &exit_flag) == 0u);
    return 0;
}

int main(void) {
    if (test_scalar_helpers() != 0 || test_container_helpers() != 0 || test_frame_empty() != 0 ||
        test_frame_notify() != 0 || test_frame_clamp_render() != 0 || test_frame_push_transition() != 0 ||
        test_frame_codes() != 0 || test_frame_requests() != 0 || test_frame_leave_ui_overlay() != 0 ||
        test_app_frame_step() != 0 || test_app_run() != 0 || test_entry_point() != 0) {
        return 1;
    }
    printf("test_startup_entry_frame_loop_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
