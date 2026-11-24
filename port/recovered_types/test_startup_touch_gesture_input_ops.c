#include "startup_touch_gesture_input_ops.h"

#include <math.h>
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

typedef struct call_log {
    uint32_t slots[16];
    uint32_t n;
} call_log;

static void log_dispatch(
    void *user, uint32_t slot, const void *record,
    const rome2_startup_input_state88_32 *state, const rome2_l70_frame *frame) {
    call_log *log = (call_log *)user;

    (void)record;
    (void)state;
    (void)frame;
    if (log->n < 16u) {
        log->slots[log->n++] = slot;
    }
}

static int modal_true(void *user) {
    (void)user;
    return 1;
}

static int slots_equal(const call_log *log, const uint32_t *want, uint32_t n) {
    return log->n == n && memcmp(log->slots, want, (size_t)n * sizeof(*want)) == 0;
}

static void feed(rome2_l70_gesture *g, uint32_t id, float x, float y, uint32_t flags) {
    rome2_startup_raw_touch24_32 r;

    memset(&r, 0, sizeof(r));
    r.x_08 = x;
    r.y_0c = y;
    r.id_10 = id;
    r.flags_14 = flags;
    (void)rome2_l70_vec_push(&g->raw_80, &r, sizeof(r));
}

static void configure(rome2_l70_gesture *g) {
    rome2_l70_gesture_init(g);
    g->hold_time_14 = 1.0f;
    g->move_threshold_18 = 0.05f;
    g->tap_window_1c = 0.25f;
    g->tap_elapsed_20 = 0.25f;
    g->pan_time_28 = 0.2f;
    g->flick_speed_38 = 0.5f;
    g->inertia_decay_5c = 4.0f;
    g->pinch_threshold_78 = 0.05f;
    g->rotate_threshold_7c = 5.0f;
}

static const rome2_startup_gesture_record64_32 *rec_at(const rome2_l70_gesture *g, uint32_t i) {
    return &((const rome2_startup_gesture_record64_32 *)g->records_98.data)[i];
}

static const rome2_startup_input_event44_32 *ev_at(const rome2_l70_vec *v, uint32_t i) {
    return &((const rome2_startup_input_event44_32 *)v->data)[i];
}

int main(void) {
    const rome2_l70_tuning tuning = {
        ROME2_L70_ROTATE_SCALE_INIT, ROME2_L70_SPAN_SCALE_INIT, ROME2_L70_PEAK_DECAY_INIT, 0.9f};
    rome2_l70_frame frame;
    rome2_l70_input_globals globals;
    rome2_l70_gesture g;
    uint32_t i;

    memset(&frame, 0, sizeof(frame));
    frame.dt_08 = 0.125f;

    /* 1. Layer 70 guest32 layouts */
    CHECK(sizeof(rome2_startup_raw_touch24_32) == 24u && sizeof(rome2_startup_touch_point48_32) == 48u &&
          sizeof(rome2_startup_mouse_state40_32) == 40u && sizeof(rome2_startup_input_event44_32) == 44u &&
          sizeof(rome2_startup_input_state88_32) == 88u && sizeof(rome2_startup_gesture_record64_32) == 64u);

    /* 2. 0x100d2690 / 0x100d6910 twelve-dword copies */
    uint8_t src48[48];
    uint8_t dst48[48];
    for (i = 0u; i < 48u; i++) {
        src48[i] = (uint8_t)(i + 1u);
    }
    memset(dst48, 0, sizeof(dst48));
    CHECK(rome2_l70_pod48_copy_assign(dst48, src48) == dst48 && memcmp(dst48, src48, 48u) == 0);
    memset(dst48, 0, sizeof(dst48));
    rome2_l70_pod48_copy(dst48, src48);
    CHECK(memcmp(dst48, src48, 48u) == 0);

    /* 3. 0x100d9e40 / 0x100d9f80 / 0x100da2b0 / 0x100da3f0 growth and aliasing */
    rome2_l70_vec v48 = {0u, 0u, NULL};
    CHECK(rome2_l70_vec48_push_back(&v48, src48) == 1 && v48.capacity == 1u && v48.count == 1u);
    CHECK(rome2_l70_vec48_push_back(&v48, v48.data) == 1 && v48.capacity == 2u && v48.count == 2u);
    CHECK(rome2_l70_vec48_push_back(&v48, (const uint8_t *)v48.data + 48) == 1 && v48.capacity == 4u);
    CHECK(v48.count == 3u && memcmp((const uint8_t *)v48.data + 96, src48, 48u) == 0);
    rome2_l70_vec_free(&v48);
    rome2_l70_vec refused = {0x40000000u, 0x40000000u, NULL};
    refused.data = src48;
    CHECK(rome2_l70_vec48_push_back(&refused, src48) == 0 && refused.count == 0x40000000u);

    /* 4. 0x1168cad5 / 0x100d7b80 / 0x100d7f30 */
    CHECK(rome2_l70_acosf(1.0f) == 0.0f && fabsf(rome2_l70_acosf(-1.0f) - 3.14159265f) < 1e-6f);
    CHECK(isnan(rome2_l70_acosf(2.0f)));
    rome2_startup_touch_point48_32 ta;
    rome2_startup_touch_point48_32 tb;
    memset(&ta, 0, sizeof(ta));
    memset(&tb, 0, sizeof(tb));
    tb.prev_10[0] = 1.0f;
    tb.cur_1c[1] = 2.0f;
    CHECK(rome2_l70_touch_pair_span_delta(&ta, &tb) == 1.0f);
    CHECK(fabsf(rome2_l70_touch_pair_signed_angle(&ta, &tb) - 89.9883f) < 0.01f);
    tb.cur_1c[1] = -2.0f;
    CHECK(fabsf(rome2_l70_touch_pair_signed_angle(&ta, &tb) + 89.9883f) < 0.01f);
    CHECK(rome2_l70_touch_pair_signed_angle(&ta, &ta) == 0.0f);

    /* 5. 0x100f1090 / 0x100f1100 / 0x100f1160 / 0x10103c50 */
    rome2_startup_input_state88_32 state;
    rome2_startup_mouse_state40_32 mouse;
    rome2_startup_mouse_state40_32 mouse_dst;
    rome2_l70_input_globals_init(&globals);
    CHECK(globals.mouse.word_0c == 0x7f7fffffu && rome2_l70_mouse_state_ptr_if_valid(&globals, &state) == &state);
    memset(&state, 0xa5, sizeof(state));
    CHECK(rome2_l70_input_state_init_from_record48(&globals, &state, src48) == &state);
    CHECK(state.mouse_00.word_0c == 0x7f7fffffu && state.mouse_00.x_00 == 0.0f &&
          memcmp(state.record_28, src48, 48u) == 0 && ((const uint8_t *)&state)[0x27] == 0xa5u);
    CHECK(globals.mouse_valid == 0u && rome2_l70_mouse_state_ptr_if_valid(&globals, &state) == NULL);
    memset(&mouse, 0, sizeof(mouse));
    mouse.x_00 = 0.25f;
    mouse.y_04 = 0.75f;
    CHECK(rome2_l70_mouse_state_set_and_publish(&globals, &mouse_dst, &mouse) == &mouse_dst);
    CHECK(mouse_dst.y_04 == 0.75f && globals.mouse.x_00 == 0.25f && globals.mouse_valid == 1u &&
          globals.aux_record[0] == 0xffu && globals.aux_record[3] == 0xffu && globals.aux_record[4] == 0u);
    CHECK(rome2_l70_input_state_snapshot(&globals, &state) == &state && state.mouse_00.x_00 == 0.25f &&
          state.record_28[0] == 0xffu);

    /* 6. Short press arms the tap window; expiry emits tag 6 */
    configure(&g);
    feed(&g, 7u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.points_8c.count == 1u && g.records_98.count == 1u && rec_at(&g, 0u)->tag_00 == 0u &&
          rec_at(&g, 0u)->ended_30 == 1u && rec_at(&g, 0u)->code_34 == -1);
    CHECK(g.events_cc.count == 1u && ev_at(&g.events_cc, 0u)->kind_00 == 0xcu &&
          ev_at(&g.events_cc, 0u)->state_04.x_00 == 0.5f && g.raw_80.count == 0u);
    feed(&g, 7u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY | ROME2_L70_TOUCH_RELEASED);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.points_8c.count == 0u && g.tap_elapsed_20 == 0.0f && g.tap_anchor_08[0] == 0.5f &&
          g.records_98.count == 1u && rec_at(&g, 0u)->tag_00 == 0u && g.state_04 == ROME2_L70_STATE_IDLE);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.tap_elapsed_20 == 0.125f && g.records_98.count == 0u);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.records_98.count == 2u && rec_at(&g, 0u)->tag_00 == 6u && rec_at(&g, 0u)->start_04[0] == 0.5f &&
          rec_at(&g, 1u)->tag_00 == 0u && g.done_00 == 0u);

    /* 7. A primary touch inside the tap window emits tag 10 and starts no point */
    feed(&g, 8u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    feed(&g, 8u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY | ROME2_L70_TOUCH_RELEASED);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    feed(&g, 9u, 0.625f, 0.625f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.records_98.count == 3u && rec_at(&g, 1u)->tag_00 == 10u && rec_at(&g, 1u)->start_04[0] == 0.5f &&
          g.points_8c.count == 0u && g.tap_elapsed_20 == g.tap_window_1c);

    /* 8. Long press: age reaching the hold time with one point emits tag 9 */
    feed(&g, 1u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    for (i = 0u; i < 8u; i++) {
        feed(&g, 1u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
        rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    }
    CHECK(g.state_04 == ROME2_L70_STATE_HOLD && g.done_00 == 1u && g.records_98.count == 1u &&
          rec_at(&g, 0u)->tag_00 == 9u);
    feed(&g, 1u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY | ROME2_L70_TOUCH_RELEASED);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.state_04 == ROME2_L70_STATE_IDLE && g.records_98.count == 1u && rec_at(&g, 0u)->tag_00 == 0u);

    /* 9. Pending pan -> drag -> flick inertia -> end */
    feed(&g, 2u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    feed(&g, 2u, 0.75f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.state_04 == ROME2_L70_STATE_PENDING && g.records_98.count == 1u && rec_at(&g, 0u)->tag_00 == 5u &&
          rec_at(&g, 0u)->prev_0c[0] == 0.5f && rec_at(&g, 0u)->cur_14[0] == 0.75f);
    CHECK(g.peak_speed_34 == 2.0f && g.dir_40[0] == 1.0f && g.dir_40[1] == 0.0f);
    feed(&g, 2u, 1.0f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.state_04 == ROME2_L70_STATE_DRAG && rec_at(&g, 0u)->tag_00 == 2u &&
          rec_at(&g, 0u)->start_04[0] == 0.75f && rec_at(&g, 0u)->ended_30 == 0u);
    feed(&g, 2u, 1.0f, 0.5f, ROME2_L70_TOUCH_PRIMARY | ROME2_L70_TOUCH_RELEASED);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.inertia_speed_58 == 1.0f && g.inertia_tag_3c == 2 && g.records_98.count == 1u &&
          rec_at(&g, 0u)->ended_30 == 1u && g.state_04 == ROME2_L70_STATE_IDLE);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.inertia_speed_58 == 0.5f && g.records_98.count == 1u && rec_at(&g, 0u)->tag_00 == 2u &&
          rec_at(&g, 0u)->flag_31 == 1u && rec_at(&g, 0u)->prev_0c[0] == 0.9375f &&
          rec_at(&g, 0u)->start_04[1] == 1.0f && rec_at(&g, 0u)->cur_14[1] == 0.5f);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.inertia_speed_58 == 0.0f && g.records_98.count == 1u && rec_at(&g, 0u)->tag_00 == 0u);
    CHECK(g.alloc_failures == 0u);
    rome2_l70_gesture_free(&g);

    /* 10. Two points: pinch record, then an ending record when one lifts */
    configure(&g);
    feed(&g, 1u, 0.375f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    feed(&g, 1u, 0.375f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    feed(&g, 2u, 0.625f, 0.5f, 0u);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.points_8c.count == 2u && g.state_04 == ROME2_L70_STATE_IDLE && g.events_cc.count == 1u);
    feed(&g, 1u, 0.25f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    feed(&g, 2u, 0.75f, 0.5f, 0u);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.state_04 == ROME2_L70_STATE_PINCH_ROTATE && g.records_98.count == 1u &&
          rec_at(&g, 0u)->tag_00 == 0xbu && rec_at(&g, 0u)->span_28 == 6.25f &&
          rec_at(&g, 0u)->angle_24 == 0.0f && rec_at(&g, 0u)->second_1c[0] == 0.75f &&
          rec_at(&g, 0u)->ended_30 == 0u);
    feed(&g, 1u, 0.25f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    feed(&g, 2u, 0.75f, 0.5f, ROME2_L70_TOUCH_RELEASED);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.points_8c.count == 1u && rec_at(&g, 0u)->tag_00 == 0xbu && rec_at(&g, 0u)->span_28 == 0.0f);
    feed(&g, 1u, 0.25f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.records_98.count == 2u && rec_at(&g, 0u)->tag_00 == 0xbu && rec_at(&g, 0u)->ended_30 == 1u &&
          rec_at(&g, 1u)->tag_00 == 2u && g.state_04 == ROME2_L70_STATE_DRAG);
    rome2_l70_gesture_free(&g);

    /* 11. Three points moving left: kind-0xc event, aux record, done */
    configure(&g);
    feed(&g, 1u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    feed(&g, 1u, 0.5f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    feed(&g, 2u, 0.625f, 0.5f, 0u);
    feed(&g, 3u, 0.75f, 0.5f, 0u);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    feed(&g, 1u, 0.375f, 0.5f, ROME2_L70_TOUCH_PRIMARY);
    feed(&g, 2u, 0.5f, 0.5f, 0u);
    feed(&g, 3u, 0.625f, 0.5f, 0u);
    rome2_l70_gesture_tick(&g, &globals, &tuning, &frame);
    CHECK(g.done_00 == 1u && g.aux_d8.count == 1u && g.events_cc.count == 1u &&
          ev_at(&g.events_cc, 0u)->kind_00 == 0xcu && ev_at(&g.events_cc, 0u)->state_04.buttons_10[7] == 1u &&
          ev_at(&g.events_cc, 0u)->state_04.x_00 == 0.375f);
    static const uint8_t zero8[8] = {0u};
    CHECK(memcmp(g.aux_d8.data, zero8, 8u) == 0 &&
          memcmp((const uint8_t *)g.aux_d8.data + 8, &globals.mouse, sizeof(globals.mouse)) == 0);
    rome2_l70_gesture_free(&g);

    /* 12. 0x100d9880 record replay */
    configure(&g);
    rome2_startup_gesture_record64_32 rr;
    memset(&rr, 0, sizeof(rr));
    rr.code_34 = 2;
    rr.code_xy_38[0] = 0.25f;
    rr.code_xy_38[1] = 0.75f;
    CHECK(rome2_l70_vec64_push_back(&g.records_98, &rr) == 1);
    rr.code_34 = -1;
    CHECK(rome2_l70_vec64_push_back(&g.records_98, &rr) == 1);
    rr.code_34 = 11;
    CHECK(rome2_l70_vec64_push_back(&g.records_98, &rr) == 1);
    rome2_l70_gesture_replay_records(&g);
    CHECK(g.events_cc.count == 5u && ev_at(&g.events_cc, 0u)->kind_00 == 0xcu &&
          ev_at(&g.events_cc, 1u)->kind_00 == 1u && ev_at(&g.events_cc, 2u)->kind_00 == 0u &&
          ev_at(&g.events_cc, 3u)->kind_00 == 5u && ev_at(&g.events_cc, 4u)->kind_00 == 4u);
    CHECK(ev_at(&g.events_cc, 0u)->state_04.x_00 == 0.25f && ev_at(&g.events_cc, 1u)->state_04.buttons_10[0] == 1u &&
          ev_at(&g.events_cc, 2u)->state_04.buttons_10[0] == 0u && ev_at(&g.events_cc, 3u)->state_04.buttons_10[4] == 1u &&
          ev_at(&g.events_cc, 3u)->state_04.buttons_10[1] == 1u && ev_at(&g.events_cc, 4u)->state_04.buttons_10[1] == 0u);
    CHECK(g.mouse_a4.buttons_10[4] == 0u && g.mouse_a4.buttons_10[6] == 1u);
    rome2_l70_gesture_free(&g);

    /* 13. 0x100dd7a0 update: record forwarding, clamp and publish */
    rome2_l70_input_mgr mgr;
    call_log log_a = {{0u}, 0u};
    call_log log_b = {{0u}, 0u};
    call_log log_c = {{0u}, 0u};
    rome2_l70_handler ha = {1u, log_dispatch, NULL};
    rome2_l70_handler hb = {0u, log_dispatch, NULL};
    rome2_l70_handler hc = {1u, log_dispatch, NULL};
    rome2_l70_handler *primary[2];
    rome2_l70_handler *secondary[1];
    ha.user = &log_a;
    hb.user = &log_b;
    hc.user = &log_c;
    primary[0] = &ha;
    primary[1] = &hb;
    secondary[0] = &hc;
    memset(&mgr, 0, sizeof(mgr));
    mgr.primary_54 = primary;
    mgr.primary_count_50 = 2u;
    mgr.secondary_64 = secondary;
    mgr.secondary_count_60 = 1u;
    configure(&g);
    feed(&g, 1u, 1.5f, -0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_input_mgr_update(&mgr, &g, &globals, &tuning, &frame);
    CHECK(log_c.n == 1u && log_c.slots[0] == 0x24u && log_a.n == 1u && log_a.slots[0] == 0x20u && log_b.n == 0u);
    CHECK(mgr.events44_8c.count == 1u && ev_at(&mgr.events44_8c, 0u)->state_04.x_00 == 1.0f &&
          ev_at(&mgr.events44_8c, 0u)->state_04.y_04 == 0.0f && globals.mouse.x_00 == 1.0f &&
          globals.mouse.y_04 == 0.0f && mgr.records48_74.count == 0u);
    /* The 0x100dd7a0 COMISS/JBE clamp leaves a NaN coordinate unchanged. */
    rome2_l70_gesture gn;
    configure(&gn);
    feed(&gn, 1u, nanf(""), 0.5f, ROME2_L70_TOUCH_PRIMARY);
    rome2_l70_input_mgr_update(&mgr, &gn, &globals, &tuning, &frame);
    CHECK(mgr.events44_8c.count == 1u && isnan(ev_at(&mgr.events44_8c, 0u)->state_04.x_00) &&
          ev_at(&mgr.events44_8c, 0u)->state_04.y_04 == 0.5f && gn.alloc_failures == 0u);
    rome2_l70_gesture_free(&gn);

    /* 14. 0x100dd280 / 0x100ddcd0 slot order */
    uint8_t rec48[48];
    rome2_startup_input_event44_32 ev44;
    memset(rec48, 0, sizeof(rec48));
    memset(&ev44, 0, sizeof(ev44));
    ev44.kind_00 = 3u;
    CHECK(rome2_l70_vec48_push_back(&mgr.records48_74, rec48) == 1 &&
          rome2_l70_vec48_push_back(&mgr.records48_a4, rec48) == 1 &&
          rome2_l70_vec44_push_back(&mgr.events44_80, &ev44) == 1);
    static const uint32_t want_primary[4] = {0x10u, 0x18u, 0x14u, 0x1cu};
    static const uint32_t want_secondary[5] = {0x14u, 0x18u, 0x20u, 0x1cu, 0x28u};
    log_a.n = 0u;
    mgr.flag_d2 = 1u;
    rome2_l70_input_mgr_dispatch_primary(&mgr, &globals, &frame);
    CHECK(slots_equal(&log_a, want_primary, 4u) && log_b.n == 0u && mgr.flag_d2 == 0u &&
          mgr.events44_copy_98.count == 1u);
    log_a.n = 0u;
    mgr.modal_query = modal_true;
    rome2_l70_input_mgr_dispatch_primary(&mgr, &globals, &frame);
    CHECK(slots_equal(&log_a, want_primary, 3u));
    log_c.n = 0u;
    rome2_l70_input_mgr_dispatch_secondary(&mgr, &globals, &frame);
    CHECK(slots_equal(&log_c, want_secondary, 5u) && globals.mouse_valid == 1u);
    log_c.n = 0u;
    globals.dispatch_suppressed = 1u;
    rome2_l70_input_mgr_dispatch_secondary(&mgr, &globals, &frame);
    CHECK(log_c.n == 0u && g.alloc_failures == 0u && mgr.alloc_failures == 0u);
    rome2_l70_gesture_free(&g);
    rome2_l70_input_mgr_free(&mgr);

    printf("test_startup_touch_gesture_input_ops: ALL PASSED (%d checks)\n", g_checks);
    return 0;
}
