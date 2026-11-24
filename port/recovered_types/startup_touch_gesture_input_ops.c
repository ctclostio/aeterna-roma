#include "startup_touch_gesture_input_ops.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

/* ---- 0x100d2690 / 0x100d6910: twelve-dword copies ---- */

void *rome2_l70_pod48_copy_assign(void *dst48, const void *src48) {
    if (dst48 != NULL && src48 != NULL) {
        memmove(dst48, src48, 48u);
    }
    return dst48;
}

void rome2_l70_pod48_copy(void *dst48, const void *src48) {
    (void)rome2_l70_pod48_copy_assign(dst48, src48);
}

/* ---- 0x100d9e40 / 0x100d9f80 / 0x100da2b0 / 0x100da3f0: {capacity, count, data} push ---- */

int rome2_l70_vec_push(rome2_l70_vec *vec, const void *elem, size_t elem_size) {
    uint8_t *old;
    uint8_t *fresh;
    const uint8_t *src;
    uint32_t doubled;
    size_t used;

    if (vec == NULL || elem == NULL || elem_size == 0u) {
        return 0;
    }
    used = (size_t)vec->count * elem_size;
    if (vec->count < vec->capacity) {
        if (vec->data == NULL) {
            return 0;
        }
        memcpy((uint8_t *)vec->data + used, elem, elem_size);
        vec->count++;
        return 1;
    }
    if (vec->capacity == 0u) {
        /* The original stores capacity 1 and writes at data + count * size. */
        if (vec->count != 0u) {
            return 0;
        }
        fresh = (uint8_t *)malloc(elem_size);
        if (fresh == NULL) {
            return 0;
        }
        memcpy(fresh, elem, elem_size);
        vec->capacity = 1u;
        vec->data = fresh;
        vec->count = 1u;
        return 1;
    }
    doubled = vec->capacity * 2u;
    /* The original allocates nothing for a zero or sign-bit capacity and then
     * writes past it; the native port refuses instead. */
    if (doubled == 0u || (doubled & 0x80000000u) != 0u || vec->data == NULL) {
        return 0;
    }
    old = (uint8_t *)vec->data;
    fresh = (uint8_t *)malloc((size_t)doubled * elem_size);
    if (fresh == NULL) {
        return 0;
    }
    memcpy(fresh, old, used);
    src = (const uint8_t *)elem;
    if ((uintptr_t)src >= (uintptr_t)old && (uintptr_t)src < (uintptr_t)old + used) {
        /* An element inside the old buffer is re-read from the new one by index. */
        src = fresh + ((size_t)((uintptr_t)src - (uintptr_t)old) / elem_size) * elem_size;
    }
    memcpy(fresh + used, src, elem_size);
    free(old);
    vec->capacity = doubled;
    vec->data = fresh;
    vec->count++;
    return 1;
}

int rome2_l70_vec48_push_back(rome2_l70_vec *vec, const void *elem48) {
    return rome2_l70_vec_push(vec, elem48, 0x30u);
}

int rome2_l70_vec44_push_back(rome2_l70_vec *vec, const rome2_startup_input_event44_32 *elem44) {
    return rome2_l70_vec_push(vec, elem44, 0x2cu);
}

int rome2_l70_vec64_push_back(rome2_l70_vec *vec, const rome2_startup_gesture_record64_32 *elem64) {
    return rome2_l70_vec_push(vec, elem64, 0x40u);
}

int rome2_l70_vec48_push_back_dwords(rome2_l70_vec *vec, const rome2_startup_touch_point48_32 *elem48) {
    return rome2_l70_vec_push(vec, elem48, 0x30u);
}

void rome2_l70_vec_free(rome2_l70_vec *vec) {
    if (vec != NULL) {
        free(vec->data);
        vec->data = NULL;
        vec->count = 0u;
        vec->capacity = 0u;
    }
}

/* ---- 0x1168cad5 / 0x100d7b80 / 0x100d7f30 ---- */

float rome2_l70_acosf(float x) {
    /* Host libm stands in for the table-driven SSE2 routine: |x| > 1 and NaN
     * yield NaN, +1 yields 0 and -1 yields pi, as in the original branches. */
    return acosf(x);
}

static float l70_clamp01(float v) {
    /* COMISS/MINSS: negative becomes 0; NaN and values above 1 become 1. */
    return (0.0f > v) ? 0.0f : ((v < 1.0f) ? v : 1.0f);
}

static float l70_len3(float dx, float dy, float dz) {
    return sqrtf((dy * dy + dx * dx) + dz * dz);
}

static float l70_dist3(const float *a, const float *b) {
    return l70_len3(a[0] - b[0], a[1] - b[1], a[2] - b[2]);
}

float rome2_l70_touch_pair_span_delta(
    const rome2_startup_touch_point48_32 *a, const rome2_startup_touch_point48_32 *b) {
    if (a == NULL || b == NULL) {
        return 0.0f;
    }
    return l70_dist3(a->cur_1c, b->cur_1c) - l70_dist3(a->prev_10, b->prev_10);
}

float rome2_l70_touch_pair_signed_angle(
    const rome2_startup_touch_point48_32 *a, const rome2_startup_touch_point48_32 *b) {
    float cx;
    float cy;
    float px;
    float py;
    float inv;
    float dot;
    float cross;

    if (a == NULL || b == NULL) {
        return 0.0f;
    }
    cx = a->cur_1c[0] - b->cur_1c[0];
    cy = a->cur_1c[1] - b->cur_1c[1];
    inv = 1.0f / l70_len3(cx, cy, a->cur_1c[2] - b->cur_1c[2]);
    cx *= inv;
    cy *= inv;
    px = a->prev_10[0] - b->prev_10[0];
    py = a->prev_10[1] - b->prev_10[1];
    inv = 1.0f / l70_len3(px, py, a->prev_10[2] - b->prev_10[2]);
    px *= inv;
    py *= inv;
    dot = l70_clamp01(py * cy + px * cx);
    cross = px * cy - py * cx;
    return rome2_l70_acosf(dot) * ((cross > 0.0f) ? ROME2_L70_ANGLE_SCALE : -ROME2_L70_ANGLE_SCALE);
}

/* ---- 0x100f1090 / 0x100f1100 / 0x100f1160 / 0x10103c50 ---- */

void rome2_l70_input_globals_init(rome2_l70_input_globals *globals) {
    if (globals != NULL) {
        memset(globals, 0, sizeof(*globals));
        globals->mouse.word_0c = 0x7f7fffffu;    /* pinned initial bytes at 0x119344cc */
        globals->mouse_valid = 1u;               /* pinned initial byte at 0x11933c7c */
    }
}

rome2_startup_input_state88_32 *rome2_l70_input_state_init_from_record48(
    rome2_l70_input_globals *globals, rome2_startup_input_state88_32 *state, const void *record48) {
    if (state != NULL && record48 != NULL) {
        /* Byte 0x27 of the pointer state is left untouched by the original. */
        memset(&state->mouse_00, 0, 0x27u);
        state->mouse_00.word_0c = 0x7f7fffffu;
        memcpy(state->record_28, record48, sizeof(state->record_28));
        if (globals != NULL) {
            globals->mouse_valid = 0u;
        }
    }
    return state;
}

void *rome2_l70_mouse_state_set_and_publish(
    rome2_l70_input_globals *globals, void *dst40, const rome2_startup_mouse_state40_32 *src40) {
    static const uint8_t all_ones[4] = {0xffu, 0xffu, 0xffu, 0xffu};

    if (dst40 != NULL && src40 != NULL) {
        memmove(dst40, src40, sizeof(*src40));
        if (globals != NULL) {
            globals->mouse_valid = 1u;
            /* src40 is re-read after the first store, as in the original. */
            memmove(&globals->mouse, src40, sizeof(*src40));
            memcpy(globals->aux_record, all_ones, sizeof(all_ones));
        }
    }
    return dst40;
}

rome2_startup_input_state88_32 *rome2_l70_input_state_snapshot(
    const rome2_l70_input_globals *globals, rome2_startup_input_state88_32 *state) {
    if (state != NULL && globals != NULL) {
        state->mouse_00 = globals->mouse;
        memcpy(state->record_28, globals->aux_record, sizeof(state->record_28));
    }
    return state;
}

void *rome2_l70_mouse_state_ptr_if_valid(const rome2_l70_input_globals *globals, void *ptr) {
    return (globals != NULL && globals->mouse_valid != 0u) ? ptr : NULL;
}

/* ---- recognizer helpers ---- */

static rome2_startup_touch_point48_32 *l70_points(const rome2_l70_gesture *g) {
    return (rome2_startup_touch_point48_32 *)g->points_8c.data;
}

static void l70_push_record(rome2_l70_gesture *g, const rome2_startup_gesture_record64_32 *rec) {
    if (!rome2_l70_vec64_push_back(&g->records_98, rec)) {
        g->alloc_failures++;
    }
}

static void l70_emit_event(rome2_l70_gesture *g, uint32_t kind) {
    rome2_startup_input_event44_32 ev;

    ev.kind_00 = kind;
    ev.state_04 = g->mouse_a4;
    if (!rome2_l70_vec44_push_back(&g->events_cc, &ev)) {
        g->alloc_failures++;
    }
}

/* Fields the original leaves as uninitialized stack are zero here. */
static void l70_simple_record(rome2_l70_gesture *g, uint32_t tag, float x, float y, uint8_t ended) {
    rome2_startup_gesture_record64_32 rec;

    memset(&rec, 0, sizeof(rec));
    rec.tag_00 = tag;
    rec.start_04[0] = x;
    rec.start_04[1] = y;
    rec.ended_30 = ended;
    rec.code_34 = -1;
    l70_push_record(g, &rec);
}

static void l70_roll_prev(rome2_l70_gesture *g) {
    rome2_startup_touch_point48_32 *p = l70_points(g);
    uint32_t i;

    for (i = 0u; i < g->points_8c.count; i++) {
        memcpy(p[i].prev_10, p[i].cur_1c, sizeof(p[i].prev_10));
    }
}

static void l70_release_second(rome2_l70_gesture *g) {
    g->mouse_a4.x_00 = g->second_pos_6c[0];
    g->mouse_a4.y_04 = g->second_pos_6c[1];
    g->mouse_a4.buttons_10[0] = 0u;
    l70_emit_event(g, 0u);
    g->second_down_68 = 0u;
}

void rome2_l70_gesture_init(rome2_l70_gesture *gesture) {
    if (gesture != NULL) {
        memset(gesture, 0, sizeof(*gesture));
        gesture->state_04 = ROME2_L70_STATE_IDLE;
    }
}

void rome2_l70_gesture_free(rome2_l70_gesture *gesture) {
    if (gesture != NULL) {
        rome2_l70_vec_free(&gesture->raw_80);
        rome2_l70_vec_free(&gesture->points_8c);
        rome2_l70_vec_free(&gesture->records_98);
        rome2_l70_vec_free(&gesture->events_cc);
        rome2_l70_vec_free(&gesture->aux_d8);
    }
}

/* ---- 0x100d8430 ---- */

void rome2_l70_gesture_ingest_raw(rome2_l70_gesture *gesture, const rome2_l70_frame *frame) {
    rome2_l70_gesture *g = gesture;
    uint32_t i;

    if (g == NULL || frame == NULL) {
        return;
    }
    for (i = 0u; i < g->raw_80.count; i++) {
        const rome2_startup_raw_touch24_32 *r = &((const rome2_startup_raw_touch24_32 *)g->raw_80.data)[i];
        rome2_startup_touch_point48_32 *p = l70_points(g);
        uint32_t j;

        for (j = 0u; j < g->points_8c.count; j++) {
            if (p[j].id_00 == r->id_10) {
                break;
            }
        }
        if (j < g->points_8c.count) {
            p[j].age_28 = frame->dt_08 + p[j].age_28;
            p[j].flags_2c = r->flags_14;
            p[j].cur_1c[0] = r->x_08;
            p[j].cur_1c[1] = r->y_0c;
            p[j].cur_1c[2] = 0.0f;
            continue;
        }
        if (g->done_00 != 0u || (g->points_8c.count == 0u && (r->flags_14 & ROME2_L70_TOUCH_PRIMARY) == 0u)) {
            continue;
        }
        if ((r->flags_14 & ROME2_L70_TOUCH_PRIMARY) != 0u) {
            g->inertia_speed_58 = 0.0f;
            l70_simple_record(g, 0u, 0.0f, 0.0f, 1u);
            g->mouse_a4.buttons_10[0] = 0u;
            g->mouse_a4.buttons_10[1] = 0u;
            if (g->tap_elapsed_20 < g->tap_window_1c) {
                /* A primary touch inside the tap window: tag 10. */
                l70_simple_record(g, 10u, g->tap_anchor_08[0], g->tap_anchor_08[1], 1u);
                g->done_00 = 1u;
                g->tap_elapsed_20 = g->tap_window_1c;
                continue;
            }
        }
        if (g->done_00 == 0u && g->cooldown_64 <= 0.0f) {
            rome2_startup_touch_point48_32 pt;

            pt.id_00 = r->id_10;
            pt.start_04[0] = pt.prev_10[0] = pt.cur_1c[0] = r->x_08;
            pt.start_04[1] = pt.prev_10[1] = pt.cur_1c[1] = r->y_0c;
            pt.start_04[2] = pt.prev_10[2] = pt.cur_1c[2] = 0.0f;
            pt.age_28 = 0.0f;
            pt.flags_2c = r->flags_14;
            if (!rome2_l70_vec48_push_back_dwords(&g->points_8c, &pt)) {
                g->alloc_failures++;
            }
            g->mouse_a4.x_00 = r->x_08;
            g->mouse_a4.y_04 = r->y_0c;
            l70_emit_event(g, 0xcu);
        }
    }
    g->raw_80.count = 0u;
}

/* ---- 0x100da620 ---- */

void rome2_l70_gesture_emit_pinch_rotate(
    rome2_l70_gesture *gesture, const rome2_l70_tuning *tuning, uint8_t ending) {
    rome2_l70_gesture *g = gesture;
    rome2_startup_touch_point48_32 *p;
    rome2_startup_gesture_record64_32 rec;

    if (g == NULL || tuning == NULL || g->points_8c.count == 0u || g->points_8c.data == NULL ||
        (ending == 0u && g->points_8c.count < 2u)) {
        return;
    }
    p = l70_points(g);
    memset(&rec, 0, sizeof(rec));
    rec.tag_00 = 0xbu;
    rec.start_04[0] = p[0].start_04[0];
    rec.start_04[1] = p[0].start_04[1];
    rec.cur_14[0] = p[0].cur_1c[0];
    rec.cur_14[1] = p[0].cur_1c[1];
    if (g->points_8c.capacity >= 2u) {
        /* Read without a count check, as in the original: after the second
         * point is erased this is the stale slot left in the buffer. */
        rec.second_1c[0] = p[1].cur_1c[0];
        rec.second_1c[1] = p[1].cur_1c[1];
    }
    if (ending != 0u) {
        rec.ended_30 = 1u;
    } else {
        float angle = rome2_l70_touch_pair_signed_angle(&p[0], &p[1]) * tuning->rotate_scale;
        float span = rome2_l70_touch_pair_span_delta(&p[0], &p[1]);
        float scaled = tuning->span_scale * span;
        float dx = p[1].cur_1c[0] - p[0].prev_10[0];
        float dy = p[1].cur_1c[1] - p[0].prev_10[1];

        if (sqrtf(dy * dy + dx * dx) > span) {
            scaled *= 0.25f;
        } else {
            angle *= 0.25f;
        }
        rec.angle_24 = angle;
        rec.span_28 = scaled;
    }
    if ((p[0].flags_2c & ROME2_L70_TOUCH_RELEASED) != 0u) {
        rec.ended_30 = 1u;
    }
    rec.code_34 = -1;
    l70_push_record(g, &rec);
    l70_roll_prev(g);
}

/* ---- 0x100d89a0 ---- */

static void l70_point_record(rome2_l70_gesture *g, uint32_t tag) {
    const rome2_startup_touch_point48_32 *p = l70_points(g);
    rome2_startup_gesture_record64_32 rec;

    memset(&rec, 0, sizeof(rec));
    rec.tag_00 = tag;
    rec.start_04[0] = p[0].start_04[0];
    rec.start_04[1] = p[0].start_04[1];
    rec.prev_0c[0] = p[0].prev_10[0];
    rec.prev_0c[1] = p[0].prev_10[1];
    rec.cur_14[0] = p[0].cur_1c[0];
    rec.cur_14[1] = p[0].cur_1c[1];
    rec.ended_30 = (uint8_t)((p[0].flags_2c & ROME2_L70_TOUCH_RELEASED) != 0u);
    rec.code_34 = -1;
    l70_push_record(g, &rec);
    l70_roll_prev(g);
}

/* A released first point with enough peak speed starts inertia. */
static void l70_try_flick(rome2_l70_gesture *g) {
    const rome2_startup_touch_point48_32 *p = l70_points(g);

    if ((p[0].flags_2c & ROME2_L70_TOUCH_RELEASED) != 0u && g->flick_speed_38 < g->peak_speed_34) {
        g->inertia_pos_4c[0] = p[0].cur_1c[0];
        g->inertia_pos_4c[1] = p[0].cur_1c[1];
        g->inertia_pos_z_54 = 0.0f;
        g->inertia_speed_58 = g->peak_speed_34;
        g->inertia_tag_3c = g->state_04;
    }
}

/* The idle (-1) branch. Returns 1 when the step is finished. */
static int l70_step_idle(rome2_l70_gesture *g) {
    rome2_startup_touch_point48_32 *p = l70_points(g);
    uint32_t n = g->points_8c.count;
    uint32_t i;

    if ((p[0].flags_2c & ROME2_L70_TOUCH_RELEASED) != 0u) {
        if (g->second_down_68 != 0u) {
            l70_release_second(g);
        }
        if (n != 2u) {
            if (g->hold_time_14 <= p[0].age_28) {
                return 1;
            }
            /* A short press arms the tap window. */
            memcpy(g->tap_anchor_08, p[0].start_04, sizeof(g->tap_anchor_08));
            g->tap_elapsed_20 = 0.0f;
            return 1;
        }
        i = (p[0].start_04[1] > p[1].start_04[1]) ? 0u : 1u;
        g->mouse_a4.x_00 = p[i].start_04[0];
        g->mouse_a4.y_04 = p[i].start_04[1];
        l70_emit_event(g, 0xcu);
        g->done_00 = 1u;
        return 1;
    }
    if (p[0].start_04[0] < 0.1f && p[0].cur_1c[0] < 0.1f) {
        if (n == 2u) {
            if (g->second_down_68 == 0u && 0.5f < p[0].cur_1c[1]) {
                g->second_down_68 = 1u;
                g->mouse_a4.x_00 = p[1].cur_1c[0];
                g->mouse_a4.y_04 = p[1].cur_1c[1];
                g->mouse_a4.buttons_10[0] = 1u;
                l70_emit_event(g, 1u);
            }
            g->mouse_a4.x_00 = p[1].cur_1c[0];
            g->mouse_a4.y_04 = p[1].cur_1c[1];
            l70_emit_event(g, 0xcu);
            memcpy(g->second_pos_6c, p[1].cur_1c, sizeof(g->second_pos_6c));
            return 1;
        }
        if (g->second_down_68 != 0u) {
            l70_release_second(g);
        }
        return 1;
    }
    if (g->second_down_68 != 0u) {
        l70_release_second(g);
        g->done_00 = 1u;
        return 1;
    }
    if (g->hold_time_14 <= p[0].age_28 && n == 1u) {
        g->state_04 = ROME2_L70_STATE_HOLD;
        l70_simple_record(g, 9u, p[0].start_04[0], p[0].start_04[1], 1u);
        g->done_00 = 1u;
        return 1;
    }
    for (i = 0u; i < n; i++) {
        if (g->move_threshold_18 <= l70_dist3(p[i].cur_1c, p[i].start_04)) {
            g->state_04 = ROME2_L70_STATE_PENDING;
            g->peak_speed_34 = 0.0f;
            break;
        }
    }
    return 0;
}

/* Re-evaluates the gesture kind. Returns 1 when the step is finished. */
static int l70_reclassify(
    rome2_l70_gesture *g, const rome2_l70_input_globals *globals, const rome2_l70_tuning *tuning) {
    rome2_startup_touch_point48_32 *p = l70_points(g);
    uint32_t n = g->points_8c.count;
    uint32_t i;

    if (g->state_04 != ROME2_L70_STATE_RECLASSIFY) {
        if (g->state_04 == ROME2_L70_STATE_PINCH_ROTATE) {
            rome2_l70_gesture_emit_pinch_rotate(g, tuning, 1u);
        }
        g->state_04 = ROME2_L70_STATE_RECLASSIFY;
        for (i = 0u; i < n; i++) {
            memcpy(p[i].start_04, p[i].prev_10, sizeof(p[i].start_04));
        }
    }
    if (n < 2u) {
        g->state_04 = ROME2_L70_STATE_DRAG;
        return 0;
    }
    if (n == 3u) {
        if (p[0].cur_1c[0] - p[0].start_04[0] < -0.003f && p[1].cur_1c[0] - p[1].start_04[0] < -0.003f &&
            p[2].cur_1c[0] - p[2].start_04[0] < -0.003f) {
            rome2_startup_input_state88_32 snap;

            g->mouse_a4.x_00 = p[0].cur_1c[0];
            g->mouse_a4.y_04 = p[0].cur_1c[1];
            g->mouse_a4.buttons_10[7] = 1u;
            l70_emit_event(g, 0xcu);
            memset(&snap, 0, sizeof(snap));
            (void)rome2_l70_input_state_snapshot(globals, &snap);
            if (rome2_l70_mouse_state_ptr_if_valid(globals, &snap) != NULL) {
                uint8_t aux[48];

                memset(aux, 0, 8u);
                memcpy(aux + 8, &snap.mouse_00, sizeof(snap.mouse_00));
                if (!rome2_l70_vec48_push_back(&g->aux_d8, aux)) {
                    g->alloc_failures++;
                }
            }
            g->done_00 = 1u;
            return 1;
        }
        g->state_04 = ROME2_L70_STATE_SWIPE3;
        return 0;
    }
    if (g->pinch_threshold_78 < fabsf(rome2_l70_touch_pair_span_delta(&p[0], &p[1])) ||
        g->rotate_threshold_7c < fabsf(rome2_l70_touch_pair_signed_angle(&p[0], &p[1]))) {
        g->state_04 = ROME2_L70_STATE_PINCH_ROTATE;
        return 0;
    }
    if (g->move_threshold_18 < l70_dist3(p[0].cur_1c, p[0].prev_10) &&
        g->move_threshold_18 < l70_dist3(p[1].cur_1c, p[1].prev_10)) {
        float ax = p[0].cur_1c[0] - p[0].prev_10[0];
        float ay = p[0].cur_1c[1] - p[0].prev_10[1];
        float az = p[0].cur_1c[2] - p[0].prev_10[2];
        float bx = p[1].cur_1c[0] - p[1].prev_10[0];
        float by = p[1].cur_1c[1] - p[1].prev_10[1];
        float bz = p[1].cur_1c[2] - p[1].prev_10[2];
        float ia = 1.0f / l70_len3(ax, ay, az);
        float ib = 1.0f / l70_len3(bx, by, bz);

        if (tuning->parallel_dot_min < (by * ib * ay * ia + bx * ib * ax * ia) + bz * ib * az * ia) {
            g->state_04 = ROME2_L70_STATE_PARALLEL;
        }
    }
    return 0;
}

void rome2_l70_gesture_state_step(
    rome2_l70_gesture *gesture, const rome2_l70_input_globals *globals,
    const rome2_l70_tuning *tuning, const rome2_l70_frame *frame) {
    rome2_l70_gesture *g = gesture;
    rome2_startup_touch_point48_32 *p;
    float vx;
    float vy;
    float len;
    float dt;
    float speed;
    uint32_t n;
    int reclass = 0;

    if (g == NULL || globals == NULL || tuning == NULL || frame == NULL) {
        return;
    }
    if (g->tap_elapsed_20 < g->tap_window_1c) {
        g->tap_elapsed_20 = frame->dt_08 + g->tap_elapsed_20;
        if (g->tap_window_1c <= g->tap_elapsed_20) {
            /* The tap window ran out without a second touch: tag 6. */
            l70_simple_record(g, 6u, g->tap_anchor_08[0], g->tap_anchor_08[1], 1u);
            g->done_00 = 1u;
            return;
        }
    }
    if (g->done_00 != 0u || g->points_8c.count == 0u) {
        return;
    }
    p = l70_points(g);
    if ((p[0].flags_2c & ROME2_L70_TOUCH_PRIMARY) == 0u) {
        return;
    }
    if (g->state_04 == ROME2_L70_STATE_IDLE && l70_step_idle(g)) {
        return;
    }
    p = l70_points(g);
    n = g->points_8c.count;
    vx = p[0].cur_1c[0] - p[0].prev_10[0];
    vy = p[0].cur_1c[1] - p[0].prev_10[1];
    len = sqrtf(vx * vx + vy * vy);
    dt = frame->dt_08;
    if (dt == 0.0f) {
        dt = 1.0f;
    }
    speed = len / dt;
    if (g->peak_speed_34 < speed) {
        g->peak_speed_34 = speed;
    }
    if (vx != 0.0f || vy != 0.0f) {
        g->dir_z_48 = 0.0f;
        g->dir_40[1] = (1.0f / len) * vy;
        g->dir_40[0] = (1.0f / len) * vx;
    }
    switch (g->state_04) {
    case ROME2_L70_STATE_RECLASSIFY:
        reclass = 1;
        break;
    case ROME2_L70_STATE_DRAG:
        reclass = (1u < n);
        break;
    case ROME2_L70_STATE_PENDING:
        reclass = (p[0].age_28 <= g->pan_time_28) ? (1u < n) : 1;
        break;
    case ROME2_L70_STATE_PINCH_ROTATE:
        reclass = (n < 2u);
        break;
    default:
        break;
    }
    if (reclass && l70_reclassify(g, globals, tuning)) {
        return;
    }
    p = l70_points(g);
    switch (g->state_04) {
    case ROME2_L70_STATE_DRAG:
    case ROME2_L70_STATE_PENDING:
    case ROME2_L70_STATE_PARALLEL:
        l70_point_record(g, (uint32_t)g->state_04);
        l70_try_flick(g);
        break;
    case ROME2_L70_STATE_PINCH_ROTATE:
        rome2_l70_gesture_emit_pinch_rotate(g, tuning, 0u);
        break;
    case ROME2_L70_STATE_SWIPE3:
        if (n < 3u || (p[0].flags_2c & ROME2_L70_TOUCH_RELEASED) != 0u) {
            if (n >= 2u) {
                /* The original reads the second point without a count check. */
                float d_start = l70_dist3(p[0].start_04, p[1].start_04);
                float d_cur = l70_dist3(p[0].cur_1c, p[1].cur_1c);
                float ratio = (d_start <= d_cur) ? d_start / d_cur : d_cur / d_start;

                if (ratio < 0.8f) {
                    l70_simple_record(g, 0xcu, 0.0f, 0.0f, (uint8_t)(d_cur < d_start));
                }
            }
            g->done_00 = 1u;
        }
        break;
    default:
        break;
    }
}

/* ---- 0x100d9880 ---- */

typedef struct l70_replay_op {
    uint8_t is_event;                            /* 1: push event `value`; 0: buttons_10[index] = value */
    uint8_t index;
    uint8_t value;
} l70_replay_op;

typedef struct l70_replay_row {
    uint8_t count;
    l70_replay_op ops[6];
} l70_replay_row;

/* buttons_10 index 0 = [ecx+0xb4], 1 = +0xb5, 2 = +0xb6, 4 = +0xb8. */
static const l70_replay_row l70_replay_table[15] = {
    {2u, {{0u, 0u, 1u}, {1u, 0u, 1u}}},
    {2u, {{0u, 0u, 0u}, {1u, 0u, 0u}}},
    {5u, {{1u, 0u, 0xcu}, {0u, 0u, 1u}, {1u, 0u, 1u}, {0u, 0u, 0u}, {1u, 0u, 0u}}},
    {4u, {{0u, 0u, 1u}, {1u, 0u, 3u}, {0u, 0u, 0u}, {1u, 0u, 2u}}},
    {2u, {{0u, 2u, 1u}, {1u, 0u, 9u}}},
    {2u, {{0u, 2u, 0u}, {1u, 0u, 8u}}},
    {4u, {{0u, 2u, 1u}, {1u, 0u, 9u}, {0u, 2u, 0u}, {1u, 0u, 8u}}},
    {2u, {{0u, 1u, 1u}, {1u, 0u, 5u}}},
    {2u, {{0u, 1u, 0u}, {1u, 0u, 4u}}},
    {4u, {{0u, 1u, 1u}, {1u, 0u, 5u}, {0u, 1u, 0u}, {1u, 0u, 4u}}},
    {4u, {{0u, 1u, 1u}, {1u, 0u, 7u}, {0u, 1u, 0u}, {1u, 0u, 6u}}},
    {6u, {{0u, 4u, 1u}, {0u, 1u, 1u}, {1u, 0u, 5u}, {0u, 1u, 0u}, {1u, 0u, 4u}, {0u, 4u, 0u}}},
    {4u, {{0u, 4u, 1u}, {0u, 1u, 1u}, {1u, 0u, 5u}, {0u, 4u, 0u}}},
    {4u, {{0u, 4u, 1u}, {0u, 1u, 0u}, {1u, 0u, 4u}, {0u, 4u, 0u}}},
    {1u, {{1u, 0u, 0xcu}}},
};

void rome2_l70_gesture_replay_records(rome2_l70_gesture *gesture) {
    rome2_l70_gesture *g = gesture;
    uint32_t i;

    if (g == NULL) {
        return;
    }
    for (i = 0u; i < g->records_98.count; i++) {
        const rome2_startup_gesture_record64_32 *rec =
            &((const rome2_startup_gesture_record64_32 *)g->records_98.data)[i];
        const l70_replay_row *row;
        uint32_t k;

        if (rec->code_34 == -1) {
            continue;
        }
        g->mouse_a4.buttons_10[6] = 1u;          /* [ecx+0xba] */
        if (rec->code_34 < 0 || rec->code_34 > 0xe) {
            continue;
        }
        g->mouse_a4.x_00 = rec->code_xy_38[0];
        g->mouse_a4.y_04 = rec->code_xy_38[1];
        row = &l70_replay_table[rec->code_34];
        for (k = 0u; k < row->count; k++) {
            if (row->ops[k].is_event != 0u) {
                l70_emit_event(g, row->ops[k].value);
            } else {
                g->mouse_a4.buttons_10[row->ops[k].index] = row->ops[k].value;
            }
        }
    }
}

/* ---- 0x100dcfe0 ---- */

void rome2_l70_gesture_tick(
    rome2_l70_gesture *gesture, const rome2_l70_input_globals *globals,
    const rome2_l70_tuning *tuning, const rome2_l70_frame *frame) {
    rome2_l70_gesture *g = gesture;
    rome2_startup_touch_point48_32 *p;
    uint32_t i;

    if (g == NULL || globals == NULL || tuning == NULL || frame == NULL) {
        return;
    }
    if (g->peak_speed_34 > 0.0f) {
        g->peak_speed_34 -= frame->dt_08 * tuning->peak_decay_rate;
    }
    if (g->cooldown_64 > 0.0f) {
        g->cooldown_64 -= frame->dt_08;
    }
    g->records_98.count = 0u;
    g->mouse_a4.buttons_10[6] = 1u;
    g->mouse_a4.buttons_10[7] = 0u;
    g->events_cc.count = 0u;
    g->aux_d8.count = 0u;
    if (g->inertia_speed_58 > 0.0f) {
        g->inertia_speed_58 -= g->inertia_decay_5c * frame->dt_08;
        if (0.001f > g->inertia_speed_58) {
            g->inertia_speed_58 = 0.0f;
            l70_simple_record(g, 0u, 0.0f, 0.0f, 1u);
        } else {
            float step = g->inertia_speed_58 * frame->dt_08;
            rome2_startup_gesture_record64_32 rec;

            memset(&rec, 0, sizeof(rec));
            rec.tag_00 = (uint32_t)g->inertia_tag_3c;
            /* The original stores the x position in both start slots. */
            rec.start_04[0] = g->inertia_pos_4c[0];
            rec.start_04[1] = g->inertia_pos_4c[0];
            rec.prev_0c[0] = l70_clamp01(g->inertia_pos_4c[0] - g->dir_40[0] * step);
            rec.prev_0c[1] = l70_clamp01(g->inertia_pos_4c[1] - g->dir_40[1] * step);
            rec.cur_14[0] = g->inertia_pos_4c[0];
            rec.cur_14[1] = g->inertia_pos_4c[1];
            rec.flag_31 = 1u;
            /* code_34 is uninitialized stack in the original; -1 keeps replay inert. */
            rec.code_34 = -1;
            l70_push_record(g, &rec);
        }
    }
    rome2_l70_gesture_ingest_raw(g, frame);
    rome2_l70_gesture_state_step(g, globals, tuning, frame);
    p = l70_points(g);
    for (i = g->points_8c.count; i > 0u; i--) {
        uint32_t flags = p[i - 1u].flags_2c;

        if ((flags & ROME2_L70_TOUCH_RELEASED) == 0u) {
            continue;
        }
        if ((flags & ROME2_L70_TOUCH_PRIMARY) != 0u) {
            g->done_00 = 1u;
        }
        memmove(&p[i - 1u], &p[i], (size_t)(g->points_8c.count - i) * sizeof(*p));
        g->points_8c.count--;
    }
    if (g->done_00 != 0u && g->points_8c.count == 0u) {
        if (g->inertia_speed_58 == 0.0f) {
            l70_simple_record(g, 0u, 0.0f, 0.0f, 1u);
        }
        g->done_00 = 0u;
        g->cooldown_64 = g->cooldown_reset_60;
        g->state_04 = ROME2_L70_STATE_IDLE;
    }
}

/* ---- 0x100dd7a0 / 0x100dd280 / 0x100ddcd0 ---- */

static void l70_call(
    const rome2_l70_handler *h, uint32_t slot, const void *record,
    const rome2_startup_input_state88_32 *state, const rome2_l70_frame *frame) {
    if (h->dispatch != NULL) {
        h->dispatch(h->user, slot, record, state, frame);
    }
}

/* Vector assignment inlined in both dispatchers: [mgr+0x98] = [mgr+0x8c]. */
static void l70_refresh_event_copy(rome2_l70_input_mgr *mgr) {
    rome2_l70_vec *dst = &mgr->events44_copy_98;
    const rome2_l70_vec *src = &mgr->events44_8c;
    uint32_t n = src->count;

    if (dst->capacity < n) {
        void *fresh = malloc((size_t)n * 0x2cu);

        if (fresh == NULL) {
            mgr->alloc_failures++;
            dst->count = 0u;
            return;
        }
        free(dst->data);
        dst->data = fresh;
        dst->capacity = n;
    }
    dst->count = n;
    if (n != 0u && dst->data != NULL && src->data != NULL) {
        memcpy(dst->data, src->data, (size_t)n * 0x2cu);
    }
}

void rome2_l70_input_mgr_free(rome2_l70_input_mgr *mgr) {
    if (mgr != NULL) {
        rome2_l70_vec_free(&mgr->records48_74);
        rome2_l70_vec_free(&mgr->events44_80);
        rome2_l70_vec_free(&mgr->events44_8c);
        rome2_l70_vec_free(&mgr->events44_copy_98);
        rome2_l70_vec_free(&mgr->records48_a4);
    }
}

void rome2_l70_input_mgr_update(
    rome2_l70_input_mgr *mgr, rome2_l70_gesture *gesture, rome2_l70_input_globals *globals,
    const rome2_l70_tuning *tuning, const rome2_l70_frame *frame) {
    rome2_startup_mouse_state40_32 scratch;
    uint32_t i;
    uint32_t k;

    if (mgr == NULL || gesture == NULL || globals == NULL || tuning == NULL || frame == NULL) {
        return;
    }
    rome2_l70_gesture_tick(gesture, globals, tuning, frame);
    for (i = 0u; i < mgr->secondary_count_60; i++) {
        const rome2_l70_handler *h = mgr->secondary_64[i];

        for (k = 0u; h->enabled_10 == 1u && k < gesture->records_98.count; k++) {
            l70_call(h, 0x24u, &((const rome2_startup_gesture_record64_32 *)gesture->records_98.data)[k], NULL, frame);
        }
    }
    for (i = 0u; i < mgr->primary_count_50; i++) {
        const rome2_l70_handler *h = mgr->primary_54[i];

        for (k = 0u; h->enabled_10 == 1u && k < gesture->records_98.count; k++) {
            l70_call(h, 0x20u, &((const rome2_startup_gesture_record64_32 *)gesture->records_98.data)[k], NULL, frame);
        }
    }
    rome2_l70_gesture_replay_records(gesture);
    if (gesture->points_8c.count != 0u || gesture->events_cc.count != 0u) {
        mgr->events44_8c.count = 0u;
        for (k = 0u; k < gesture->events_cc.count; k++) {
            rome2_startup_input_event44_32 *ev = &((rome2_startup_input_event44_32 *)gesture->events_cc.data)[k];

            /* COMISS/JBE pairs clamp in place; unlike the MINSS clamps, NaN is left unchanged. */
            if (0.0f > ev->state_04.x_00) {
                ev->state_04.x_00 = 0.0f;
            } else if (ev->state_04.x_00 > 1.0f) {
                ev->state_04.x_00 = 1.0f;
            }
            if (0.0f > ev->state_04.y_04) {
                ev->state_04.y_04 = 0.0f;
            } else if (ev->state_04.y_04 > 1.0f) {
                ev->state_04.y_04 = 1.0f;
            }
            (void)rome2_l70_mouse_state_set_and_publish(globals, &scratch, &ev->state_04);
            if (!rome2_l70_vec44_push_back(&mgr->events44_8c, ev)) {
                mgr->alloc_failures++;
            }
        }
    }
    if (gesture->points_8c.count != 0u || gesture->aux_d8.count != 0u) {
        mgr->records48_74.count = 0u;
        for (k = 0u; k < gesture->aux_d8.count; k++) {
            if (!rome2_l70_vec48_push_back(&mgr->records48_74, (const uint8_t *)gesture->aux_d8.data + (size_t)k * 0x30u)) {
                mgr->alloc_failures++;
            }
        }
    }
}

void rome2_l70_input_mgr_dispatch_primary(
    rome2_l70_input_mgr *mgr, rome2_l70_input_globals *globals, const rome2_l70_frame *frame) {
    rome2_startup_input_state88_32 state;
    int modal;
    uint32_t i;
    uint32_t k;

    if (mgr == NULL || globals == NULL) {
        return;
    }
    memset(&state, 0, sizeof(state));
    modal = (mgr->modal_query != NULL) ? (mgr->modal_query(mgr->modal_user) != 0) : 0;
    for (i = 0u; i < mgr->primary_count_50; i++) {
        const rome2_l70_handler *h = mgr->primary_54[i];

        if (h->enabled_10 != 1u) {
            continue;
        }
        for (k = 0u; k < mgr->records48_74.count; k++) {
            const uint8_t *rec = (const uint8_t *)mgr->records48_74.data + (size_t)k * 0x30u;

            (void)rome2_l70_mouse_state_set_and_publish(
                globals, &state.mouse_00, (const rome2_startup_mouse_state40_32 *)(const void *)(rec + 8));
            l70_call(h, 0x10u, rec, &state, frame);
        }
        for (k = 0u; k < mgr->records48_a4.count; k++) {
            l70_call(h, 0x18u, (const uint8_t *)mgr->records48_a4.data + (size_t)k * 0x30u, NULL, frame);
        }
        l70_refresh_event_copy(mgr);
        for (k = 0u; k < mgr->events44_copy_98.count; k++) {
            const rome2_startup_input_event44_32 *ev =
                &((const rome2_startup_input_event44_32 *)mgr->events44_copy_98.data)[k];

            (void)rome2_l70_mouse_state_set_and_publish(globals, &state.mouse_00, &ev->state_04);
            l70_call(h, 0x14u, ev, &state, frame);
        }
        if (!modal) {
            (void)rome2_l70_input_state_snapshot(globals, &state);
            l70_call(h, 0x1cu, NULL, &state, frame);
        }
    }
    mgr->flag_d2 = 0u;
}

void rome2_l70_input_mgr_dispatch_secondary(
    rome2_l70_input_mgr *mgr, rome2_l70_input_globals *globals, const rome2_l70_frame *frame) {
    rome2_startup_input_state88_32 state;
    uint32_t i;
    uint32_t k;

    if (mgr == NULL || globals == NULL || globals->dispatch_suppressed != 0u) {
        return;
    }
    memset(&state, 0, sizeof(state));
    for (i = 0u; i < mgr->secondary_count_60; i++) {
        const rome2_l70_handler *h = mgr->secondary_64[i];

        if (h->enabled_10 != 1u) {
            continue;
        }
        for (k = 0u; k < mgr->records48_74.count; k++) {
            const uint8_t *rec = (const uint8_t *)mgr->records48_74.data + (size_t)k * 0x30u;

            (void)rome2_l70_mouse_state_set_and_publish(
                globals, &state.mouse_00, (const rome2_startup_mouse_state40_32 *)(const void *)(rec + 8));
            l70_call(h, 0x14u, rec, &state, frame);
        }
        for (k = 0u; k < mgr->events44_80.count; k++) {
            const rome2_startup_input_event44_32 *ev =
                &((const rome2_startup_input_event44_32 *)mgr->events44_80.data)[k];

            (void)rome2_l70_mouse_state_set_and_publish(globals, &state.mouse_00, &ev->state_04);
            l70_call(h, 0x18u, ev, &state, frame);
        }
        for (k = 0u; k < mgr->records48_a4.count; k++) {
            const uint8_t *rec = (const uint8_t *)mgr->records48_a4.data + (size_t)k * 0x30u;

            (void)rome2_l70_input_state_init_from_record48(globals, &state, rec);
            l70_call(h, 0x20u, rec, &state, frame);
        }
        l70_refresh_event_copy(mgr);
        for (k = 0u; k < mgr->events44_copy_98.count; k++) {
            const rome2_startup_input_event44_32 *ev =
                &((const rome2_startup_input_event44_32 *)mgr->events44_copy_98.data)[k];

            (void)rome2_l70_mouse_state_set_and_publish(globals, &state.mouse_00, &ev->state_04);
            l70_call(h, 0x1cu, ev, &state, frame);
        }
        (void)rome2_l70_input_state_snapshot(globals, &state);
        l70_call(h, 0x28u, NULL, &state, frame);
    }
}
