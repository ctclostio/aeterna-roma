#ifndef ROME2_STARTUP_TOUCH_GESTURE_INPUT_OPS_H
#define ROME2_STARTUP_TOUCH_GESTURE_INPUT_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

/*
 * Layer 70 Partition 8 recovery:
 * 21 touch-gesture recognizer / input-handler dispatch / mouse-state /
 * 48B-44B-64B vector push / libm acosf functions (0x100d2690..0x1168cad5).
 *
 * Native adaptations: vectors hold native pointers, by-value 48B stack
 * arguments are passed by pointer, virtual slots are one tagged callback,
 * allocation failures are counted instead of faulting, and floating results
 * use the host libm, so they are not claimed bit-identical to the original
 * table-driven SSE2 code.
 */

#define ROME2_L70_TOUCH_RELEASED 0x04u
#define ROME2_L70_TOUCH_PRIMARY 0x10u

#define ROME2_L70_STATE_IDLE (-1)
#define ROME2_L70_STATE_RECLASSIFY 1
#define ROME2_L70_STATE_DRAG 2
#define ROME2_L70_STATE_PENDING 5
#define ROME2_L70_STATE_PARALLEL 7
#define ROME2_L70_STATE_HOLD 9
#define ROME2_L70_STATE_PINCH_ROTATE 0xb
#define ROME2_L70_STATE_SWIPE3 0xc

/* Initial image values of the pinned .data tunables. */
#define ROME2_L70_ROTATE_SCALE_INIT (-0.1f)    /* 0x119331d8 */
#define ROME2_L70_SPAN_SCALE_INIT 100.0f       /* 0x119331dc */
#define ROME2_L70_PEAK_DECAY_INIT 8.0f         /* 0x119331e0 */
#define ROME2_L70_ANGLE_SCALE 57.288353f       /* 0x1173e2f0, negated at 0x1173e2f8 */

typedef struct rome2_l70_vec {
    uint32_t capacity;
    uint32_t count;
    void *data;
} rome2_l70_vec;

typedef struct rome2_l70_tuning {
    float rotate_scale;                          /* 0x119331d8 */
    float span_scale;                            /* 0x119331dc */
    float peak_decay_rate;                       /* 0x119331e0 */
    float parallel_dot_min;                      /* 0x119331d4: initial value not pinned */
} rome2_l70_tuning;

typedef struct rome2_l70_input_globals {
    rome2_startup_mouse_state40_32 mouse;        /* 0x119344c0..0x119344e7 */
    uint8_t mouse_valid;                         /* 0x11933c7c */
    uint8_t aux_record[48];                      /* 0x119f3d90..0x119f3dbf */
    uint8_t dispatch_suppressed;                 /* 0x119f30a0 */
} rome2_l70_input_globals;

typedef struct rome2_l70_frame {
    uint32_t unread_00[2];
    float dt_08;                                 /* frame time read at [frame+8] */
} rome2_l70_frame;

/* Recognizer object; the comment on each field is its 32-bit offset. */
typedef struct rome2_l70_gesture {
    uint8_t done_00;
    int32_t state_04;
    float tap_anchor_08[3];
    float hold_time_14;
    float move_threshold_18;
    float tap_window_1c;
    float tap_elapsed_20;
    float pan_time_28;
    float peak_speed_34;
    float flick_speed_38;
    int32_t inertia_tag_3c;
    float dir_40[2];
    float dir_z_48;
    float inertia_pos_4c[2];
    float inertia_pos_z_54;
    float inertia_speed_58;
    float inertia_decay_5c;
    float cooldown_reset_60;
    float cooldown_64;
    uint8_t second_down_68;
    float second_pos_6c[3];
    float pinch_threshold_78;
    float rotate_threshold_7c;
    rome2_l70_vec raw_80;                        /* 24B raw touches; count +0x84, data +0x88 */
    rome2_l70_vec points_8c;                     /* 48B tracked points */
    rome2_l70_vec records_98;                    /* 64B gesture records */
    rome2_startup_mouse_state40_32 mouse_a4;     /* pointer state stamped into events */
    rome2_l70_vec events_cc;                     /* 44B events */
    rome2_l70_vec aux_d8;                        /* 48B {0, 0, mouse40} records */
    uint32_t alloc_failures;                     /* native only */
} rome2_l70_gesture;

/* One callback stands in for a handler vtable; slot is the 32-bit slot offset. */
typedef void (*rome2_l70_dispatch_fn)(
    void *user, uint32_t slot, const void *record,
    const rome2_startup_input_state88_32 *state, const rome2_l70_frame *frame);

typedef struct rome2_l70_handler {
    uint8_t enabled_10;                          /* byte at [handler+0x10]; dispatched only when 1 */
    rome2_l70_dispatch_fn dispatch;
    void *user;
} rome2_l70_handler;

typedef struct rome2_l70_input_mgr {
    int (*modal_query)(void *user);              /* top entry of [mgr+0x34] x [mgr+0x30], slot +0x28 */
    void *modal_user;
    rome2_l70_handler **primary_54;
    uint32_t primary_count_50;
    rome2_l70_handler **secondary_64;
    uint32_t secondary_count_60;
    rome2_l70_vec records48_74;                  /* count +0x78, data +0x7c */
    rome2_l70_vec events44_80;                   /* count +0x84, data +0x88 */
    rome2_l70_vec events44_8c;                   /* count +0x90, data +0x94 */
    rome2_l70_vec events44_copy_98;              /* count +0x9c, data +0xa0 */
    rome2_l70_vec records48_a4;                  /* count +0xa8, data +0xac */
    uint8_t flag_d2;
    uint32_t alloc_failures;                     /* native only */
} rome2_l70_input_mgr;

/* 0x100d2690 / 0x100d6910 */
void *rome2_l70_pod48_copy_assign(void *dst48, const void *src48);
void rome2_l70_pod48_copy(void *dst48, const void *src48);

/* 0x100d9e40 / 0x100d9f80 / 0x100da2b0 / 0x100da3f0 share one growth policy. */
int rome2_l70_vec_push(rome2_l70_vec *vec, const void *elem, size_t elem_size);
int rome2_l70_vec48_push_back(rome2_l70_vec *vec, const void *elem48);
int rome2_l70_vec44_push_back(rome2_l70_vec *vec, const rome2_startup_input_event44_32 *elem44);
int rome2_l70_vec64_push_back(rome2_l70_vec *vec, const rome2_startup_gesture_record64_32 *elem64);
int rome2_l70_vec48_push_back_dwords(rome2_l70_vec *vec, const rome2_startup_touch_point48_32 *elem48);
void rome2_l70_vec_free(rome2_l70_vec *vec);

/* 0x1168cad5 / 0x100d7b80 / 0x100d7f30 */
float rome2_l70_acosf(float x);
float rome2_l70_touch_pair_span_delta(
    const rome2_startup_touch_point48_32 *a, const rome2_startup_touch_point48_32 *b);
float rome2_l70_touch_pair_signed_angle(
    const rome2_startup_touch_point48_32 *a, const rome2_startup_touch_point48_32 *b);

/* 0x100f1090 / 0x100f1100 / 0x100f1160 / 0x10103c50 */
void rome2_l70_input_globals_init(rome2_l70_input_globals *globals);
rome2_startup_input_state88_32 *rome2_l70_input_state_init_from_record48(
    rome2_l70_input_globals *globals, rome2_startup_input_state88_32 *state, const void *record48);
void *rome2_l70_mouse_state_set_and_publish(
    rome2_l70_input_globals *globals, void *dst40, const rome2_startup_mouse_state40_32 *src40);
rome2_startup_input_state88_32 *rome2_l70_input_state_snapshot(
    const rome2_l70_input_globals *globals, rome2_startup_input_state88_32 *state);
void *rome2_l70_mouse_state_ptr_if_valid(const rome2_l70_input_globals *globals, void *ptr);

/* 0x100d8430 / 0x100da620 / 0x100d89a0 / 0x100d9880 / 0x100dcfe0 */
void rome2_l70_gesture_init(rome2_l70_gesture *gesture);
void rome2_l70_gesture_free(rome2_l70_gesture *gesture);
void rome2_l70_gesture_ingest_raw(rome2_l70_gesture *gesture, const rome2_l70_frame *frame);
void rome2_l70_gesture_emit_pinch_rotate(
    rome2_l70_gesture *gesture, const rome2_l70_tuning *tuning, uint8_t ending);
void rome2_l70_gesture_state_step(
    rome2_l70_gesture *gesture, const rome2_l70_input_globals *globals,
    const rome2_l70_tuning *tuning, const rome2_l70_frame *frame);
void rome2_l70_gesture_replay_records(rome2_l70_gesture *gesture);
void rome2_l70_gesture_tick(
    rome2_l70_gesture *gesture, const rome2_l70_input_globals *globals,
    const rome2_l70_tuning *tuning, const rome2_l70_frame *frame);

/* 0x100dd7a0 / 0x100dd280 / 0x100ddcd0 */
void rome2_l70_input_mgr_free(rome2_l70_input_mgr *mgr);
void rome2_l70_input_mgr_update(
    rome2_l70_input_mgr *mgr, rome2_l70_gesture *gesture, rome2_l70_input_globals *globals,
    const rome2_l70_tuning *tuning, const rome2_l70_frame *frame);
void rome2_l70_input_mgr_dispatch_primary(
    rome2_l70_input_mgr *mgr, rome2_l70_input_globals *globals, const rome2_l70_frame *frame);
void rome2_l70_input_mgr_dispatch_secondary(
    rome2_l70_input_mgr *mgr, rome2_l70_input_globals *globals, const rome2_l70_frame *frame);

#endif
