#ifndef ROME2_STARTUP_ENTRY_FRAME_LOOP_OPS_H
#define ROME2_STARTUP_ENTRY_FRAME_LOOP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"

/*
 * Layer 71 Partition 8 recovery:
 * 17 entry_point / application run loop / frame step / per-frame
 * screen-manager update / timing and vector helper functions
 * (0x100d6cc0..0x112e2bf0).
 *
 * Native adaptations: virtual slots are tagged callbacks named by their
 * 32-bit slot offset, Win32/COM/CRT calls and already-recovered callees are
 * one injected hook, vectors hold native pointers, a null top handler is
 * skipped where the original would fault, and allocation failures are counted.
 * 0x10cb6520, reached from 0x10cb0440 by a conditional tail jump, is not
 * recovered and is a callback here.
 */

#define ROME2_L71_FRAME_MS_CAP 300u
#define ROME2_L71_FRAME_RING 50u
#define ROME2_L71_STEP_LIMIT 1000u
#define ROME2_L71_FP_CONTROL_MASK 0x030f031fu
#define ROME2_L71_FP_CONTROL_DEFAULT 0x000a001fu
#define ROME2_L71_WAIT_BUSY 10000u
#define ROME2_L71_WAIT_IDLE_SECONDS 8.0f
#define ROME2_L71_POWER_SAVE_CAP 30u

/* handler_step24 code_10 values as acted on by 0x100dbf80. */
#define ROME2_L71_CODE_NONE 0
#define ROME2_L71_CODE_PUSH 1
#define ROME2_L71_CODE_POP 2
#define ROME2_L71_CODE_REPLACE 3
#define ROME2_L71_CODE_REPLACE_NO_RESET 4
#define ROME2_L71_CODE_KEEP_BOTTOM 5
#define ROME2_L71_CODE_CLEAR 6

/* Hook ids: calls that leave the recovered Layer 71 bodies. */
enum {
    ROME2_L71_HOOK_REMOTE_POLL = 1,              /* 0x10cba590 */
    ROME2_L71_HOOK_CLOCK_MODE,                   /* 0x112e3d20() slot +0x54 (arg) */
    ROME2_L71_HOOK_OPEN_HANDLER,                 /* 0x100d81c0 */
    ROME2_L71_HOOK_INPUT_UPDATE,                 /* 0x100dd7a0 (data: frame_time12) */
    ROME2_L71_HOOK_INPUT_PRIMARY,                /* 0x100dd280 (data: frame_time12) */
    ROME2_L71_HOOK_INPUT_SECONDARY,              /* 0x100ddcd0 (data: frame_time12) */
    ROME2_L71_HOOK_TEARDOWN,                     /* 0x100d6db0 */
    ROME2_L71_HOOK_SOUND_EVENT,                  /* [[mgr+0x70]+8] slots +0x6c(0x814a7e77), +0xc */
    ROME2_L71_HOOK_DEVICE_SLOT94,                /* [[mgr+0x70]] slot +0x94 */
    ROME2_L71_HOOK_FP_PRECISION,                 /* 0x101150a0 (arg) */
    ROME2_L71_HOOK_OVERLAY_POP,                  /* 0x100dd4c0 */
    ROME2_L71_HOOK_DEVICE_FRAME,                 /* [[mgr+0x70]] slot +0x360 (arg 1 begin, 0 end) */
    ROME2_L71_HOOK_DEVICE_PRESENT,               /* [[mgr+0x70]] slot +0x354 */
    ROME2_L71_HOOK_SLEEP,                        /* SleepEx(arg ms, 1) */
    ROME2_L71_HOOK_POLL_INPUT,                   /* 0x1010eda0 */
    ROME2_L71_HOOK_LOG,                          /* text line (data: const char *) */
    ROME2_L71_HOOK_FPS_LINE,                     /* fwrite to [app+0x89c] (data: const char *) */
    ROME2_L71_HOOK_BENCHMARK_EXIT,               /* noreturn 0x100edcd0 (arg: whole seconds) */
    ROME2_L71_HOOK_APP_CONSTRUCT,                /* 0x100df270 */
    ROME2_L71_HOOK_APP_INIT,                     /* 0x100ea060 */
    ROME2_L71_HOOK_APP_RESTART,                  /* reverse delete of [app+0x870] x [app+0x86c] */
    ROME2_L71_HOOK_APP_DESTROY,                  /* 0x100e0650 */
    ROME2_L71_HOOK_STARTUP_INFO,                 /* 0x112f6190, 0x100e2980 */
    ROME2_L71_HOOK_COM,                          /* arg 1 CoInitialize, 0 CoUninitialize */
    ROME2_L71_HOOK_RELEASE_RESERVE,              /* VirtualFree(*reserve_slot, 0, MEM_RELEASE) */
    ROME2_L71_HOOK_ACCESS_DENIED_DIALOG,         /* 0x100de6d0 with string id 0x67 */
    ROME2_L71_HOOK_INVALID_PARAMETER_HANDLER,    /* 0x11687a4a(0x100ee5d0) */
    ROME2_L71_HOOK_KEEPER                        /* 0x101136d0(1), 0x101150f0(0x100d6560) */
};

/* Query ids: boolean results read from outside the recovered bodies. */
enum {
    ROME2_L71_QUERY_DEVICE_IDLE = 1,             /* [[mgr+0x70]] slot +0x3b0 */
    ROME2_L71_QUERY_QUIT_PUMP,                   /* 0x101061b0 */
    ROME2_L71_QUERY_WINDOW_ALIVE,                /* IsWindow([app+0x810]) */
    ROME2_L71_QUERY_POWER_SAVE,                  /* *0x10101980(&info) == 1 */
    ROME2_L71_QUERY_DEVICE_SLOT3FC,              /* [ctx+0xc] slot +0x3fc */
    ROME2_L71_QUERY_TOP_SLOT50,                  /* top handler slot +0x50 */
    ROME2_L71_QUERY_TOP_SLOT54,                  /* top handler slot +0x54 */
    ROME2_L71_QUERY_TOP_SLOT4C,                  /* top handler slot +0x4c */
    ROME2_L71_QUERY_BENCHMARK_NAME_SET,          /* 0x101028f0(0x119f3174) != 0 */
    ROME2_L71_QUERY_VFS_QUIT_FLAG                /* 0x112bff20 */
};

typedef struct rome2_l71_env {
    void *user;
    uint64_t (*now_us)(void *user);              /* 0x112e2bb0 */
    uint64_t (*counter)(void *user);             /* QueryPerformanceCounter */
    void (*hook)(void *user, uint32_t id, uint32_t arg, const void *data);
    uint8_t (*query)(void *user, uint32_t id);
} rome2_l71_env;

typedef struct rome2_l71_ptr_vec {
    uint32_t capacity;
    uint32_t count;
    void **data;
} rome2_l71_ptr_vec;

typedef struct rome2_l71_u64_vec {
    uint32_t capacity;                           /* 0x11933190 (initial image value 0x00010000) */
    uint32_t count;                              /* 0x11933194 */
    uint64_t *data;                              /* 0x11933198 */
} rome2_l71_u64_vec;

/* One interface behind [holder+0x14], used by 0x10c8fff0 / 0x10c914d0. */
typedef struct rome2_l71_iface {
    uint8_t (*slot28)(void *user);
    void (*slot14)(void *user);
    void (*slot08)(void *user);
    void *user;
} rome2_l71_iface;

typedef struct rome2_l71_iface_holder {
    rome2_l71_iface *iface_14;
} rome2_l71_iface_holder;

typedef struct rome2_l71_advice_state {
    uint8_t enabled;                             /* 0x11f83ca5 */
    uint32_t pending_count;                      /* 0x1196fc24 */
    void (*issue_pending)(void *user);           /* unrecovered 0x10cb6520 */
    void *user;
} rome2_l71_advice_state;

typedef struct rome2_l71_toggle {
    uint8_t enabled_10;
    uint8_t (*set)(struct rome2_l71_toggle *self, uint8_t enable);  /* slot +0x04 enable, +0x00 disable */
    void *user;
} rome2_l71_toggle;

typedef struct rome2_l71_ui_entry {
    uint8_t wanted_00;
    rome2_l71_toggle *handler_04;
    const char *owner_name;                      /* string at [[entry+8]+8] */
    void (*destroy_owner)(void *user);           /* [entry+8] slot +0x00 with argument 1 */
    void *user;
} rome2_l71_ui_entry;

typedef struct rome2_l71_listener {
    uint8_t enabled_10;
    void (*notify)(struct rome2_l71_listener *self, uint32_t slot, const void *arg);
    void *user;
} rome2_l71_listener;

typedef struct rome2_l71_handler rome2_l71_handler;
typedef struct rome2_l71_factory rome2_l71_factory;

typedef struct rome2_l71_step_result {
    uint8_t advanced;
    uint32_t ms;
    uint8_t again;
    rome2_l71_factory *factory;
    int32_t code;
    uint8_t leave_ui;
    uint8_t notify;
} rome2_l71_step_result;

struct rome2_l71_handler {
    uint32_t elapsed_ms_04;
    void (*step)(rome2_l71_handler *self, rome2_l71_step_result *out);                   /* slot +0x00 */
    rome2_l71_factory *(*request)(rome2_l71_handler *self, uint32_t slot, uint32_t arg); /* +0x40, +0x44, +0x48 */
    int (*time_scale)(rome2_l71_handler *self, float *out);    /* slot +0x5c object, then its slot +0x1c */
    void (*notify)(rome2_l71_handler *self, uint32_t slot, const void *arg);             /* void slots */
    void *user;
};

struct rome2_l71_factory {
    rome2_l71_handler *(*create)(rome2_l71_factory *self, uint8_t flag);                 /* slot +0x04 */
    void (*notify)(rome2_l71_factory *self, uint32_t slot);                              /* +0x0c, +0x00 */
    void *user;
};

typedef struct rome2_l71_render_args {
    rome2_l71_handler *top;
    const rome2_startup_frame_time16_32 *frame;
    uint32_t render_ms;
} rome2_l71_render_args;

typedef struct rome2_l71_globals {
    uint32_t fixed_fps;                          /* 0x119ef0c8 */
    uint8_t sample_counter;                      /* 0x119ef0cc */
    uint8_t flag_cd;                             /* 0x119ef0cd */
    uint8_t flag_ce;                             /* 0x119ef0ce */
    uint8_t capture_request;                     /* 0x119ef0cf */
    uint8_t flag_8d0;                            /* 0x119ef8d0 */
    uint8_t quit_all;                            /* 0x119ef8d6 */
    uint32_t capture_name_length;                /* length of the string at 0x119f06ac */
    float time_scale;                            /* 0x119f1da8 */
    uint8_t last_us_valid;                       /* guard 0x119f3088 */
    uint64_t last_us;                            /* 0x119f3080 */
    uint8_t movie_skip_enabled;                  /* 0x11933000 */
    uint32_t wait_value;                         /* 0x11934468 */
    float wait_seconds;                          /* 0x119f3ea8 */
    uint64_t counter_base;                       /* 0x11933188 */
    rome2_l71_u64_vec samples;
    void *accum_2c;                              /* [0x11f83cc4]: 0x10cb8480 */
    void *accum_0c;                              /* [0x11f83cbc]: 0x10cb8420 */
    void *accum_28;                              /* [0x11f83cc0]: 0x10cb8450 */
} rome2_l71_globals;

/* Screen manager; names end in the 32-bit offset of the count or flag. */
typedef struct rome2_l71_screen_mgr {
    rome2_l71_ptr_vec ui_entries_20;             /* count +0x20, data +0x24 */
    rome2_l71_ptr_vec handlers_2c;               /* capacity +0x2c, count +0x30, data +0x34 */
    rome2_l71_ptr_vec listeners_40;              /* count +0x40, data +0x44 */
    rome2_l71_ptr_vec primary_50;                /* count +0x50, data +0x54 */
    rome2_l71_ptr_vec secondary_60;              /* count +0x60, data +0x64 */
    rome2_l71_iface_holder *movie;               /* [[mgr+0x70]+0x28] */
    uint8_t has_sound;                           /* [[mgr+0x70]+8] != 0 */
    uint32_t records_count_78;
    const uint32_t (*records_7c)[12];            /* 48B records; dwords 0 and 1 are tested */
    uint32_t events_count_84;
    uint32_t events_count_90;
    uint32_t records_count_a8;
    rome2_l71_ptr_vec renderers_b4;              /* count +0xb4, data +0xb8 */
    uint32_t total_ms_c0;
    uint32_t scaled_total_ms_c4;
    uint8_t loading_c8;
    uint8_t reload_c9;
    uint8_t request_cb[4];                       /* +0xcb..+0xce */
    uint8_t pop_request_cf;
    uint8_t request_d0;
    uint8_t notify_d1;
    uint8_t render_blocked_d3;
    int32_t present_delay_d4;
    uint32_t frame_ms_e8[ROME2_L71_FRAME_RING];
    uint32_t frame_count_1b0;
    uint32_t frame_index_1b4;
    uint8_t overlay_1b8;
    rome2_l71_advice_state *advice;
    uint32_t alloc_failures;                     /* native only */
} rome2_l71_screen_mgr;

/* Application object fields read by 0x100ec5c0 / 0x100ed3c0. */
typedef struct rome2_l71_app {
    uint64_t last_frame_us_8a0;
    float fps_window_start_894;
    int32_t fps_frames_898;                      /* -1 until the first logged frame */
    uint8_t fps_log_open_89c;
    uint8_t first_frame_pending;                 /* 0x11933ad0 (initial 1) */
    uint32_t overlay_cap;                        /* 0x119f33f8 */
    uint32_t forced_cap;                         /* 0x119f3378 */
    uint8_t started_flags[2];                    /* 0x119f31c8, 0x119f31c5 */
} rome2_l71_app;

typedef struct rome2_l71_crash_ctx {
    uint32_t arg6_58;
    uint32_t arg7_5c;
    uint32_t arg4_60;
    uintptr_t *reserve_slot_64;
} rome2_l71_crash_ctx;

typedef struct rome2_l71_entry_env {
    rome2_l71_env base;
    int32_t (*game_explorer_create)(void *user);                   /* CoCreateInstance HRESULT */
    int32_t (*game_explorer_verify)(void *user, int32_t *allowed); /* slot +0x18 HRESULT */
    void (*run)(void *user, int guarded);                          /* 0x100ed3c0 */
} rome2_l71_entry_env;

/* 0x104274b0 / 0x112ac410 / 0x112e2bf0 */
rome2_startup_u64_pair8_32 *rome2_l71_u64_pair_ctor(rome2_startup_u64_pair8_32 *self, uint32_t lo, uint32_t hi);
rome2_startup_u64_pair8_32 *rome2_l71_u64_add(
    rome2_startup_u64_pair8_32 *out, const rome2_startup_u64_pair8_32 *lhs, const rome2_startup_u64_pair8_32 *rhs);
uint32_t rome2_l71_us_to_scaled_ms(const rome2_startup_u64_pair8_32 *us, float scale);

/* 0x10cb8420 / 0x10cb8450 / 0x10cb8480: {last, accumulator} floats at +0x0c, +0x28 and +0x2c. */
void rome2_l71_time_accum_0c(void *object, float value, float scale);
void rome2_l71_time_accum_28(void *object, float value, float scale);
void rome2_l71_time_accum_2c(void *object, float value, float scale);

/* 0x100f6940 / 0x10114ee0 */
int rome2_l71_fp_control_is_engine_default(uint32_t control_word);
void rome2_l71_set_wait_params(rome2_l71_globals *globals, uint32_t value, float seconds);

/* 0x100d9d90 */
int rome2_l71_ptr_vec_push_back(rome2_l71_ptr_vec *vec, void *value);
void rome2_l71_ptr_vec_free(rome2_l71_ptr_vec *vec);

/* 0x10c8fff0 / 0x10c914d0 / 0x10cb0440 */
void rome2_l71_iface_call_slot14_if_slot28(const rome2_l71_iface_holder *holder);
void rome2_l71_iface_call_slot08_if_present(const rome2_l71_iface_holder *holder);
int rome2_l71_advice_set_enabled(rome2_l71_advice_state *state, uint8_t enabled);

/* 0x100d6cc0 */
uint32_t rome2_l71_remove_ui_entries(rome2_l71_ptr_vec *entries, const char *prefix_or_null);

/* Pieces of 0x100dbf80 */
uint32_t rome2_l71_scale_frame_ms(uint32_t ms, float time_scale);
void rome2_l71_frame_ring_push(rome2_l71_screen_mgr *mgr, uint32_t ms);
int rome2_l71_u64_vec_push(rome2_l71_u64_vec *vec, uint64_t value);

/* 0x100dbf80 */
uint8_t rome2_l71_screen_mgr_frame_update(
    rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env);

/* 0x100ec5c0 */
size_t rome2_l71_format_fps_line(char *out, size_t out_size, uint32_t frames, uint32_t seconds);
uint32_t rome2_l71_app_frame_step(
    rome2_l71_app *app, rome2_l71_screen_mgr *mgr, rome2_l71_globals *globals, const rome2_l71_env *env);

/* 0x100ed3c0 */
void rome2_l71_app_run(
    rome2_l71_app *app, const rome2_l71_env *env, uint32_t (*frame_step)(void *user), void *step_user);

/* 0x100edd70 */
int rome2_l71_command_line_disables_exception_handler(const uint16_t *command_line);
uint8_t rome2_l71_entry_point(
    const rome2_l71_entry_env *env, rome2_l71_crash_ctx *ctx, const uint16_t *command_line,
    uint32_t arg4, uintptr_t *reserve_slot, uint32_t arg6, uint32_t arg7, const uint8_t *exit_flag_119f3144);

#endif
