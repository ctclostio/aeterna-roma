#include "startup_handler_stdio_close_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned g_checks = 0u;

static void check_impl(int cond, const char *expr, int line) {
    if (!cond) {
        fprintf(stderr, "CHECK FAILED line %d: %s\n", line, expr);
        exit(1);
    }
    g_checks += 1u;
}

#define CHECK(cond) check_impl((cond) != 0, #cond, __LINE__)

static void test_layouts_and_crt_stdio_close(void) {
    rome2_startup_crt_stdio_env *crt =
        (rome2_startup_crt_stdio_env *)calloc(1u, sizeof(*crt));
    rome2_startup_crt_stream_model *stream =
        (rome2_startup_crt_stream_model *)calloc(1u, sizeof(*stream));
    rome2_startup_crt_stream_model *str_stream =
        (rome2_startup_crt_stream_model *)calloc(1u, sizeof(*str_stream));
    rome2_startup_fwrite_capture16_32 cap = { 0x2000u, 0x2004u, 0x2008u, 0x200cu };

    CHECK(crt != NULL && stream != NULL && str_stream != NULL);
    CHECK(sizeof(rome2_startup_log_file_box8_32) == 8u);
    CHECK(offsetof(rome2_startup_log_file_box8_32, last_errno_04) == 4u);
    CHECK(sizeof(rome2_startup_fwrite_capture16_32) == 16u);
    CHECK(sizeof(rome2_startup_handler_slot4_32) == 4u);
    CHECK(sizeof(rome2_startup_crt_ioinfo56_32) == 0x38u);
    CHECK(offsetof(rome2_startup_crt_ioinfo56_32, osfhnd_18) == 0x18u);
    CHECK(offsetof(rome2_startup_crt_ioinfo56_32, osfile_28) == 0x28u);

    crt->nhandle = 8u;
    CHECK(rome2_startup_crt_get_std_handle_policy_116bc6d8(crt) == 0u);
    crt->std_handle_free_policy = 1u;
    CHECK(rome2_startup_crt_get_std_handle_policy_116bc6d8(crt) == 1u);

    /* Freeing invalid fd / unset handle */
    CHECK(rome2_startup_crt_free_osfhnd_116ae9c8(crt, -1) == -1);
    CHECK(crt->last_errno == ROME2_STARTUP_CRT_EBADF);
    CHECK(rome2_startup_crt_close_116ab5cb(crt, -2) == -1);
    CHECK(crt->invalid_param_calls == 0u);
    CHECK(rome2_startup_crt_close_116ab5cb(crt, 9) == -1);
    CHECK(crt->invalid_param_calls == 1u);

    /* Stdout/stderr alias close skips CloseHandle when handles match, then closes second one */
    crt->io_slots[0].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[0].osfhnd_18 = 0x100u;
    crt->io_slots[1].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[1].osfhnd_18 = 0x200u;
    crt->io_slots[2].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[2].osfhnd_18 = 0x200u;
    CHECK(rome2_startup_crt_close_116ab5cb(crt, 1) == 0);
    CHECK(crt->close_handle_calls == 0u);
    CHECK(crt->set_std_handle_calls == 1u);
    CHECK(crt->last_std_handle_id == ROME2_STARTUP_STD_OUTPUT_HANDLE);
    CHECK(crt->io_slots[1].osfile_28 == 0u);
    CHECK(crt->lock_fhandle_calls == 1u && crt->unlock_fhandle_calls == 1u);

    CHECK(rome2_startup_crt_close_116ab5cb(crt, 2) == 0);
    CHECK(crt->close_handle_calls == 1u);
    CHECK(crt->closed_handles[0] == 0x200u);
    CHECK(crt->last_std_handle_id == ROME2_STARTUP_STD_ERROR_HANDLE);

    CHECK(rome2_startup_crt_free_osfhnd_116ae9c8(crt, 0) == 0);
    CHECK(crt->last_std_handle_id == ROME2_STARTUP_STD_INPUT_HANDLE);
    CHECK(crt->io_slots[0].osfhnd_18 == ROME2_STARTUP_CRT_INVALID_HANDLE);

    /* CloseHandle error path */
    crt->io_slots[4].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[4].osfhnd_18 = 0xBADu;
    crt->fail_close_os_handle = 0xBADu;
    crt->simulated_last_error = 6u;
    CHECK(rome2_startup_crt_close_116ab5cb(crt, 4) == -1);
    CHECK(crt->last_doserrno == 6u && crt->last_errno == ROME2_STARTUP_CRT_EBADF);

    /* Buffered fwrite + _feof + _fclose on stream */
    CHECK(rome2_startup_crt_feof_11687a7a(crt, NULL) == 0);
    CHECK(crt->last_errno == ROME2_STARTUP_CRT_EINVAL);
    CHECK(rome2_startup_crt_fwrite_11688039(crt, "abc", 1u, 0u, stream) == 0u);
    CHECK(rome2_startup_crt_fwrite_11688039(crt, "abc", 1u, 1u, NULL) == 0u);

    crt->io_slots[3].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[3].osfhnd_18 = 0x333u;
    stream->guest.file_10 = 3;
    stream->guest.bufsiz_18 = 16;
    stream->guest.base_04 = 0x30001000u;
    stream->guest.ptr_00 = 0x30001000u;
    stream->guest.tmpfname_1c = 0x30002000u;
    stream->guest.flags_0c = ROME2_STARTUP_IOALLOCATED | ROME2_STARTUP_IOBUFFER_CRT;
    stream->guest.cnt_08 = 16;

    CHECK(rome2_startup_crt_fwrite_lambda_11687e75(crt, &cap, "hi", 1u, 2u, stream) == 2u);
    CHECK(crt->flock_lock_calls == 1u && crt->flock_unlock_calls == 1u);
    CHECK(rome2_startup_crt_fwrite_11688039(crt, "0123456789abcdef0123", 1u, 20u, stream) == 20u);
    CHECK(rome2_startup_crt_feof_11687a7a(crt, stream) == 0);
    CHECK(rome2_startup_crt_fclose_1168ed98(crt, stream) == 0);
    CHECK(stream->sink_len == 22u);
    CHECK(memcmp(stream->sink, "hi0123456789abcdef0123", 22u) == 0);
    CHECK(stream->guest.file_10 == -1 && stream->guest.flags_0c == 0u);
    CHECK(crt->io_slots[3].osfhnd_18 == ROME2_STARTUP_CRT_INVALID_HANDLE);
    CHECK(crt->freed_va_count == 2u);
    CHECK(crt->freed_vas[0] == 0x30001000u && crt->freed_vas[1] == 0x30002000u);
    CHECK(crt->lock_file_calls == 2u && crt->unlock_file_calls == 2u);

    /* _IOSTRG fclose path */
    str_stream->guest.flags_0c = ROME2_STARTUP_IOSTRG;
    str_stream->guest.file_10 = 5;
    CHECK(rome2_startup_crt_fclose_1168ed98(crt, str_stream) == -1);
    CHECK(str_stream->guest.flags_0c == 0u && str_stream->guest.file_10 == -1);

    /* Null fclose + non-return unlock helpers direct smoke */
    CHECK(rome2_startup_crt_fclose_1168ed98(crt, NULL) == -1);
    rome2_startup_crt_seh_fwrite_unlock_11687e69(crt, stream);
    rome2_startup_crt_seh_fclose_unlock_1168ee12(crt, stream);
    rome2_startup_crt_seh_close_unlock_116ab5bf(crt, 0);

    free(str_stream);
    free(stream);
    free(crt);
}

static void test_teardown_and_log_close(void) {
    rome2_startup_app_teardown_buffers bufs;
    rome2_startup_app_observer_array *obs =
        (rome2_startup_app_observer_array *)calloc(1u, sizeof(*obs));
    rome2_startup_crt_stdio_env *crt =
        (rome2_startup_crt_stdio_env *)calloc(1u, sizeof(*crt));
    rome2_startup_crt_stream_model *log_fp =
        (rome2_startup_crt_stream_model *)calloc(1u, sizeof(*log_fp));
    rome2_startup_app_log_state log_state;

    CHECK(obs != NULL && crt != NULL && log_fp != NULL);
    memset(&bufs, 0, sizeof(bufs));
    bufs.ptr_0e0 = 0x10e0u;
    bufs.ptr_0a0 = 0x10a0u;
    bufs.ptr_088 = 0x1088u;
    rome2_startup_app_cleanup_five_buffers_100d3620(&bufs);
    CHECK(bufs.freed_count == 3u);
    CHECK(bufs.freed_vas[0] == 0x10e0u && bufs.freed_vas[1] == 0x10a0u && bufs.freed_vas[2] == 0x1088u);
    CHECK(bufs.ptr_0e0 == 0u && bufs.ptr_094 == 0u && bufs.ptr_088 == 0u);

    obs->active_count = 4u;
    obs->slot_vas[0] = 0xA000u;
    obs->slot_vas[1] = 0u;
    obs->slot_vas[2] = 0xA002u;
    obs->slot_vas[3] = 0xA003u;
    rome2_startup_app_destroy_observer_slots_100e7690(obs);
    CHECK(obs->active_count == 0u && obs->destroyed_count == 3u);
    CHECK(obs->destroyed_vas[0] == 0xA003u && obs->destroyed_vas[1] == 0xA002u && obs->destroyed_vas[2] == 0xA000u);

    crt->nhandle = 8u;
    crt->io_slots[5].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[5].osfhnd_18 = 0x555u;
    log_fp->guest.file_10 = 5;
    log_fp->guest.bufsiz_18 = 32;
    log_fp->guest.base_04 = 0x40001000u;
    log_fp->guest.ptr_00 = 0x40001000u;
    log_fp->guest.flags_0c = ROME2_STARTUP_IOALLOCATED | ROME2_STARTUP_IOBUFFER_CRT;
    log_fp->guest.cnt_08 = 32;

    memset(&log_state, 0, sizeof(log_state));
    CHECK(rome2_startup_app_close_log_100e32e0(&log_state, crt) == 0u);
    log_state.box_va = 0x50000100u;
    log_state.box.stdio_file_00 = 0x50000200u;
    log_state.open_stream = log_fp;
    CHECK(rome2_startup_app_close_log_100e32e0(&log_state, crt) == 1u);
    CHECK(log_fp->sink_len == ROME2_STARTUP_LOG_END_LEN);
    CHECK(memcmp(log_fp->sink, "End Logging\r\n", ROME2_STARTUP_LOG_END_LEN) == 0);
    CHECK(log_state.box_va == 0u && log_state.box.stdio_file_00 == 0u && log_state.box.last_errno_04 == 0);
    CHECK(log_state.freed_box_count == 1u && log_state.freed_box_vas[0] == 0x50000100u);

    /* Short write + EOF triggers sentinel 0x26 before fclose */
    memset(log_fp, 0, sizeof(*log_fp));
    crt->io_slots[6].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[6].osfhnd_18 = 0x666u;
    log_fp->guest.file_10 = 6;
    log_fp->guest.flags_0c = ROME2_STARTUP_IOALLOCATED | ROME2_STARTUP_IOBUFFER_NONE;
    log_fp->fail_write = 1u;
    log_fp->simulate_eof_on_error = 1u;
    log_fp->fail_flush = 1u;
    log_state.box_va = 0x50000300u;
    log_state.box.stdio_file_00 = 0x50000400u;
    log_state.open_stream = log_fp;
    CHECK(rome2_startup_crt_fwrite_11688039(crt, "X", 1u, 1u, log_fp) == 0u);
    CHECK(rome2_startup_crt_feof_11687a7a(crt, log_fp) == 1);
    CHECK(rome2_startup_log_file_box_close_10121170(&log_state, crt) == 1u); /* clears errno when fclose succeeds despite flush err */

    memset(log_fp, 0, sizeof(*log_fp));
    crt->io_slots[7].osfile_28 = ROME2_STARTUP_IOFILE_FOPEN;
    crt->io_slots[7].osfhnd_18 = 0x777u;
    log_fp->guest.file_10 = 7;
    log_fp->guest.flags_0c = ROME2_STARTUP_IOALLOCATED | ROME2_STARTUP_IOBUFFER_NONE;
    log_fp->fail_write = 1u;
    log_fp->simulate_eof_on_error = 1u;
    crt->fail_close_os_handle = 0x777u;
    log_state.box_va = 0x50000500u;
    log_state.box.stdio_file_00 = 0x50000600u;
    log_state.open_stream = log_fp;
    CHECK(rome2_startup_app_close_log_100e32e0(&log_state, crt) == 0u);
    CHECK(log_state.box.last_errno_04 == ROME2_STARTUP_CRT_EBADF);

    free(log_fp);
    free(crt);
    free(obs);
}

static void test_startup_handler_methods(void) {
    rome2_startup_handler_dispatch_env env;
    rome2_startup_handler_slot4_32 h;
    rome2_startup_timing_env *tbase =
        (rome2_startup_timing_env *)calloc(1u, sizeof(*tbase));
    rome2_startup_alloc_table *alloc_tbl =
        (rome2_startup_alloc_table *)calloc(1u, sizeof(*alloc_tbl));
    rome2_startup_winmm_env winmm;
    rome2_startup_timing_report_env *trep =
        (rome2_startup_timing_report_env *)calloc(1u, sizeof(*trep));

    CHECK(tbase != NULL && alloc_tbl != NULL && trep != NULL);
    memset(&env, 0, sizeof(env));
    memset(&winmm, 0, sizeof(winmm));
    CHECK(rome2_startup_init_section_timings_112dc9f0(tbase, alloc_tbl, "VFS", 16u, 100u) ==
          ROME2_VFS_REG_OK);
    winmm.current_time_ms = 250u;
    trep->base = tbase;
    trep->alloc_tbl = alloc_tbl;
    trep->winmm = &winmm;
    trep->vec_header.cap_00 = 8u;
    env.timing_env = trep;

    h.vtable_00 = 0u;
    CHECK(rome2_startup_handler_scalar_dtor_base_100d38b0(&h, 0x7001u, 0u, &env) == &h);
    CHECK(h.vtable_00 == ROME2_STARTUP_VTABLE_BASE_ADAPTER && env.freed_handler_count == 0u);

    env.singleton_119f385c = 0x8001u;
    CHECK(rome2_startup_handler_singleton_dtor_100e14d0(&h, 0x7002u, 1u, &env) == &h);
    CHECK(env.singleton_119f385c == 0u && h.vtable_00 == ROME2_STARTUP_VTABLE_BASE_ADAPTER);
    CHECK(env.freed_handler_count == 1u && env.freed_handler_vas[0] == 0x7002u);

    env.crash_slot04 = 0x8002u;
    CHECK(rome2_startup_handler_crash_slot04_dtor_100e16a0(&h, 0x7003u, 0u, &env) == &h);
    CHECK(env.crash_slot04 == 0u);

    CHECK(rome2_startup_handler_vfs_slot50_dtor_100e1820(&h, 0x7004u, 1u, &env) == &h);
    CHECK(env.vfs_slot50_calls == 1u);

    env.crash_slot2c = 0x802cu;
    env.crash_slot28 = 0x8028u;
    env.crash_slot24 = 0x8024u;
    CHECK(rome2_startup_handler_crash_slots_2c_28_24_dtor_100e1a70(&h, 0x7005u, 0u, &env) == &h);
    CHECK(env.crash_slot2c == 0u && env.crash_slot28 == 0u && env.crash_slot24 == 0u);
    CHECK(env.destroyed_count == 5u);

    CHECK(rome2_startup_handler_clear_flag_100e85d0(&env, 0x11u) == 1u);
    CHECK(env.flag_100d6560_calls == 1u && env.flag_100d6560_last_arg == 0u);

    env.crash_vslot104_obj = 0x9001u;
    CHECK(rome2_startup_handler_crash_vslot104_vslot68_100e8be0(&env, 0x22u) == 1u);
    CHECK(env.crash_vslot104_calls == 1u && env.crash_vslot68_calls == 1u);
    CHECK(rome2_startup_handler_crash_vslot344_100ea040(&env, 0x33u) == 1u);
    CHECK(env.crash_vslot344_calls == 1u);

    env.vfs_slot08_ready = 0u;
    CHECK(rome2_startup_handler_vfs_load_release_100e8e50(&env, 0x44u) == 0u);
    env.vfs_slot08_ready = 1u;
    CHECK(rome2_startup_handler_vfs_load_release_100e8e50(&env, 0x44u) == 1u);
    CHECK(strstr(trep->primary_banner, "Finished VFS load_release") != NULL);

    env.vfs_slot58_ready = 0u;
    CHECK(rome2_startup_handler_vfs_start_100e9230(&env, 0x55u) == 0u);
    env.vfs_slot58_ready = 1u;
    winmm.current_time_ms = 300u;
    CHECK(rome2_startup_handler_vfs_start_100e9230(&env, 0x55u) == 1u);
    CHECK(env.vfs_slot54_calls == 1u && env.vfs_slot54_arg == 1u);
    CHECK(strstr(trep->primary_banner, "VFS started") != NULL);
    CHECK(trep->vec_header.count_04 == 2u);

    free(trep);
    free(alloc_tbl);
    free(tbase);
}

int main(void) {
    test_layouts_and_crt_stdio_close();
    test_teardown_and_log_close();
    test_startup_handler_methods();
    printf("test_startup_handler_stdio_close_ops: ALL PASSED (%u checks)\n", g_checks);
    return 0;
}
