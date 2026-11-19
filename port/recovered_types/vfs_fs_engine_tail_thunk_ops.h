#ifndef ROME2_VFS_FS_ENGINE_TAIL_THUNK_OPS_H
#define ROME2_VFS_FS_ENGINE_TAIL_THUNK_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "guest32_layouts.h"
#include "vfs_fs_engine_codec_ops.h"
#include "vfs_fs_engine_crt_env_ops.h"
#include "vfs_fs_engine_crt_lconv_ops.h"
#include "vfs_fs_engine_crt_sec_ops.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_VFS_L57_INVALID_INDEX UINT32_MAX
#define ROME2_VFS_L57_MAX_CHANNEL_NODES 64u
#define ROME2_VFS_L57_MAX_FOLDER_NODES 32u
#define ROME2_VFS_L57_MAX_FOLDER_DEPTH 16u
#define ROME2_VFS_L57_MAX_HASH_SLOTS 32u
#define ROME2_VFS_L57_CH_BASE_VTABLE_VA 0x11756480u
#define ROME2_VFS_L57_CH_DERIVED_VTABLE_VA 0x1184926cu
#define ROME2_VFS_L57_PACK_POOL_VA 0x11934518u
#define ROME2_VFS_L57_EINTR 4
#define ROME2_VFS_L57_EINVAL_MSVC 0x16

/* `0x100d12c0`: engine free thunk forwarding directly to `0x100fcc50`. */
typedef void (*rome2_vfs_tail_free_fn)(uint32_t ptr_va, void *ctx);

uint8_t rome2_vfs_tail_free_thunk_100d12c0(
    uint32_t ptr_va,
    rome2_vfs_tail_free_fn free_cb,
    void *ctx);

/* `0x100f2a70`: UTF-16LE slice vs sentinel-terminated wide C-string inequality check. */
uint8_t rome2_vfs_utf16_str_ne_cstr_100f2a70(
    const uint16_t *view_units,
    uint32_t view_count,
    const uint16_t *cstr,
    uint32_t cstr_max_units,
    uint16_t sentinel_word);

/* `0x1011fc50`: 12-byte element vector capacity growth/relocation and append plan. */
typedef struct rome2_vfs_elem12_push_plan {
    uint8_t did_grow;
    uint32_t new_cap;
    uint32_t alloc_bytes;
    uint32_t move_count;
    uint32_t old_data_va;
    uint32_t append_dst_va;
} rome2_vfs_elem12_push_plan;

rome2_vfs_reg_status rome2_vfs_elem12_vec_push_plan_1011fc50(
    rome2_vfs_elem12_vec12_32 *vec,
    uint32_t new_buf_va,
    uint8_t alloc_ok,
    rome2_vfs_elem12_push_plan *out_plan);

/* `0x101cfaf0` & `0x10f69830`: observable channel base & derived socket channel dtors. */
typedef struct rome2_vfs_l57_peer_node {
    uint32_t prev_idx;
    uint32_t next_idx;
    uint32_t peer_channel_idx;
    uint8_t in_use;
} rome2_vfs_l57_peer_node;

typedef struct rome2_vfs_l57_channel_slot {
    uint32_t vtable_va;
    uint32_t head_idx;
    uint32_t tail_idx;
} rome2_vfs_l57_channel_slot;

typedef struct rome2_vfs_l57_channel_graph {
    rome2_vfs_l57_channel_slot channels[8];
    uint32_t channel_count;
    rome2_vfs_l57_peer_node nodes[ROME2_VFS_L57_MAX_CHANNEL_NODES];
    uint32_t node_count;
    uint32_t freed_node_count;
} rome2_vfs_l57_channel_graph;

rome2_vfs_reg_status rome2_vfs_channel_base_dtor_101cfaf0(
    rome2_vfs_l57_channel_graph *graph,
    uint32_t self_channel_idx);

typedef struct rome2_vfs_l57_derived_channel_state {
    uint32_t aux_owner_ptr_4048;
    uint32_t aux_owner_link_04;
    uint32_t queue_406c_len;
    uint32_t queue_4054_len;
    uint32_t sock_fd_10;
    uint8_t active_24;
    uint8_t did_reset_slots;
    uint8_t did_close_socket;
    uint32_t closed_sock_fd;
    uint32_t queue_nodes_freed;
} rome2_vfs_l57_derived_channel_state;

rome2_vfs_reg_status rome2_vfs_channel_derived_dtor_10f69830(
    rome2_vfs_l57_channel_graph *graph,
    uint32_t self_channel_idx,
    rome2_vfs_l57_derived_channel_state *state);

/* `0x10f71f70`: signed range check and re-centered tail-call to 0x10f71eb0. */
rome2_vfs_reg_status rome2_vfs_write_signed_ranged_bits_10f71f70(
    uint8_t *buf,
    uint32_t byte_cap,
    uint32_t *inout_bit_cursor,
    int32_t value,
    int32_t min_val,
    int32_t max_val,
    uint32_t *out_bits_written);

/* `0x112ab060` & `0x112ab150`: VFS 16B and 48B UTF-16 hash-table destructors. */
typedef struct rome2_vfs_l57_hash48_slot {
    uint16_t key[16];
    uint32_t key_len;
    uint8_t val0_live;
    uint8_t val1_live;
    uint8_t val2_live;
} rome2_vfs_l57_hash48_slot;

typedef struct rome2_vfs_l57_hash_dtor_stats {
    uint32_t keys_destroyed;
    uint32_t values_destroyed;
    uint32_t data_freed;
    uint32_t sentinels_destroyed;
} rome2_vfs_l57_hash_dtor_stats;

rome2_vfs_reg_status rome2_vfs_hash16_table_dtor_112ab060(
    rome2_vfs_folder_hashtable32_32 *hdr,
    rome2_vfs_l57_hash_dtor_stats *out_stats);

rome2_vfs_reg_status rome2_vfs_hash48_table_dtor_112ab150(
    rome2_vfs_folder_hashtable32_32 *hdr,
    const rome2_vfs_l57_hash48_slot *slots,
    uint32_t slot_cap,
    const uint16_t *empty_key,
    uint32_t empty_key_len,
    const uint16_t *deleted_key,
    uint32_t deleted_key_len,
    rome2_vfs_l57_hash_dtor_stats *out_stats);

/* `0x112ab6b0`: VFS pack-entry hash map destructor releasing occupied entries to pool 0x11934518. */
typedef struct rome2_vfs_l57_pack_entry_slot {
    uint32_t name_tag;
    uint32_t entry_id;
} rome2_vfs_l57_pack_entry_slot;

typedef struct rome2_vfs_l57_pack_map_dtor_stats {
    uint32_t virtual_dtor_calls;
    uint32_t pool_freelist_pushes;
    uint8_t path_str_destroyed;
    uint8_t array_teardown_called;
} rome2_vfs_l57_pack_map_dtor_stats;

rome2_vfs_reg_status rome2_vfs_pack_entry_map_dtor_112ab6b0(
    uint32_t empty_name_tag,
    const rome2_vfs_l57_pack_entry_slot *slots,
    uint32_t cap,
    rome2_vfs_l57_pack_map_dtor_stats *out_stats);

/* `0x112ab8b0`: recursive 128B VFS folder-node destructor with cycle & depth bounds. */
typedef struct rome2_vfs_l57_folder_subdir_slot {
    uint16_t key[20];
    uint32_t key_len;
    uint32_t child_indices[4];
    uint32_t child_count;
    uint8_t has_vec;
} rome2_vfs_l57_folder_subdir_slot;

typedef struct rome2_vfs_l57_folder_node_model {
    rome2_vfs_folder_node128_32 raw;
    uint16_t subdirs_empty_key[16];
    uint32_t subdirs_empty_len;
    uint16_t subdirs_deleted_key[16];
    uint32_t subdirs_deleted_len;
    rome2_vfs_l57_folder_subdir_slot subdirs[8];
    uint32_t subdir_slot_count;
    uint16_t files_empty_key[16];
    uint32_t files_empty_len;
    uint16_t files_deleted_key[16];
    uint32_t files_deleted_len;
    rome2_vfs_l57_hash48_slot files[8];
    uint32_t files_slot_count;
} rome2_vfs_l57_folder_node_model;

typedef struct rome2_vfs_l57_folder_dtor_stats {
    uint32_t nodes_destroyed;
    uint32_t child_nodes_freed80;
    uint32_t child_vec_arrays_freed;
    uint32_t child_vec_headers_freed12;
    uint32_t tuple_arrays_torndown;
    uint32_t aux_buffers_freed;
    uint32_t files_tables_torndown;
    uint32_t subdirs_tables_torndown;
    uint32_t path_and_name_strs_destroyed;
} rome2_vfs_l57_folder_dtor_stats;

rome2_vfs_reg_status rome2_vfs_folder_node_dtor_112ab8b0(
    rome2_vfs_l57_folder_node_model *nodes,
    uint32_t node_count,
    uint32_t root_idx,
    rome2_vfs_l57_folder_dtor_stats *out_stats);

/* `0x11684240`: CRT __alloca_probe_16 16-byte alignment & _chkstk page-probe delegation. */
uint32_t rome2_vfs_crt_alloca_probe_16_11684240(
    uint32_t stack_top,
    uint32_t alloc_bytes,
    uint32_t *out_aligned_bytes,
    uint32_t *out_touched_pages);

/* `0x1168a23e`: __crt_stdio_output::output_processor<wchar_t>::state_case_size. */
uint8_t rome2_vfs_crt_wprintf_state_case_size_1168a23e(
    rome2_vfs_crt_wprintf_state64_32 *st,
    const uint16_t *fmt_units,
    uint32_t fmt_rem_units,
    uint32_t *inout_fmt_off,
    int32_t *out_errno,
    uint8_t *out_invparam,
    uint8_t *out_delegated_type_case);

/* `0x1168d0c3`: CRT malloc thunk forwarding straight to __malloc_base (0x116a59a1). */
uint8_t rome2_vfs_crt_malloc_thunk_1168d0c3(
    uint32_t size_bytes,
    uint32_t *out_alloc_bytes,
    int32_t *out_errno);

/* `0x100f3880`, `0x100f3890`, `0x116c80c5..0x116c8125`: Win32 & Winsock IAT JMP thunks. */
typedef struct rome2_vfs_iat_thunk_desc {
    uint32_t thunk_va;
    uint32_t iat_slot_va;
    const char *dll_name;
    const char *import_name;
    uint32_t stack_bytes;
} rome2_vfs_iat_thunk_desc;

typedef struct rome2_vfs_ws2_mock_socket {
    uint32_t fd;
    uint8_t open;
    uint8_t nonblocking;
    uint32_t last_error;
    uint8_t rx_buf[64];
    uint32_t rx_len;
    uint8_t tx_buf[64];
    uint32_t tx_len;
} rome2_vfs_ws2_mock_socket;

uint8_t rome2_vfs_iat_thunk_describe(
    uint32_t thunk_va,
    rome2_vfs_iat_thunk_desc *out_desc);

uint32_t rome2_vfs_win32_get_last_error_100f3880(uint32_t recorded_err);
uint32_t rome2_vfs_win32_get_tick_count_100f3890(uint32_t monotonic_ms);
int32_t rome2_vfs_ws2_closesocket_116c80c5(rome2_vfs_ws2_mock_socket *sock);
int32_t rome2_vfs_ws2_ioctlsocket_116c80d1(rome2_vfs_ws2_mock_socket *sock, uint32_t cmd, uint32_t *argp);
uint16_t rome2_vfs_ws2_htons_116c80d7(uint16_t hostshort);
int32_t rome2_vfs_ws2_recv_116c80ef(rome2_vfs_ws2_mock_socket *sock, uint8_t *buf, uint32_t len, uint32_t flags);
int32_t rome2_vfs_ws2_send_116c80fb(rome2_vfs_ws2_mock_socket *sock, const uint8_t *buf, uint32_t len, uint32_t flags);
uint32_t rome2_vfs_ws2_socket_116c810d(rome2_vfs_ws2_mock_socket *sock, int32_t af, int32_t type, int32_t protocol, uint32_t next_fd);
uint32_t rome2_vfs_ws2_get_last_error_116c8125(const rome2_vfs_ws2_mock_socket *sock);

#ifdef __cplusplus
}
#endif

#endif
