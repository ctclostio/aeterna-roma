#ifndef ROME2_RECOVERED_GUEST32_LAYOUTS_H
#define ROME2_RECOVERED_GUEST32_LAYOUTS_H

#include <stddef.h>
#include <stdint.h>

/* Original-image identities, never dereferenceable native pointers. A code
 * identity is deliberately not a C function pointer. These are little-endian
 * image layouts; decode unaligned/external bytes through guest32 accessors.
 * See contracts.json for pinned functions and instruction witnesses.
 */
typedef uint32_t rome2_data_address32;
typedef uint32_t rome2_code_address32;
typedef uint32_t rome2_vtable_address32;

typedef struct rome2_string8_layout32 {
    int32_t length;
    int32_t capacity;
    rome2_data_address32 data;
} rome2_string8_layout32;

typedef struct rome2_string16_layout32 {
    int32_t length_units;
    int32_t capacity_units;
    rome2_data_address32 data;
} rome2_string16_layout32;

/* FUN_101b9270 follows +0 until NULL, then reads only the root's byte +4.
 * FUN_112aab60 initializes +0 to zero and the word at +4 to one. This is an
 * observed prefix, not a complete XML class or an ownership declaration. */
typedef struct rome2_xml_state_prefix32 {
    rome2_data_address32 state_source;
    uint8_t ready;
    uint8_t unobserved_005[3];
} rome2_xml_state_prefix32;

/* The XML loader selects the interface at manager+4. Only these two
 * dispatch words are admitted here, not the full manager class or vtables. */
typedef struct rome2_vfs_dispatch_prefix32 {
    rome2_vtable_address32 table_000;
    rome2_vtable_address32 table_004;
} rome2_vfs_dispatch_prefix32;

/* FUN_112c1130's name table. Name words are compared as opaque 32-bit
 * identities; neither their ownership nor interning policy is admitted. */
typedef struct rome2_vfs_name_table_layout32 {
    rome2_data_address32 items;
    uint32_t bucket_count;
    uint32_t empty_name;
} rome2_vfs_name_table_layout32;
typedef struct rome2_vfs_name_slot_layout32 {
    uint32_t name;
    rome2_data_address32 value;
} rome2_vfs_name_slot_layout32;

/* FUN_112a7550 initializes +0 to the 24-byte sentinel node and +4 to zero;
 * FUN_112c0250 reads +0 as the tree sentinel head. */
typedef struct rome2_vfs_tree_header_layout32 {
    rome2_data_address32 head;
    uint32_t count;
} rome2_vfs_tree_header_layout32;

/* FUN_112a7550 allocates 24-byte sentinel nodes and writes 0x0101 at +0xc;
 * FUN_112c0250 reads +0 (left), +4 (root on head), +8 (right), +0xd (is_nil),
 * +0x10 (key name identity), and FUN_112ce0c0 reads +0x14 (candidate set). */
typedef struct rome2_vfs_tree_node_prefix32 {
    rome2_data_address32 left;
    rome2_data_address32 parent;
    rome2_data_address32 right;
    uint8_t color;
    uint8_t is_nil;
    uint8_t unobserved_00e[2];
    uint32_t key;
    rome2_data_address32 value;
} rome2_vfs_tree_node_prefix32;

/* FUN_112a7690 copies comparator code identity to +0, stores the 20-byte
 * sentinel head at +4, and zeroes +8; FUN_112ce0c0 reads +4. */
typedef struct rome2_vfs_candidate_set_layout32 {
    rome2_code_address32 comparator;
    rome2_data_address32 head;
    uint32_t count;
} rome2_vfs_candidate_set_layout32;

/* FUN_112a7690 allocates 20-byte sentinel nodes; FUN_112ce0c0 reads +0 on
 * the sentinel head to select the leftmost node and +0x10 for the archive. */
typedef struct rome2_vfs_candidate_node_prefix32 {
    rome2_data_address32 left;
    rome2_data_address32 parent;
    rome2_data_address32 right;
    uint8_t color;
    uint8_t is_nil;
    uint8_t unobserved_00e[2];
    rome2_data_address32 archive;
} rome2_vfs_candidate_node_prefix32;

/* FUN_112a77b0 initializes the 32-byte dependency hash-map header at 0x12032a58
 * (8 bucket pairs, mask 7, max_idx 8); FUN_112afff0 hashes key [str+8], masks
 * with +0x18, reads bucket pair at +0x0c, and compares against +0x04 list_head. */
typedef struct rome2_vfs_dep_bucket_pair32 {
    rome2_data_address32 first;
    rome2_data_address32 last;
} rome2_vfs_dep_bucket_pair32;

typedef struct rome2_vfs_dep_hashmap_layout32 {
    uint32_t load_factor_bits;
    rome2_data_address32 list_head;
    uint32_t count;
    rome2_data_address32 buckets;
    rome2_data_address32 buckets_end;
    rome2_data_address32 buckets_cap;
    uint32_t mask;
    uint32_t max_idx;
} rome2_vfs_dep_hashmap_layout32;

/* FUN_112afff0, FUN_112b5090, and FUN_112bb620 inspect the 36-byte hash-map
 * list nodes: +0/+4 list links, +0x08 string8 key, +0x1c dependency RB-tree. */
typedef struct rome2_vfs_dep_graph_node_prefix32 {
    rome2_data_address32 next;
    rome2_data_address32 prev;
    rome2_string8_layout32 name;
    uint32_t unobserved_014[2];
    rome2_vfs_tree_header_layout32 deps;
} rome2_vfs_dep_graph_node_prefix32;

/* FUN_112b5090, FUN_112bb620, and FUN_112a4c00 read the 28-byte dependency
 * edge RB-tree nodes: +0x0d is_nil, +0x10 target string8. */
typedef struct rome2_vfs_dep_edge_node_prefix32 {
    rome2_data_address32 left;
    rome2_data_address32 parent;
    rome2_data_address32 right;
    uint8_t color;
    uint8_t is_nil;
    uint8_t unobserved_00e[2];
    rome2_string8_layout32 target_name;
} rome2_vfs_dep_edge_node_prefix32;

/* FUN_112e1500 reads +0x00 pack_props (checking low nibble of byte +0x1c) and
 * passes +0x14 archive_name (string8) to FUN_112d59f0. FUN_112a9560 fills +0x00
 * with open_pack_payload, +0x04..+0x0f with an 8-byte-slot VFS name table
 * (initial capacity 8, empty_key from FUN_112e3690), and +0x14 with the leaf
 * pack name after the final '\\'; FUN_112c0bb0 iterates +0x04. */
typedef struct rome2_vfs_archive_candidate_prefix32 {
    rome2_data_address32 pack_props;
    rome2_vfs_name_table_layout32 name_table;
    uint32_t unobserved_010;
    rome2_string8_layout32 archive_name;
} rome2_vfs_archive_candidate_prefix32;

/* Global pending archive-entry observer vector at 0x12032a7c..0x12032a84,
 * appended in FUN_112a9560 and drained/reset in FUN_112cfc10. */
typedef struct rome2_vfs_pending_entry_vec_layout32 {
    uint32_t capacity;
    uint32_t count;
    rome2_data_address32 items;
} rome2_vfs_pending_entry_vec_layout32;

/* Observed prefix of open-pack payload / properties struct passed to
 * FUN_112a9560, FUN_101146c0, FUN_101157c0, and FUN_101048f0 (+0x00 handle,
 * +0x04 last_error, +0x1c flags, +0x24 header_base, +0x28 entry_count,
 * +0x2c index_bytes, +0x30 default_meta, +0x34 pack_path, +0x40 open_ok). */
typedef struct rome2_vfs_pack_props_prefix32 {
    uint32_t file_handle;
    uint32_t last_error;
    uint32_t unobserved_008[5];
    uint32_t flags;
    uint32_t unobserved_020;
    uint32_t header_base;
    uint32_t entry_count;
    uint32_t index_bytes;
    uint32_t default_entry_meta;
    rome2_string8_layout32 pack_path;
    uint8_t flag_040;
    uint8_t unobserved_041[3];
} rome2_vfs_pack_props_prefix32;

/* 40-byte (0x28) pack-entry object initialized in FUN_112a9560 with vtable
 * 0x118976c0 from pool 0x10106120 (0x103282b0 stride 0x28). Slot +0x04
 * (0x112d3270) reads +0x04 name_id; slot +0x34 (0x112d2900) sets +0x24 = 1. */
typedef struct rome2_vfs_pack_entry_layout32 {
    rome2_vtable_address32 vtable;
    uint32_t name_id;
    uint32_t byte_size;
    uint32_t unobserved_00c;
    uint32_t data_offset_lo;
    uint32_t data_offset_hi;
    uint32_t entry_meta;
    rome2_data_address32 carrier;
    rome2_data_address32 stream_state;
    uint8_t winner_notified;
    uint8_t unobserved_025[3];
} rome2_vfs_pack_entry_layout32;

/* Open-pack 20-byte hash slot and 20-byte table at 0x120329e0 (probed by
 * FUN_112c13f0 and iterated by FUN_112c0b20; +0x0c is the returned payload). */
typedef struct rome2_vfs_open_pack_slot_layout32 {
    rome2_string8_layout32 name;
    uint32_t unobserved_00c;
    uint32_t unobserved_010;
} rome2_vfs_open_pack_slot_layout32;

typedef struct rome2_vfs_open_pack_table_layout32 {
    rome2_data_address32 items;
    uint32_t bucket_count;
    rome2_string8_layout32 empty_key;
} rome2_vfs_open_pack_table_layout32;

/* 12-byte freelist pool headers at 0x119344f4, 0x11934500, 0x1193450c,
 * and 0x11934518 returned by 0x10106000..0x10106120 (+0x00 is pushed/popped
 * singly-linked node head). */
typedef struct rome2_vfs_freelist_pool_header32 {
    rome2_data_address32 freelist_head;
    rome2_data_address32 slab_chain_head;
    uint32_t reserved_008;
} rome2_vfs_freelist_pool_header32;

/* 8-byte slab descriptor initialized by 0x10328250(count, next_slab) over a
 * contiguous array of 0x1c-byte (28-byte) singly-linked nodes. */
typedef struct rome2_vfs_slab_descriptor32 {
    rome2_data_address32 node_array;
    rome2_data_address32 next_slab;
} rome2_vfs_slab_descriptor32;

/* 24-byte archive-name node disposer backed by vtable 0x1189a434
 * (scalar deleting dtor 0x112acd70 frees 0x18 bytes; slot +0x00 0x112afd00
 * destroys +0x10 owned_node and recycles it to pool 0x119344f4). */
typedef struct rome2_vfs_archive_name_disposer32 {
    rome2_vtable_address32 vtable;
    uint32_t unobserved_004;
    uint32_t unobserved_008;
    uint32_t subobj_00c;
    rome2_data_address32 owned_node;
    uint32_t tail_014;
} rome2_vfs_archive_name_disposer32;

/* 28-byte VFS mutex wrapper at 0x12032b10 returned by 0x112bff80
 * (+0x04 = 0x12032b14 is the Win32 x86 RTL_CRITICAL_SECTION). */
typedef struct rome2_vfs_mutex_box32 {
    rome2_vtable_address32 vtable_or_tag;
    uint32_t cs_debug_info;
    int32_t cs_lock_count;
    int32_t cs_recursion_count;
    rome2_data_address32 cs_owning_thread;
    rome2_data_address32 cs_lock_semaphore;
    uint32_t cs_spin_count;
} rome2_vfs_mutex_box32;

/* 36-byte global UTF-16LE hash table at 0x12032bf4 returned by 0x112e32b0
 * (0x12032bf8 = 8 initial buckets * 16 bytes; 0x12032bfc "Removed_key",
 * 0x12032c08 "Unused_key"; followed immediately by TLS guard 0x12032c18). */
typedef struct rome2_vfs_global_map32 {
    rome2_data_address32 buckets;
    uint32_t bucket_count;
    rome2_string16_layout32 removed_key;
    rome2_string16_layout32 unused_key;
    uint32_t reserved_020;
} rome2_vfs_global_map32;

/* 28-byte wire header read into pack_props+0x18..+0x33 by 0x112a9bc0. */
typedef struct rome2_vfs_pack_header_wire32 {
    uint32_t signature;
    uint32_t flags;
    uint32_t dep_count;
    uint32_t dep_bytes;
    uint32_t entry_count;
    uint32_t index_bytes;
    uint32_t default_entry_meta;
} rome2_vfs_pack_header_wire32;

/* 20-byte RB-tree node allocated by 0x112e3eb0 (0x12032944) and erased by
 * 0x10cf4d20 onto pool 0x119344f4 (+0x0c color, +0x0d is_nil sentinel). */
typedef struct rome2_vfs_rb_sentinel_node32 {
    rome2_data_address32 left;
    rome2_data_address32 parent;
    rome2_data_address32 right;
    uint8_t color;
    uint8_t is_nil;
    uint8_t unobserved_00e[2];
    uint32_t reserved_010;
} rome2_vfs_rb_sentinel_node32;

/* 32-byte per-thread VFS quota frame prefix updated by 0x112a45c0. */
typedef struct rome2_vfs_quota_frame32 {
    uint32_t unobserved_000;
    uint32_t max_ops;
    uint32_t max_bytes;
    uint32_t unobserved_00c[3];
    uint32_t used_bytes;
    uint32_t used_ops;
} rome2_vfs_quota_frame32;

/* 16-byte stream slice request wrapper initialized by 0x112aa5d0. */
typedef struct rome2_vfs_stream_slice_view32 {
    rome2_data_address32 entry;
    uint32_t offset;
    uint32_t length;
    uint8_t mode_flag;
    uint8_t unobserved_00d[3];
} rome2_vfs_stream_slice_view32;

/* 12-byte ref-counted header prefix of the 0x50-byte block in 0x112d4160
 * preceding embedded 0x44-byte pack_props at +0x0c.
 */
typedef struct rome2_vfs_ref_pack_block_header32 {
    rome2_vtable_address32 vtable;               /* 00: 0x1189a424 */
    int32_t strong_ref;                          /* 04 */
    int32_t weak_ref;                            /* 08 */
} rome2_vfs_ref_pack_block_header32;

/* 24-byte chained-bucket hash map header shared by 0x101f4f90 and 0x112cbe10. */
typedef struct rome2_vfs_open_bucket_map32 {
    uint32_t tag_000;                            /* 00 */
    uint32_t sentinel_004;                       /* 04 */
    uint32_t bucket_count;                       /* 08 */
    rome2_data_address32 buckets;                /* 0c */
    uint32_t element_count;                      /* 10 */
    uint32_t max_load_factor_bits;               /* 14: IEEE-754 float32 */
} rome2_vfs_open_bucket_map32;

/* 12-byte bucket descriptor & 12-byte thread-ID chain node for 0x101f4f90. */
typedef struct rome2_vfs_open_bucket_slot32 {
    rome2_data_address32 head;                   /* 00 */
    rome2_data_address32 tail_or_sentinel;       /* 04 */
    uint32_t reserved_008;                       /* 08 */
} rome2_vfs_open_bucket_slot32;

typedef struct rome2_vfs_thread_node32 {
    rome2_data_address32 prev;                   /* 00 */
    rome2_data_address32 next;                   /* 04 */
    uint32_t thread_id;                          /* 08 */
} rome2_vfs_thread_node32;

/* 16-byte post-scan archive slot descriptor (0x120329c8) initialized by
 * 0x112baf90 (0x3cb slots x 8 bytes) and swept by 0x112b5450.
 */
typedef struct rome2_vfs_post_scan_table32 {
    rome2_data_address32 entries;                /* 00: 0x120329c8 */
    uint32_t entry_count;                        /* 04: 0x120329cc (0x3cb) */
    uint64_t default_entry;                      /* 08: 0x120329d0..0x120329d7 */
} rome2_vfs_post_scan_table32;

/* 0x38-byte and 0x3c-byte stream wrapper layouts initialized by 0x112a7ae0
 * (0x118977ec) and 0x112a94d0 (0x11897790).
 */
typedef struct rome2_vfs_stream_wrap_a32 {
    rome2_vtable_address32 vtable;               /* 00: 0x118977ec */
    uint32_t flag_004;                           /* 04 */
    uint32_t name_a;                             /* 08 */
    uint32_t name_b;                             /* 0c */
    uint32_t args_010[4];                        /* 10..1c */
    uint32_t zero_020;                           /* 20 */
    uint32_t zero_024;                           /* 24 */
    uint8_t flag_028;                            /* 28 */
    uint8_t unobserved_029[3];
    uint32_t zero_02c;                           /* 2c */
    uint32_t zero_030;                           /* 30 */
    uint8_t flag_034;                            /* 34 */
    uint8_t unobserved_035[3];
} rome2_vfs_stream_wrap_a32;

typedef struct rome2_vfs_stream_wrap_b32 {
    rome2_vtable_address32 vtable;               /* 00: 0x11897790 */
    uint32_t flag_004;                           /* 04 */
    uint32_t name_str;                           /* 08 */
    uint32_t tag_00c;                            /* 0c */
    uint32_t inner_010[4];                       /* 10..1c */
    uint32_t zero_020[4];                        /* 20..2c */
    uint8_t flag_030;                            /* 30 */
    uint8_t unobserved_031[3];
    uint8_t flag_034;                            /* 34 */
    uint8_t unobserved_035[3];
    uint32_t zero_038;                           /* 38 */
} rome2_vfs_stream_wrap_b32;

/* 40-byte dependency RB-tree node allocated by 0x112a7700, freed by
 * 0x112a2760/0x112be300, and searched by {name_a @ +0x10, name_b @ +0x1c} in
 * 0x112a4090 and 0x112a4b60. */
typedef struct rome2_vfs_dep_rb_node32 {
    rome2_data_address32 left;                   /* 00 */
    rome2_data_address32 parent;                 /* 04 */
    rome2_data_address32 right;                  /* 08 */
    uint8_t color;                               /* 0c */
    uint8_t is_nil;                              /* 0d */
    uint8_t unobserved_00e[2];                   /* 0e */
    uint32_t name_a[3];                          /* 10..1b */
    uint32_t name_b[3];                          /* 1c..27 */
} rome2_vfs_dep_rb_node32;

/* 28-byte RB-tree sentinel/node allocated by 0x112e3ae0 (`PUSH 0x1c`,
 * color/is_nil 0x0101 at +0x0c). */
typedef struct rome2_vfs_cycle_rb_sentinel32 {
    rome2_data_address32 left;                   /* 00 */
    rome2_data_address32 parent;                 /* 04 */
    rome2_data_address32 right;                  /* 08 */
    uint8_t color;                               /* 0c */
    uint8_t is_nil;                              /* 0d */
    uint8_t unobserved_00e[2];                   /* 0e */
    uint32_t payload_010[3];                     /* 10..1b */
} rome2_vfs_cycle_rb_sentinel32;

/* 16-byte 4-slot vtable 0x1189a424 for 0x50-byte ref_pack_block. */
typedef struct rome2_vfs_ref_block_vtable32 {
    rome2_code_address32 destroy_embedded;       /* 00: 0x112afce0 */
    rome2_code_address32 get_deleter;            /* 04: 0x1090bb10 */
    rome2_code_address32 scalar_deleting_dtor;   /* 08: 0x112acd50 */
    rome2_code_address32 noop_release;           /* 0c: 0x10128c50 */
} rome2_vfs_ref_block_vtable32;

/* 32-byte 8-slot vtable prefix shared by 0x118977ec and 0x11897790. */
typedef struct rome2_vfs_stream_wrap_vtable_prefix32 {
    rome2_code_address32 scalar_deleting_dtor;   /* 00: 0x112acde0 / 0x112ad0f0 */
    rome2_code_address32 open_checked;           /* 04: 0x112d8d30 / 0x112d8e20 */
    rome2_code_address32 slot_008;               /* 08: 0x10190580 (noop3) */
    rome2_code_address32 slot_00c;               /* 0c: 0x100e22c0 (noop2) */
    rome2_code_address32 slot_010;               /* 10: 0x112da9f0 / 0x112dab00 (release_ref) */
    rome2_code_address32 slot_014;               /* 14: 0x112c8b80 / 0x112c8bc0 (is_valid_or_ready) */
    rome2_code_address32 slot_018;               /* 18: 0x112d9860 / 0x10369160 (is_open) */
    rome2_code_address32 slot_01c;               /* 1c: 0x112badf0 / 0x112baef0 (get_data_or_inner) */
} rome2_vfs_stream_wrap_vtable_prefix32;

/* 20-byte ref-counted stream handle box released/freed (`PUSH 0x14`) by
 * 0x112ac430 (`stream_wrap_a` +0x30 handle). */
typedef struct rome2_vfs_stream_handle_box32 {
    uint32_t unobserved_000[2];                  /* 00..07 */
    rome2_data_address32 secondary_ctrl;         /* 08 */
    rome2_data_address32 sentinel_or_state;      /* 0c */
    rome2_data_address32 primary_ctrl;           /* 10 */
} rome2_vfs_stream_handle_box32;

/* 12-byte bucket-array vector header managing 0x0c-byte open-bucket slots
 * in 0x112d8550, 0x112dbe10, and 0x112ab310 (used inside 0x112d9e20). */
typedef struct rome2_vfs_bucket_vec_header32 {
    uint32_t capacity;                           /* 00 */
    uint32_t count;                              /* 04 */
    rome2_data_address32 slots;                  /* 08 */
} rome2_vfs_bucket_vec_header32;

/* 8-byte mapped view box pointed to by `stream_wrap_b32 + 0x20`
 * (freed via 0x112ad0f0 / 0x112dab00, data_ptr read by 0x112baef0). */
typedef struct rome2_vfs_stream_view_box32 {
    rome2_data_address32 mapped_view_base;       /* 00 */
    rome2_data_address32 data_ptr;               /* 04 */
} rome2_vfs_stream_view_box32;

/* 16-byte stream handle state prefix pointed to by
 * `rome2_vfs_stream_handle_box32.sentinel_or_state` (+0x0c). */
typedef struct rome2_vfs_stream_state_prefix32 {
    rome2_vtable_address32 vtable;               /* 00 */
    uint32_t unobserved_004[2];                  /* 04..0b */
    uint8_t eof_or_closed_00c;                   /* 0c */
    uint8_t closed_00d;                          /* 0d */
    uint8_t unobserved_00e[2];                   /* 0e..0f */
} rome2_vfs_stream_state_prefix32;

/* 8-byte RB-tree header `{ sentinel, size }` observed in 0x112a2470,
 * 0x112b0710, and 0x112b07a0. */
typedef struct rome2_vfs_rb_tree_head32 {
    rome2_data_address32 sentinel;               /* 00 */
    uint32_t size;                               /* 04 */
} rome2_vfs_rb_tree_head32;

/* 36-byte (0x24B) adjacency hash-list node allocated (`PUSH 0x24`) and torn
 * down by 0x112ac1a0, bounded (`max_size = 0x071c71c7`) by 0x112a2910. */
typedef struct rome2_vfs_adj_hash_node32 {
    rome2_data_address32 next;                   /* 00 */
    rome2_data_address32 prev;                   /* 04 */
    uint32_t key_name[3];                        /* 08..13 */
    rome2_vfs_rb_tree_head32 sub_tree_a;         /* 14..1b */
    rome2_vfs_rb_tree_head32 sub_tree_b;         /* 1c..23 */
} rome2_vfs_adj_hash_node32;

/* 8-byte recursive VFS mutex prefix returned by 0x112bff80 and unwound/restored
 * by 0x112c0c60 (`recursion_depth` at +0x00, `CRITICAL_SECTION` prefix at +0x04). */
typedef struct rome2_vfs_recursive_mutex_prefix32 {
    uint32_t recursion_depth;                    /* 00 */
    uint32_t cs_prefix_004;                      /* 04 */
} rome2_vfs_recursive_mutex_prefix32;

/* 12-byte pointer-triple vector `{ first, last, end }` used by `0x112d8c50`. */
typedef struct rome2_vfs_u32_ptr_vec32 {
    rome2_data_address32 first;                  /* 00 */
    rome2_data_address32 last;                   /* 04 */
    rome2_data_address32 end;                    /* 08 */
} rome2_vfs_u32_ptr_vec32;

/* 8-byte singly-linked flag-clear node traversed recursively by `0x112cd4c0`. */
typedef struct rome2_vfs_flag_chain_node32 {
    rome2_data_address32 next;                   /* 00 */
    uint8_t flag_004;                            /* 04 */
    uint8_t unobserved_005[3];                   /* 05..07 */
} rome2_vfs_flag_chain_node32;

/* FUN_100e2460's handler vector: capacity precedes count. */
typedef struct rome2_handler_vector_layout32 {
    uint32_t unobserved_00;
    uint32_t capacity;
    uint32_t count;
    rome2_data_address32 backing;
} rome2_handler_vector_layout32;

/* FUN_10cbe350 reads +4 and +8 only. +0 has no admitted meaning. */
typedef struct rome2_entity_source_layout32 {
    uint32_t unobserved_00;
    uint32_t count;
    rome2_data_address32 items;
} rome2_entity_source_layout32;

/* FUN_10132ce0 copies a vector whose element stride is 0x88. The nested
 * vector's stride is 0x4c. +0 of each source vector is not read by this
 * helper; destination +0 and +4 both receive the source count at +4.
 * Scalar names are byte offsets, not recovered semantic types.
 */
typedef struct rome2_tag_vector_layout32 {
    int32_t capacity;
    int32_t count;
    rome2_data_address32 items;
} rome2_tag_vector_layout32;

typedef struct rome2_scalar_vector_layout32 {
    uint32_t capacity, count;
    rome2_data_address32 items;
} rome2_scalar_vector_layout32;
typedef struct rome2_float2_layout32 {
    uint32_t x_bits, y_bits;
} rome2_float2_layout32;
typedef struct rome2_fauna_record_layout32 {
    union {
        uint32_t words_000[8];
        struct {
            uint32_t animal_type, min_entities, max_entities, spawn_probability_bits;
            uint32_t tile_mask, season_mask, time_of_day_mask, precipitation_mask;
        } values;
    };
    rome2_scalar_vector_layout32 strings;
} rome2_fauna_record_layout32;

typedef struct rome2_xml_named_bucket32 {
    rome2_string16_layout32 key;
    rome2_data_address32 matching_nodes; /* points to a capacity/count/items list */
} rome2_xml_named_bucket32;
typedef struct rome2_xml_index_prefix32 {
    rome2_data_address32 buckets;
    uint32_t bucket_count;
    rome2_string16_layout32 unused_key, removed_key;
} rome2_xml_index_prefix32;

/* Known XML prefix, NOT a complete class-size declaration. 112b5150 selects
 * the first item in a named-child list indexed by the table at +0x20;
 * 112b5130/112b51a0 expose count+0x6c and item pointers+0x70. A linked state
 * source at +0 leads to the readiness flag+4 (101b9270). 112aab60 constructs
 * two indices with bucket strides16/48; the second bucket payload and the
 * unobserved words remain opaque. No identity is a native pointer. */
typedef struct rome2_xml_node_prefix32 {
    rome2_data_address32 state_source;
    uint8_t ready, selected, unobserved_006[2];
    rome2_string16_layout32 name, text;
    rome2_xml_index_prefix32 named_children;
    uint32_t unobserved_040;
    rome2_xml_index_prefix32 secondary_index;
    uint32_t unobserved_064;
    rome2_scalar_vector_layout32 children;
    uint32_t unobserved_074[3];
} rome2_xml_node_prefix32;
/* FUN_1015e280 receives a pointer to a stack holder containing this, not the
 * unit-card directly. Its stack argument is a separate XML-node identity. */
typedef struct rome2_unit_card_setup_receiver32 {
    rome2_data_address32 card;
} rome2_unit_card_setup_receiver32;

_Static_assert(sizeof(rome2_scalar_vector_layout32) == 12, "scalar vector extent");
_Static_assert(sizeof(rome2_float2_layout32) == 8, "guest coordinate stride");
_Static_assert(sizeof(rome2_fauna_record_layout32) == 44, "guest fauna stride");
_Static_assert(offsetof(rome2_fauna_record_layout32, strings) == 0x20, "fauna nested vector");
_Static_assert(offsetof(rome2_fauna_record_layout32, values.spawn_probability_bits) == 12, "guest probability bits");
_Static_assert(sizeof(rome2_xml_node_prefix32) == 0x80, "known XML prefix extent");
_Static_assert(sizeof(rome2_xml_named_bucket32) == 16, "XML named bucket stride");
_Static_assert(sizeof(rome2_xml_index_prefix32) == 32, "known XML index prefix");
_Static_assert(offsetof(rome2_xml_node_prefix32, name) == 8, "XML name descriptor");
_Static_assert(offsetof(rome2_xml_node_prefix32, text) == 0x14, "XML text descriptor");
_Static_assert(offsetof(rome2_xml_node_prefix32, named_children) == 0x20, "XML named index");
_Static_assert(offsetof(rome2_xml_node_prefix32, secondary_index) == 0x44, "XML secondary index");
_Static_assert(offsetof(rome2_xml_node_prefix32, children.count) == 0x6c, "XML child count");
_Static_assert(offsetof(rome2_xml_node_prefix32, children.items) == 0x70, "XML child pointers");
_Static_assert(sizeof(rome2_unit_card_setup_receiver32) == 4, "setup holder extent");

typedef struct rome2_tag_leaf_layout32 {
    rome2_string8_layout32 name;                  /* 00 */
    uint32_t words_00c[16];                      /* 0c..48 */
} rome2_tag_leaf_layout32;

typedef struct rome2_tag_element_layout32 {
    rome2_string8_layout32 name;                  /* 00 */
    uint32_t words_00c[4];                       /* 0c..18 */
    uint16_t word_01c;
    uint8_t unobserved_01e[2];
    uint32_t words_020[12];                      /* 20..4c */
    uint8_t bytes_050[7];                        /* 50..56 */
    uint8_t unobserved_057;
    uint32_t word_058;
    rome2_string16_layout32 text;                /* 5c */
    uint32_t words_068[5];                       /* 68..78 */
    rome2_tag_vector_layout32 children;          /* 7c */
} rome2_tag_element_layout32;

/* The original allocation is exactly 16 bytes, NOT the x64 record size. */
typedef struct rome2_unit_card_tag_layout32 {
    rome2_vtable_address32 vtable;
    rome2_tag_vector_layout32 elements;          /* 04 */
} rome2_unit_card_tag_layout32;

_Static_assert(sizeof(rome2_tag_vector_layout32) == 12, "guest tag vector");
_Static_assert(offsetof(rome2_tag_vector_layout32, count) == 4, "tag count");
_Static_assert(offsetof(rome2_tag_vector_layout32, items) == 8, "tag items");
_Static_assert(sizeof(rome2_tag_leaf_layout32) == 0x4c, "guest leaf stride");
_Static_assert(sizeof(rome2_tag_element_layout32) == 0x88, "guest outer stride");
_Static_assert(offsetof(rome2_tag_element_layout32, words_00c) == 0x0c, "tag words");
_Static_assert(offsetof(rome2_tag_element_layout32, word_01c) == 0x1c, "tag word");
_Static_assert(offsetof(rome2_tag_element_layout32, words_020) == 0x20, "tag words");
_Static_assert(offsetof(rome2_tag_element_layout32, bytes_050) == 0x50, "tag bytes");
_Static_assert(offsetof(rome2_tag_element_layout32, word_058) == 0x58, "tag word");
_Static_assert(offsetof(rome2_tag_element_layout32, text) == 0x5c, "tag UTF16");
_Static_assert(offsetof(rome2_tag_element_layout32, words_068) == 0x68, "tag words");
_Static_assert(offsetof(rome2_tag_element_layout32, children) == 0x7c, "tag children");
_Static_assert(sizeof(rome2_unit_card_tag_layout32) == 16, "guest tag extent");
_Static_assert(offsetof(rome2_unit_card_tag_layout32, elements) == 4, "guest tag receiver");

/* Allocation strides proved by the two compile-island pool constructors.
 * Payloads have known extents, but no recovered member semantics yet.
 */
typedef struct rome2_pool80_slot_layout32 {
    rome2_data_address32 next;
    uint8_t unobserved_payload[76];
} rome2_pool80_slot_layout32;
typedef struct rome2_pool76_slot_layout32 {
    rome2_data_address32 next;
    uint8_t unobserved_payload[72];
} rome2_pool76_slot_layout32;
typedef struct rome2_pool_descriptor_layout32 {
    rome2_data_address32 first;
    uint32_t tag_word;
} rome2_pool_descriptor_layout32;

/* The three original vtable identities installed in the observed prefix.
 * No claim is made about methods' native signatures or whole class sizes.
 */
typedef struct rome2_dispatch_prefix32 {
    rome2_vtable_address32 primary;
    rome2_vtable_address32 secondary;
    rome2_vtable_address32 tertiary;
} rome2_dispatch_prefix32;

typedef struct rome2_climate_prefix32 {
    rome2_dispatch_prefix32 dispatch;
    rome2_string8_layout32 name;
    rome2_string8_layout32 alternate_name;
    uint32_t grid_a;
    uint32_t grid_b;
    uint32_t grid_c;
} rome2_climate_prefix32;

/* Known constructor projection [this,this+0xe5), rounded to the four-byte
 * alignment needed by these members. This is NOT proof of sizeof(class).
 * unobserved_* members preserve gaps, not invented field semantics.
 */
typedef struct rome2_battle_entity_prefix32 {
    rome2_dispatch_prefix32 dispatch;             /* 000 */
    uint32_t field_00c;
    rome2_string8_layout32 effect_name;           /* 010 */
    rome2_string8_layout32 category;              /* 01c */
    uint32_t origin_x;                           /* 028 */
    uint32_t origin_y;                           /* 02c */
    rome2_string8_layout32 label;                 /* 030 */
    uint32_t grid_extent_min_bits;               /* 03c */
    uint32_t grid_extent_max_bits;               /* 040 */
    rome2_string8_layout32 descriptor_text;       /* 044 */
    uint32_t field_050;                          /* copied by FUN_101350c0 */
    uint32_t activation_radius_min_bits;         /* 054 */
    uint32_t activation_radius_max_bits;         /* 058 */
    uint32_t point_count;                        /* 05c */
    uint32_t owner_word;                         /* 060 */
    uint8_t mode;                                /* 064 */
    uint8_t unobserved_065[3];
    uint32_t field_068;
    uint32_t owner_reference_word;               /* 06c, pointer unproven */
    rome2_climate_prefix32 climate;               /* 070 */
    rome2_string8_layout32 alternate_label;       /* 0a0 */
    uint32_t tag_lo;                             /* 0ac */
    uint32_t tag_hi;                             /* 0b0 */
    uint32_t item_capacity;                      /* 0b4 */
    uint32_t item_count;                         /* 0b8 */
    rome2_data_address32 items;                  /* 0bc */
    rome2_string8_layout32 effect_kind;           /* 0c0 */
    uint8_t flag_0cc;
    uint8_t unobserved_0cd[3];
    rome2_string8_layout32 source_name;           /* 0d0 */
    uint8_t flag_0dc;
    uint8_t unobserved_0dd[3];
    uint32_t field_0e0;
    uint8_t flag_0e4;
    uint8_t unobserved_0e5[3];
} rome2_battle_entity_prefix32;

/* FUN_1024e480 initializes four dwords, with no pointer interpretation. */
typedef struct rome2_zero_quad_layout32 {
    uint32_t words[4];
} rome2_zero_quad_layout32;

/* Original stack words. These are ABI records, not native callable function
 * declarations. Narrow byte arguments still occupy one full x86 stack word.
 */
typedef struct rome2_unit_card_arguments32 {
    rome2_data_address32 arg00, arg01;
    uint32_t arg02, arg03, arg04, arg05, arg06, arg07, arg08;
    uint32_t arg09_float_bits;
    uint32_t arg10, arg11, arg12, arg13, arg14, arg15, arg16;
} rome2_unit_card_arguments32;

typedef struct rome2_entity_arguments32 {
    rome2_data_address32 arg00, arg01;
    uint32_t arg02, arg03, arg04, arg05;
    rome2_string8_layout32 by_value_arg06_08;
    rome2_data_address32 arg09, arg10, arg11;
    uint32_t arg12, arg13, arg14, arg15, arg16;
    rome2_data_address32 arg17;
    uint32_t arg18;
} rome2_entity_arguments32;

typedef struct rome2_climate_arguments32 {
    rome2_string8_layout32 by_value_name;
    uint32_t grid_a, grid_b, grid_c;
} rome2_climate_arguments32;

/* Same distinction for the unit-card constructor's known 0x178-byte prefix.
 * Scalar argument words remain scalar until evidence proves otherwise.
 */
typedef struct rome2_unit_card_prefix32 {
    uint32_t field_000, field_004, field_008, owner_word;
    rome2_string8_layout32 str_010;
    rome2_data_address32 attachment;
    rome2_data_address32 tag;
    uint8_t selector;
    uint8_t unobserved_025[3];
    rome2_string8_layout32 str_028, str_034;
    uint8_t variant;
    uint8_t unobserved_041[3];
    rome2_string8_layout32 str_044;
    uint16_t zero_050;
    uint16_t unobserved_052;
    uint32_t priority, control_flags;
    rome2_scalar_vector_layout32 words;          /* 05c, stride 4 */
    rome2_scalar_vector_layout32 coordinates;    /* 068, stride 8 */
    uint32_t unit_class, deployment_bits, strength, field_080;
    uint8_t field_084;
    uint8_t unobserved_085[3];
    uint32_t field_088, field_08c, field_090;
    uint32_t colour_lo_x_bits, colour_lo_y_bits, colour_hi_x_bits, colour_hi_y_bits;
    rome2_string8_layout32 str_0a4, str_0b0, str_0bc, str_0c8, str_0d4, str_0e0;
    uint32_t field_0ec;
    rome2_string8_layout32 str_0f0;
    rome2_string16_layout32 str_0fc; /* initialized by the UTF-16 sentinel helper */
    rome2_string8_layout32 str_108;
    uint32_t field_114;
    uint8_t enabled, flag_119, flag_11a, flag_11b, flag_11c, field_11d;
    uint16_t unobserved_11e;
    uint32_t last_common_index, slot_count;
    uint8_t mutable_class;
    uint8_t unobserved_129[3];
    rome2_string8_layout32 str_12c;
    uint8_t flag_138;
    uint8_t zero_139[2];
    uint8_t unobserved_13b;
    rome2_zero_quad_layout32 auxiliary;
    uint32_t field_14c, field_150, grid_min_bits, grid_max_bits;
    rome2_scalar_vector_layout32 fauna;          /* 15c, stride 44 */
    uint32_t field_168, field_16c, field_170;
    uint8_t field_174;
    uint8_t unobserved_175;
    uint16_t zero_176;
} rome2_unit_card_prefix32;

#define ROME2_LAYOUT_ASSERT(type, field, offset) \
    _Static_assert(offsetof(type, field) == (offset), #type "." #field)

_Static_assert(sizeof(rome2_data_address32) == 4, "guest data addresses stay 32-bit");
_Static_assert(sizeof(rome2_code_address32) == 4, "guest code addresses stay 32-bit");
_Static_assert(sizeof(rome2_string8_layout32) == 12, "narrow descriptor extent");
_Static_assert(sizeof(rome2_string16_layout32) == 12, "UTF-16 descriptor extent");
_Static_assert(sizeof(rome2_xml_state_prefix32) == 8, "known XML state prefix extent");
ROME2_LAYOUT_ASSERT(rome2_xml_state_prefix32, ready, 4);
_Static_assert(sizeof(rome2_vfs_dispatch_prefix32) == 8, "known VFS dispatch prefix extent");
ROME2_LAYOUT_ASSERT(rome2_vfs_dispatch_prefix32, table_004, 4);
_Static_assert(sizeof(rome2_vfs_name_table_layout32) == 12, "known VFS name-table descriptor");
ROME2_LAYOUT_ASSERT(rome2_vfs_name_table_layout32, bucket_count, 4);
ROME2_LAYOUT_ASSERT(rome2_vfs_name_table_layout32, empty_name, 8);
_Static_assert(sizeof(rome2_vfs_name_slot_layout32) == 8, "original VFS name-table slot stride");
ROME2_LAYOUT_ASSERT(rome2_vfs_name_slot_layout32, value, 4);
_Static_assert(sizeof(rome2_vfs_tree_header_layout32) == 8, "known VFS tree header extent");
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_header_layout32, count, 4);
_Static_assert(sizeof(rome2_vfs_tree_node_prefix32) == 24, "original VFS tree node extent");
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_node_prefix32, parent, 4);
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_node_prefix32, right, 8);
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_node_prefix32, color, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_node_prefix32, is_nil, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_node_prefix32, key, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_tree_node_prefix32, value, 0x14);
_Static_assert(sizeof(rome2_vfs_candidate_set_layout32) == 12, "known VFS candidate set extent");
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_set_layout32, head, 4);
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_set_layout32, count, 8);
_Static_assert(sizeof(rome2_vfs_candidate_node_prefix32) == 20, "original VFS candidate node extent");
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_node_prefix32, parent, 4);
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_node_prefix32, right, 8);
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_node_prefix32, color, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_node_prefix32, is_nil, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_candidate_node_prefix32, archive, 0x10);
ROME2_LAYOUT_ASSERT(rome2_string8_layout32, capacity, 4);
ROME2_LAYOUT_ASSERT(rome2_string8_layout32, data, 8);
ROME2_LAYOUT_ASSERT(rome2_string16_layout32, data, 8);
_Static_assert(sizeof(rome2_handler_vector_layout32) == 16, "handler vector extent");
ROME2_LAYOUT_ASSERT(rome2_handler_vector_layout32, count, 8);
ROME2_LAYOUT_ASSERT(rome2_handler_vector_layout32, backing, 12);
_Static_assert(sizeof(rome2_entity_source_layout32) == 12, "entity source extent");
ROME2_LAYOUT_ASSERT(rome2_entity_source_layout32, items, 8);
_Static_assert(sizeof(rome2_pool80_slot_layout32) == 0x50, "original pool slot stride");
_Static_assert(sizeof(rome2_pool76_slot_layout32) == 0x4c, "original pool slot stride");
_Static_assert(sizeof(rome2_pool_descriptor_layout32) == 8, "original pool descriptor extent");
ROME2_LAYOUT_ASSERT(rome2_pool80_slot_layout32, unobserved_payload, 4);
ROME2_LAYOUT_ASSERT(rome2_pool76_slot_layout32, unobserved_payload, 4);
_Static_assert(sizeof(rome2_dispatch_prefix32) == 12, "dispatch prefix extent");
_Static_assert(sizeof(rome2_climate_prefix32) == 0x30, "known climate prefix extent");
ROME2_LAYOUT_ASSERT(rome2_climate_prefix32, name, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_climate_prefix32, alternate_name, 0x18);
ROME2_LAYOUT_ASSERT(rome2_climate_prefix32, grid_a, 0x24);
ROME2_LAYOUT_ASSERT(rome2_climate_prefix32, grid_c, 0x2c);
_Static_assert(sizeof(rome2_battle_entity_prefix32) == 0xe8, "known entity prefix extent");
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, origin_x, 0x28);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, label, 0x30);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, grid_extent_min_bits, 0x3c);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, activation_radius_min_bits, 0x54);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, climate, 0x70);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, alternate_label, 0xa0);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, field_050, 0x50);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, item_capacity, 0xb4);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, item_count, 0xb8);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, items, 0xbc);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, effect_kind, 0xc0);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, source_name, 0xd0);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, field_0e0, 0xe0);
ROME2_LAYOUT_ASSERT(rome2_battle_entity_prefix32, flag_0e4, 0xe4);
_Static_assert(sizeof(rome2_zero_quad_layout32) == 16, "four original dwords");
_Static_assert(sizeof(rome2_unit_card_arguments32) == 0x44, "RET 0x44 arguments");
ROME2_LAYOUT_ASSERT(rome2_unit_card_arguments32, arg09_float_bits, 0x24);
ROME2_LAYOUT_ASSERT(rome2_unit_card_arguments32, arg16, 0x40);
_Static_assert(sizeof(rome2_entity_arguments32) == 0x4c, "RET 0x4c arguments");
ROME2_LAYOUT_ASSERT(rome2_entity_arguments32, by_value_arg06_08, 0x18);
ROME2_LAYOUT_ASSERT(rome2_entity_arguments32, arg09, 0x24);
ROME2_LAYOUT_ASSERT(rome2_entity_arguments32, arg10, 0x28);
ROME2_LAYOUT_ASSERT(rome2_entity_arguments32, arg17, 0x44);
_Static_assert(sizeof(rome2_climate_arguments32) == 0x18, "RET 0x18 arguments");
_Static_assert(sizeof(rome2_unit_card_prefix32) == 0x178, "known unit-card prefix extent");
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, str_010, 0x10);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, attachment, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, selector, 0x24);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, str_044, 0x44);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, priority, 0x54);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, words, 0x5c);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, coordinates, 0x68);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, unit_class, 0x74);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, colour_lo_x_bits, 0x94);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, str_0a4, 0xa4);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, str_0fc, 0xfc);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, enabled, 0x118);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, last_common_index, 0x120);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, str_12c, 0x12c);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, auxiliary, 0x13c);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, grid_min_bits, 0x154);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, fauna, 0x15c);
ROME2_LAYOUT_ASSERT(rome2_unit_card_prefix32, zero_176, 0x176);

_Static_assert(sizeof(rome2_vfs_dep_bucket_pair32) == 8, "dependency bucket pair size");
_Static_assert(sizeof(rome2_vfs_dep_hashmap_layout32) == 0x20, "dependency hashmap size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_hashmap_layout32, list_head, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_hashmap_layout32, count, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_hashmap_layout32, buckets, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_hashmap_layout32, mask, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_hashmap_layout32, max_idx, 0x1c);
_Static_assert(sizeof(rome2_vfs_dep_graph_node_prefix32) == 0x24, "dependency graph node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_graph_node_prefix32, name, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_graph_node_prefix32, deps, 0x1c);
_Static_assert(sizeof(rome2_vfs_dep_edge_node_prefix32) == 0x1c, "dependency edge node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_edge_node_prefix32, is_nil, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_edge_node_prefix32, target_name, 0x10);
_Static_assert(sizeof(rome2_vfs_archive_candidate_prefix32) == 0x20, "archive candidate prefix size");
ROME2_LAYOUT_ASSERT(rome2_vfs_archive_candidate_prefix32, pack_props, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_archive_candidate_prefix32, name_table, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_archive_candidate_prefix32, archive_name, 0x14);
_Static_assert(sizeof(rome2_vfs_pending_entry_vec_layout32) == 12, "pending entry vector size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pending_entry_vec_layout32, capacity, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pending_entry_vec_layout32, count, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pending_entry_vec_layout32, items, 0x08);
_Static_assert(sizeof(rome2_vfs_pack_props_prefix32) == 0x44, "pack props prefix size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, file_handle, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, last_error, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, flags, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, header_base, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, entry_count, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, index_bytes, 0x2c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, default_entry_meta, 0x30);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, pack_path, 0x34);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_props_prefix32, flag_040, 0x40);
_Static_assert(sizeof(rome2_vfs_pack_entry_layout32) == 0x28, "pack entry object size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, name_id, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, byte_size, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, data_offset_lo, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, data_offset_hi, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, entry_meta, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, carrier, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, stream_state, 0x20);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_entry_layout32, winner_notified, 0x24);
_Static_assert(sizeof(rome2_vfs_open_pack_slot_layout32) == 0x14, "open pack slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_pack_slot_layout32, name, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_pack_slot_layout32, unobserved_00c, 0x0c);
_Static_assert(sizeof(rome2_vfs_open_pack_table_layout32) == 0x14, "open pack table size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_pack_table_layout32, items, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_pack_table_layout32, bucket_count, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_pack_table_layout32, empty_key, 0x08);
_Static_assert(sizeof(rome2_vfs_freelist_pool_header32) == 0x0c, "freelist pool header size");
ROME2_LAYOUT_ASSERT(rome2_vfs_freelist_pool_header32, freelist_head, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_freelist_pool_header32, slab_chain_head, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_freelist_pool_header32, reserved_008, 0x08);
_Static_assert(sizeof(rome2_vfs_slab_descriptor32) == 0x08, "slab descriptor size");
ROME2_LAYOUT_ASSERT(rome2_vfs_slab_descriptor32, node_array, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_slab_descriptor32, next_slab, 0x04);
_Static_assert(sizeof(rome2_vfs_archive_name_disposer32) == 0x18, "archive name disposer size");
ROME2_LAYOUT_ASSERT(rome2_vfs_archive_name_disposer32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_archive_name_disposer32, subobj_00c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_archive_name_disposer32, owned_node, 0x10);
_Static_assert(sizeof(rome2_vfs_mutex_box32) == 0x1c, "VFS mutex box size");
ROME2_LAYOUT_ASSERT(rome2_vfs_mutex_box32, vtable_or_tag, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_mutex_box32, cs_debug_info, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_mutex_box32, cs_spin_count, 0x18);
_Static_assert(sizeof(rome2_vfs_global_map32) == 0x24, "VFS global map size");
ROME2_LAYOUT_ASSERT(rome2_vfs_global_map32, buckets, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_global_map32, bucket_count, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_global_map32, removed_key, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_global_map32, unused_key, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_global_map32, reserved_020, 0x20);
_Static_assert(sizeof(rome2_vfs_pack_header_wire32) == 0x1c, "pack wire header size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, signature, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, flags, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, dep_count, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, dep_bytes, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, entry_count, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, index_bytes, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_header_wire32, default_entry_meta, 0x18);
_Static_assert(sizeof(rome2_vfs_rb_sentinel_node32) == 0x14, "RB sentinel node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_sentinel_node32, left, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_sentinel_node32, right, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_sentinel_node32, is_nil, 0x0d);
_Static_assert(sizeof(rome2_vfs_quota_frame32) == 0x20, "VFS quota frame size");
ROME2_LAYOUT_ASSERT(rome2_vfs_quota_frame32, max_ops, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_quota_frame32, max_bytes, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_quota_frame32, used_bytes, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_quota_frame32, used_ops, 0x1c);
_Static_assert(sizeof(rome2_vfs_stream_slice_view32) == 0x10, "stream slice view size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_slice_view32, entry, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_slice_view32, offset, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_slice_view32, length, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_slice_view32, mode_flag, 0x0c);
_Static_assert(sizeof(rome2_vfs_ref_pack_block_header32) + sizeof(rome2_vfs_pack_props_prefix32) == 0x50, "ref pack block size");
ROME2_LAYOUT_ASSERT(rome2_vfs_ref_pack_block_header32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_ref_pack_block_header32, strong_ref, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_ref_pack_block_header32, weak_ref, 0x08);
_Static_assert(sizeof(rome2_vfs_open_bucket_map32) == 0x18, "open bucket map size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_map32, sentinel_004, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_map32, bucket_count, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_map32, buckets, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_map32, element_count, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_map32, max_load_factor_bits, 0x14);
_Static_assert(sizeof(rome2_vfs_open_bucket_slot32) == 0x0c, "open bucket slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_slot32, head, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_bucket_slot32, tail_or_sentinel, 0x04);
_Static_assert(sizeof(rome2_vfs_thread_node32) == 0x0c, "thread node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_thread_node32, next, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_thread_node32, thread_id, 0x08);
_Static_assert(sizeof(rome2_vfs_post_scan_table32) == 0x10, "post-scan table size");
ROME2_LAYOUT_ASSERT(rome2_vfs_post_scan_table32, entries, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_post_scan_table32, entry_count, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_post_scan_table32, default_entry, 0x08);
_Static_assert(sizeof(rome2_vfs_stream_wrap_a32) == 0x38, "stream wrap A size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_wrap_a32, flag_034, 0x34);
_Static_assert(sizeof(rome2_vfs_stream_wrap_b32) == 0x3c, "stream wrap B size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_wrap_b32, zero_038, 0x38);
_Static_assert(sizeof(rome2_vfs_dep_rb_node32) == 0x28, "dep RB node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_rb_node32, is_nil, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_rb_node32, name_a, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_dep_rb_node32, name_b, 0x1c);
_Static_assert(sizeof(rome2_vfs_cycle_rb_sentinel32) == 0x1c, "cycle RB sentinel size");
ROME2_LAYOUT_ASSERT(rome2_vfs_cycle_rb_sentinel32, is_nil, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_cycle_rb_sentinel32, payload_010, 0x10);
_Static_assert(sizeof(rome2_vfs_ref_block_vtable32) == 0x10, "ref block vtable size");
ROME2_LAYOUT_ASSERT(rome2_vfs_ref_block_vtable32, destroy_embedded, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_ref_block_vtable32, scalar_deleting_dtor, 0x08);
_Static_assert(sizeof(rome2_vfs_stream_wrap_vtable_prefix32) == 0x20, "stream wrap vtable prefix size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_wrap_vtable_prefix32, scalar_deleting_dtor, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_wrap_vtable_prefix32, open_checked, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_wrap_vtable_prefix32, slot_01c, 0x1c);
_Static_assert(sizeof(rome2_vfs_stream_handle_box32) == 0x14, "stream handle box size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle_box32, secondary_ctrl, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle_box32, sentinel_or_state, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle_box32, primary_ctrl, 0x10);
_Static_assert(sizeof(rome2_vfs_bucket_vec_header32) == 0x0c, "bucket vec header size");
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_vec_header32, capacity, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_vec_header32, count, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_vec_header32, slots, 0x08);
_Static_assert(sizeof(rome2_vfs_stream_view_box32) == 0x08, "stream view box size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_view_box32, mapped_view_base, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_view_box32, data_ptr, 0x04);
_Static_assert(sizeof(rome2_vfs_stream_state_prefix32) == 0x10, "stream state prefix size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_state_prefix32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_state_prefix32, eof_or_closed_00c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_state_prefix32, closed_00d, 0x0d);
_Static_assert(sizeof(rome2_vfs_rb_tree_head32) == 0x08, "RB tree head size");
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_tree_head32, sentinel, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_tree_head32, size, 0x04);
_Static_assert(sizeof(rome2_vfs_adj_hash_node32) == 0x24, "adj hash node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_adj_hash_node32, next, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_adj_hash_node32, prev, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_adj_hash_node32, key_name, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_adj_hash_node32, sub_tree_a, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_adj_hash_node32, sub_tree_b, 0x1c);
_Static_assert(sizeof(rome2_vfs_recursive_mutex_prefix32) == 0x08, "recursive mutex prefix size");
ROME2_LAYOUT_ASSERT(rome2_vfs_recursive_mutex_prefix32, recursion_depth, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_recursive_mutex_prefix32, cs_prefix_004, 0x04);
_Static_assert(sizeof(rome2_vfs_u32_ptr_vec32) == 0x0c, "u32 ptr vec size");
ROME2_LAYOUT_ASSERT(rome2_vfs_u32_ptr_vec32, first, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_u32_ptr_vec32, last, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_u32_ptr_vec32, end, 0x08);
_Static_assert(sizeof(rome2_vfs_flag_chain_node32) == 0x08, "flag chain node size");
ROME2_LAYOUT_ASSERT(rome2_vfs_flag_chain_node32, next, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_flag_chain_node32, flag_004, 0x04);

#undef ROME2_LAYOUT_ASSERT
#endif
