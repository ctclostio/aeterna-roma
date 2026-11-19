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

/* 44-byte (0x2cB) stream-state reference block (`0x1189a444`, freed `0x112acd30`)
 * constructed in `0x112a7860` with inner vtable `0x118977bc`/`0x118977d4` at `+0x0c`. */
typedef struct rome2_vfs_state_ref_block32 {
    rome2_vtable_address32 vtable;               /* 00 */
    uint32_t use_count;                          /* 04 */
    uint32_t weak_count;                         /* 08 */
    rome2_vtable_address32 inner_vtable;         /* 0c */
    uint32_t state_word_010;                     /* 10 */
    rome2_data_address32 view_box_ptr;           /* 14 */
    uint8_t eof_or_closed_018;                   /* 18 (state +0x0c) */
    uint8_t closed_019;                          /* 19 (state +0x0d) */
    uint8_t unobserved_01a[2];                   /* 1a..1b */
    rome2_data_address32 handle_ptr;             /* 1c */
    uint32_t word_020;                           /* 20 */
    uint32_t word_024;                           /* 24 */
    uint8_t flag_028;                            /* 28 */
    uint8_t unobserved_029[3];                   /* 29..2b */
} rome2_vfs_state_ref_block32;

/* 108-byte (0x6cB) pack-open telemetry singleton (`0x118976a4` at `0x12032e68`)
 * lazily constructed by `0x112e1830` with 997 (`0x3e5`) 8-byte hash buckets. */
typedef struct rome2_vfs_pack_telemetry_mgr32 {
    rome2_vtable_address32 vtable;               /* 00 */
    uint32_t unobserved_004;                     /* 04 */
    uint16_t unobserved_008;                     /* 08 */
    uint8_t flag_00a;                            /* 0a */
    uint8_t unobserved_00b;                      /* 0b */
    uint32_t process_id;                         /* 0c */
    uint32_t zero_010;                           /* 10 */
    uint32_t cs_014[6];                          /* 14..2b (24B CRITICAL_SECTION) */
    uint32_t table_words_02c[6];                 /* 2c..43 */
    uint32_t bucket_cap_044;                     /* 44 (0x3e5) */
    uint32_t bucket_count_048;                   /* 48 (0x3e5) */
    rome2_data_address32 buckets_04c;            /* 4c */
    uint32_t zero_050;                           /* 50 */
    uint32_t cs_054[6];                          /* 54..6b (24B CRITICAL_SECTION) */
} rome2_vfs_pack_telemetry_mgr32;

/* 40-byte (0x28B) pack-entry object (`0x118976c0`, deleted `0x112ad1b0`), exposing
 * `name` at `+0x04` (`0x112d3270`) and `backing_01c` at `+0x1c` (`0x112e0d80`/`0x112c9540`). */
typedef struct rome2_vfs_pack_vtable_76c0_prefix32 {
    rome2_vtable_address32 vtable;               /* 00 */
    rome2_string8_layout32 name;                 /* 04..0f */
    uint32_t unobserved_010[3];                  /* 10..1b */
    rome2_data_address32 backing_01c;            /* 1c */
    uint32_t unobserved_020[2];                  /* 20..27 */
} rome2_vfs_pack_vtable_76c0_prefix32;

/* 28-byte (0x1cB) async stream-state ref block (`0x1189a474`, inner vtable
 * `0x118977bc -> 0x118977e0` at `+0x0c`) allocated by `0x112d91c0`. */
typedef struct rome2_vfs_state_ref_block28_32 {
    rome2_vtable_address32 vtable;               /* 00 */
    uint32_t use_count;                          /* 04 */
    uint32_t weak_count;                         /* 08 */
    rome2_vtable_address32 inner_vtable;         /* 0c */
    rome2_data_address32 view_box_ptr_010;       /* 10 */
    uint32_t size_014;                           /* 14 */
    uint8_t eof_or_closed_018;                   /* 18 */
    uint8_t closed_019;                          /* 19 */
    uint8_t unobserved_01a[2];                   /* 1a..1b */
} rome2_vfs_state_ref_block28_32;

/* 28-byte (0x1cB) inner stream-state object with listener chain (`0x118977c8`
 * -> `0x118977bc`, destroyed by `0x112acfe0`). */
typedef struct rome2_vfs_state_inner_listener28_32 {
    rome2_vtable_address32 vtable;               /* 00 */
    rome2_data_address32 view_box_ptr_004;       /* 04 */
    uint32_t size_008;                           /* 08 */
    uint8_t eof_or_closed_00c;                   /* 0c */
    uint8_t closed_00d;                          /* 0d */
    uint8_t unobserved_00e[2];                   /* 0e..0f */
    rome2_data_address32 listener_head_010;      /* 10 */
    rome2_data_address32 listener_sentinel_014;  /* 14 */
    uint32_t unobserved_018;                     /* 18..1b */
} rome2_vfs_state_inner_listener28_32;

/* 36-byte (0x24B) Win32 SYSTEM_INFO block at `0x11af40e0` populated lazily
 * by `0x10115730` when `[0x11af4104] == 0`. */
typedef struct rome2_vfs_sys_info32 {
    uint32_t oem_id_000;                         /* 00 */
    uint32_t page_size_004;                      /* 04 */
    uint32_t unobserved_008[5];                  /* 08..1b */
    uint32_t allocation_granularity_01c;         /* 1c */
    uint32_t unobserved_020;                     /* 20..23 */
} rome2_vfs_sys_info32;

/* 28-byte (7-slot) virtual dispatch table for pack telemetry manager `0x118976a4`. */
typedef struct rome2_vfs_pack_vtable_76a4_32 {
    rome2_code_address32 slot_000_d36f0;         /* 00 */
    rome2_code_address32 slot_004_e80b0;         /* 04 */
    rome2_code_address32 slot_008_badd0;         /* 08 */
    rome2_code_address32 slot_00c_99640;         /* 0c */
    rome2_code_address32 slot_010_97c50;         /* 10 */
    rome2_code_address32 slot_014_e1780;         /* 14 */
    rome2_code_address32 slot_018_e17e0;         /* 18 */
} rome2_vfs_pack_vtable_76a4_32;

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
_Static_assert(sizeof(rome2_vfs_state_ref_block32) == 0x2c, "state ref block size");
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block32, inner_vtable, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block32, view_box_ptr, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block32, eof_or_closed_018, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block32, handle_ptr, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block32, flag_028, 0x28);
_Static_assert(sizeof(rome2_vfs_pack_telemetry_mgr32) == 0x6c, "pack telemetry mgr size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_telemetry_mgr32, process_id, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_telemetry_mgr32, cs_014, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_telemetry_mgr32, bucket_cap_044, 0x44);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_telemetry_mgr32, buckets_04c, 0x4c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_telemetry_mgr32, cs_054, 0x54);
_Static_assert(sizeof(rome2_vfs_pack_vtable_76c0_prefix32) == 0x28, "pack vtable 76c0 prefix size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_prefix32, name, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_prefix32, backing_01c, 0x1c);
_Static_assert(sizeof(rome2_vfs_state_ref_block28_32) == 0x1c, "state ref block 28 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block28_32, inner_vtable, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block28_32, view_box_ptr_010, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block28_32, size_014, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block28_32, eof_or_closed_018, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_ref_block28_32, closed_019, 0x19);
_Static_assert(sizeof(rome2_vfs_state_inner_listener28_32) == 0x1c, "state inner listener 28 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_state_inner_listener28_32, view_box_ptr_004, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_inner_listener28_32, size_008, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_inner_listener28_32, eof_or_closed_00c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_inner_listener28_32, listener_head_010, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_state_inner_listener28_32, listener_sentinel_014, 0x14);
_Static_assert(sizeof(rome2_vfs_sys_info32) == 0x24, "sys info 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_sys_info32, page_size_004, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_sys_info32, allocation_granularity_01c, 0x1c);
_Static_assert(sizeof(rome2_vfs_pack_vtable_76a4_32) == 0x1c, "pack vtable 76a4 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76a4_32, slot_000_d36f0, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76a4_32, slot_008_badd0, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76a4_32, slot_014_e1780, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76a4_32, slot_018_e17e0, 0x18);

/* 16-byte (0x10B) open-stream cache entry suffix passed as `ECX = block + 0x10`
 * to `0x100f19f0` / `0x100ff8c0` in `0x112c0300` (inside `0x20B` `0x1189a464` ref-block). */
typedef struct rome2_vfs_open_cache_entry16_32 {
    uint32_t unobserved_000;                     /* 00 (tail of 0x1011fe30 subobject) */
    uint32_t zero_004;                           /* 04 (zeroed by 0x100f19f0) */
    uint32_t token_lo_008;                       /* 08 (arg2 / 0x10104b60, copied by 0x100ff8c0) */
    uint32_t token_hi_00c;                       /* 0c (arg3 / 0x100fcb00, copied by 0x100ff8c0) */
} rome2_vfs_open_cache_entry16_32;
_Static_assert(sizeof(rome2_vfs_open_cache_entry16_32) == 0x10, "open cache entry 16 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_cache_entry16_32, zero_004, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_cache_entry16_32, token_lo_008, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_cache_entry16_32, token_hi_00c, 0x0c);

/* 56-byte (0x38B) async view-map worker ref-block (`0x1189a454`, allocated via
 * `0x100d12b0(0x38)` in `0x112b2f40` and stored into `[0x12032b08]`/`[0x12032b04]`). */
typedef struct rome2_vfs_async_worker_ref_block56_32 {
    rome2_vtable_address32 vtable;               /* 00 (0x1189a454) */
    uint32_t strong_refs_004;                    /* 04 */
    uint32_t weak_refs_008;                      /* 08 */
    rome2_data_address32 queue_head_00c;         /* 0c (worker obj start: block + 0x10) */
    rome2_data_address32 queue_tail_010;         /* 10 */
    uint32_t zero_014;                           /* 14 */
    uint32_t active_count_018;                   /* 18 ([worker + 0x0c]) */
    uint32_t cs_01c[6];                          /* 1c..33 (24B CRITICAL_SECTION at worker+0x10) */
    uint32_t semaphore_034;                      /* 34 (4B semaphore at worker+0x28 via 0x100f12c0) */
} rome2_vfs_async_worker_ref_block56_32;
_Static_assert(sizeof(rome2_vfs_async_worker_ref_block56_32) == 0x38, "async worker ref block 56 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_async_worker_ref_block56_32, strong_refs_004, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_async_worker_ref_block56_32, queue_head_00c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_async_worker_ref_block56_32, active_count_018, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_async_worker_ref_block56_32, cs_01c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_async_worker_ref_block56_32, semaphore_034, 0x34);

/* 44-byte (0x2cB) complete 11-slot stream vtable shared by `0x11897790` and `0x118977ec`. */
typedef struct rome2_vfs_stream_vtable_11slot32 {
    rome2_code_address32 scalar_deleting_dtor_000; /* 00: 0x112ad0f0 / 0x112acde0 */
    rome2_code_address32 open_checked_004;         /* 04: 0x112d8e20 / 0x112d8d30 */
    rome2_code_address32 slot_008;                 /* 08: 0x10190580 */
    rome2_code_address32 slot_00c;                 /* 0c: 0x100e22c0 */
    rome2_code_address32 slot_010;                 /* 10: 0x112dab00 / 0x112da9f0 */
    rome2_code_address32 slot_014;                 /* 14: 0x112c8bc0 / 0x112c8b80 */
    rome2_code_address32 slot_018;                 /* 18: 0x10369160 / 0x112d9860 */
    rome2_code_address32 slot_01c;                 /* 1c: 0x112baef0 / 0x112badf0 */
    rome2_code_address32 get_field_020;            /* 20: 0x1018ad20 / 0x101a0430 */
    rome2_code_address32 has_state_024;            /* 24: 0x108b2600 / 0x105cd140 */
    rome2_code_address32 state_u64_ne_028;         /* 28: 0x112b3190 / 0x112b30b0 */
} rome2_vfs_stream_vtable_11slot32;
_Static_assert(sizeof(rome2_vfs_stream_vtable_11slot32) == 0x2c, "stream vtable 11slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_vtable_11slot32, get_field_020, 0x20);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_vtable_11slot32, has_state_024, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_vtable_11slot32, state_u64_ne_028, 0x28);

/* 80-byte (0x50B) complete 20-slot pack-entry vtable `0x118976c0` (+0x00..+0x4c). */
typedef struct rome2_vfs_pack_vtable_76c0_full32 {
    rome2_code_address32 slot_000_ad1b0;           /* 00 */
    rome2_code_address32 slot_004_d3270;           /* 04 */
    rome2_code_address32 slot_008_e0d80;           /* 08 */
    rome2_code_address32 slot_00c_71400;           /* 0c */
    rome2_code_address32 slot_010_01a40;           /* 10 */
    rome2_code_address32 slot_014_c8be0;           /* 14 */
    rome2_code_address32 slot_018_c9540;           /* 18 */
    rome2_code_address32 slot_01c_d0c90;           /* 1c */
    rome2_code_address32 slot_020_d0d80;           /* 20 */
    rome2_code_address32 slot_024_dab70;           /* 24 */
    rome2_code_address32 slot_028_69610;           /* 28 */
    rome2_code_address32 slot_02c_baf20;           /* 2c */
    rome2_code_address32 slot_030_d9890;           /* 30 */
    rome2_code_address32 slot_034_d2900;           /* 34 */
    rome2_code_address32 slot_038_d0bd0;           /* 38 */
    rome2_code_address32 slot_03c_c0dd0;           /* 3c */
    rome2_code_address32 slot_040_dd2f0;           /* 40 */
    rome2_code_address32 slot_044_e0d80;           /* 44 */
    rome2_code_address32 slot_048_c0090;           /* 48 */
    rome2_code_address32 slot_04c_c0c40;           /* 4c */
} rome2_vfs_pack_vtable_76c0_full32;
_Static_assert(sizeof(rome2_vfs_pack_vtable_76c0_full32) == 0x50, "pack vtable 76c0 full size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_full32, slot_000_ad1b0, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_full32, slot_02c_baf20, 0x2c);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_full32, slot_030_d9890, 0x30);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_full32, slot_048_c0090, 0x48);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_76c0_full32, slot_04c_c0c40, 0x4c);

/* 8-byte (0x08B) Win32 handle box (`0x100f1080` ctor / `0x100f2170` dtor). */
typedef struct rome2_vfs_win32_handle_box8_32 {
    uint32_t handle_00;                          /* 00 (INVALID_HANDLE_VALUE / -1 when closed) */
    uint32_t last_status_04;                     /* 04 (6 = ERROR_INVALID_HANDLE sentinel) */
} rome2_vfs_win32_handle_box8_32;
_Static_assert(sizeof(rome2_vfs_win32_handle_box8_32) == 0x08, "win32 handle box 8 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_handle_box8_32, handle_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_handle_box8_32, last_status_04, 0x04);

/* 16-byte (0x10B) open file/mapping handle box (`0x100f1a30` / `0x100f2350` /
 * `0x10104b60` / `0x100fcb00`; embedded at offset 0 of stream/pack handles). */
typedef struct rome2_vfs_open_file_mapping16_32 {
    uint32_t last_error_00;                      /* 00 (mapped error code or 0 / 3) */
    uint32_t open_flags_04;                      /* 04 (bit 0 = file handle, bit 1 = mapping) */
    uint32_t file_handle_08;                     /* 08 (INVALID_HANDLE_VALUE / -1 when closed) */
    uint32_t mapping_handle_0c;                  /* 0c (INVALID_HANDLE_VALUE / -1 when closed) */
} rome2_vfs_open_file_mapping16_32;
_Static_assert(sizeof(rome2_vfs_open_file_mapping16_32) == 0x10, "open file mapping 16 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_file_mapping16_32, last_error_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_file_mapping16_32, open_flags_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_file_mapping16_32, file_handle_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_file_mapping16_32, mapping_handle_0c, 0x0c);

/* 8-byte (0x08B) `std::bad_alloc` exception header (`0x100f1c50` ctor). */
typedef struct rome2_vfs_bad_alloc_exc8_32 {
    rome2_vtable_address32 vtable_00;            /* 00 (0x11741d78) */
    rome2_data_address32 what_str_04;            /* 04 (0x11741d84 -> "bad allocation") */
} rome2_vfs_bad_alloc_exc8_32;
_Static_assert(sizeof(rome2_vfs_bad_alloc_exc8_32) == 0x08, "bad_alloc exc 8 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_bad_alloc_exc8_32, vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_bad_alloc_exc8_32, what_str_04, 0x04);

/* 68-byte (0x44B) complete 17-slot pack/resource ref vtable `0x11897be0`. */
typedef struct rome2_vfs_pack_vtable_7be0_17slot32 {
    rome2_code_address32 slot_000_acf80;         /* 00 (0x112acf80) */
    rome2_code_address32 slot_004_d3270;         /* 04 (0x112d3270) */
    rome2_code_address32 slot_008_d3270;         /* 08 (0x112d3270) */
    rome2_code_address32 slot_00c_dbc00;         /* 0c (0x100dbc00) */
    rome2_code_address32 slot_010_dbc00;         /* 10 (0x100dbc00) */
    rome2_code_address32 slot_014_d6770;         /* 14 (0x100d6770) */
    rome2_code_address32 slot_018_d6900;         /* 18 (0x100d6900) */
    rome2_code_address32 slot_01c_d0c80;         /* 1c (0x112d0c80) */
    rome2_code_address32 slot_020_f3d00;         /* 20 (0x100f3d00) */
    rome2_code_address32 slot_024_daae0;         /* 24 (0x112daae0) */
    rome2_code_address32 slot_028_dbc00;         /* 28 (0x100dbc00) */
    rome2_code_address32 slot_02c_dbc00;         /* 2c (0x100dbc00) */
    rome2_code_address32 slot_030_d6770;         /* 30 (0x100d6770) */
    rome2_code_address32 slot_034_d6560;         /* 34 (0x100d6560) */
    rome2_code_address32 slot_038_d6770;         /* 38 (0x100d6770) */
    rome2_code_address32 slot_03c_d6770;         /* 3c (0x100d6770) */
    rome2_code_address32 slot_040_dbc00;         /* 40 (0x100dbc00) */
} rome2_vfs_pack_vtable_7be0_17slot32;
_Static_assert(sizeof(rome2_vfs_pack_vtable_7be0_17slot32) == 0x44, "pack vtable 7be0 17slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_7be0_17slot32, slot_000_acf80, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_7be0_17slot32, slot_024_daae0, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_7be0_17slot32, slot_040_dbc00, 0x40);

/* 32-byte (0x20B) complete 8-slot pack/stream cursor sub-vtable `0x11897c44`. */
typedef struct rome2_vfs_pack_vtable_7c44_8slot32 {
    rome2_code_address32 slot_000_ad6d0;         /* 00 (0x112ad6d0) */
    rome2_code_address32 slot_004_c8c60;         /* 04 (0x112c8c60) */
    rome2_code_address32 slot_008_d6900;         /* 08 (0x100d6900) */
    rome2_code_address32 slot_00c_c0d90;         /* 0c (0x112c0d90) */
    rome2_code_address32 slot_010_dc250;         /* 10 (0x112dc250) */
    rome2_code_address32 slot_014_d32b0;         /* 14 (0x112d32b0) */
    rome2_code_address32 slot_018_e48d0;         /* 18 (0x101e48d0) */
    rome2_code_address32 slot_01c_d6560;         /* 1c (0x100d6560) */
} rome2_vfs_pack_vtable_7c44_8slot32;
_Static_assert(sizeof(rome2_vfs_pack_vtable_7c44_8slot32) == 0x20, "pack vtable 7c44 8slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_7c44_8slot32, slot_000_ad6d0, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_7c44_8slot32, slot_014_d32b0, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_vtable_7c44_8slot32, slot_01c_d6560, 0x1c);

/* 32-byte (0x20B) loose-file VFS entry (`0x11897710` vtable; `0x112acf40` frees `0x20`B). */
typedef struct rome2_vfs_loose_file_entry32 {
    rome2_vtable_address32 vtable_00;            /* 00 (0x11897710) */
    uint32_t dir_str_04;                         /* 04 (parent directory string word) */
    uint32_t rel_path_str_08;                    /* 08 (relative path string word) */
    uint32_t file_handle_0c;                     /* 0c (Win32 HANDLE or -1) */
    uint32_t aux_handle_10;                      /* 10 (secondary handle/meta or -1) */
    uint32_t file_size_14;                       /* 14 (loose file byte length) */
    uint32_t mtime_or_meta_18;                   /* 18 (mtime/metadata word) */
    uint32_t backing_view_1c;                    /* 1c (cached backing stream/view ptr) */
} rome2_vfs_loose_file_entry32;
_Static_assert(sizeof(rome2_vfs_loose_file_entry32) == 0x20, "loose file entry 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_file_entry32, vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_file_entry32, file_handle_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_file_entry32, file_size_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_file_entry32, backing_view_1c, 0x1c);

/* 40-byte (0x28B) buffered parent-releasing substream (`0x11897c24` vtable). */
typedef struct rome2_vfs_buffered_substream40_32 {
    rome2_vtable_address32 vtable_00;            /* 00 (0x11897c24) */
    uint32_t window_base_04;                     /* 04 (mapped parent window ptr) */
    uint32_t window_size_08;                     /* 08 (mapped parent window bytes) */
    uint32_t window_offset_0c;                   /* 0c (cursor within current window) */
    uint32_t stream_pos_10;                      /* 10 (logical stream byte position) */
    uint32_t parent_entry_14;                    /* 14 (parent stream/entry ptr) */
    uint32_t reset_req_0_or_str_18;              /* 18 (zero-arg reset descriptor / str) */
    uint32_t initial_pos_or_cursor_1c;           /* 1c (base/reset stream offset) */
    uint32_t limit_or_flags_20;                  /* 20 (reserved/limit word) */
    uint8_t eof_flag_24;                         /* 24 (1 when stream_pos >= parent_size) */
    uint8_t error_flag_25;                       /* 25 (1 on parent/read failure) */
    uint8_t pad_26[2];                           /* 26 (tail padding) */
} rome2_vfs_buffered_substream40_32;
_Static_assert(sizeof(rome2_vfs_buffered_substream40_32) == 0x28, "buffered substream 40 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_buffered_substream40_32, vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_buffered_substream40_32, window_offset_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_buffered_substream40_32, stream_pos_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_buffered_substream40_32, parent_entry_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_buffered_substream40_32, eof_flag_24, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_buffered_substream40_32, error_flag_25, 0x25);

/* 20-byte (0x14B) file stat output initialized by `0x1011fda0` and populated by `0x101153f0`. */
typedef struct rome2_vfs_file_stat20_32 {
    uint32_t file_size_low_00;                   /* 00 */
    uint32_t file_size_high_04;                  /* 04 */
    uint32_t mtime_low_08;                       /* 08 */
    uint32_t mtime_high_0c;                      /* 0c */
    uint8_t attr_flags_10;                       /* 10 */
    uint8_t pad_11[3];                           /* 11 */
} rome2_vfs_file_stat20_32;
_Static_assert(sizeof(rome2_vfs_file_stat20_32) == 0x14, "file stat 20 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat20_32, file_size_low_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat20_32, mtime_low_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat20_32, attr_flags_10, 0x10);

/* 80-byte (0x50B) complete 20-slot loose-file entry vtable `0x11897710`. */
typedef struct rome2_vfs_loose_vtable_7710_20slot32 {
    rome2_code_address32 slot_00;                /* 00 (0x112acf40) */
    rome2_code_address32 slot_04;                /* 04 (0x112d3270) */
    rome2_code_address32 slot_08;                /* 08 (0x10a34b40) */
    rome2_code_address32 slot_0c;                /* 0c (0x10171400) */
    rome2_code_address32 slot_10;                /* 10 (0x101d9800) */
    rome2_code_address32 slot_14;                /* 14 (0x112c8b90) */
    rome2_code_address32 slot_18;                /* 18 (0x100d6900) */
    rome2_code_address32 slot_1c;                /* 1c (0x112d0bf0) */
    rome2_code_address32 slot_20;                /* 20 (0x112d0d20) */
    rome2_code_address32 slot_24;                /* 24 (0x112daa40) */
    rome2_code_address32 slot_28;                /* 28 (0x101d97f0) */
    rome2_code_address32 slot_2c;                /* 2c (0x112baeb0) */
    rome2_code_address32 slot_30;                /* 30 (0x112d9880) */
    rome2_code_address32 slot_34;                /* 34 (0x100d6560) */
    rome2_code_address32 slot_38;                /* 38 (0x112d0bb0) */
    rome2_code_address32 slot_3c;                /* 3c (0x112c0db0) */
    rome2_code_address32 slot_40;                /* 40 (0x112dd2e0) */
    rome2_code_address32 slot_44;                /* 44 (0x112d3270) */
    rome2_code_address32 slot_48;                /* 48 (0x112bffe0) */
    rome2_code_address32 slot_4c;                /* 4c (0x100dbc00) */
} rome2_vfs_loose_vtable_7710_20slot32;
_Static_assert(sizeof(rome2_vfs_loose_vtable_7710_20slot32) == 0x50, "loose vtable 7710 20slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_vtable_7710_20slot32, slot_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_vtable_7710_20slot32, slot_24, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_vtable_7710_20slot32, slot_4c, 0x4c);

/* 48-byte (0x30B) complete 12-slot pack/stream wrapper vtable `0x11897760`. */
typedef struct rome2_vfs_pack_wrap_vtable_7760_12slot32 {
    rome2_code_address32 slot_00;                /* 00 (0x112ace20) */
    rome2_code_address32 slot_04;                /* 04 (0x112d3270) */
    rome2_code_address32 slot_08;                /* 08 (0x112d3270) */
    rome2_code_address32 slot_0c;                /* 0c (0x101d9800) */
    rome2_code_address32 slot_10;                /* 10 (0x101a0430) */
    rome2_code_address32 slot_14;                /* 14 (0x10abbf90) */
    rome2_code_address32 slot_18;                /* 18 (0x112c9520) */
    rome2_code_address32 slot_1c;                /* 1c (0x100e22c0) */
    rome2_code_address32 slot_20;                /* 20 (0x100f3d00) */
    rome2_code_address32 slot_24;                /* 24 (0x100dbc00) */
    rome2_code_address32 slot_28;                /* 28 (0x100dbc00) */
    rome2_code_address32 slot_2c;                /* 2c (0x112c8c80) */
} rome2_vfs_pack_wrap_vtable_7760_12slot32;
_Static_assert(sizeof(rome2_vfs_pack_wrap_vtable_7760_12slot32) == 0x30, "pack wrap vtable 7760 12slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_wrap_vtable_7760_12slot32, slot_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_wrap_vtable_7760_12slot32, slot_2c, 0x2c);

/* 32-byte (0x20B) complete 8-slot parent-releasing buffered substream vtable `0x11897c24`. */
typedef struct rome2_vfs_substream_vtable_7c24_8slot32 {
    rome2_code_address32 slot_00;                /* 00 (0x112ad6a0) */
    rome2_code_address32 slot_04;                /* 04 (0x112c8c40) */
    rome2_code_address32 slot_08;                /* 08 (0x112d98c0) */
    rome2_code_address32 slot_0c;                /* 0c (0x112c0cf0) */
    rome2_code_address32 slot_10;                /* 10 (0x112dc1a0) */
    rome2_code_address32 slot_14;                /* 14 (0x112d3290) */
    rome2_code_address32 slot_18;                /* 18 (0x112d5690) */
    rome2_code_address32 slot_1c;                /* 1c (0x112d57d0) */
} rome2_vfs_substream_vtable_7c24_8slot32;
_Static_assert(sizeof(rome2_vfs_substream_vtable_7c24_8slot32) == 0x20, "substream vtable 7c24 8slot size");
ROME2_LAYOUT_ASSERT(rome2_vfs_substream_vtable_7c24_8slot32, slot_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_substream_vtable_7c24_8slot32, slot_1c, 0x1c);

/* 16-byte (0x10B) dual-slot async/mapped backing view slot entry (`0x112a2090` / `0x112ab500`). */
typedef struct rome2_vfs_dual_slot_entry32 {
    uint32_t task_ptr_00;                        /* 00 (active 0x14B async task ptr or 0) */
    uint32_t window_len_04;                      /* 04 (mapped byte length) */
    uint32_t window_off_08;                      /* 08 (mapped start file offset) */
    uint8_t flags_0c;                            /* 0c (slot state/flags byte) */
    uint8_t pad_0d[3];                           /* 0d (tail padding) */
} rome2_vfs_dual_slot_entry32;
_Static_assert(sizeof(rome2_vfs_dual_slot_entry32) == 0x10, "dual slot entry 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_entry32, task_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_entry32, window_len_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_entry32, window_off_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_entry32, flags_0c, 0x0c);

/* 84-byte (0x54B) dual-slot async/mapped backing view (`0x11897818` vtable; `0x112ba840` / `0x112ad210`). */
typedef struct rome2_vfs_dual_slot_view32 {
    rome2_vtable_address32 vtable;               /* 00 (0x11897818, reset to 0x11849278) */
    uint32_t ref_or_reserved_04;                 /* 04 (reserved/zero word) */
    uint32_t name_str_08;                        /* 08 (copied stream name word) */
    uint32_t path_str_0c;                        /* 0c (copied file path word) */
    uint32_t total_size_10;                      /* 10 (total stream size in bytes) */
    uint32_t file_handle_14;                     /* 14 (primary Win32 file handle) */
    uint32_t aux_handle_18;                      /* 18 (secondary Win32 file handle) */
    uint32_t chunk_cap_1c;                       /* 1c (maximum window chunk bytes) */
    uint32_t cipher_flags_20;                    /* 20 (XOR decipher flags forwarded to task) */
    uint32_t active_ref_count_24;                /* 24 (outstanding active map reference count) */
    rome2_vfs_dual_slot_entry32 slot0_28;        /* 28 (slot 0 window entry) */
    rome2_vfs_dual_slot_entry32 slot1_38;        /* 38 (slot 1 window entry) */
    uint32_t slot0_rel_off_48;                   /* 48 (cursor offset within slot 0 buffer) */
    uint32_t slot1_rel_off_4c;                   /* 4c (cursor offset within slot 1 buffer) */
    uint8_t active_slot_idx_50;                  /* 50 (0 or 1 active slot selector) */
    uint8_t pad_51[3];                           /* 51 (tail padding) */
} rome2_vfs_dual_slot_view32;
_Static_assert(sizeof(rome2_vfs_dual_slot_view32) == 0x54, "dual slot view 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, chunk_cap_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, active_ref_count_24, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, slot0_28, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, slot1_38, 0x38);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, slot0_rel_off_48, 0x48);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, slot1_rel_off_4c, 0x4c);
ROME2_LAYOUT_ASSERT(rome2_vfs_dual_slot_view32, active_slot_idx_50, 0x50);

/* 32-byte (0x20B) async in-memory/cipher backing view (`0x11897844` vtable; `0x112dc8db` / `0x112ace20`). */
typedef struct rome2_vfs_cipher_mem_view32 {
    rome2_vtable_address32 vtable;               /* 00 (0x11897844, reset to 0x11849278) */
    uint32_t ref_or_reserved_04;                 /* 04 (reserved/zero word) */
    uint32_t name_str_08;                        /* 08 (copied stream name word) */
    uint32_t cipher_flags_0c;                    /* 0c (bit 0 triggers XOR decipher 0x100fcfd0) */
    uint8_t valid_flag_10;                       /* 10 (1 initially, cleared on NULL install) */
    uint8_t ready_flag_11;                       /* 11 (0 pending, 1 once buffer installed/failed) */
    uint8_t pad_12[2];                           /* 12 (alignment padding) */
    uint32_t buffer_ptr_14;                      /* 14 (installed buffer address) */
    uint32_t buffer_size_18;                     /* 18 (installed buffer byte length) */
    uint32_t active_ref_count_1c;                /* 1c (saturating decrement active ref count) */
} rome2_vfs_cipher_mem_view32;
_Static_assert(sizeof(rome2_vfs_cipher_mem_view32) == 0x20, "cipher mem view 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, cipher_flags_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, valid_flag_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, ready_flag_11, 0x11);
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, buffer_ptr_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, buffer_size_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_cipher_mem_view32, active_ref_count_1c, 0x1c);

/* 20-byte (0x14B) delegating stream adapter (`0x11897c90` vtable; `0x112c6b10` / `0x112ad1e0`). */
typedef struct rome2_vfs_stream_delegate_adapter32 {
    rome2_vtable_address32 vtable;               /* 00 (0x11897c90, reset to 0x1173db9c) */
    uint32_t inner_stream_04;                    /* 04 (wrapped inner stream pointer) */
    uint32_t wide_path_len_08;                   /* 08 (UTF-16 string length in units) */
    uint32_t wide_path_cap_0c;                   /* 0c (UTF-16 string capacity in units) */
    uint32_t wide_path_buf_10;                   /* 10 (UTF-16 string data address) */
} rome2_vfs_stream_delegate_adapter32;
_Static_assert(sizeof(rome2_vfs_stream_delegate_adapter32) == 0x14, "stream delegate adapter 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_delegate_adapter32, vtable, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_delegate_adapter32, inner_stream_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_delegate_adapter32, wide_path_len_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_delegate_adapter32, wide_path_buf_10, 0x10);

/* 16-byte (0x10B) stat64i32 output populated by `0x101153f0` and `0x101154a0`. */
typedef struct rome2_vfs_file_stat32 {
    uint32_t mtime_lo_00;                        /* 00 (low 32 bits of st_mtime) */
    uint32_t mtime_hi_04;                        /* 04 (high 32 bits of st_mtime) */
    uint32_t file_size_08;                       /* 08 (32-bit st_size) */
    uint8_t is_readable_0c;                      /* 0c ((st_mode >> 8) & 1) */
    uint8_t is_writable_0d;                      /* 0d ((st_mode >> 7) & 1) */
    uint8_t is_dir_0e;                           /* 0e ((st_mode >> 14) & 1) */
    uint8_t pad_0f;                              /* 0f (unmodified padding) */
} rome2_vfs_file_stat32;
_Static_assert(sizeof(rome2_vfs_file_stat32) == 0x10, "file stat 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat32, mtime_lo_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat32, file_size_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat32, is_readable_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat32, is_writable_0d, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_file_stat32, is_dir_0e, 0x0e);

/* Layer 28: Base/static FileSystem (0x119e1004), _Ref_count_base (0x1189a520), and active FileSystem secondary interface (0x118978e8). */

/* 8-byte dual-vptr base FileSystem object at 0x119e1004 (`0x117240b0` & `0x112acfb0`). */
typedef struct rome2_vfs_base_fs_obj32 {
    uint32_t primary_vptr_00;                    /* 00 (0x1189791c) */
    uint32_t secondary_vptr_04;                  /* 04 (0x11897994) */
} rome2_vfs_base_fs_obj32;
_Static_assert(sizeof(rome2_vfs_base_fs_obj32) == 0x08, "base fs obj 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_base_fs_obj32, primary_vptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_base_fs_obj32, secondary_vptr_04, 0x04);

/* 120-byte (30-slot) primary FileSystem vtable (`0x1189791c` / active `0x11897870`). */
typedef struct rome2_vfs_base_fs_vtable_30slot32 {
    uint32_t slots[30];                          /* 00..74 */
} rome2_vfs_base_fs_vtable_30slot32;
_Static_assert(sizeof(rome2_vfs_base_fs_vtable_30slot32) == 0x78, "base fs primary vtable 30slot 32 size");

/* 52-byte (13-slot) secondary FileSystem vtable (`0x11897994` & `0x118978e8`). */
typedef struct rome2_vfs_fs_secondary_vtable_13slot32 {
    uint32_t slots[13];                          /* 00..30 */
} rome2_vfs_fs_secondary_vtable_13slot32;
_Static_assert(sizeof(rome2_vfs_fs_secondary_vtable_13slot32) == 0x34, "fs secondary vtable 13slot 32 size");

/* 16-byte `std::tr1::_Ref_count`-style shared-pointer control block (`0x1189a520`). */
typedef struct rome2_vfs_sp_ctrl_block32 {
    uint32_t vtable_00;                          /* 00 (0x1189a520) */
    uint32_t uses_04;                            /* 04 (strong refcount) */
    uint32_t weaks_08;                           /* 08 (weak/ctrl refcount) */
    uint32_t payload_ptr_0c;                     /* 0c (managed object pointer or 0) */
} rome2_vfs_sp_ctrl_block32;
_Static_assert(sizeof(rome2_vfs_sp_ctrl_block32) == 0x10, "sp ctrl block 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_block32, vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_block32, uses_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_block32, weaks_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_block32, payload_ptr_0c, 0x0c);

/* 16-byte (4-slot) `_Ref_count_base` vtable at `0x1189a520`. */
typedef struct rome2_vfs_sp_ctrl_vtable_4slot32 {
    uint32_t destroy_00;                         /* 00 (0x112afc90) */
    uint32_t delete_this_04;                     /* 04 (0x1090bb10) */
    uint32_t deleting_dtor_08;                   /* 08 (0x112accb0) */
    uint32_t get_deleter_0c;                     /* 0c (0x10128c50) */
} rome2_vfs_sp_ctrl_vtable_4slot32;
_Static_assert(sizeof(rome2_vfs_sp_ctrl_vtable_4slot32) == 0x10, "sp ctrl vtable 4slot 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_vtable_4slot32, destroy_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_vtable_4slot32, delete_this_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_vtable_4slot32, deleting_dtor_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_ctrl_vtable_4slot32, get_deleter_0c, 0x0c);

/* 8-byte `std::shared_ptr` representation `{ptr, rep}` populated by `0x112e0ed0`/`0x112ce3b0`/`0x112e10e0`/`0x112e0f30`/`0x112ce410`. */
typedef struct rome2_vfs_sp_pair32 {
    uint32_t ptr_00;                             /* 00 (pointee) */
    uint32_t rep_04;                             /* 04 (`rome2_vfs_sp_ctrl_block32 *`) */
} rome2_vfs_sp_pair32;
_Static_assert(sizeof(rome2_vfs_sp_pair32) == 0x08, "sp pair 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_pair32, ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_sp_pair32, rep_04, 0x04);

/* 8-byte zeroed 64-bit pair written by `0x11002ca0`. */
typedef struct rome2_vfs_u64_pair32 {
    uint32_t low_00;                             /* 00 */
    uint32_t high_04;                            /* 04 */
} rome2_vfs_u64_pair32;
_Static_assert(sizeof(rome2_vfs_u64_pair32) == 0x08, "u64 pair 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_u64_pair32, low_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_u64_pair32, high_04, 0x04);

/* 32-byte entry metadata descriptor populated by `0x112c9550`. */
typedef struct rome2_vfs_entry_info32 {
    uint32_t size_lo_00;                         /* 00 (0xffffffff) */
    uint32_t size_hi_04;                         /* 04 (0xffffffff) */
    uint32_t name_str_08;                        /* 08 (interned empty string handle) */
    uint32_t pad_0c;                             /* 0c (untouched by 0x112c9550) */
    uint32_t zero_10;                            /* 10 */
    uint32_t zero_14;                            /* 14 */
    uint32_t zero_18;                            /* 18 */
    uint8_t flag_1c;                             /* 1c */
    uint8_t pad_1d[3];                           /* 1d..1f */
} rome2_vfs_entry_info32;
_Static_assert(sizeof(rome2_vfs_entry_info32) == 0x20, "entry info 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_entry_info32, size_lo_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_entry_info32, size_hi_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_entry_info32, name_str_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_entry_info32, zero_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_entry_info32, flag_1c, 0x1c);

/* 28-byte lazy `0x11897760` pack-wrap singleton initialized in `0x112d2980` (`0x120328c8`) and `0x112d2a70` (`0x120328a0`). */
typedef struct rome2_vfs_pack_wrap_singleton28_32 {
    uint32_t vtable_00;                          /* 00 (0x11897760, reset to 0x11849278 on atexit) */
    uint32_t name_str_04;                        /* 04 (`<empty file>`) */
    uint32_t zero_08;                            /* 08 */
    uint32_t zero_0c;                            /* 0c */
    uint32_t zero_10;                            /* 10 */
    uint32_t zero_14;                            /* 14 */
    uint32_t zero_18;                            /* 18 */
} rome2_vfs_pack_wrap_singleton28_32;
_Static_assert(sizeof(rome2_vfs_pack_wrap_singleton28_32) == 0x1c, "pack wrap singleton28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_wrap_singleton28_32, vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_wrap_singleton28_32, name_str_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_wrap_singleton28_32, zero_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_wrap_singleton28_32, zero_18, 0x18);

/* 32-byte active FileSystem secondary-interface header (`this = primary_fs + 4`) observed across `0x118978e8`. */
typedef struct rome2_vfs_fs_secondary_hdr32 {
    uint32_t secondary_vtable_00;                /* 00 (0x118978e8) */
    uint32_t active_ops_04;                      /* 04 (in-flight lock counter) */
    uint8_t lock_cs_08[24];                      /* 08 (Win32 CRITICAL_SECTION @ primary+0x0c) */
} rome2_vfs_fs_secondary_hdr32;
_Static_assert(sizeof(rome2_vfs_fs_secondary_hdr32) == 0x20, "fs secondary hdr 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_fs_secondary_hdr32, secondary_vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_fs_secondary_hdr32, active_ops_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_fs_secondary_hdr32, lock_cs_08, 0x08);

/* Layer 29: Active FileSystem primary object (0x11897870), mount vectors, and archive hash headers. */

/* 40-byte (0x28B) active FileSystem object allocated by `0x112c00b0` (`0x112a8ff0` ctor / `0x112ad070` dtor). */
typedef struct rome2_vfs_active_fs_obj32 {
    uint32_t primary_vtable_00;                  /* 00 (0x11897870) */
    uint32_t secondary_vtable_04;                /* 04 (0x118978e8) */
    uint32_t active_ops_08;                      /* 08 (re-entrancy / lock hold counter) */
    uint8_t lock_cs_0c[24];                      /* 0c (Win32 CRITICAL_SECTION initialized at 0x112a9012) */
    uint8_t mode_flag_24;                        /* 24 (returned by 0x100ead40; set in 0x112c0118) */
    uint8_t pad_25[3];                           /* 25..27 */
} rome2_vfs_active_fs_obj32;
_Static_assert(sizeof(rome2_vfs_active_fs_obj32) == 0x28, "active fs obj 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_active_fs_obj32, primary_vtable_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_active_fs_obj32, secondary_vtable_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_active_fs_obj32, active_ops_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_active_fs_obj32, lock_cs_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_active_fs_obj32, mode_flag_24, 0x24);

/* 12-byte mount-entry vector header (`0x119e11b8` active, `0x119e11c4` pending) manipulated by `0x100eb330`. */
typedef struct rome2_vfs_mount_vec_header12_32 {
    uint32_t capacity_00;                        /* 00 (initial 0x10; doubles on push_back growth) */
    uint32_t count_04;                           /* 04 (element count) */
    uint32_t data_ptr_08;                        /* 08 (`0xc0`-byte initial allocation for 12B elements) */
} rome2_vfs_mount_vec_header12_32;
_Static_assert(sizeof(rome2_vfs_mount_vec_header12_32) == 0x0c, "mount vec header12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_vec_header12_32, capacity_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_vec_header12_32, count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_vec_header12_32, data_ptr_08, 0x08);

/* 20-byte root archive descriptor (`0x119e11e8..0x119e11fb`) queried by `0x112d4c50` and `0x112e36f0`. */
typedef struct rome2_vfs_root_archive_header20_32 {
    uint32_t table_ptr_00;                       /* 00 (0x119e11e8 -> 0x180B table via 0x10102f50(0x180,4,0)) */
    uint32_t count_04;                           /* 04 (0x119e11ec, reset to 0) */
    uint32_t capacity_08;                        /* 08 (0x119e11f0, reset to 0x20) */
    uint32_t aux_0c;                             /* 0c (0x119e11f4, reset to 0) */
    uint32_t extra_10;                           /* 10 (0x119e11f8, reset to 0) */
} rome2_vfs_root_archive_header20_32;
_Static_assert(sizeof(rome2_vfs_root_archive_header20_32) == 0x14, "root archive header20 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_root_archive_header20_32, table_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_root_archive_header20_32, count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_root_archive_header20_32, capacity_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_root_archive_header20_32, aux_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_root_archive_header20_32, extra_10, 0x10);

/* 12-byte loose/mod hash header (`0x119e11d0`) initialized by `0x112bbca0` (`0x3cb` * 4B = `0xf2c` bytes). */
typedef struct rome2_vfs_loose_table12_32 {
    uint32_t bucket_count_00;                    /* 00 (initial 0x3cb) */
    uint32_t count_04;                           /* 04 (initial 0) */
    uint32_t table_ptr_08;                       /* 08 (0xf2c-byte allocation at 0x119e11d8) */
} rome2_vfs_loose_table12_32;
_Static_assert(sizeof(rome2_vfs_loose_table12_32) == 0x0c, "loose table12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_table12_32, bucket_count_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_table12_32, count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_loose_table12_32, table_ptr_08, 0x08);

/* 16-byte hash-map header (`0x12032920..0x1203292f`) initialized by `0x112e3c60` (`0x23b1b` * 8B slots). */
typedef struct rome2_vfs_large_hash16_32 {
    uint32_t table_ptr_00;                       /* 00 (0x12032920 -> 0x23b1b * 8B allocation) */
    uint32_t bucket_count_04;                    /* 04 (0x12032924 = 0x23b1b) */
    uint32_t default_pair_08[2];                 /* 08..0f (0x12032928 default 8B entry copied per bucket) */
} rome2_vfs_large_hash16_32;
_Static_assert(sizeof(rome2_vfs_large_hash16_32) == 0x10, "large hash16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_large_hash16_32, table_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_large_hash16_32, bucket_count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_large_hash16_32, default_pair_08, 0x08);

/* Layer 30: Open-addressing hash containers, iterators, RB-tree copy, unordered_map, and 48B mount entry layouts. */

/* 8-byte open-addressing hash slot {CAString key, uint32_t value} in 0x112de360 / 0x112dc030 / 0x112ddd70. */
typedef struct rome2_vfs_hash_entry8_32 {
    uint32_t key_str_00;                         /* 00 (interned CAString handle or sentinel) */
    uint32_t value_04;                           /* 04 (mapped dword id / index / payload) */
} rome2_vfs_hash_entry8_32;
_Static_assert(sizeof(rome2_vfs_hash_entry8_32) == 0x08, "hash entry8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_hash_entry8_32, key_str_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_hash_entry8_32, value_04, 0x04);

/* 16-byte open-addressing hash table header (0x120329fc with 0x199 buckets via 0x112d2e80; also 0x112de360 / 0x112dc030). */
typedef struct rome2_vfs_open_hash16_32 {
    uint32_t table_ptr_00;                       /* 00 (array of bucket_count_04 * 8B slots) */
    uint32_t bucket_count_04;                    /* 04 (0x199 in 0x12032a00, rehashes to 2*n + 1) */
    uint32_t sentinel_a_08;                      /* 08 (primary empty-key sentinel CAString) */
    uint32_t sentinel_b_0c;                      /* 0c (secondary tombstone/alt sentinel CAString) */
} rome2_vfs_open_hash16_32;
_Static_assert(sizeof(rome2_vfs_open_hash16_32) == 0x10, "open hash16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_open_hash16_32, table_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_hash16_32, bucket_count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_hash16_32, sentinel_a_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_open_hash16_32, sentinel_b_0c, 0x0c);

/* 20-byte forward hash iterator constructed by 0x112c0940 and stepped by 0x112ac3b0. */
typedef struct rome2_vfs_hash_iter20_32 {
    uint32_t cur_ptr_00;                         /* 00 (initialized to begin - 8, stepped by +8) */
    uint32_t prev_ptr_04;                        /* 04 */
    uint32_t end_ptr_08;                         /* 08 (begin + bucket_count * 8) */
    uint32_t sentinel_a_0c;                      /* 0c */
    uint32_t sentinel_b_10;                      /* 10 */
} rome2_vfs_hash_iter20_32;
_Static_assert(sizeof(rome2_vfs_hash_iter20_32) == 0x14, "hash iter20 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_hash_iter20_32, cur_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_hash_iter20_32, end_ptr_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_hash_iter20_32, sentinel_a_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_hash_iter20_32, sentinel_b_10, 0x10);

/* 32-byte MSVC std::unordered_map container layout (0x12032834..0x12032853; used by 0x112a2ba0 / 0x112c14b0 / 0x112e1a00). */
typedef struct rome2_vfs_unordered_map32_32 {
    uint32_t max_load_factor_f32_00;             /* 00 (float32 max load factor, e.g. 0x3f800000 = 1.0f) */
    uint32_t list_head_04;                       /* 04 (0x12032838 doubly-linked sentinel list node) */
    uint32_t list_size_08;                       /* 08 (0x1203283c active node count, max 0x5555555) */
    uint32_t vec_begin_0c;                       /* 0c (0x12032840 bucket-pair vector begin) */
    uint32_t vec_end_10;                         /* 10 (0x12032844 bucket-pair vector end) */
    uint32_t vec_cap_14;                         /* 14 (0x12032848 bucket-pair vector end capacity) */
    uint32_t mask_18;                            /* 18 (0x1203284c bitmask bucket_count - 1) */
    uint32_t maxidx_1c;                          /* 1c (power-of-two bucket count) */
} rome2_vfs_unordered_map32_32;
_Static_assert(sizeof(rome2_vfs_unordered_map32_32) == 0x20, "unordered map32 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_unordered_map32_32, max_load_factor_f32_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_unordered_map32_32, list_head_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_unordered_map32_32, list_size_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_unordered_map32_32, vec_begin_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_unordered_map32_32, mask_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_unordered_map32_32, maxidx_1c, 0x1c);

/* 12-byte MSVC std::_Tree header (copied by 0x112a75b0, lower/upper-bound queried by 0x112be150). */
typedef struct rome2_vfs_rbtree_header12_32 {
    uint32_t allocator_word_00;                  /* 00 */
    uint32_t myhead_04;                          /* 04 (root = head->parent_04, min = head->left_00, max = head->right_08) */
    uint32_t mysize_08;                          /* 08 */
} rome2_vfs_rbtree_header12_32;
_Static_assert(sizeof(rome2_vfs_rbtree_header12_32) == 0x0c, "rbtree header12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_rbtree_header12_32, allocator_word_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_rbtree_header12_32, myhead_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_rbtree_header12_32, mysize_08, 0x08);

/* 48-byte (0x30B) mount-descriptor element stored in vec<0x30B> (0x112d7f50 / 0x112a7440 / 0x112b5670 / 0x112a8540). */
typedef struct rome2_vfs_mount_entry48_32 {
    uint32_t name_str_00;                        /* 00 */
    uint32_t reserved_04;                        /* 04 */
    uint32_t flags_or_root_08;                   /* 08 */
    uint32_t aux_words_0c[6];                    /* 0c..23 */
    rome2_vfs_mount_vec_header12_32 child_vec_24;/* 24..2f (`0x112a74d0` copies 4B string vec at +0x24) */
} rome2_vfs_mount_entry48_32;
_Static_assert(sizeof(rome2_vfs_mount_entry48_32) == 0x30, "mount entry48 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_entry48_32, name_str_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_entry48_32, child_vec_24, 0x24);

/* Pack-entry singleton 28-byte record at 0x10122cb0 / 0x10122640 (`0x11afa694`, `0x11afa690`). */
typedef struct rome2_vfs_pack_index_singleton28_32 {
    uint32_t reserved_00;
    uint32_t tag_words_04[3];
    uint32_t entries_ptr_10;
    uint32_t count_14;
    uint32_t capacity_18;
} rome2_vfs_pack_index_singleton28_32;
_Static_assert(sizeof(rome2_vfs_pack_index_singleton28_32) == 0x1c, "pack index singleton28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_index_singleton28_32, tag_words_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_index_singleton28_32, entries_ptr_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_index_singleton28_32, count_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_pack_index_singleton28_32, capacity_18, 0x18);

/* Decoded Win32 find entry metadata block ([ebp+0x34..0x43]) passed to 0x100fec00 callback. */
typedef struct rome2_vfs_win32_find_info_32 {
    uint32_t file_size_00;
    uint32_t reserved_04;
    uint32_t mtime_unix_08;
    uint8_t valid_0c;
    uint8_t writable_0d;
    uint8_t is_dir_0e;
    uint8_t hidden_0f;
} rome2_vfs_win32_find_info_32;
_Static_assert(sizeof(rome2_vfs_win32_find_info_32) == 0x10, "win32 find info 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_find_info_32, file_size_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_find_info_32, mtime_unix_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_find_info_32, writable_0d, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_find_info_32, is_dir_0e, 0x0e);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_find_info_32, hidden_0f, 0x0f);

/* Inner 12-byte bucket pointer vector at offset +0x0c in 0x112b03b0 (`unordered_map::_Rehash`). */
typedef struct rome2_vfs_bucket_pair8_vec12_32 {
    uint32_t begin_00;
    uint32_t end_04;
    uint32_t cap_end_08;
} rome2_vfs_bucket_pair8_vec12_32;
_Static_assert(sizeof(rome2_vfs_bucket_pair8_vec12_32) == 0x0c, "bucket pair8 vec12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_pair8_vec12_32, end_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_pair8_vec12_32, cap_end_08, 0x08);

/* Ref-counted RB-tree node header torn down by 0x112a26f0 and 0x11724b00 (`0x12032a34`). */
typedef struct rome2_vfs_rb_ref_node28_32 {
    uint32_t left_00;
    uint32_t parent_04;
    uint32_t right_08;
    uint8_t color_0c;
    uint8_t is_nil_0d;
    uint8_t pad_0e[2];
    uint32_t payload_10[2];
    uint32_t shared_ctrl_18;
} rome2_vfs_rb_ref_node28_32;
_Static_assert(sizeof(rome2_vfs_rb_ref_node28_32) == 0x1c, "rb ref node28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_ref_node28_32, right_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_ref_node28_32, is_nil_0d, 0x0d);
ROME2_LAYOUT_ASSERT(rome2_vfs_rb_ref_node28_32, shared_ctrl_18, 0x18);

/* Chunked 12-byte string array node cleared by 0x112b5420. */
typedef struct rome2_vfs_chunked_str_node16_32 {
    uint32_t items_ptr_00;
    uint32_t count_04;
    uint32_t reserved_08;
    uint32_t next_0c;
} rome2_vfs_chunked_str_node16_32;
_Static_assert(sizeof(rome2_vfs_chunked_str_node16_32) == 0x10, "chunked str node16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_chunked_str_node16_32, count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_chunked_str_node16_32, next_0c, 0x0c);

/* String-interning hash table 32B singleton at 0x11afa698 initialized by 0x10121930. */
typedef struct rome2_vfs_intern_table32_32 {
    uint32_t max_load_factor_f32_00;             /* 00 (0x3f800000 = 1.0f) */
    uint32_t list_head_04;                       /* 04 */
    uint32_t list_size_08;                       /* 08 */
    uint32_t bucket_begin_0c;                    /* 0c (0x40B array = 8 pair<head,tail>) */
    uint32_t bucket_end_10;                      /* 10 */
    uint32_t bucket_cap_14;                      /* 14 */
    uint32_t mask_18;                            /* 18 (7) */
    uint32_t buckets_1c;                         /* 1c (8) */
} rome2_vfs_intern_table32_32;
_Static_assert(sizeof(rome2_vfs_intern_table32_32) == 0x20, "intern table32 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_intern_table32_32, list_head_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_intern_table32_32, bucket_begin_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_intern_table32_32, mask_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_intern_table32_32, buckets_1c, 0x1c);

/* 28B Win32 CRITICAL_SECTION lock wrapper at 0x11afa6a8 initialized by 0x10122dc0. */
typedef struct rome2_vfs_lock_wrapper28_32 {
    uint32_t depth_00;                           /* 00 */
    uint32_t crit_sec_04[6];                     /* 04..1b (24B CRITICAL_SECTION, spin 0x2710) */
} rome2_vfs_lock_wrapper28_32;
_Static_assert(sizeof(rome2_vfs_lock_wrapper28_32) == 0x1c, "lock wrapper28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_lock_wrapper28_32, depth_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_lock_wrapper28_32, crit_sec_04, 0x04);

/* Small 12B observer record constructed by 0x112a85e0 (`vtable 0x11897be0`). */
typedef struct rome2_vfs_observer_small12_32 {
    uint32_t vptr_00;                            /* 00 (0x11897be0) */
    uint32_t path_str_04;                        /* 04 */
    uint32_t flags_08;                           /* 08 */
} rome2_vfs_observer_small12_32;
_Static_assert(sizeof(rome2_vfs_observer_small12_32) == 0x0c, "observer small12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_observer_small12_32, path_str_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_observer_small12_32, flags_08, 0x08);

/* Full 40B observer/stream wrapper constructed by 0x112aa670 (`vtable 0x11897c24`). */
typedef struct rome2_vfs_observer_full40_32 {
    uint32_t vptr_00;                            /* 00 (0x11897c24) */
    uint32_t fields_04[4];                       /* 04..13 */
    uint32_t callback_obj_14;                    /* 14 */
    uint32_t key_words_18[2];                    /* 18..1f */
    uint8_t key_flag_20;                         /* 20 */
    uint8_t pad_21[3];
    uint16_t ready_flags_24;                     /* 24 */
    uint16_t pad_26;
} rome2_vfs_observer_full40_32;
_Static_assert(sizeof(rome2_vfs_observer_full40_32) == 0x28, "observer full40 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_observer_full40_32, callback_obj_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_observer_full40_32, key_words_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_observer_full40_32, key_flag_20, 0x20);
ROME2_LAYOUT_ASSERT(rome2_vfs_observer_full40_32, ready_flags_24, 0x24);

/* 28B mount/provider singleton initialized by 0x112d3640 at 0x12032ad0 (`vtable 0x11897760`). */
typedef struct rome2_vfs_mount_singleton28_32 {
    uint32_t vptr_00;                            /* 00 (0x11897760) */
    uint32_t name_str_04;                        /* 04 */
    uint32_t qword_pair_08[2];                   /* 08..0f */
    uint32_t tail_words_10[3];                   /* 10..1b */
} rome2_vfs_mount_singleton28_32;
_Static_assert(sizeof(rome2_vfs_mount_singleton28_32) == 0x1c, "mount singleton28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_singleton28_32, name_str_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_singleton28_32, qword_pair_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_mount_singleton28_32, tail_words_10, 0x10);

/* 48B 4-part split path carrier initialized by 0x100f0a80 (`[0x11afa69c]`). */
typedef struct rome2_vfs_path_parts48_32 {
    uint32_t drive_str_00[3];                    /* 00..0b */
    uint32_t dir_str_0c[3];                      /* 0c..17 */
    uint32_t file_str_18[3];                     /* 18..23 */
    uint32_t ext_str_24[3];                      /* 24..2f */
} rome2_vfs_path_parts48_32;
_Static_assert(sizeof(rome2_vfs_path_parts48_32) == 0x30, "path parts48 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_path_parts48_32, dir_str_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_path_parts48_32, file_str_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_path_parts48_32, ext_str_24, 0x24);

/* 24B (key, value) string pair element torn down by 0x10126f60 and grown by 0x10127900. */
typedef struct rome2_vfs_pair_entry24_32 {
    uint32_t key_str_00[3];                      /* 00..0b */
    uint32_t val_str_0c[3];                      /* 0c..17 */
} rome2_vfs_pair_entry24_32;
_Static_assert(sizeof(rome2_vfs_pair_entry24_32) == 0x18, "pair entry24 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pair_entry24_32, key_str_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pair_entry24_32, val_str_0c, 0x0c);

/* 60B recursive folder-index entry torn down by 0x10126fa0 and copied by 0x10126e50. */
typedef struct rome2_vfs_folder_entry60_32 {
    uint32_t name_str_00[3];                     /* 00..0b */
    uint32_t pairs_vec_0c[3];                    /* 0c..17 (vec<rome2_vfs_pair_entry24_32>) */
    uint32_t root_str_18[3];                     /* 18..23 */
    uint32_t children_vec_24[3];                 /* 24..2f (vec<rome2_vfs_folder_entry60_32>) */
    uint32_t tag_str_30[3];                      /* 30..3b */
} rome2_vfs_folder_entry60_32;
_Static_assert(sizeof(rome2_vfs_folder_entry60_32) == 0x3c, "folder entry60 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_folder_entry60_32, pairs_vec_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_folder_entry60_32, root_str_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_folder_entry60_32, children_vec_24, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_folder_entry60_32, tag_str_30, 0x30);

/* 20B linked pool slab slot initialized by 0x1011fd40. */
typedef struct rome2_vfs_pool_slab20_32 {
    uint32_t next_slot_00;                       /* 00 */
    uint32_t payload_04[4];                      /* 04..13 */
} rome2_vfs_pool_slab20_32;
_Static_assert(sizeof(rome2_vfs_pool_slab20_32) == 0x14, "pool slab20 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_pool_slab20_32, next_slot_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_pool_slab20_32, payload_04, 0x04);

/* 36B Win32 stream/file handle state initialized by 0x100f11b0 and closed by 0x100f21c0. */
typedef struct rome2_vfs_stream_handle36_32 {
    uint32_t state_tag_00;                       /* 00 (3 on init/destroy) */
    uint32_t owned_flags_04;                     /* 04 (bit 0 primary, bit 1 secondary) */
    uint32_t primary_handle_08;                  /* 08 (INVALID_HANDLE_VALUE -1) */
    uint32_t secondary_handle_0c;                /* 0c (INVALID_HANDLE_VALUE -1) */
    uint32_t state_words_10[3];                  /* 10..1b */
    uint8_t byte_flag_1c;                        /* 1c */
    uint8_t pad_1d[3];                           /* 1d..1f */
    uint32_t mapped_view_ptr_20;                 /* 20 -> 8B UnmapViewOfFile holder */
} rome2_vfs_stream_handle36_32;
_Static_assert(sizeof(rome2_vfs_stream_handle36_32) == 0x24, "stream handle36 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle36_32, owned_flags_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle36_32, primary_handle_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle36_32, secondary_handle_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle36_32, byte_flag_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_stream_handle36_32, mapped_view_ptr_20, 0x20);

/* 8B Win32 GetFileSize probe state updated by 0x101153c0. */
typedef struct rome2_vfs_file_size_state8_32 {
    uint32_t file_handle_00;                     /* 00 */
    uint32_t last_error_04;                      /* 04 */
} rome2_vfs_file_size_state8_32;
_Static_assert(sizeof(rome2_vfs_file_size_state8_32) == 0x08, "file size state8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_file_size_state8_32, last_error_04, 0x04);

/* 448B dlmalloc mstate block at 0x11afa700 managed by 0x10124e50 and 0x101254a0. */
typedef struct rome2_vfs_dlmalloc_mstate448_32 {
    uint32_t smallmap_00;                        /* 00 (32 smallbin bits) */
    uint32_t treemap_04;                         /* 04 (32 treebin bits) */
    uint32_t dvsize_08;                          /* 08 */
    uint32_t topsize_0c;                         /* 0c */
    uint32_t least_addr_10;                      /* 10 */
    uint32_t dv_ptr_14;                          /* 14 */
    uint32_t top_ptr_18;                         /* 18 */
    uint32_t trim_check_1c;                      /* 1c */
    uint32_t release_checks_20;                  /* 20 */
    uint32_t reserved_24;                        /* 24 */
    uint32_t smallbins_28[66];                   /* 28..12f */
    uint32_t treebins_130[32];                   /* 130..1af */
    uint32_t footprint_1b0;                      /* 1b0 */
    uint32_t max_footprint_1b4;                  /* 1b4 */
    uint32_t footprint_limit_1b8;                /* 1b8 */
    uint32_t mflags_1bc;                         /* 1bc */
} rome2_vfs_dlmalloc_mstate448_32;
_Static_assert(sizeof(rome2_vfs_dlmalloc_mstate448_32) == 0x1c0, "dlmalloc mstate448 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, treemap_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, dvsize_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, topsize_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, smallbins_28, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, treebins_130, 0x130);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, footprint_1b0, 0x1b0);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mstate448_32, mflags_1bc, 0x1bc);

/* 64B Win32 MEMORYSTATUSEX record at 0x11af4098 populated by 0x10103220. */
typedef struct rome2_vfs_mem_status_ex64_32 {
    uint32_t dw_length_00;                       /* 00 (0x40) */
    uint32_t dw_memory_load_04;                  /* 04 */
    uint64_t ull_total_phys_08;                  /* 08..0f */
    uint64_t ull_avail_phys_10;                  /* 10..17 */
    uint64_t ull_total_pagefile_18;              /* 18..1f */
    uint64_t ull_avail_pagefile_20;              /* 20..27 */
    uint64_t ull_total_virtual_28;               /* 28..2f */
    uint64_t ull_avail_virtual_30;               /* 30..37 */
    uint64_t ull_avail_ext_virtual_38;           /* 38..3f */
} rome2_vfs_mem_status_ex64_32;
_Static_assert(sizeof(rome2_vfs_mem_status_ex64_32) == 0x40, "mem status ex64 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_mem_status_ex64_32, ull_total_phys_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_mem_status_ex64_32, ull_total_virtual_28, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_mem_status_ex64_32, ull_avail_ext_virtual_38, 0x38);

/* 36B 3-string entry element appended and grown by 0x112d8ae0. */
typedef struct rome2_vfs_tuple36_entry32 {
    uint32_t first_str_00[3];                    /* 00..0b */
    uint32_t second_str_0c[3];                   /* 0c..17 */
    uint32_t third_str_18[3];                    /* 18..23 */
} rome2_vfs_tuple36_entry32;
_Static_assert(sizeof(rome2_vfs_tuple36_entry32) == 0x24, "tuple36 entry 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_tuple36_entry32, second_str_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_tuple36_entry32, third_str_18, 0x18);

/* 44B descriptor record whose trailing string vector is torn down by 0x1017ff40. */
typedef struct rome2_vfs_str_array44_32 {
    uint32_t head_words_00[9];                   /* 00..23 */
    uint32_t str_count_24;                       /* 24 */
    uint32_t str_data_ptr_28;                    /* 28 */
} rome2_vfs_str_array44_32;
_Static_assert(sizeof(rome2_vfs_str_array44_32) == 0x2c, "str array44 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_str_array44_32, str_count_24, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_str_array44_32, str_data_ptr_28, 0x28);

/* 28B dlmalloc global mparams block at 0x11afa6e0..0x11afa6fc initialized by 0x10123640. */
typedef struct rome2_vfs_dlmalloc_mparams28_32 {
    uint32_t spinlock_00;                        /* 00 (0x11afa6e0) */
    uint32_t magic_04;                           /* 04 (0x11afa6e4) */
    uint32_t page_size_08;                       /* 08 (0x11afa6e8) */
    uint32_t granularity_0c;                     /* 0c (0x11afa6ec) */
    uint32_t mmap_threshold_10;                  /* 10 (0x11afa6f0 = 0x40000) */
    uint32_t trim_threshold_14;                  /* 14 (0x11afa6f4 = 0x200000) */
    uint32_t default_mflags_18;                  /* 18 (0x11afa6f8 = 7) */
} rome2_vfs_dlmalloc_mparams28_32;
_Static_assert(sizeof(rome2_vfs_dlmalloc_mparams28_32) == 0x1c, "dlmalloc mparams28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mparams28_32, magic_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mparams28_32, page_size_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_dlmalloc_mparams28_32, default_mflags_18, 0x18);

/* 12B unordered-bucket list-pair header managed by 0x100e3950, 0x100eb8a0, and 0x112d87a0. */
typedef struct rome2_vfs_bucket_slot12_32 {
    uint32_t begin_00;                           /* 00 */
    uint32_t end_or_self_04;                     /* 04 */
    uint32_t tail_ptr_08;                        /* 08 */
} rome2_vfs_bucket_slot12_32;
_Static_assert(sizeof(rome2_vfs_bucket_slot12_32) == 0x0c, "bucket slot12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_slot12_32, end_or_self_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_bucket_slot12_32, tail_ptr_08, 0x08);

/* 8B MSVC std::istreambuf_iterator<wchar_t> cursor used by 0x11347190/0x11348d50/0x11349790. */
typedef struct rome2_vfs_wstreambuf_iter8_32 {
    uint32_t streambuf_ptr_00;                   /* 00 */
    uint8_t got_flag_04;                         /* 04 */
    uint8_t pad_05;                              /* 05 */
    uint16_t val_06;                             /* 06 */
} rome2_vfs_wstreambuf_iter8_32;
_Static_assert(sizeof(rome2_vfs_wstreambuf_iter8_32) == 0x08, "wstreambuf iter8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_wstreambuf_iter8_32, got_flag_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstreambuf_iter8_32, val_06, 0x06);

/* 12B MSVC std::_Ref_count_base decremented via lock xadd by 0x1039db80. */
typedef struct rome2_vfs_refcount_ctrl12_32 {
    uint32_t vptr_00;                            /* 00 */
    int32_t uses_04;                             /* 04 */
    int32_t weaks_08;                            /* 08 */
} rome2_vfs_refcount_ctrl12_32;
_Static_assert(sizeof(rome2_vfs_refcount_ctrl12_32) == 0x0c, "refcount ctrl12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_refcount_ctrl12_32, uses_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_refcount_ctrl12_32, weaks_08, 0x08);

/* 12B channel bit-stream cursor consumed and normalized by 0x10fd77f0 and 0x10fd7b10. */
typedef struct rome2_vfs_bit_cursor12_32 {
    uint32_t words_ptr_00;                       /* 00 */
    uint32_t byte_cap_04;                        /* 04 */
    uint32_t bits_used_08;                       /* 08 */
} rome2_vfs_bit_cursor12_32;
_Static_assert(sizeof(rome2_vfs_bit_cursor12_32) == 0x0c, "bit cursor12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_bit_cursor12_32, byte_cap_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_bit_cursor12_32, bits_used_08, 0x08);

/* 24B channel slot endpoint header copied/reset by 0x10fd74d0, 0x10fd7a70, and 0x10fd9660. */
typedef struct rome2_vfs_channel_slot_hdr24_32 {
    uint32_t addr_dword_00;                      /* 00 */
    uint16_t port_or_tag_04;                     /* 04 */
    uint16_t pad_06;                             /* 06 */
    uint32_t id_lo_08;                           /* 08 */
    uint32_t id_hi_0c;                           /* 0c */
    uint32_t sock_fd_10;                         /* 10 (INVALID_SOCKET -1) */
    uint8_t active_flag_14;                      /* 14 */
    uint8_t pad_15[3];                           /* 15..17 */
} rome2_vfs_channel_slot_hdr24_32;
_Static_assert(sizeof(rome2_vfs_channel_slot_hdr24_32) == 0x18, "channel slot hdr24 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_hdr24_32, port_or_tag_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_hdr24_32, sock_fd_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_hdr24_32, active_flag_14, 0x14);

typedef struct rome2_vfs_wstringbuf60_32 {
    uint32_t vftable_00;                         /* 00 (0x1173dadc base) */
    uint32_t g_first_val_04;                     /* 04 */
    uint32_t p_first_val_08;                     /* 08 */
    uint32_t g_first_ptr_0c;                     /* 0c (&g_first_val_04) */
    uint32_t p_first_ptr_10;                     /* 10 (&p_first_val_08) */
    uint32_t g_next_val_14;                      /* 14 */
    uint32_t p_next_val_18;                      /* 18 */
    uint32_t g_next_ptr_1c;                      /* 1c (&g_next_val_14) */
    uint32_t p_next_ptr_20;                      /* 20 (&p_next_val_18) */
    uint32_t g_count_val_24;                     /* 24 */
    uint32_t p_count_val_28;                     /* 28 */
    uint32_t g_count_ptr_2c;                     /* 2c (&g_count_val_24) */
    uint32_t p_count_ptr_30;                     /* 30 (&p_count_val_28) */
    uint32_t seek_high_34;                       /* 34 */
    uint32_t mystate_38;                         /* 38 (_Allocated=1, _Nocreate=2, _Noread=4, _Append=8, _Atend=0x10) */
} rome2_vfs_wstringbuf60_32;
_Static_assert(sizeof(rome2_vfs_wstringbuf60_32) == 0x3c, "wstringbuf60 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, g_first_ptr_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, p_first_ptr_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, g_next_ptr_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, p_next_ptr_20, 0x20);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, g_count_ptr_2c, 0x2c);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, p_count_ptr_30, 0x30);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, seek_high_34, 0x34);
ROME2_LAYOUT_ASSERT(rome2_vfs_wstringbuf60_32, mystate_38, 0x38);

typedef struct rome2_vfs_channel_queue24_32 {
    uint32_t list_ptr_or_self_00;                /* 00 (&head_04) */
    uint32_t head_04;                            /* 04 */
    uint32_t tail_08;                            /* 08 */
    uint32_t owner_or_arg_0c;                    /* 0c */
    uint32_t count_or_size_10;                   /* 10 */
    uint32_t payload_or_flags_14;                /* 14 */
} rome2_vfs_channel_queue24_32;
_Static_assert(sizeof(rome2_vfs_channel_queue24_32) == 0x18, "channel queue24 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_queue24_32, head_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_queue24_32, owner_or_arg_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_queue24_32, count_or_size_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_queue24_32, payload_or_flags_14, 0x14);

typedef struct rome2_vfs_sock_endpoint12_32 {
    uint32_t flags_or_tag_00;                    /* 00 */
    uint16_t sin_family_04;                      /* 04 (AF_INET = 2) */
    uint16_t sin_port_be_06;                     /* 06 (htons(port)) */
    uint32_t sin_addr_08;                        /* 08 */
} rome2_vfs_sock_endpoint12_32;
_Static_assert(sizeof(rome2_vfs_sock_endpoint12_32) == 0x0c, "sock endpoint12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_sock_endpoint12_32, sin_family_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_sock_endpoint12_32, sin_port_be_06, 0x06);
ROME2_LAYOUT_ASSERT(rome2_vfs_sock_endpoint12_32, sin_addr_08, 0x08);

typedef struct rome2_vfs_threadname_info16_32 {
    uint32_t dw_type_00;                         /* 00 (0x1000) */
    uint32_t sz_name_04;                         /* 04 */
    uint32_t dw_thread_id_08;                    /* 08 */
    uint32_t dw_flags_0c;                        /* 0c (0) */
} rome2_vfs_threadname_info16_32;
_Static_assert(sizeof(rome2_vfs_threadname_info16_32) == 0x10, "threadname info16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_threadname_info16_32, sz_name_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_threadname_info16_32, dw_thread_id_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_threadname_info16_32, dw_flags_0c, 0x0c);

typedef struct rome2_vfs_seq_ack_ring36_32 {
    uint32_t head_00;                            /* 00 */
    uint32_t sentinel_04;                        /* 04 */
    uint32_t reserved_08;                        /* 08 */
    uint32_t base_seq_0c;                        /* 0c */
    uint32_t ack_out_arr_10;                     /* 10 */
    uint32_t bitmap_14;                          /* 14 */
    uint32_t stride_18;                          /* 18 */
    uint32_t cap_1c;                             /* 1c */
    uint32_t ack_count_20;                       /* 20 */
} rome2_vfs_seq_ack_ring36_32;
_Static_assert(sizeof(rome2_vfs_seq_ack_ring36_32) == 0x24, "seq ack ring36 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_seq_ack_ring36_32, base_seq_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_seq_ack_ring36_32, bitmap_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_seq_ack_ring36_32, stride_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_seq_ack_ring36_32, cap_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_seq_ack_ring36_32, ack_count_20, 0x20);

typedef struct rome2_vfs_channel_slot_meta36_32 {
    uint32_t ep_addr_00;                         /* +0x4030 */
    uint16_t ep_port_04;                         /* +0x4034 */
    uint16_t pad_06;                             /* +0x4036 */
    uint32_t id_lo_08;                           /* +0x4038 */
    uint32_t id_hi_0c;                           /* +0x403c */
    uint32_t aux_sock_10;                        /* +0x4040 */
    uint32_t reserved_14;                        /* +0x4044 */
    uint32_t state_flag_word_18;                 /* +0x4048 */
    uint8_t byte_flag_1c;                        /* +0x404c */
    uint8_t pad_1d[3];                           /* +0x404d..4f */
    uint32_t tail_word_20;                       /* +0x4050 */
} rome2_vfs_channel_slot_meta36_32;
_Static_assert(sizeof(rome2_vfs_channel_slot_meta36_32) == 0x24, "channel slot meta36 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_meta36_32, ep_port_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_meta36_32, id_lo_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_meta36_32, aux_sock_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_meta36_32, byte_flag_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_slot_meta36_32, tail_word_20, 0x20);

/* 56B (0x38) MSVC CRT _FILEX slot in 0x119ebe18 (_iob[0..2]) indexed by 0x11699f33 and tested by 0x11687aa6. */
typedef struct rome2_vfs_crt_filex56_32 {
    uint32_t ptr_00;                             /* 00 */
    uint32_t cnt_04;                             /* 04 */
    uint32_t base_08;                            /* 08 */
    uint32_t flag_0c;                            /* 0c (0x10=_IOEOF checked by 0x11687aa6) */
    int32_t file_10;                             /* 10 (fd: 0=stdin, 1=stdout, 2=stderr) */
    uint32_t charbuf_14;                         /* 14 */
    uint32_t bufsiz_18;                          /* 18 */
    uint32_t tmpfname_1c;                        /* 1c */
    uint8_t lock_cs_20[24];                      /* 20..37 */
} rome2_vfs_crt_filex56_32;
_Static_assert(sizeof(rome2_vfs_crt_filex56_32) == 0x38, "crt filex56 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_filex56_32, ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_filex56_32, flag_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_filex56_32, file_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_filex56_32, lock_cs_20, 0x20);

/* 32B MSVC _CxxThrowException stack template loaded from 0x1191fd50 by 0x116bebf1. */
typedef struct rome2_vfs_cxx_throw_template32_32 {
    uint32_t exception_code_00;                  /* 00 (0xe06d7363) */
    uint32_t exception_flags_04;                 /* 04 (1 = EXCEPTION_NONCONTINUABLE) */
    uint32_t exception_record_08;                /* 08 */
    uint32_t exception_address_0c;               /* 0c */
    uint32_t number_parameters_10;               /* 10 (3) */
    uint32_t magic_number_14;                    /* 14 (0x19930520 or 0x01994000) */
    uint32_t exception_object_18;                /* 18 */
    uint32_t throw_info_1c;                      /* 1c */
} rome2_vfs_cxx_throw_template32_32;
_Static_assert(sizeof(rome2_vfs_cxx_throw_template32_32) == 0x20, "cxx throw template32 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_cxx_throw_template32_32, exception_code_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_cxx_throw_template32_32, number_parameters_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_cxx_throw_template32_32, magic_number_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_cxx_throw_template32_32, throw_info_1c, 0x1c);

/* 564B (0x234 = 47 * 12B) channel manager singleton at 0x1201ae48..0x1201b07c initialized by 0x10fdad30. */
typedef struct rome2_vfs_channel_mgr564_32 {
    uint32_t slots_00[47][3];                    /* 00..233: 47 inline 12B list headers */
} rome2_vfs_channel_mgr564_32;
_Static_assert(sizeof(rome2_vfs_channel_mgr564_32) == 0x234, "channel mgr564 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_channel_mgr564_32, slots_00, 0x00);

/* 16B timestamped sample queue node allocated by 0x10f7c1a0 and retired by 0x10fba190. */
typedef struct rome2_vfs_ts_node16_32 {
    uint32_t next_00;                            /* 00 */
    uint32_t prev_04;                            /* 04 */
    uint32_t timestamp_ms_08;                    /* 08 */
    uint32_t byte_len_0c;                        /* 0c */
} rome2_vfs_ts_node16_32;
_Static_assert(sizeof(rome2_vfs_ts_node16_32) == 0x10, "ts node16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_node16_32, next_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_node16_32, timestamp_ms_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_node16_32, byte_len_0c, 0x0c);

/* 24B sliding-window throughput queue updated by 0x10f7c1a0 and trimmed by 0x10fba190. */
typedef struct rome2_vfs_ts_queue24_32 {
    uint32_t head_00;                            /* 00 -> rome2_vfs_ts_node16_32 */
    uint32_t sentinel_next_04;                   /* 04 */
    uint32_t sentinel_prev_08;                   /* 08 */
    uint32_t window_secs_0c;                     /* 0c (* 1000 ms in 0x10fba1aa) */
    uint32_t count_10;                           /* 10 */
    uint32_t byte_sum_14;                        /* 14 */
} rome2_vfs_ts_queue24_32;
_Static_assert(sizeof(rome2_vfs_ts_queue24_32) == 0x18, "ts queue24 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_queue24_32, head_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_queue24_32, window_secs_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_queue24_32, count_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_ts_queue24_32, byte_sum_14, 0x14);

/* 20B CRT thread startup parameter block allocated by 0x1169b5ed and released by 0x1169b55f. */
typedef struct rome2_vfs_crt_thread_param20_32 {
    uint32_t start_addr_00;                      /* 00 */
    uint32_t arg_04;                             /* 04 */
    uint32_t thread_handle_08;                   /* 08 (CloseHandle) */
    uint32_t module_handle_0c;                   /* 0c (FreeLibrary) */
    uint32_t reserved_10;                        /* 10 */
} rome2_vfs_crt_thread_param20_32;
_Static_assert(sizeof(rome2_vfs_crt_thread_param20_32) == 0x14, "crt thread param20 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_thread_param20_32, start_addr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_thread_param20_32, thread_handle_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_thread_param20_32, module_handle_0c, 0x0c);

/* 16B stack _LocaleUpdate guard constructed by 0x11688f63 in 0x116891b2 and 0x11698f1e. */
typedef struct rome2_vfs_crt_locale_update16_32 {
    uint32_t ptd_00;                             /* 00 (_ptiddata) */
    uint32_t locinfo_04;                         /* 04 (pthreadlocinfo) */
    uint32_t mbcinfo_08;                         /* 08 (pthreadmbcinfo) */
    uint8_t updated_0c;                          /* 0c (1 if ownlocale bit 1 set by ctor) */
    uint8_t pad_0d[3];                           /* 0d..0f */
} rome2_vfs_crt_locale_update16_32;
_Static_assert(sizeof(rome2_vfs_crt_locale_update16_32) == 0x10, "crt locale update16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_update16_32, ptd_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_update16_32, locinfo_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_update16_32, mbcinfo_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_update16_32, updated_0c, 0x0c);

/* 8B Win32->errno table entry at 0x119108c8 (45 entries) searched by 0x11698a9d. */
typedef struct rome2_vfs_crt_errentry8_32 {
    uint32_t oserr_00;                           /* 00 */
    int32_t errnocode_04;                        /* 04 */
} rome2_vfs_crt_errentry8_32;
_Static_assert(sizeof(rome2_vfs_crt_errentry8_32) == 0x08, "crt errentry8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_errentry8_32, oserr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_errentry8_32, errnocode_04, 0x04);

/* 56B (0x38) CRT _stat32i64 buffer zeroed by 0x11699b02 and populated by 0x1169941c/0x116994a6. */
typedef struct rome2_vfs_crt_stat56_32 {
    uint32_t st_dev_00;                          /* 00 */
    uint16_t st_ino_04;                          /* 04 */
    uint16_t st_mode_06;                         /* 06 */
    int16_t st_nlink_08;                         /* 08 */
    int16_t st_uid_0a;                           /* 0a */
    int16_t st_gid_0c;                           /* 0c */
    uint16_t pad_0e;                             /* 0e */
    uint32_t st_rdev_10;                         /* 10 */
    uint32_t pad_14;                             /* 14 */
    int64_t st_size_18;                          /* 18 */
    int64_t st_atime_20;                         /* 20 */
    int64_t st_mtime_28;                         /* 28 */
    int64_t st_ctime_30;                         /* 30 */
} rome2_vfs_crt_stat56_32;
_Static_assert(sizeof(rome2_vfs_crt_stat56_32) == 0x38, "crt stat56 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stat56_32, st_mode_06, 0x06);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stat56_32, st_nlink_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stat56_32, st_rdev_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stat56_32, st_size_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stat56_32, st_mtime_28, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stat56_32, st_ctime_30, 0x30);

/* 868B (0x364) CRT _tiddata block allocated by 0x116a4789 with observed errno/locale/handler slots. */
typedef struct rome2_vfs_crt_tiddata868_32 {
    uint8_t prefix_00[0x10];                     /* 00..0f */
    int32_t terrno_10;                           /* 10 (0x11698b16) */
    uint32_t tdoserrno_14;                       /* 14 (0x11698b03) */
    uint8_t middle_18[0x30];                     /* 18..47 */
    uint32_t ptmbcinfo_48;                       /* 48 (0x116a42c8, 0x116a4434) */
    uint32_t ptlocinfo_4c;                       /* 4c (0x116a2553, 0x116a45bb) */
    uint8_t middle_50[0x300];                    /* 50..34f */
    uint32_t ownlocale_350;                      /* 350 (0x11688f63, 0x11698f1e) */
    uint8_t mid2_354[8];                         /* 354..35b */
    uint32_t invalid_parameter_handler_35c;      /* 35c (0x11687985) */
    uint32_t tail_360;                           /* 360 */
} rome2_vfs_crt_tiddata868_32;
_Static_assert(sizeof(rome2_vfs_crt_tiddata868_32) == 0x364, "crt tiddata868 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tiddata868_32, terrno_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tiddata868_32, tdoserrno_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tiddata868_32, ptmbcinfo_48, 0x48);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tiddata868_32, ptlocinfo_4c, 0x4c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tiddata868_32, ownlocale_350, 0x350);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tiddata868_32, invalid_parameter_handler_35c, 0x35c);

/* 8B Win32 EXCEPTION_POINTERS pair pushed by 0x1168783d to UnhandledExceptionFilter. */
typedef struct rome2_vfs_win32_exception_pointers8_32 {
    uint32_t exception_record_00;                /* 00 -> rome2_vfs_win32_exception_record80_32 */
    uint32_t context_record_04;                  /* 04 -> 716B CONTEXT */
} rome2_vfs_win32_exception_pointers8_32;
_Static_assert(sizeof(rome2_vfs_win32_exception_pointers8_32) == 0x08, "win32 exception pointers8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_exception_pointers8_32, exception_record_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_exception_pointers8_32, context_record_04, 0x04);

/* 80B (0x50) Win32 EXCEPTION_RECORD zeroed and populated by 0x1168783d. */
typedef struct rome2_vfs_win32_exception_record80_32 {
    uint32_t exception_code_00;                  /* 00 */
    uint32_t exception_flags_04;                 /* 04 */
    uint32_t exception_record_08;                /* 08 */
    uint32_t exception_address_0c;               /* 0c */
    uint32_t number_parameters_10;               /* 10 */
    uint32_t exception_information_14[15];       /* 14..4f */
} rome2_vfs_win32_exception_record80_32;
_Static_assert(sizeof(rome2_vfs_win32_exception_record80_32) == 0x50, "win32 exception record80 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_exception_record80_32, exception_code_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_exception_record80_32, exception_flags_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_exception_record80_32, exception_address_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_exception_record80_32, exception_information_14, 0x14);

/* 76B (0x4c) __crt_stdio_input::format_string_parser<char> state initialized by 0x11692cc4 and advanced by 0x11692f4e. */
typedef struct rome2_vfs_crt_fmt_parser76_32 {
    uint32_t locinfo_00;                         /* 00 */
    uint32_t state_val_04;                       /* 04 */
    uint32_t fmt_cur_08;                         /* 08 */
    int32_t err_0c;                              /* 0c */
    uint32_t mode_10;                            /* 10 (1=EOF, 2=space, 3=lit, 4=conv) */
    uint16_t lit_ch_14;                          /* 14 */
    uint8_t suppress_16;                         /* 16 ('*') */
    uint8_t pad_17;                              /* 17 */
    uint32_t width_18;                           /* 18 */
    uint32_t length_mod_1c;                      /* 1c */
    uint32_t length_idx_20;                      /* 20 */
    uint8_t is_wide_24;                          /* 24 */
    uint8_t pad_25[3];                           /* 25..27 */
    uint32_t conv_idx_28;                        /* 28 */
    uint32_t scanset_words_2c[8];                /* 2c..4b (rep stosd x8) */
} rome2_vfs_crt_fmt_parser76_32;
_Static_assert(sizeof(rome2_vfs_crt_fmt_parser76_32) == 0x4c, "crt fmt parser76 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fmt_parser76_32, fmt_cur_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fmt_parser76_32, err_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fmt_parser76_32, mode_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fmt_parser76_32, conv_idx_28, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fmt_parser76_32, scanset_words_2c, 0x2c);

/* 32B (0x20) MSVC struct _exception built on stack by 0x116a234d (__umatherr). */
typedef struct rome2_vfs_crt_math_exception32_32 {
    int32_t type_00;                             /* 00 */
    uint32_t name_04;                            /* 04 */
    double arg1_08;                              /* 08 */
    double arg2_10;                              /* 10 */
    double retval_18;                            /* 18 */
} rome2_vfs_crt_math_exception32_32;
_Static_assert(sizeof(rome2_vfs_crt_math_exception32_32) == 0x20, "crt math exception32 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_math_exception32_32, type_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_math_exception32_32, name_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_math_exception32_32, arg1_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_math_exception32_32, retval_18, 0x18);

/* 24B (0x18) __crt_win32_buffer<wchar_t> header used by 0x1168c5c8/0x1168c77b/0x1168c7bc. */
typedef struct rome2_vfs_crt_win32_buffer24_32 {
    uint32_t policy_00[2];                       /* 00..07 */
    uint32_t data_08;                            /* 08 */
    uint32_t capacity_words_0c;                  /* 0c */
    uint32_t size_words_10;                      /* 10 */
    uint8_t allocated_14;                        /* 14 */
    uint8_t pad_15[3];                           /* 15..17 */
} rome2_vfs_crt_win32_buffer24_32;
_Static_assert(sizeof(rome2_vfs_crt_win32_buffer24_32) == 0x18, "crt win32 buffer24 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_win32_buffer24_32, data_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_win32_buffer24_32, capacity_words_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_win32_buffer24_32, size_words_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_win32_buffer24_32, allocated_14, 0x14);

/* 12B (0x0c) MSVC CRT _strflt struct updated by 0x116a8dad. */
typedef struct rome2_vfs_crt_strflt12_32 {
    int32_t sign_00;                             /* 00 */
    int32_t decpt_04;                            /* 04 */
    uint32_t digits_ptr_08;                      /* 08 */
} rome2_vfs_crt_strflt12_32;
_Static_assert(sizeof(rome2_vfs_crt_strflt12_32) == 0x0c, "crt strflt12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_strflt12_32, sign_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_strflt12_32, decpt_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_strflt12_32, digits_ptr_08, 0x08);

/* 8B (0x08) CRT x87/SSE FP control state pair captured/applied by 0x116b822e..0x116b8296. */
typedef struct rome2_vfs_crt_fp_env8_32 {
    uint32_t word0_00;                           /* 00 */
    uint32_t word1_04;                           /* 04 */
} rome2_vfs_crt_fp_env8_32;
_Static_assert(sizeof(rome2_vfs_crt_fp_env8_32) == 0x08, "crt fp env8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fp_env8_32, word0_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fp_env8_32, word1_04, 0x04);

/* 12B (0x0c) CRT __crt_onexit_table encoded vector bounds modified by 0x116a1825. */
typedef struct rome2_vfs_crt_onexit_table12_32 {
    uint32_t first_enc_00;                       /* 00 */
    uint32_t last_enc_04;                        /* 04 */
    uint32_t end_enc_08;                         /* 08 */
} rome2_vfs_crt_onexit_table12_32;
_Static_assert(sizeof(rome2_vfs_crt_onexit_table12_32) == 0x0c, "crt onexit table12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_onexit_table12_32, first_enc_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_onexit_table12_32, last_enc_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_onexit_table12_32, end_enc_08, 0x08);

/* 24B (0x18) Win32 RTL_CRITICAL_SECTION slot in CRT __acrt_lock_table (0x12125da8) indexed by 0x116a24dd. */
typedef struct rome2_vfs_win32_critsec24_32 {
    uint32_t debug_info_00;                      /* 00 */
    int32_t lock_count_04;                       /* 04 */
    int32_t recursion_count_08;                  /* 08 */
    uint32_t owning_thread_0c;                   /* 0c */
    uint32_t lock_sem_10;                        /* 10 */
    uint32_t spin_count_14;                      /* 14 */
} rome2_vfs_win32_critsec24_32;
_Static_assert(sizeof(rome2_vfs_win32_critsec24_32) == 0x18, "win32 critsec24 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_critsec24_32, debug_info_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_critsec24_32, lock_count_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_critsec24_32, recursion_count_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_win32_critsec24_32, spin_count_14, 0x14);

/* 56B (0x38) CRT __crt_lowio_handle_data chunk slot indexed by 0x116b6038 (__isatty). */
typedef struct rome2_vfs_crt_ioinfo56_32 {
    uint32_t osfhnd_00;                          /* 00 */
    uint8_t pad_04[0x24];                        /* 04..27 */
    uint8_t osfile_28;                           /* 28 (0x40=_FDEV bit tested by __isatty) */
    uint8_t pad_29[0x0f];                        /* 29..37 */
} rome2_vfs_crt_ioinfo56_32;
_Static_assert(sizeof(rome2_vfs_crt_ioinfo56_32) == 0x38, "crt ioinfo56 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_ioinfo56_32, osfhnd_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_ioinfo56_32, osfile_28, 0x28);

/* 28B (0x1c) 32-bit protected-mode x87 FPU environment loaded/stored by fnstenv/fldenv (0x116b89d3..0x116b8b73). */
typedef struct rome2_vfs_x87_env28_32 {
    uint32_t cw_00;                              /* 00 */
    uint32_t sw_04;                              /* 04 */
    uint32_t tw_08;                              /* 08 */
    uint32_t fip_0c;                             /* 0c */
    uint32_t fcs_10;                             /* 10 */
    uint32_t foo_14;                             /* 14 */
    uint32_t fos_18;                             /* 18 */
} rome2_vfs_x87_env28_32;
_Static_assert(sizeof(rome2_vfs_x87_env28_32) == 0x1c, "x87 env28 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_x87_env28_32, cw_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_x87_env28_32, sw_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_x87_env28_32, tw_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_x87_env28_32, fos_18, 0x18);

/* 8B (0x08) __crt_strtox::c_string_character_source<char> initialized by 0x1169de44. */
typedef struct rome2_vfs_crt_cstr_source8_32 {
    uint32_t cur_00;                             /* 00 */
    uint32_t endptr_slot_04;                     /* 04 */
} rome2_vfs_crt_cstr_source8_32;
_Static_assert(sizeof(rome2_vfs_crt_cstr_source8_32) == 0x08, "crt cstr source8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_cstr_source8_32, cur_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_cstr_source8_32, endptr_slot_04, 0x04);

/* 16B (0x10) MSVC __crt_locale_data category entry traversed by 0x116b5c9e..0x116b5ee6. */
typedef struct rome2_vfs_crt_locale_cat16_32 {
    uint32_t locale_name_00;                     /* 00 */
    uint32_t wlocale_name_04;                    /* 04 (0x119ec000 = "C" sentinel) */
    uint32_t refcount_ptr_08;                    /* 08 */
    uint32_t wrefcount_ptr_0c;                   /* 0c */
} rome2_vfs_crt_locale_cat16_32;
_Static_assert(sizeof(rome2_vfs_crt_locale_cat16_32) == 0x10, "crt locale cat16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_cat16_32, locale_name_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_cat16_32, wlocale_name_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_cat16_32, refcount_ptr_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_cat16_32, wrefcount_ptr_0c, 0x0c);

/* 184B (0xb8) MSVC __crt_locale_data prefix traversed by 0x116b5c9e, 0x116b5d1b, 0x116b5ee6. */
typedef struct rome2_vfs_crt_threadlocinfo184_32 {
    uint32_t pctype_00;                          /* 00 (_pctype table ptr read by 0x116b1590) */
    int32_t mb_cur_max_04;                       /* 04 (_mb_cur_max checked by _mbtowc_l 0x116a5aa6) */
    uint32_t lc_codepage_08;                     /* 08 (codepage returned by ____lc_codepage_func 0x116a25f6) */
    int32_t refcount_0c;                         /* 0c */
    uint8_t pad_10[0x0c];                        /* 10..1b */
    rome2_vfs_crt_locale_cat16_32 cats_1c[6];    /* 1c..7b */
    uint32_t lconv_intl_refcount_7c;             /* 7c */
    uint32_t lconv_num_refcount_80;              /* 80 */
    uint32_t lconv_mon_refcount_84;              /* 84 */
    uint32_t lconv_88;                           /* 88 (0x119ebed0 sentinel) */
    uint32_t ctype1_refcount_8c;                 /* 8c */
    uint32_t ctype1_90;                          /* 90 (-0xfe base on free) */
    uint32_t pclmap_94;                          /* 94 (-0x80 base on free) */
    uint32_t pcumap_98;                          /* 98 (-0x80 base on free) */
    uint32_t lc_time_curr_9c;                    /* 9c */
    uint32_t lc_name_dup_a0[6];                  /* a0..b7 (freed when wrefcount==0) */
} rome2_vfs_crt_threadlocinfo184_32;
_Static_assert(sizeof(rome2_vfs_crt_threadlocinfo184_32) == 0xb8, "crt threadlocinfo184 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, lc_codepage_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, refcount_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, cats_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, lconv_intl_refcount_7c, 0x7c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, lconv_88, 0x88);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, ctype1_90, 0x90);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, lc_time_curr_9c, 0x9c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_threadlocinfo184_32, lc_name_dup_a0, 0xa0);

/* 64B (0x40) __crt_stdio_output::output_processor<wchar_t> state core (`0x11689d22..0x1168ae87`). */
typedef struct rome2_vfs_crt_wprintf_state64_32 {
    uint32_t flags_opt_00;                       /* 00 */
    uint32_t locinfo_04;                         /* 04 */
    uint32_t adapter_08;                         /* 08 */
    uint32_t reserved_0c;                        /* 0c */
    uint32_t fmt_ptr_10;                         /* 10 */
    uint32_t valist_14;                          /* 14 */
    int32_t chars_written_18;                    /* 18 */
    uint32_t fsm_state_1c;                       /* 1c */
    uint32_t fmt_flags_20;                       /* 20 (1='+',2=' ',4='-',8='0',0x20='#') */
    int32_t width_24;                            /* 24 */
    int32_t precision_28;                        /* 28 */
    uint32_t length_mod_2c;                      /* 2c */
    uint8_t byte_30;                             /* 30 */
    uint8_t pad_31;                              /* 31 */
    uint16_t cur_ch_32;                          /* 32 (wchar_t) */
    uint32_t pad_34;                             /* 34 */
    uint32_t suppress_38;                        /* 38 */
    uint8_t cap_exp_3c;                          /* 3c */
    uint8_t pad_3d[3];                           /* 3d..3f */
} rome2_vfs_crt_wprintf_state64_32;
_Static_assert(sizeof(rome2_vfs_crt_wprintf_state64_32) == 0x40, "crt wprintf state64 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_wprintf_state64_32, valist_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_wprintf_state64_32, fsm_state_1c, 0x1c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_wprintf_state64_32, fmt_flags_20, 0x20);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_wprintf_state64_32, width_24, 0x24);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_wprintf_state64_32, precision_28, 0x28);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_wprintf_state64_32, cur_ch_32, 0x32);

/* 116B (0x74) __crt_stdio_input::input_processor<char> layout (`0x11696308`, `0x11696278`, `0x11697068`). */
typedef struct rome2_vfs_crt_scanf_input116_32 {
    uint32_t options_00;                         /* 00 */
    uint32_t reserved_04;                        /* 04 */
    uint32_t input_begin_08;                     /* 08 */
    uint32_t input_end_0c;                       /* 0c */
    uint32_t input_cur_10;                       /* 10 */
    uint32_t valist_14;                          /* 14 */
    rome2_vfs_crt_fmt_parser76_32 fmt_18;        /* 18..63 */
    uint32_t reserved_64;                        /* 64 */
    uint32_t locinfo_arg_68;                     /* 68 */
    uint32_t reserved_6c;                        /* 6c */
    uint32_t converted_count_70;                 /* 70 */
} rome2_vfs_crt_scanf_input116_32;
_Static_assert(sizeof(rome2_vfs_crt_scanf_input116_32) == 0x74, "crt scanf input116 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_scanf_input116_32, input_begin_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_scanf_input116_32, fmt_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_scanf_input116_32, locinfo_arg_68, 0x68);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_scanf_input116_32, converted_count_70, 0x70);

/* 80B (0x50) MSVC CRT struct lconv checked against __lconv_c defaults in 0x116b60c7/0x116b657c. */
typedef struct rome2_vfs_crt_lconv80_32 {
    uint32_t decimal_point_00;                   /* 00 */
    uint32_t thousands_sep_04;                   /* 04 */
    uint32_t grouping_08;                        /* 08 */
    uint32_t int_curr_symbol_0c;                 /* 0c */
    uint32_t currency_symbol_10;                 /* 10 */
    uint32_t mon_decimal_point_14;               /* 14 */
    uint32_t mon_thousands_sep_18;               /* 18 */
    uint32_t mon_grouping_1c;                    /* 1c */
    uint32_t positive_sign_20;                   /* 20 */
    uint32_t negative_sign_24;                   /* 24 */
    uint8_t digits_and_signs_28[8];              /* 28..2f */
    uint32_t w_decimal_point_30;                 /* 30 */
    uint32_t w_thousands_sep_34;                 /* 34 */
    uint32_t w_int_curr_symbol_38;               /* 38 */
    uint32_t w_currency_symbol_3c;               /* 3c */
    uint32_t w_mon_decimal_point_40;             /* 40 */
    uint32_t w_mon_thousands_sep_44;             /* 44 */
    uint32_t w_positive_sign_48;                 /* 48 */
    uint32_t w_negative_sign_4c;                 /* 4c */
} rome2_vfs_crt_lconv80_32;
_Static_assert(sizeof(rome2_vfs_crt_lconv80_32) == 0x50, "crt lconv80 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lconv80_32, decimal_point_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lconv80_32, int_curr_symbol_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lconv80_32, w_decimal_point_30, 0x30);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lconv80_32, w_negative_sign_4c, 0x4c);

/* 180B (0xb4) MSVC __lc_time_data prefix up through refcount_b0 inspected by 0x116b5e63..0x116b5ebd. */
typedef struct rome2_vfs_crt_lc_time_data180_32 {
    uint32_t narrow_and_meta_00[43];             /* 00..ab */
    uint32_t ww_caltype_ac;                      /* ac */
    int32_t refcount_b0;                         /* b0 */
} rome2_vfs_crt_lc_time_data180_32;
_Static_assert(sizeof(rome2_vfs_crt_lc_time_data180_32) == 0xb4, "crt lc time data180 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lc_time_data180_32, ww_caltype_ac, 0xac);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lc_time_data180_32, refcount_b0, 0xb0);

/* 12B (0x0c) CRT lowio write result returned on stack by 0x116a49a3..0x116a4fea. */
typedef struct rome2_vfs_crt_lowio_write_result12_32 {
    uint32_t os_err_00;                          /* 00 */
    uint32_t bytes_written_04;                   /* 04 */
    uint32_t extra_lf_or_chars_08;               /* 08 */
} rome2_vfs_crt_lowio_write_result12_32;
_Static_assert(sizeof(rome2_vfs_crt_lowio_write_result12_32) == 0x0c, "crt lowio write result12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lowio_write_result12_32, os_err_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lowio_write_result12_32, bytes_written_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lowio_write_result12_32, extra_lf_or_chars_08, 0x08);

/* 12B (0x0c) CRT DST transition cache (dststart 0x119ec1d0, dstend 0x119ec1dc). */
typedef struct rome2_vfs_crt_tz_transition_date12_32 {
    int32_t yr_00;                               /* 00 */
    int32_t yd_04;                               /* 04 */
    int32_t ms_08;                               /* 08 */
} rome2_vfs_crt_tz_transition_date12_32;
_Static_assert(sizeof(rome2_vfs_crt_tz_transition_date12_32) == 0x0c, "crt tz transition date12 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tz_transition_date12_32, yr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tz_transition_date12_32, yd_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tz_transition_date12_32, ms_08, 0x08);

/* 8B (0x08) Win32 ANSI_STRING / UNICODE_STRING descriptor formatted by 0x1168af61 (%Z). */
typedef struct rome2_vfs_crt_unicode_string8_32 {
    uint16_t length_00;                          /* 00 */
    uint16_t max_length_02;                      /* 02 */
    uint32_t buffer_04;                          /* 04 */
} rome2_vfs_crt_unicode_string8_32;
_Static_assert(sizeof(rome2_vfs_crt_unicode_string8_32) == 0x08, "crt unicode string8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_unicode_string8_32, length_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_unicode_string8_32, max_length_02, 0x02);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_unicode_string8_32, buffer_04, 0x04);

/* 1032B (0x408) CRT __crt_stdio_output::formatting_buffer at wprintf +0x40 (0x11688991..0x11688b3c). */
typedef struct rome2_vfs_crt_formatting_buffer1032_32 {
    uint8_t inline_buf_000[1024];                /* 000..3ff */
    uint32_t allocated_bytes_400;                /* 400 */
    uint32_t heap_ptr_404;                       /* 404 */
} rome2_vfs_crt_formatting_buffer1032_32;
_Static_assert(sizeof(rome2_vfs_crt_formatting_buffer1032_32) == 0x408, "crt formatting buffer1032 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_formatting_buffer1032_32, inline_buf_000, 0x000);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_formatting_buffer1032_32, allocated_bytes_400, 0x400);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_formatting_buffer1032_32, heap_ptr_404, 0x404);

/* 172B (0xac) Win32 TIME_ZONE_INFORMATION stored at tzinfo 0x12126220..0x121262cb (0x116b0111). */
typedef struct rome2_vfs_crt_time_zone_info172_32 {
    int32_t bias_00;                             /* 00 */
    uint16_t standard_name_04[32];               /* 04..43 */
    uint16_t standard_date_44[8];                /* 44..53 (SYSTEMTIME 16B) */
    int32_t standard_bias_54;                    /* 54 */
    uint16_t daylight_name_58[32];               /* 58..97 */
    uint16_t daylight_date_98[8];                /* 98..a7 (SYSTEMTIME 16B) */
    int32_t daylight_bias_a8;                    /* a8 */
} rome2_vfs_crt_time_zone_info172_32;
_Static_assert(sizeof(rome2_vfs_crt_time_zone_info172_32) == 0xac, "crt time zone info172 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, bias_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, standard_name_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, standard_date_44, 0x44);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, standard_bias_54, 0x54);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, daylight_name_58, 0x58);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, daylight_date_98, 0x98);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_time_zone_info172_32, daylight_bias_a8, 0xa8);

/* 8B (0x08) CRT _tzname[2] 32-bit pointer pair updated by 0x116aff36 and 0x116b0111. */
typedef struct rome2_vfs_crt_tzname_pair8_32 {
    uint32_t std_name_ptr_00;                    /* 00 */
    uint32_t dst_name_ptr_04;                    /* 04 */
} rome2_vfs_crt_tzname_pair8_32;
_Static_assert(sizeof(rome2_vfs_crt_tzname_pair8_32) == 0x08, "crt tzname pair8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tzname_pair8_32, std_name_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_tzname_pair8_32, dst_name_ptr_04, 0x04);

/* 8B (0x08) UCRT mbstate_t accumulator state used by __mbrtoc32_utf8 (0x116b15ac, fallback 0x121262ec). */
typedef struct rome2_vfs_crt_mbstate8_32 {
    uint32_t wchar_00;                           /* 00 */
    uint16_t byte_04;                            /* 04 (expected UTF-8 sequence byte length 2..4) */
    uint16_t state_06;                           /* 06 (remaining trailing bytes) */
} rome2_vfs_crt_mbstate8_32;
_Static_assert(sizeof(rome2_vfs_crt_mbstate8_32) == 0x08, "crt mbstate8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_mbstate8_32, wchar_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_mbstate8_32, byte_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_mbstate8_32, state_06, 0x06);

/* 64B (0x40) 16-entry NaN/Infinity pointer LUT at 0x11914110 indexed by __acrt_fp_format_nan_or_infinity (0x116a649f). */
typedef struct rome2_vfs_crt_fp_nan_inf_table64_32 {
    uint32_t entries_00[16];                     /* 00..3f (upper/lower INF/NAN/NAN(SNAN)/NAN(IND) pointers) */
} rome2_vfs_crt_fp_nan_inf_table64_32;
_Static_assert(sizeof(rome2_vfs_crt_fp_nan_inf_table64_32) == 0x40, "crt fp nan inf table64 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_fp_nan_inf_table64_32, entries_00, 0x00);

/* 4B (0x04) __crt_unique_heap_ptr<T> single owned 32-bit guest pointer slot managed by 0x11689010. */
typedef struct rome2_vfs_crt_unique_heap_ptr4_32 {
    uint32_t ptr_00;                             /* 00 */
} rome2_vfs_crt_unique_heap_ptr4_32;
_Static_assert(sizeof(rome2_vfs_crt_unique_heap_ptr4_32) == 0x04, "crt unique heap ptr4 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_unique_heap_ptr4_32, ptr_00, 0x00);

/* 56B (0x38) UCRT __crt_stdio_stream_data layout observed across 0x1169e514, 0x116a66a3, 0x1168bcc3, 0x116a5864, 0x116a586f, and 0x116b1c0d. */
typedef struct rome2_vfs_crt_stdio_stream56_32 {
    uint32_t ptr_00;                             /* 00 */
    uint32_t base_04;                            /* 04 */
    int32_t cnt_08;                              /* 08 */
    uint32_t flags_0c;                           /* 0c (_IOREAD=1, _IOWRITE=2, _IORW=4, _IOYOURBUF=8, _IOERR=0x10, _IOBUFFER_CRT=0x40, _IOBUFFER_NONE=0x400, _IOSTRG=0x1000) */
    int32_t file_10;                             /* 10 */
    uint32_t charbuf_14;                         /* 14 (inline 2B fallback buffer) */
    int32_t bufsiz_18;                           /* 18 (4096 or 2) */
    uint32_t tmpfname_1c;                        /* 1c */
    uint8_t lock_cs_20[24];                      /* 20..37 */
} rome2_vfs_crt_stdio_stream56_32;
_Static_assert(sizeof(rome2_vfs_crt_stdio_stream56_32) == 0x38, "crt stdio stream56 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, base_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, cnt_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, flags_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, file_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, charbuf_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, bufsiz_18, 0x18);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_stdio_stream56_32, lock_cs_20, 0x20);

/* 8B (0x08) Win32 API module descriptor record (0x11914d60, sentinel 0x11914d68) passed by 0x116a83bd. */
typedef struct rome2_vfs_crt_api_mod_desc8_32 {
    uint32_t module_id_00;                       /* 00 */
    uint32_t min_version_04;                     /* 04 */
} rome2_vfs_crt_api_mod_desc8_32;
_Static_assert(sizeof(rome2_vfs_crt_api_mod_desc8_32) == 0x08, "crt api mod desc8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_api_mod_desc8_32, module_id_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_api_mod_desc8_32, min_version_04, 0x04);

/* 16B (0x10) MSVC SEH4 scope table header (e.g. 0x119256b0) pushed by 0x1169ecd8 (_getenv_s). */
typedef struct rome2_vfs_crt_seh4_scope16_32 {
    uint32_t gscookie_offset_00;                 /* 00 */
    uint32_t gscookie_xor_offset_04;             /* 04 */
    uint32_t ehcookie_offset_08;                 /* 08 */
    uint32_t ehcookie_xor_offset_0c;             /* 0c */
} rome2_vfs_crt_seh4_scope16_32;
_Static_assert(sizeof(rome2_vfs_crt_seh4_scope16_32) == 0x10, "crt seh4 scope16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope16_32, gscookie_offset_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope16_32, gscookie_xor_offset_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope16_32, ehcookie_offset_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope16_32, ehcookie_xor_offset_0c, 0x0c);

/* 32B (0x20) __crt_strtox::input_adapter_character_source constructed by 0x1168f338 / 0x11692d4c for 0x11691750 / 0x11695a17 / 0x11696503 / 0x116971c4 / 0x116972d5. */
typedef struct rome2_vfs_crt_input_char_source32_32 {
    uint32_t adapter_ptr_00;                     /* 00 */
    uint32_t pad_04;                             /* 04 (8-byte alignment padding before width_u64) */
    uint32_t width_lo_08;                        /* 08 */
    uint32_t width_hi_0c;                        /* 0c */
    uint32_t read_count_lo_10;                   /* 10 */
    uint32_t read_count_hi_14;                   /* 14 */
    uint32_t succeeded_ptr_18;                   /* 18 (bool *out_succeeded) */
    uint32_t pad_1c;                             /* 1c (trailing alignment padding) */
} rome2_vfs_crt_input_char_source32_32;
_Static_assert(sizeof(rome2_vfs_crt_input_char_source32_32) == 0x20, "crt input char source32 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_input_char_source32_32, adapter_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_input_char_source32_32, width_lo_08, 0x08);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_input_char_source32_32, width_hi_0c, 0x0c);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_input_char_source32_32, read_count_lo_10, 0x10);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_input_char_source32_32, read_count_hi_14, 0x14);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_input_char_source32_32, succeeded_ptr_18, 0x18);

/* 8B (0x08) downlevel LCID->name table entry (0x1191c408) indexed by 0x116b81e9. */
typedef struct rome2_vfs_crt_lcid_name_entry8_32 {
    uint32_t lcid_00;                            /* 00 */
    uint32_t locale_name_ptr_04;                 /* 04 */
} rome2_vfs_crt_lcid_name_entry8_32;
_Static_assert(sizeof(rome2_vfs_crt_lcid_name_entry8_32) == 0x08, "crt lcid name entry8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lcid_name_entry8_32, lcid_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_lcid_name_entry8_32, locale_name_ptr_04, 0x04);

/* 8B (0x08) sorted locale-name->index entry (0x1191cb28) binary-searched by 0x116b80ef. */
typedef struct rome2_vfs_crt_locale_index_entry8_32 {
    uint32_t locale_name_ptr_00;                 /* 00 */
    int32_t lcid_table_idx_04;                   /* 04 */
} rome2_vfs_crt_locale_index_entry8_32;
_Static_assert(sizeof(rome2_vfs_crt_locale_index_entry8_32) == 0x08, "crt locale index entry8 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_index_entry8_32, locale_name_ptr_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_locale_index_entry8_32, lcid_table_idx_04, 0x04);

/* 257B (0x101) CRT default _mbctype table (0x119ec430) published at [0x121262fc] by 0x116b4bf0. */
typedef struct rome2_vfs_crt_mbctype_table257_32 {
    uint8_t entries_00[257];                     /* 00..100 (EOF byte at [0], byte ch at [ch + 1]) */
} rome2_vfs_crt_mbctype_table257_32;
_Static_assert(sizeof(rome2_vfs_crt_mbctype_table257_32) == 0x101, "crt mbctype table257 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_mbctype_table257_32, entries_00, 0x00);

/* 256B (0x100) CRT default _mbcasemap table (0x119ec538) published at [0x12126300] by 0x116b4bf0. */
typedef struct rome2_vfs_crt_mbcasemap_table256_32 {
    uint8_t entries_00[256];                     /* 00..ff */
} rome2_vfs_crt_mbcasemap_table256_32;
_Static_assert(sizeof(rome2_vfs_crt_mbcasemap_table256_32) == 0x100, "crt mbcasemap table256 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_mbcasemap_table256_32, entries_00, 0x00);

/* 16B (0x10) MSVC SEH4 scope entry record following 16B scope header (0x11925670 + 0x10 for common_lseek<int64>). */
typedef struct rome2_vfs_crt_seh4_scope_entry16_32 {
    uint32_t enclosing_level_00;                 /* 00 (-2 = outermost) */
    uint32_t filter_func_04;                     /* 04 (0 for __finally) */
    uint32_t handler_func_08;                    /* 08 (e.g. 0x1169e71f) */
    uint32_t reserved_0c;                        /* 0c */
} rome2_vfs_crt_seh4_scope_entry16_32;
_Static_assert(sizeof(rome2_vfs_crt_seh4_scope_entry16_32) == 0x10, "crt seh4 scope entry16 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope_entry16_32, enclosing_level_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope_entry16_32, filter_func_04, 0x04);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope_entry16_32, handler_func_08, 0x08);

/* 32B (0x20) single-scope MSVC SEH4 scope table (header + scope0) at 0x11925670. */
typedef struct rome2_vfs_crt_seh4_scope_table32_32 {
    rome2_vfs_crt_seh4_scope16_32 header_00;     /* 00..0f */
    rome2_vfs_crt_seh4_scope_entry16_32 scope_10;/* 10..1f */
} rome2_vfs_crt_seh4_scope_table32_32;
_Static_assert(sizeof(rome2_vfs_crt_seh4_scope_table32_32) == 0x20, "crt seh4 scope table32 32 size");
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope_table32_32, header_00, 0x00);
ROME2_LAYOUT_ASSERT(rome2_vfs_crt_seh4_scope_table32_32, scope_10, 0x10);

#undef ROME2_LAYOUT_ASSERT
#endif
