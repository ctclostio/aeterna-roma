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

#undef ROME2_LAYOUT_ASSERT
#endif
