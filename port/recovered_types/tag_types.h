#ifndef ROME2_RECOVERED_TAG_TYPES_H
#define ROME2_RECOVERED_TAG_TYPES_H

#include "owned_string.h"

/* Native projections of FUN_10132ce0's observed copy domain. Original field
 * offsets are in guest32_layouts.h. Scalar words remain opaque bits. These
 * are not overlays of guest memory and vtable_identity is never callable.
 * Views and everything they reach are read-only to their consumers.
 */
typedef struct rome2_unit_card_tag_leaf {
    rome2_host_string8 name;
    uint32_t words_00c[16];
} rome2_unit_card_tag_leaf;

typedef struct rome2_unit_card_tag_leaf_vector {
    int32_t capacity;
    int32_t count;
    const rome2_unit_card_tag_leaf *items;
} rome2_unit_card_tag_leaf_vector;

typedef struct rome2_unit_card_tag_element {
    rome2_host_string8 name;
    uint32_t words_00c[4];
    uint16_t word_01c;
    uint8_t unobserved_01e[2];
    uint32_t words_020[12];
    uint8_t bytes_050[7];
    uint8_t unobserved_057;
    uint32_t word_058;
    rome2_host_string16 text;
    uint32_t words_068[5];
    rome2_unit_card_tag_leaf_vector children;
} rome2_unit_card_tag_element;

typedef struct rome2_unit_card_tag_vector {
    int32_t capacity;
    int32_t count;
    const rome2_unit_card_tag_element *items;
} rome2_unit_card_tag_vector;

typedef struct rome2_unit_card_tag {
    uint32_t vtable_identity;
    rome2_unit_card_tag_vector elements;
} rome2_unit_card_tag;

#define ROME2_TAG_VTABLE_IDENTITY UINT32_C(0x1173fae4)
/* Bounds preserve positive guest byte products, without the original wrap. */
#define ROME2_TAG_MAX_ELEMENTS ((size_t)INT32_MAX / 0x88u)
#define ROME2_TAG_MAX_CHILDREN ((size_t)INT32_MAX / 0x4cu)

_Static_assert(sizeof(rome2_unit_card_tag_leaf) == 80, "native tag leaf stride");
_Static_assert(offsetof(rome2_unit_card_tag_leaf, words_00c) == 16, "native leaf words");
_Static_assert(sizeof(rome2_unit_card_tag_leaf_vector) == 16, "native leaf vector");
_Static_assert(sizeof(rome2_unit_card_tag_vector) == 16, "native tag vector");
_Static_assert(sizeof(rome2_unit_card_tag_element) == 152, "native tag element stride");
_Static_assert(offsetof(rome2_unit_card_tag_element, word_01c) == 0x20, "native tag word");
_Static_assert(offsetof(rome2_unit_card_tag_element, words_020) == 0x24, "native tag words");
_Static_assert(offsetof(rome2_unit_card_tag_element, bytes_050) == 0x54, "native tag bytes");
_Static_assert(offsetof(rome2_unit_card_tag_element, word_058) == 0x5c, "native tag word");
_Static_assert(offsetof(rome2_unit_card_tag_element, text) == 0x60, "native UTF16");
_Static_assert(offsetof(rome2_unit_card_tag_element, words_068) == 0x70, "native tag words");
_Static_assert(offsetof(rome2_unit_card_tag_element, children) == 0x88, "native children");
_Static_assert(sizeof(rome2_unit_card_tag) == 24, "native tag allocation extent");
_Static_assert(offsetof(rome2_unit_card_tag, elements) == 8, "native tag receiver");

#endif
