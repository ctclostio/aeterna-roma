#ifndef ROME2_RECOVERED_OWNED_UNIT_CARD_H
#define ROME2_RECOVERED_OWNED_UNIT_CARD_H

#include "owned_entity.h"
#include "owned_tag.h"
#include "owned_fauna.h"
#include "scalar_vectors.h"

/* Native projection of the known guest prefix, with real native subobject
 * pointers, two scalar vectors, a fauna vector and a typed UTF-16 descriptor.
 * This is a new host type, not a guest overlay or the old legacy projection.
 */
typedef struct rome2_native_unit_card {
    uint32_t field_000, field_004, field_008, owner;
    rome2_host_string8 str_010;
    const rome2_battle_entity *attachment;
    const rome2_unit_card_tag *tag;
    uint8_t selector;
    rome2_host_string8 str_028, str_034;
    uint8_t variant;
    rome2_host_string8 str_044;
    uint16_t zero_050, unobserved_052;
    uint32_t priority, control_flags;
    rome2_u32_vector_view words;
    rome2_float2_vector_view coordinates;
    uint32_t unit_class;
    float deployment;
    uint32_t strength, field_080;
    uint8_t field_084, unobserved_085[3];
    uint32_t field_088, field_08c, field_090;
    float colour_lo_x, colour_lo_y, colour_hi_x, colour_hi_y;
    rome2_host_string8 str_0a4, str_0b0, str_0bc, str_0c8, str_0d4, str_0e0;
    uint32_t field_0ec;
    rome2_host_string8 str_0f0;
    rome2_host_string16 str_0fc;
    rome2_host_string8 str_108;
    uint32_t field_114;
    uint8_t enabled, flag_119, flag_11a, flag_11b, flag_11c, field_11d;
    uint16_t unobserved_11e;
    uint32_t last_common_index, slot_count;
    uint8_t mutable_class, unobserved_129[3];
    rome2_host_string8 str_12c;
    uint8_t flag_138, zero_139[2], unobserved_13b;
    uint32_t auxiliary[4];
    uint32_t field_14c, field_150;
    float grid_extent_min, grid_extent_max;
    rome2_fauna_vector_view fauna;
    uint32_t field_168, field_16c, field_170;
    uint8_t field_174, unobserved_175;
    uint16_t zero_176;
} rome2_native_unit_card;

_Static_assert(sizeof(rome2_native_unit_card) == 0x1d8, "native unit-card prefix extent");
_Static_assert(offsetof(rome2_native_unit_card, words) == 0x80, "native word vector");
_Static_assert(offsetof(rome2_native_unit_card, coordinates) == 0x90, "native coordinate vector");
_Static_assert(offsetof(rome2_native_unit_card, str_0fc) == 0x148, "native UTF16 descriptor");
_Static_assert(offsetof(rome2_native_unit_card, last_common_index) == 0x174, "native shared index");
_Static_assert(offsetof(rome2_native_unit_card, auxiliary) == 0x194, "native four-word subobject");
_Static_assert(offsetof(rome2_native_unit_card, fauna) == 0x1b8, "native fauna vector");

typedef struct rome2_owned_unit_card rome2_owned_unit_card;
typedef enum rome2_unit_card_status {
    ROME2_UNIT_CARD_OK = 0,
    ROME2_UNIT_CARD_BAD_ARGUMENT,
    ROME2_UNIT_CARD_INVALID_ALLOCATOR,
    ROME2_UNIT_CARD_INVALID_HANDLE,
    ROME2_UNIT_CARD_MALFORMED_SOURCE,
    ROME2_UNIT_CARD_COUNT_OUT_OF_RANGE,
    ROME2_UNIT_CARD_ALLOCATION_FAILED,
    ROME2_UNIT_CARD_UNSUPPORTED_COORDINATE,
    ROME2_UNIT_CARD_CONFIG_REQUIRED,
    ROME2_UNIT_CARD_INTERNAL_ERROR
} rome2_unit_card_status;

/* Compose the recovered native owning domain. Initial words contains arg06;
 * coordinates contains the unit-disk-normalized global colour pair; tag and
 * optional attachment are deep copies; thirteen narrow members are readable
 * native empties and str_0fc starts at the native UTF-16 sentinel without an
 * allocation. Its nonempty values are owned. Scalar fields keep
 * the previously verified constructor projection. Unknown gaps are zeroed.
 *
 * decoded_config MUST be explicit (count=0 is valid). This API accepts already
 * decoded fauna records: it does not execute the game's XML/resource loader,
 * infer missing configuration, call original addresses or fake successful I/O.
 * Native config capacity is ignored. NULL arg01 means an empty tag; NULL arg00
 * skips the attachment. NULL globals select the original initial-image values.
 *
 * Validate all source forests and the coordinate domain before effects.
 * Every supported error preserves *out and rolls back grants. Captured class-0
 * allocators accept any raw alignment. All views and every reachable object
 * are read-only; their pointers may change after successful mutators. Source
 * ownership is never consumed. Callback and synchronisation rules follow
 * owned_string.h. Original scratch allocations, exception/failure order,
 * callable virtual methods and resource parsing remain outside this API.
 */
rome2_unit_card_status rome2_owned_unit_card_create_from_config(
    rome2_owned_unit_card **out,
    const rome2_unit_card_args *args,
    const rome2_unit_card_globals *globals,
    const rome2_fauna_vector_view *decoded_config,
    const rome2_owned_string_allocator *allocator);

const rome2_native_unit_card *rome2_owned_unit_card_get(const rome2_owned_unit_card *h);
/* Consumes *h before releasing children. Cached views are invalidated when
 * destruction begins; release callbacks must not read those invalidated views. */
rome2_unit_card_status rome2_owned_unit_card_destroy(rome2_owned_unit_card **h);

/* Recovered append effects, including last_common_index = min(counts)-1
 * when both counts are nonzero, otherwise zero. append_coordinate normalizes
 * to the unit disk; non-finite/overflowing inputs return UNSUPPORTED_COORDINATE
 * without effects. Supported input/allocation failures are atomic. INTERNAL_ERROR
 * denotes a broken private invariant and may follow a committed change. */
rome2_unit_card_status rome2_owned_unit_card_append_word(rome2_owned_unit_card *h, uint32_t value);
rome2_unit_card_status rome2_owned_unit_card_append_coordinate(rome2_owned_unit_card *h, rome2_float2 value);

/* Explicit native UTF-16 writer. Deep copy before releasing the previous
 * value, so source may borrow that value. Input/allocation failure preserves
 * the old string. Negative/too-large lengths and nonempty NULL data return
 * MALFORMED_SOURCE. The new view is published before releasing the old value.
 * This writer composes the verified string primitive, not an unobserved game
 * setter. Embedded zeros and surrogate units are preserved. */
rome2_unit_card_status rome2_owned_unit_card_set_text16(rome2_owned_unit_card *h, rome2_string16_view source);

/* Decoded FUN_101a97f0 setup domain: destroy old nested strings and rebuild.
 * clear retains capacity. replace is a native transactional adaptation that
 * also retains at least the old capacity; supported input/allocation failures
 * preserve the previous configuration. INTERNAL_ERROR may be reported after
 * commit if a private invariant is broken. The supplied view may alias the
 * current fauna view. Cached views see count=0 before clear releases strings. */
rome2_unit_card_status rome2_owned_unit_card_clear_fauna(rome2_owned_unit_card *h);
rome2_unit_card_status rome2_owned_unit_card_replace_config(rome2_owned_unit_card *h,
    const rome2_fauna_vector_view *decoded_config);

#endif
