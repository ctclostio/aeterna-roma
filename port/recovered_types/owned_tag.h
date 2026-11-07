#ifndef ROME2_RECOVERED_OWNED_TAG_H
#define ROME2_RECOVERED_OWNED_TAG_H

#include "tag_types.h"

/* Deep-owned native counterpart of the admitted FUN_10132ce0 copy domain.
 * The source is a native borrowed tag vector: pass &native_source.elements
 * for the source corresponding to original arg01+4. No guest address is
 * accepted or cast. Input vector capacity and source vtable are not read:
 * the original helper reads count/items only. Published capacities == count.
 *
 * Every name, UTF-16 text and child's name is independently owned. Scalar
 * bits are preserved; unobserved gaps/native padding are zeroed (a host
 * choice). Count zero reads no items pointer, allocates no array and publishes
 * NULL. Empty strings read no source data and publish native sentinels.
 *
 * All counts/descriptors are checked before allocator effects. The caller
 * supplies live readable native objects and string ranges. Source descriptors
 * require nonnegative lengths, capacity >= length and non-NULL nonempty data.
 * Counts are bounded by tag_types.h, string lengths by owned_string.h.
 * Every failure leaves *out unchanged and rolls back all grants. Destroy an
 * earlier handle before creating into its pointer; it is never auto-released.
 *
 * The allocator is captured by value once. All metadata uses class 0 and
 * alignment slack; raw results may have any alignment. Release uses private
 * allocation records, not published pointers/counts. String payloads alone
 * notify release_observer. Callbacks/synchronisation follow owned_string.h.
 * Output and every array/string it reaches must not be modified by callers.
 * A handle's storage never moves. Pointer aliases dangle after destruction.
 *
 * These are explicit host lifetime/failure rules, not reconstructed original
 * destructor order, exception behavior, allocator failures, or callable vtable
 * methods. This API alone does not complete FUN_10145c70's other helpers.
 */
typedef struct rome2_owned_unit_card_tag rome2_owned_unit_card_tag;

typedef enum rome2_owned_tag_status {
    ROME2_OWNED_TAG_OK = 0,
    ROME2_OWNED_TAG_BAD_ARGUMENT,
    ROME2_OWNED_TAG_INVALID_ALLOCATOR,
    ROME2_OWNED_TAG_COUNT_OUT_OF_RANGE,
    ROME2_OWNED_TAG_MALFORMED_STRING,
    ROME2_OWNED_TAG_ALLOCATION_FAILED,
    ROME2_OWNED_TAG_INVALID_HANDLE,
    ROME2_OWNED_TAG_INTERNAL_ERROR
} rome2_owned_tag_status;

/* Pure descriptor validation for composed owners; no allocator effects. */
rome2_owned_tag_status rome2_unit_card_tag_validate(const rome2_unit_card_tag_vector *source);

rome2_owned_tag_status rome2_owned_unit_card_tag_create(
    rome2_owned_unit_card_tag **out,
    const rome2_unit_card_tag_vector *source,
    const rome2_owned_string_allocator *allocator);

const rome2_unit_card_tag *rome2_owned_unit_card_tag_get(
    const rome2_owned_unit_card_tag *handle);

/* NULL pointer-to-handle: BAD_ARGUMENT. *handle == NULL: OK, no effect.
 * Otherwise consume *handle before releasing resources, then return OK.
 */
rome2_owned_tag_status rome2_owned_unit_card_tag_destroy(
    rome2_owned_unit_card_tag **handle);

#endif
