#ifndef ROME2_RECOVERED_SCALAR_VECTORS_H
#define ROME2_RECOVERED_SCALAR_VECTORS_H

#include "owned_string.h"

/* Native counterparts of the unit-card's guest +0x5c word vector and +0x68
 * pair vector. Values are scalar bits, never guessed native pointers.
 * Guest descriptors are three 32-bit cells; native pointers widen the views.
 */
typedef struct rome2_float2 { float x, y; } rome2_float2;
typedef struct rome2_u32_vector_view {
    uint32_t capacity, count;
    const uint32_t *items;
} rome2_u32_vector_view;
typedef struct rome2_float2_vector_view {
    uint32_t capacity, count;
    const rome2_float2 *items;
} rome2_float2_vector_view;

_Static_assert(sizeof(rome2_float2) == 8, "pair stride");
_Static_assert(sizeof(rome2_u32_vector_view) == 16, "native word vector");
_Static_assert(sizeof(rome2_float2_vector_view) == 16, "native pair vector");

#define ROME2_U32_VECTOR_MAX_CAPACITY ((uint32_t)INT32_MAX / 4u)
#define ROME2_FLOAT2_VECTOR_MAX_CAPACITY ((uint32_t)INT32_MAX / 8u)

/* Both handles share a private owner representation. Named APIs check kind;
 * their payload views retain distinct types. No original class identity is
 * inferred from these host owner aliases. */
typedef struct rome2_owned_scalar_vector rome2_owned_u32_vector;
typedef struct rome2_owned_scalar_vector rome2_owned_float2_vector;
typedef enum rome2_scalar_vector_status {
    ROME2_SCALAR_VECTOR_OK = 0,
    ROME2_SCALAR_VECTOR_BAD_ARGUMENT,
    ROME2_SCALAR_VECTOR_INVALID_ALLOCATOR,
    ROME2_SCALAR_VECTOR_INVALID_HANDLE,
    ROME2_SCALAR_VECTOR_COUNT_OUT_OF_RANGE,
    ROME2_SCALAR_VECTOR_ALLOCATION_FAILED
} rome2_scalar_vector_status;

/* Empty create captures the allocator and allocates only a stable owner.
 * Backing capacity grows 0->1 then doubles, as in FUN_1016db10/101a9110.
 * The MAX_CAPACITY values are byte-product bounds; only powers of two at
 * or below them are reachable through this growth sequence.
 * Native backing grants add three bytes of alignment slack. Raw results may
 * have any alignment. Class 0, exact raw release, captured callbacks; no string
 * release observers run for these scalar/metadata blocks.
 *
 * Every error preserves caller output/state and releases any partial grants.
 * All views, arrays and handle records are read-only to callers. A pair push
 * snapshots the input before growth, so &get(h)->items[i] is a valid source
 * even when growth invalidates that view. Word input is already by value.
 * No API is thread-safe; callbacks follow owned_string.h's contract.
 * Overflow, allocation failure, and exceptions are checked native rules, not
 * an emulation of the original invalid/wrapped routes.
 */
rome2_scalar_vector_status rome2_owned_u32_vector_create(
    rome2_owned_u32_vector **out, const rome2_owned_string_allocator *allocator);
rome2_scalar_vector_status rome2_owned_float2_vector_create(
    rome2_owned_float2_vector **out, const rome2_owned_string_allocator *allocator);
const rome2_u32_vector_view *rome2_owned_u32_vector_get(const rome2_owned_u32_vector *h);
const rome2_float2_vector_view *rome2_owned_float2_vector_get(const rome2_owned_float2_vector *h);
rome2_scalar_vector_status rome2_owned_u32_vector_push(rome2_owned_u32_vector *h, uint32_t value);
rome2_scalar_vector_status rome2_owned_float2_vector_push(rome2_owned_float2_vector *h,
    const rome2_float2 *value);
rome2_scalar_vector_status rome2_owned_u32_vector_destroy(rome2_owned_u32_vector **h);
rome2_scalar_vector_status rome2_owned_float2_vector_destroy(rome2_owned_float2_vector **h);

/* FUN_1016ee30's finite, non-overflowing binary32 arithmetic domain. Rejects
 * non-finite components and squared-length overflow before writing output.
 * Squared length <=1 is unchanged. Otherwise multiply both components by
 * 1/sqrtf(y*y+x*x), preserving the original arithmetic order. No allocation.
 */
bool rome2_float2_normalize_unit_disk(rome2_float2 input, rome2_float2 *output);

#endif
