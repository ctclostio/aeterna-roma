#ifndef ROME2_RECOVERED_OWNED_FAUNA_H
#define ROME2_RECOVERED_OWNED_FAUNA_H

#include "owned_string.h"

/* FUN_10141630 identifies the eight scalar fields; FUN_101a8b20 copies them
 * plus the owned climate-string vector. Guest stride44; native stride48.
 * The word view remains available for exact binary32 bit comparisons. */
typedef struct rome2_fauna_fields {
    uint32_t animal_type, min_entities, max_entities;
    float spawn_probability;
    uint32_t tile_mask, season_mask, time_of_day_mask, precipitation_mask;
} rome2_fauna_fields;
_Static_assert(sizeof(rome2_fauna_fields) == 32, "eight fauna scalars");
typedef struct rome2_string8_vector_view {
    uint32_t capacity, count;
    const rome2_host_string8 *items;
} rome2_string8_vector_view;
typedef struct rome2_fauna_record {
    union {
        uint32_t words_000[8];
        rome2_fauna_fields values;
    };
    rome2_string8_vector_view strings;
} rome2_fauna_record;
typedef struct rome2_fauna_vector_view {
    uint32_t capacity, count;
    const rome2_fauna_record *items;
} rome2_fauna_vector_view;

_Static_assert(sizeof(rome2_fauna_record) == 48, "native fauna stride");
_Static_assert(offsetof(rome2_fauna_fields, spawn_probability) == 12, "fauna probability");
_Static_assert(offsetof(rome2_fauna_record, strings) == 32, "native fauna strings");
#define ROME2_FAUNA_MAX_CAPACITY ((uint32_t)INT32_MAX / 44u)
#define ROME2_FAUNA_MAX_STRINGS ((uint32_t)INT32_MAX / 12u)

typedef struct rome2_owned_fauna_vector rome2_owned_fauna_vector;
typedef enum rome2_fauna_status {
    ROME2_FAUNA_OK = 0,
    ROME2_FAUNA_BAD_ARGUMENT,
    ROME2_FAUNA_INVALID_ALLOCATOR,
    ROME2_FAUNA_INVALID_HANDLE,
    ROME2_FAUNA_COUNT_OUT_OF_RANGE,
    ROME2_FAUNA_MALFORMED_STRING,
    ROME2_FAUNA_ALLOCATION_FAILED,
    ROME2_FAUNA_INTERNAL_ERROR
} rome2_fauna_status;

/* Pure descriptor validation, including every nested source string. */
rome2_fauna_status rome2_fauna_record_validate(const rome2_fauna_record *source);

/* Stable private owners survive backing-array growth. Published records and
 * nested string descriptors are separate const views, never release authority.
 * Growth starts at 1 and doubles. MAX_CAPACITY is the guest byte-product
 * bound; only powers of two at or below it are reachable (largest is 2^25).
 * reserve_min rejects a request whose rounded growth capacity exceeds that
 * bound, even when the requested count itself fits. clear
 * destroys every nested string vector, sets count=0, and retains backing
 * capacity as FUN_101a97f0 does. push deep-copies even when source aliases an
 * existing element. Source vector capacity is unread; output capacity=count.
 *
 * Inputs/descriptors are checked before allocator effects. Every failed push
 * or reserve leaves the vector unchanged and rolls back new grants. Captured
 * class-zero allocator, arbitrary raw alignment, exact raw/size release and
 * string-only observers follow owned_string.h. Views and all reachable data
 * are read-only, callbacks are non-reentrant, and access requires caller
 * synchronisation. This is native ownership/failure behavior, not original
 * exception order, original allocation requests or a game XML parser.
 */
rome2_fauna_status rome2_owned_fauna_vector_create(rome2_owned_fauna_vector **out,
    const rome2_owned_string_allocator *allocator);
const rome2_fauna_vector_view *rome2_owned_fauna_vector_get(const rome2_owned_fauna_vector *h);
rome2_fauna_status rome2_owned_fauna_vector_push(rome2_owned_fauna_vector *h,
    const rome2_fauna_record *source);
rome2_fauna_status rome2_owned_fauna_vector_reserve_min(rome2_owned_fauna_vector *h,
    uint32_t minimum);
rome2_fauna_status rome2_owned_fauna_vector_clear(rome2_owned_fauna_vector *h);
rome2_fauna_status rome2_owned_fauna_vector_destroy(rome2_owned_fauna_vector **h);

#endif
