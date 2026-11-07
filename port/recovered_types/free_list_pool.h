#ifndef ROME2_RECOVERED_FREE_LIST_POOL_H
#define ROME2_RECOVERED_FREE_LIST_POOL_H

/*
 * free_list_pool - native x64 owning adapters for two pool-constructor slices.
 *
 * Ordinary host C17.  Nothing here reads the game image, models guest memory,
 * converts a guest address into a pointer, or names an original address as a
 * callable or data identity.  It is NOT a recovery of either original class.
 *
 * Frozen facts (supplied by the coordinating root; no analysis is done here)
 * --------------------------------------------------------------------------
 * 0x10328370 (86 bytes) and 0x1064d4e0 (84 bytes): x86, receiver in ECX,
 * two stack arguments, receiver returned.  Each one:
 *   - requests slot_count * stride bytes from heap class 0, where slot_count
 *     is the first (unsigned) stack argument and stride is 0x50 (10328370)
 *     or 0x4c (1064d4e0);
 *   - stores the block address at receiver+0;
 *   - stores the 32 bits of the second stack argument at receiver+4;
 *   - writes only the first four bytes of every slot i: the address of slot
 *     i+1, or zero for the final slot.  The remaining bytes of each slot are
 *     not written.
 * A guest slot is therefore a four-byte next address followed by 76 (0x50)
 * or 72 (0x4c) unobserved bytes.  Those extents come from the allocation
 * stride.  They are not recovered object fields.  The receiver's size and
 * any other receiver members are not admitted, and nothing here describes
 * them.
 *
 * Native contract
 * ---------------
 *   - Slots are typed records: an 8-byte native next pointer, then the
 *     unobserved payload bytes, with natural x64 padding (sizes 88 and 80).
 *     Native slot i is slots[i] and its next is &slots[i + 1], or NULL for
 *     the final slot.  This is the guest chain normalised to slot indices:
 *     guest (next - block) / stride == native next - head == i + 1, and the
 *     guest terminal zero is NULL.  No pointer is ever narrowed to 32 bits.
 *   - Only next members are written.  Payload bytes, padding and alignment
 *     slack keep whatever the allocator returned.  They are never zeroed,
 *     filled, read or interpreted.
 *   - The tag is the second argument kept as an opaque uint32_t word.  It is
 *     stored bit for bit and never interpreted as a pointer.
 *   - Count limit: the guest request slot_count * stride must fit in 32 bits
 *     (slot_count <= ROME2_FREE_LIST_POOL_*_MAX_SLOTS).  The native request
 *     slot_count * sizeof(slot) + alignment slack is also overflow-checked.
 *     Larger counts are rejected before any effect.
 *   - Zero slots: the native pool has head == NULL and no slot grant.  Only
 *     the handle record is allocated.  This differs from the original route,
 *     which issues a zero-byte class-0 request and stores its result at
 *     receiver+0.  That request, its result identity and anything the
 *     original does for zero slots are not reproduced.
 *   - Not admitted and not emulated: the original's allocation-failure route
 *     and its wrapped-count route (a 32-bit product that wraps).  The native
 *     adapter returns a status instead.
 *   - No method other than construction is admitted.  There is no pop, push,
 *     reset or traversal API.  Any later use of the slots is the consumer's
 *     own contract.
 *
 * Ownership and allocation
 * ------------------------
 * *allocator is read once and captured by value.  The captured copy serves
 * both grants and their matching releases, so a later edit of the caller's
 * allocator object has no effect.  A pool makes at most two grants, both in
 * class ROME2_FREE_LIST_POOL_ALLOCATION_CLASS (0):
 *   1. the slot array, only when slot_count > 0:
 *        slot_count * sizeof(slot) + (_Alignof(slot) - 1) bytes;
 *   2. the handle record:  sizeof(record) + (_Alignof(record) - 1) bytes.
 * Both accept any returned alignment, including byte alignment.  The adapter
 * aligns inside each grant and keeps the exact raw base and byte count in
 * the record.  Destroy releases the slot grant, then the record.  Both are
 * storage, so release_observer is never invoked, as for owned_string vector
 * storage.  The callback contract of owned_string.h applies: allocate may
 * return any alignment, and release receives the exact (raw, bytes, class)
 * of its grant once.  Callbacks must return normally and must not re-enter
 * this API on the pool being created or destroyed.  Nothing is thread-safe.
 * No borrowed object is ever released.
 */

#include <stddef.h>
#include <stdint.h>

#include "owned_string.h"

_Static_assert(sizeof(void *) == 8, "free_list_pool is an x64 host runtime");

/* ------------------------------------------------------------------------ */
/* Original (guest) facts, kept as separate constants.                       */
/* ------------------------------------------------------------------------ */

#define ROME2_FREE_LIST_POOL_ALLOCATION_CLASS ROME2_OWNED_STRING_ALLOCATION_CLASS
#define ROME2_FREE_LIST_POOL_GUEST_HEAD_OFFSET   0u   /* receiver+0: block */
#define ROME2_FREE_LIST_POOL_GUEST_TAG_OFFSET    4u   /* receiver+4: arg 2 */
#define ROME2_FREE_LIST_POOL_GUEST_NEXT_BYTES    4u   /* slot +0: next */

#define ROME2_FREE_LIST_POOL_10328370_GUEST_STRIDE   0x50u
#define ROME2_FREE_LIST_POOL_10328370_PAYLOAD_BYTES  76u
#define ROME2_FREE_LIST_POOL_10328370_MAX_SLOTS \
    (UINT32_MAX / ROME2_FREE_LIST_POOL_10328370_GUEST_STRIDE)

#define ROME2_FREE_LIST_POOL_1064D4E0_GUEST_STRIDE   0x4cu
#define ROME2_FREE_LIST_POOL_1064D4E0_PAYLOAD_BYTES  72u
#define ROME2_FREE_LIST_POOL_1064D4E0_MAX_SLOTS \
    (UINT32_MAX / ROME2_FREE_LIST_POOL_1064D4E0_GUEST_STRIDE)

_Static_assert(ROME2_FREE_LIST_POOL_GUEST_NEXT_BYTES +
    ROME2_FREE_LIST_POOL_10328370_PAYLOAD_BYTES ==
    ROME2_FREE_LIST_POOL_10328370_GUEST_STRIDE,
    "10328370 guest slot is next + payload");
_Static_assert(ROME2_FREE_LIST_POOL_GUEST_NEXT_BYTES +
    ROME2_FREE_LIST_POOL_1064D4E0_PAYLOAD_BYTES ==
    ROME2_FREE_LIST_POOL_1064D4E0_GUEST_STRIDE,
    "1064d4e0 guest slot is next + payload");

/* ------------------------------------------------------------------------ */
/* Native slots and published descriptors.                                   */
/* ------------------------------------------------------------------------ */

typedef struct rome2_free_list_slot_10328370 rome2_free_list_slot_10328370;
struct rome2_free_list_slot_10328370 {
    rome2_free_list_slot_10328370 *next;        /* +0 */
    uint8_t unobserved_payload[ROME2_FREE_LIST_POOL_10328370_PAYLOAD_BYTES];
};                                              /* +8..+83, padding to 88 */

typedef struct rome2_free_list_slot_1064d4e0 rome2_free_list_slot_1064d4e0;
struct rome2_free_list_slot_1064d4e0 {
    rome2_free_list_slot_1064d4e0 *next;        /* +0 */
    uint8_t unobserved_payload[ROME2_FREE_LIST_POOL_1064D4E0_PAYLOAD_BYTES];
};                                              /* +8..+79 */

_Static_assert(offsetof(rome2_free_list_slot_10328370, next) == 0, "next +0");
_Static_assert(sizeof(((rome2_free_list_slot_10328370 *)0)->next) == 8,
    "10328370 next is a native pointer");
_Static_assert(offsetof(rome2_free_list_slot_10328370, unobserved_payload) == 8,
    "10328370 payload +8");
_Static_assert(sizeof(((rome2_free_list_slot_10328370 *)0)->unobserved_payload)
    == 76, "10328370 payload is 76 bytes");
_Static_assert(_Alignof(rome2_free_list_slot_10328370) == 8, "10328370 align");
_Static_assert(sizeof(rome2_free_list_slot_10328370) == 88,
    "10328370 native slot: 8 + 76 + 4 tail padding");

_Static_assert(offsetof(rome2_free_list_slot_1064d4e0, next) == 0, "next +0");
_Static_assert(sizeof(((rome2_free_list_slot_1064d4e0 *)0)->next) == 8,
    "1064d4e0 next is a native pointer");
_Static_assert(offsetof(rome2_free_list_slot_1064d4e0, unobserved_payload) == 8,
    "1064d4e0 payload +8");
_Static_assert(sizeof(((rome2_free_list_slot_1064d4e0 *)0)->unobserved_payload)
    == 72, "1064d4e0 payload is 72 bytes");
_Static_assert(_Alignof(rome2_free_list_slot_1064d4e0) == 8, "1064d4e0 align");
_Static_assert(sizeof(rome2_free_list_slot_1064d4e0) == 80,
    "1064d4e0 native slot: 8 + 72, no padding");

/* Native counterparts of receiver+0 and receiver+4.  Read-only to callers. */
typedef struct rome2_free_list_pool_10328370 {
    rome2_free_list_slot_10328370 *head;  /* +0  slot 0, or NULL if no slots */
    uint32_t tag;                         /* +8  opaque second argument */
} rome2_free_list_pool_10328370;

typedef struct rome2_free_list_pool_1064d4e0 {
    rome2_free_list_slot_1064d4e0 *head;  /* +0  slot 0, or NULL if no slots */
    uint32_t tag;                         /* +8  opaque second argument */
} rome2_free_list_pool_1064d4e0;

_Static_assert(offsetof(rome2_free_list_pool_10328370, head) == 0, "head +0");
_Static_assert(offsetof(rome2_free_list_pool_10328370, tag) == 8, "tag +8");
_Static_assert(sizeof(rome2_free_list_pool_10328370) == 16, "descriptor 16");
_Static_assert(offsetof(rome2_free_list_pool_1064d4e0, head) == 0, "head +0");
_Static_assert(offsetof(rome2_free_list_pool_1064d4e0, tag) == 8, "tag +8");
_Static_assert(sizeof(rome2_free_list_pool_1064d4e0) == 16, "descriptor 16");

/* Opaque, heap-owned, address-bound handles.  Never copy the record. */
typedef struct rome2_owned_free_list_pool_10328370
    rome2_owned_free_list_pool_10328370;
typedef struct rome2_owned_free_list_pool_1064d4e0
    rome2_owned_free_list_pool_1064d4e0;

typedef enum rome2_free_list_pool_status {
    ROME2_FREE_LIST_POOL_OK = 0,
    /* out_handle, or the destroy pointer-to-handle, is NULL. */
    ROME2_FREE_LIST_POOL_BAD_ARGUMENT = 1,
    /* allocator is NULL, or its allocate or release callback is NULL. */
    ROME2_FREE_LIST_POOL_INVALID_ALLOCATOR = 2,
    /* slot_count above the kind's MAX_SLOTS, or native size overflow. */
    ROME2_FREE_LIST_POOL_COUNT_OUT_OF_RANGE = 3,
    /* allocate returned NULL; every earlier grant was released once. */
    ROME2_FREE_LIST_POOL_ALLOCATION_FAILED = 4,
    /* destroy found no coherent LIVE handle of this kind; nothing done. */
    ROME2_FREE_LIST_POOL_INVALID_HANDLE = 5
} rome2_free_list_pool_status;

/* ------------------------------------------------------------------------ */
/* API.  The two kinds are identical apart from their types and stride.      */
/* ------------------------------------------------------------------------ */

/*
 * Create a pool of slot_count linked slots tagged with tag.
 *
 * Checked before any allocator effect, in this order: out_handle non-NULL
 * (BAD_ARGUMENT); allocator non-NULL with allocate and release
 * (INVALID_ALLOCATOR); slot_count within MAX_SLOTS and native size
 * arithmetic (COUNT_OUT_OF_RANGE).
 *
 * On OK, *out_handle receives the new handle.  On every other status,
 * *out_handle is neither read nor written and no grant remains live.  A
 * previous handle in *out_handle is not released, so destroy it first.
 */
rome2_free_list_pool_status rome2_free_list_pool_10328370_create(
    rome2_owned_free_list_pool_10328370 **out_handle,
    uint32_t slot_count,
    uint32_t tag,
    const rome2_owned_string_allocator *allocator);

rome2_free_list_pool_status rome2_free_list_pool_1064d4e0_create(
    rome2_owned_free_list_pool_1064d4e0 **out_handle,
    uint32_t slot_count,
    uint32_t tag,
    const rome2_owned_string_allocator *allocator);

/*
 * Const descriptor, valid until the handle is destroyed.  Returns NULL for
 * NULL or for a handle that is not a coherent LIVE pool of this kind.  The
 * descriptor is read-only.  The slots it reaches are pool-owned writable
 * storage released at destroy.  Release never consults the descriptor.
 */
const rome2_free_list_pool_10328370 *rome2_free_list_pool_10328370_get(
    const rome2_owned_free_list_pool_10328370 *handle);

const rome2_free_list_pool_1064d4e0 *rome2_free_list_pool_1064d4e0_get(
    const rome2_owned_free_list_pool_1064d4e0 *handle);

/*
 * Idempotent destruction through a pointer-to-handle.
 *   handle == NULL                     -> BAD_ARGUMENT, no effect.
 *   *handle == NULL                    -> OK, no effect (repeated destroy).
 *   *handle not a coherent LIVE pool   -> INVALID_HANDLE, no effect.
 *   otherwise *handle becomes NULL, the record is consumed, and the slot
 *   grant (if any) and then the record are released through the allocator
 *   captured at create.
 * Destroy each handle through one pointer variable.  Other copies of the
 * pointer dangle afterwards, and passing one here is undefined behaviour.
 */
rome2_free_list_pool_status rome2_free_list_pool_10328370_destroy(
    rome2_owned_free_list_pool_10328370 **handle);

rome2_free_list_pool_status rome2_free_list_pool_1064d4e0_destroy(
    rome2_owned_free_list_pool_1064d4e0 **handle);

#endif /* ROME2_RECOVERED_FREE_LIST_POOL_H */
