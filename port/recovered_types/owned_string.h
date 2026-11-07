#ifndef ROME2_RECOVERED_OWNED_STRING_H
#define ROME2_RECOVERED_OWNED_STRING_H

/*
 * owned_string - native x64 owned-string runtime for ported code.
 *
 * This is an ordinary host C17 runtime.  It does not model guest memory,
 * does not read the game image, and never converts a guest address into a
 * native pointer.  It gives ported x64 code owned narrow and UTF-16 strings
 * whose published descriptor behaves like the original string helpers, while
 * every lifetime decision is carried by explicit native owner state.
 *
 * Frozen behavioural evidence (supplied by the coordinating root; this file
 * performs no reverse engineering of its own):
 *
 *   0x100ef2c0  narrow construct from the range [begin, begin + length):
 *               capacity = length.  Length 0 publishes the narrow empty
 *               sentinel.  Otherwise it requests length + 9 bytes in
 *               allocator class 0, places the payload at (raw + 8) & ~3,
 *               stores the 32-bit raw address in the four bytes at
 *               payload - 4, copies exactly `length` bytes and writes one
 *               zero byte at payload + length.
 *   0x100ef330  UTF-16 analogue: requests 2 * length + 10 bytes, copies
 *               opaque 16-bit units and writes one literal zero unit.
 *   0x100f1c80  narrow release: a non-null, non-sentinel descriptor is
 *               released through its hidden raw allocation base, then an
 *               optional release observer is notified.
 *
 * The original 12-byte guest descriptors are rome2_string8_layout32 and
 * rome2_string16_layout32 in guest32_layouts.h.  Their data member is an
 * opaque 32-bit guest identity.  This runtime never produces, consumes or
 * dereferences such an identity, and it defines no original-image address.
 *
 * Preserved observable semantics
 * ------------------------------
 *   - Published descriptor {length, capacity = length, data}.
 *   - Length 0 publishes a readable native empty sentinel, with no allocation.
 *   - Nonempty: a real deep copy of exactly `length` units from a borrowed,
 *     explicit-length view (no strlen; embedded zero bytes/units and lone or
 *     paired surrogates are copied verbatim), followed by one zero
 *     terminator unit.
 *   - Allocation request: length + 9 bytes (narrow) or 2 * length + 10 bytes
 *     (UTF-16), always in allocator class 0.
 *   - Payload at (raw + 8) & ~3, so it is 4-byte aligned for any raw
 *     alignment.  The terminator lies inside the requested extent.
 *   - Release returns the exact raw base and byte count to the allocator
 *     that supplied them, then notifies the optional release observer.
 *
 * Host design choices (NOT original metadata, NOT a full emulation)
 * ----------------------------------------------------------------
 *   - Release authority lives in a separate native rome2_owned_string_owner,
 *     never in string memory.  The four bytes at payload - 4 hold a
 *     host-defined uint32: the payload's byte offset from the raw base (5..8).
 *     That value is not the original 32-bit raw address and not a host
 *     pointer.  It carries no authority and this runtime never reads it back.
 *     Nothing is inferred by reading memory in front of source data.
 *   - The allocator (context, allocate, release, optional observer) is
 *     captured by value at successful construction.  Cleanup uses that
 *     captured copy even if the caller later edits its allocator object.
 *   - The observer receives the released raw base as an integer identity
 *     plus the byte count.  It is not the original (raw, 0) callback ABI.
 *   - Every failure is a fail-safe status returned before any effect, or
 *     after a full rollback.  This includes negative or oversize lengths,
 *     NULL nonempty data, invalid owners, occupied destinations, allocation
 *     failure and count overflow.  The original's behaviour on those routes
 *     (exceptions, 32-bit wrap-around, undefined behaviour) is not emulated.
 *   - Length limits keep every request representable in 32 bits, as in the
 *     original: narrow <= INT32_MAX, UTF-16 <= (UINT32_MAX - 10) / 2.
 *   - destroy publishes the empty sentinel into a supplied descriptor.  The
 *     original left a dangling descriptor.
 *   - The narrow string-vector API is wholly host-defined.  The original
 *     vector layout and growth policy are NOT reproduced.
 *   - Nothing here makes any whole original constructor (unit card, entity,
 *     ...) equivalent.  A consumer is equivalent only for what it proves.
 *
 * Owner contract (non-copyable, address-bound)
 * --------------------------------------------
 * An owner is a unique, address-bound capability.  Start it as all-zero
 * (ROME2_OWNED_STRING_OWNER_INIT, static storage, or memset 0), which is the
 * canonical VACANT state.  Never duplicate it with struct assignment or
 * memcpy.  Transfer it only with *_move.  Every API checks that a LIVE owner
 * still sits at the address it was created or moved to.  A byte copy at a
 * different address is therefore rejected as INVALID_OWNER and cannot
 * release.  This is detection, not prevention.  C cannot stop a program from
 * writing a stale byte snapshot back to the original address after that owner
 * was moved or destroyed, and such a resurrected owner would release a second
 * time.  Relocating a LIVE owner by raw copy (for example realloc of an array
 * that contains it) also invalidates it.  The allocation then leaks instead of
 * being released twice.  Use *_move to relocate.
 *
 * A LIVE owner also pins its published descriptor.  The descriptor must keep
 * exactly {length, length, payload} until it is moved or destroyed.  This
 * runtime provides no in-place mutation.
 *
 * Callback contract
 * -----------------
 * allocate(context, byte_count, class) returns NULL or a pointer to at least
 * byte_count writable bytes of any alignment.  The memory must not overlap
 * any live object passed to this API.  release(context, raw, byte_count,
 * class) is called exactly once per successful allocation, with the exact
 * values from that allocation.  release_observer(observer_context, identity,
 * byte_count) runs after release.  identity is the released raw base as an
 * integer and must never be dereferenced.  Callbacks must return normally,
 * must not mutate the source, destination or owner objects of the call in
 * progress, and must not re-enter this API on those objects.  An owner is
 * already consumed (VACANT) before release runs.  No API here is thread-safe;
 * callers must synchronise access to each descriptor, owner and vector.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

_Static_assert(sizeof(void *) == 8, "owned_string is an x64 host runtime");

/* ------------------------------------------------------------------------ */
/* Host descriptors (x64).                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Host narrow descriptor.  Same field order as the 12-byte guest layout, but
 * data is a native pointer, so the record is 16 bytes with data at +8.  This
 * byte layout matches rome2_recovered_str in ported_10145c70_unitcard.h.  It
 * is still a distinct C type, so do not access one through a pointer to the
 * other.
 */
typedef struct rome2_host_string8 {
    int32_t length;            /* +0  bytes, excluding the terminator */
    int32_t capacity;          /* +4  equals length for owned copies */
    const char *data;          /* +8  readable, zero-terminated at [length] */
} rome2_host_string8;

/* Host UTF-16 descriptor; units are opaque uint16_t, never validated. */
typedef struct rome2_host_string16 {
    int32_t length_units;      /* +0  units, excluding the terminator */
    int32_t capacity_units;    /* +4  equals length_units for owned copies */
    const uint16_t *data;      /* +8  readable, zero unit at [length_units] */
} rome2_host_string16;

_Static_assert(sizeof(rome2_host_string8) == 16, "x64 narrow descriptor");
_Static_assert(offsetof(rome2_host_string8, length) == 0, "length at +0");
_Static_assert(offsetof(rome2_host_string8, capacity) == 4, "capacity at +4");
_Static_assert(offsetof(rome2_host_string8, data) == 8, "data at +8");
_Static_assert(sizeof(rome2_host_string16) == 16, "x64 UTF-16 descriptor");
_Static_assert(offsetof(rome2_host_string16, length_units) == 0,
    "length_units at +0");
_Static_assert(offsetof(rome2_host_string16, capacity_units) == 4,
    "capacity_units at +4");
_Static_assert(offsetof(rome2_host_string16, data) == 8, "data at +8");

/*
 * Native empty sentinels: real, readable, zero-filled host objects.  They
 * are the native counterparts of the original empty-sentinel roles, are
 * never owned, and are never passed to any release callback.
 */
extern const char rome2_host_string8_empty_sentinel[1];
extern const uint16_t rome2_host_string16_empty_sentinel[1];

/* Borrowed, explicit-length source views.  Nothing is read beyond length. */
typedef struct rome2_string8_view {
    const char *data;          /* may be NULL only when length == 0 */
    ptrdiff_t length;          /* bytes; zero bytes are ordinary data */
} rome2_string8_view;

typedef struct rome2_string16_view {
    const uint16_t *data;      /* may be NULL only when length_units == 0 */
    ptrdiff_t length_units;    /* opaque 16-bit units */
} rome2_string16_view;

/* ------------------------------------------------------------------------ */
/* Limits and constants.                                                     */
/* ------------------------------------------------------------------------ */

#define ROME2_OWNED_STRING_ALLOCATION_CLASS   UINT32_C(0)
#define ROME2_OWNED_STRING_PAYLOAD_ALIGNMENT  4u
/* Narrow request length + 9 stays <= 0x80000008. */
#define ROME2_OWNED_STRING8_MAX_LENGTH        INT32_C(0x7FFFFFFF)
/* UTF-16 request 2 * length + 10 stays <= 0xFFFFFFFE. */
#define ROME2_OWNED_STRING16_MAX_UNITS        INT32_C(0x7FFFFFFA)
/* Host vector bound, matching the 32-bit index width of the original. */
#define ROME2_OWNED_STRING8_VECTOR_MAX_COUNT  ((size_t)INT32_MAX)

/* Owner and vector states.  All-zero is VACANT (owns nothing). */
#define ROME2_OWNED_STRING_STATE_VACANT       UINT32_C(0)
#define ROME2_OWNED_STRING_STATE_LIVE         UINT32_C(0x4C495645)
#define ROME2_OWNED_STRING8_VECTOR_STATE_LIVE UINT32_C(0x56454354)
#define ROME2_OWNED_STRING_KIND_NONE          UINT32_C(0)
#define ROME2_OWNED_STRING_KIND_NARROW        UINT32_C(1)
#define ROME2_OWNED_STRING_KIND_UTF16         UINT32_C(2)

typedef enum rome2_owned_string_status {
    ROME2_OWNED_STRING_OK = 0,
    /* A required pointer is NULL, or objects alias or overlap illegally. */
    ROME2_OWNED_STRING_BAD_ARGUMENT = 1,
    ROME2_OWNED_STRING_NEGATIVE_LENGTH = 2,
    ROME2_OWNED_STRING_LENGTH_OUT_OF_RANGE = 3,
    /* NULL data with a nonzero length. */
    ROME2_OWNED_STRING_NULL_DATA = 4,
    /* Vector count above the bound or byte arithmetic would overflow. */
    ROME2_OWNED_STRING_COUNT_OUT_OF_RANGE = 5,
    /* Allocator missing, or its allocate/release callback is NULL. */
    ROME2_OWNED_STRING_INVALID_ALLOCATOR = 6,
    /* Owner/vector record is neither canonical VACANT nor a coherent LIVE
     * record bound at this address for this kind. */
    ROME2_OWNED_STRING_INVALID_OWNER = 7,
    /* Destination owner/vector is LIVE; destroy or move it out first. */
    ROME2_OWNED_STRING_DESTINATION_OCCUPIED = 8,
    /* Descriptor does not equal what its owner published. */
    ROME2_OWNED_STRING_DESCRIPTOR_MISMATCH = 9,
    /* allocate returned NULL; any partial work was rolled back. */
    ROME2_OWNED_STRING_ALLOCATION_FAILED = 10
} rome2_owned_string_status;

/* ------------------------------------------------------------------------ */
/* Allocator and owner.                                                      */
/* ------------------------------------------------------------------------ */

typedef void *(*rome2_owned_string_allocate_fn)(
    void *context, size_t byte_count, uint32_t allocation_class);
typedef void (*rome2_owned_string_release_fn)(
    void *context, void *raw_base, size_t byte_count,
    uint32_t allocation_class);
typedef void (*rome2_owned_string_observer_fn)(
    void *observer_context, uintptr_t released_raw_identity,
    size_t byte_count);

typedef struct rome2_owned_string_allocator {
    rome2_owned_string_allocate_fn allocate;          /* required */
    rome2_owned_string_release_fn release;            /* required */
    void *context;
    rome2_owned_string_observer_fn release_observer;  /* optional */
    void *observer_context;
} rome2_owned_string_allocator;

/*
 * Treat every member as private.  It is visible only so that callers can
 * declare storage, and so that tests can audit it.
 */
typedef struct rome2_owned_string_owner rome2_owned_string_owner;
struct rome2_owned_string_owner {
    uint32_t state;                          /* VACANT or STATE_LIVE */
    uint32_t kind;                           /* KIND_NONE/NARROW/UTF16 */
    int32_t length;                          /* units, 1..max when LIVE */
    uint32_t reserved;                       /* always 0 */
    const rome2_owned_string_owner *self;    /* address binding */
    void *raw_base;                          /* exact allocate() result */
    const void *payload;                     /* (raw + 8) & ~3 */
    size_t allocation_bytes;                 /* exact request */
    rome2_owned_string_allocator allocator;  /* captured at construction */
};

_Static_assert(sizeof(rome2_owned_string_allocator) == 40,
    "allocator record has no padding on x64");
_Static_assert(sizeof(rome2_owned_string_owner) == 88,
    "owner record has no padding on x64");
_Static_assert(offsetof(rome2_owned_string_owner, self) == 16, "owner.self");
_Static_assert(offsetof(rome2_owned_string_owner, raw_base) == 24,
    "owner.raw_base");
_Static_assert(offsetof(rome2_owned_string_owner, allocation_bytes) == 40,
    "owner.allocation_bytes");
_Static_assert(offsetof(rome2_owned_string_owner, allocator) == 48,
    "owner.allocator");

#define ROME2_OWNED_STRING_OWNER_INIT { 0 }

/* ------------------------------------------------------------------------ */
/* Descriptor helpers.                                                       */
/* ------------------------------------------------------------------------ */

/* {0, 0, native empty sentinel}; owns nothing. */
rome2_host_string8 rome2_host_string8_empty(void);
rome2_host_string16 rome2_host_string16_empty(void);

/* Borrow {data, length} from a descriptor.  capacity is not used. */
rome2_string8_view rome2_host_string8_as_view(rome2_host_string8 descriptor);
rome2_string16_view rome2_host_string16_as_view(
    rome2_host_string16 descriptor);

/* True only for a coherent LIVE owner bound at this address. */
bool rome2_owned_string_owner_is_live(const rome2_owned_string_owner *owner);

/* ------------------------------------------------------------------------ */
/* Single strings.                                                           */
/* ------------------------------------------------------------------------ */

/*
 * Deep-copy `source` into a new owned string.
 *
 * Preconditions, all checked before any effect:
 *   - destination and destination_owner are non-NULL and do not overlap;
 *   - destination_owner is canonical VACANT (LIVE -> DESTINATION_OCCUPIED,
 *     anything else -> INVALID_OWNER);
 *   - 0 <= source length <= the kind's maximum, and data is non-NULL when
 *     the length is nonzero;
 *   - when the length is nonzero, allocator is non-NULL with allocate and
 *     release set.  A non-NULL allocator is validated even for length 0.
 *
 * Length 0: writes the empty descriptor.  No allocation; the owner stays
 * VACANT.
 * Otherwise: makes exactly one allocate(context, request, class 0) call.
 * NULL -> ALLOCATION_FAILED with destination and owner byte-for-byte
 * unchanged.  On success the payload is built, *destination becomes
 * {n, n, payload} and the owner becomes LIVE with the captured allocator.
 * The source is read once and never retained or released.  It may alias
 * the destination's previous (unowned) content.
 */
rome2_owned_string_status rome2_owned_string8_copy(
    rome2_host_string8 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_string8_view source,
    const rome2_owned_string_allocator *allocator);

rome2_owned_string_status rome2_owned_string16_copy(
    rome2_host_string16 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_string16_view source,
    const rome2_owned_string_allocator *allocator);

/*
 * Transfer ownership without copying or allocating.
 *
 * Self-move (same descriptor and same owner) validates the pair and changes
 * nothing.  Otherwise all four objects must be pairwise disjoint.  The source
 * must be a coherent pair: a LIVE owner with its published descriptor, or a
 * VACANT owner with exactly the empty descriptor.  The destination owner must
 * be VACANT.  On success the destination receives the descriptor and the
 * owner, rebound to destination_owner.  The source becomes the empty
 * descriptor plus a VACANT owner, and destroying it is a harmless no-op.
 * Every failure leaves all four objects unchanged.
 */
rome2_owned_string_status rome2_owned_string8_move(
    rome2_host_string8 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_host_string8 *source,
    rome2_owned_string_owner *source_owner);

rome2_owned_string_status rome2_owned_string16_move(
    rome2_host_string16 *destination,
    rome2_owned_string_owner *destination_owner,
    rome2_host_string16 *source,
    rome2_owned_string_owner *source_owner);

/*
 * Release an owned string exactly once.  The operation is idempotent.
 *
 * A VACANT owner: returns OK with no effect.  descriptor is not touched.
 * A LIVE owner: if descriptor is non-NULL it must equal the published
 * {n, n, payload} (else DESCRIPTOR_MISMATCH, no effect).  Pass NULL when the
 * descriptor's storage no longer exists.  The owner is consumed (set to
 * VACANT) and the descriptor, if any, is set to the empty descriptor.  Only
 * then does the captured release(context, raw, bytes, class 0) run, followed
 * by the captured optional observer.  A further destroy returns OK without
 * effect.  An owner of the other kind, or any incoherent owner, is rejected
 * as INVALID_OWNER with no effect.
 */
rome2_owned_string_status rome2_owned_string8_destroy(
    rome2_host_string8 *descriptor,
    rome2_owned_string_owner *owner);

rome2_owned_string_status rome2_owned_string16_destroy(
    rome2_host_string16 *descriptor,
    rome2_owned_string_owner *owner);

/* ------------------------------------------------------------------------ */
/* Owned narrow string vector (host-defined container).                      */
/* ------------------------------------------------------------------------ */

/*
 * One allocation holds `count` descriptors (stride 16), followed by `count`
 * owners, after alignment of the raw base up to 8 bytes:
 *   request = count * (16 + 88) + 7, in allocator class 0.
 * items[i]/owners[i] are an ordinary descriptor/owner pair.  Read
 * items[i] freely.  A pair may be moved out with rome2_owned_string8_move
 * (it becomes empty), or an owned string from any allocator may be moved
 * into a VACANT slot.  Each element is released with the allocator captured
 * by its own owner.  The storage is released with the vector's captured
 * allocator.  The observer is notified for string payloads only, never for
 * the storage.  The address-bound, non-copyable owner contract applies to
 * the vector record itself as well.  All-zero is VACANT, which is also the
 * representation of an empty vector.
 */
typedef struct rome2_owned_string8_vector rome2_owned_string8_vector;
struct rome2_owned_string8_vector {
    rome2_host_string8 *items;               /* NULL when VACANT */
    rome2_owned_string_owner *owners;        /* NULL when VACANT */
    size_t count;                            /* 0 when VACANT */
    uint32_t state;                          /* VACANT or VECTOR_STATE_LIVE */
    uint32_t reserved;                       /* always 0 */
    const rome2_owned_string8_vector *self;  /* address binding */
    void *storage_raw;                       /* exact allocate() result */
    size_t storage_bytes;                    /* exact request */
    rome2_owned_string_allocator allocator;  /* captured at construction */
};

_Static_assert(sizeof(rome2_owned_string8_vector) == 96,
    "vector record has no padding on x64");
_Static_assert(offsetof(rome2_owned_string8_vector, allocator) == 56,
    "vector.allocator");

#define ROME2_OWNED_STRING8_VECTOR_INIT { 0 }

/*
 * Deep-copy `count` borrowed source descriptors.  Only length and data are
 * read; capacity is ignored and each copy gets capacity = length.
 *
 * Checked before any allocation or source-data read:
 *   - destination is non-NULL and VACANT;
 *   - count <= ROME2_OWNED_STRING8_VECTOR_MAX_COUNT and the storage
 *     arithmetic does not overflow;
 *   - source is non-NULL and allocator is valid when count > 0;
 *   - every element's length and data, as for rome2_owned_string8_copy.
 * count == 0 succeeds with no allocation and leaves the destination VACANT.
 *
 * If any allocation fails, every element copied so far and the storage are
 * released through the same captured allocator.  ALLOCATION_FAILED is then
 * returned with the destination and the source unchanged.
 */
rome2_owned_string_status rome2_owned_string8_vector_copy(
    rome2_owned_string8_vector *destination,
    const rome2_host_string8 *source,
    size_t count,
    const rome2_owned_string_allocator *allocator);

/* Ownership transfer with the same contract as rome2_owned_string8_move. */
rome2_owned_string_status rome2_owned_string8_vector_move(
    rome2_owned_string8_vector *destination,
    rome2_owned_string8_vector *source);

/*
 * Idempotent destruction.  Before any effect, this validates the vector
 * record and every element pair: each owner must be VACANT, or LIVE NARROW
 * with a matching descriptor.  It then consumes the record, releases each
 * LIVE element (release, then observer, then the next element) and releases
 * the storage last.
 */
rome2_owned_string_status rome2_owned_string8_vector_destroy(
    rome2_owned_string8_vector *vector);

#endif /* ROME2_RECOVERED_OWNED_STRING_H */
