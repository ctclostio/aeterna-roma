#ifndef ROME2_RECOVERED_OWNED_ENTITY_H
#define ROME2_RECOVERED_OWNED_ENTITY_H

/*
 * owned_entity - owning native consumer of the owned_string runtime for the
 * bounded host projection of FUN_10cbe350 (port/x64_ported/
 * ported_10cbe350_entity.h).
 *
 * The existing projection borrows its string data and owns only the item
 * vector metadata.  This adapter publishes the same native
 * rome2_battle_entity, but owns everything it points to:
 *
 *   - Nine string members are independent owned copies made by
 *     rome2_owned_string8_copy:
 *       effect_name, category, label, descriptor_text, climate.name,
 *       climate.name_alt, label_alt, effect_kind, source_name.
 *     Empty members use the readable native sentinel
 *     rome2_host_string8_empty_sentinel ({0, 0, ""}).  No published member
 *     keeps the image-sentinel identity that the old projection writes for
 *     empty strings.
 *   - Every item is deep-copied by rome2_owned_string8_vector_copy.
 *     entity.items is a separate rome2_recovered_str array.  Each element's
 *     fields are copied explicitly from the owned vector's rome2_host_string8
 *     descriptors.  The two types are never aliased or cast.
 *   - Scalar fields come from the unchanged rome2_battle_entity_ctor.  It runs
 *     into private storage with a substituted count-zero arg10 descriptor, so
 *     its allocation callbacks are never used.  The adapter then replaces all
 *     nine strings and the items field.
 *
 * Scope
 * -----
 * This is a checked host adapter, NOT an equivalence claim for the original
 * FUN_10cbe350 constructor.  It does not reproduce raw write order, the
 * original allocation requests or allocation-failure behaviour, callable
 * vtables, or the incoming by-value arg06..arg08 string destructor.
 * arg06..arg08 are never read or released.  The caller keeps ownership of
 * that string and of every other source; nothing borrowed is ever freed.
 *
 * Ownership and allocation
 * ------------------------
 * The handle is heap-allocated through the supplied allocator.  Its owned
 * string records stay at one address for their whole lifetime and never move
 * through a struct copy.  *allocator is read once and captured by value.  The
 * captured copy serves every allocation and release: the handle record, a
 * transient borrowed-view array (released before create returns), the
 * owned-vector storage, the native items array and every string payload.  A
 * later change to the caller's allocator object has no effect.  All requests
 * use allocation class ROME2_OWNED_STRING_ALLOCATION_CLASS.  Metadata blocks
 * accept any returned alignment; this adapter aligns within them.  As
 * owned_string specifies, release_observer is notified for string payloads
 * only, never for metadata blocks.  The callback contract of owned_string.h
 * applies: callbacks are total and non-reentrant, and must not touch any
 * object of a call in progress.  Nothing here is thread-safe.
 *
 * Accepted input
 * --------------
 * All input is validated before any allocator effect:
 *   - out_handle, args and allocator (with allocate and release) non-NULL;
 *   - arg00, arg11 and arg17 are each NULL (empty), or a descriptor with
 *     length >= 0, capacity >= length, and non-NULL data when length > 0.
 *     Data of an empty descriptor is never read and may be any value;
 *   - arg10 NULL (no items), or item_count <= ROME2_ENTITY_MAX_ITEM_COUNT
 *     with non-NULL items when nonzero, and every item well-formed as above;
 *   - arg01, arg09 and globals keep the old projection's contract (NULL means
 *     zero / image defaults).
 * Every source must be readable for the duration of the call and must not
 * overlap memory returned by the allocator.  Sources are only read.
 */

#include <stdint.h>

#include "owned_string.h"
#include "../x64_ported/ported_10cbe350_entity.h"

/* Opaque, heap-owned and address-bound.  Never copy the record itself. */
typedef struct rome2_owned_battle_entity rome2_owned_battle_entity;

typedef enum rome2_owned_entity_status {
    ROME2_OWNED_ENTITY_OK = 0,
    /* out_handle, args or the destroy pointer-to-handle is NULL. */
    ROME2_OWNED_ENTITY_BAD_ARGUMENT = 1,
    /* allocator is NULL, or its allocate or release callback is NULL. */
    ROME2_OWNED_ENTITY_INVALID_ALLOCATOR = 2,
    /* A string descriptor has negative length or capacity, capacity below
     * length, or NULL data with a nonzero length. */
    ROME2_OWNED_ENTITY_MALFORMED_STRING = 3,
    /* arg10 has a nonzero item_count with NULL items. */
    ROME2_OWNED_ENTITY_MALFORMED_DESCRIPTOR = 4,
    /* item_count above ROME2_ENTITY_MAX_ITEM_COUNT, or size arithmetic
     * would overflow. */
    ROME2_OWNED_ENTITY_COUNT_OUT_OF_RANGE = 5,
    /* allocate returned NULL; every acquired resource was released once. */
    ROME2_OWNED_ENTITY_ALLOCATION_FAILED = 6,
    /* destroy found no coherent LIVE handle at that address; nothing done. */
    ROME2_OWNED_ENTITY_INVALID_HANDLE = 7,
    /* An internal invariant failed (for example the old projection rejected
     * validated input).  create releases everything it acquired.  destroy
     * releases every coherent resource and leaks any corrupted owner rather
     * than releasing it twice. */
    ROME2_OWNED_ENTITY_INTERNAL_ERROR = 8
} rome2_owned_entity_status;

/*
 * Build an owned entity.  On ROME2_OWNED_ENTITY_OK, *out_handle receives the
 * new handle.  On every other status, *out_handle is not written (its prior
 * value is never read), no source is modified, and no allocation remains
 * live.  A previous handle in *out_handle is not released.  Destroy it first.
 */
rome2_owned_entity_status rome2_owned_battle_entity_create(
    rome2_owned_battle_entity **out_handle,
    const rome2_entity_ctor_args *args,
    const rome2_entity_globals *globals,
    const rome2_owned_string_allocator *allocator);

/* Native deep-copy counterpart of FUN_101350c0's admitted entity prefix.
 * Reconstructs the fixed dispatch identities and the two literal names, so
 * source.effect_name, source.climate.name, source dispatch words and field_00c
 * are not read. All seven other strings and the item strings are independent
 * owned copies. The observed scalar fields, including field_050, preserve
 * their bits; unobserved gaps use the native projection's zero-fill policy.
 * Source item_capacity is ignored; source item_count is the guest +0xb8 count.
 * The output capacity equals that count. Input validation, captured allocators,
 * failure atomicity and destroy/get use the same rules as create above.
 * This does not reproduce scratch-string allocations, original write order,
 * exceptions, or callable virtual methods.
 */
rome2_owned_entity_status rome2_owned_battle_entity_copy(
    rome2_owned_battle_entity **out_handle,
    const rome2_battle_entity *source,
    const rome2_owned_string_allocator *allocator);

/* Pure validation of the attachment copy's seven strings and item vector. */
rome2_owned_entity_status rome2_battle_entity_copy_source_validate(const rome2_battle_entity *source);

/*
 * Const view of the native projection, valid until the handle is destroyed.
 * Returns NULL for NULL or for a handle that is not LIVE.  Every published
 * string, including items[i], is readable with a zero byte at data[length],
 * and capacity == length.  The record and the strings and items it reaches
 * are read-only to callers.  Release bookkeeping is held separately, so a
 * stray write to the view cannot redirect a release.  Never pass the view to
 * rome2_battle_entity_release_items(): this adapter, not an entity host, owns
 * the items array.
 */
const rome2_battle_entity *rome2_owned_battle_entity_get(
    const rome2_owned_battle_entity *handle);

/*
 * Idempotent destruction through a pointer-to-handle.
 *   handle == NULL           -> BAD_ARGUMENT, no effect.
 *   *handle == NULL          -> OK, no effect (repeated destroy).
 *   *handle not a coherent LIVE record -> INVALID_HANDLE, no effect.
 *   otherwise *handle is set to NULL.  Then each owned item string, the vector
 *   storage, each owned scalar string, the native items array and finally
 *   the handle record are released through the allocator captured at create.
 * Destroy each handle through one pointer variable.  Another copy of the
 * pointer dangles afterwards, and passing it here is undefined behaviour.
 */
rome2_owned_entity_status rome2_owned_battle_entity_destroy(
    rome2_owned_battle_entity **handle);

#endif /* ROME2_RECOVERED_OWNED_ENTITY_H */
