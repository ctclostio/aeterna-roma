#include "pack_resource.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/*
 * Host PFH4 reader.  Frozen plain PFH4 layout (supplied by root):
 *   header (28 bytes, little endian): "PFH4", type_flags, dependency_count,
 *   dependency_index_bytes, file_count, file_index_bytes, timestamp.
 *   dependency index: dependency_count nonempty NUL-terminated names that
 *   consume exactly dependency_index_bytes.
 *   file index: file_count entries {u32 size, [u32 timestamp if 0x40],
 *   nonempty NUL-terminated path} that consume exactly file_index_bytes.
 *   payloads: sequential in entry order from 28 + both index sizes.
 *
 * Host policy (not original game behaviour):
 *   - Validation order: arguments, allocator, open, file length,
 *     short header (CORRUPT, any file under 28 bytes), magic and flags
 *     (UNSUPPORTED), aggregate index cap (LIMIT_EXCEEDED), count/size
 *     contradictions and index-beyond-EOF (CORRUPT), then one index
 *     allocation, full index scan, payload range checks for every entry,
 *     the per-call payload limit, and only then the result allocation.
 *   - The index buffer is released before the result is allocated.
 *   - Entry path bytes are opaque except for NUL; UTF-8 is not validated.
 *     Duplicate non-target paths are not detected; duplicate target matches
 *     are CORRUPT.
 *   - Result = one class-0 grant: the private handle at the first 8-aligned
 *     address of the grant, followed by the payload.  Release authority is
 *     the private {raw, raw_bytes, allocator}; the published view is never
 *     read for liveness or release.  No release observer is ever called.
 *   - A zero-size payload publishes a static readable byte sentinel.
 */

_Static_assert(sizeof(wchar_t) == sizeof(uint16_t), "Windows UTF-16 paths");
_Static_assert(_Generic((const wchar_t *)0, const uint16_t *: 1, default: 0),
    "wchar_t and uint16_t are the same type on MSVC");

#define PACK_HEADER_BYTES 28u
#define PACK_INDEX_LIMIT (UINT64_C(64) * 1024u * 1024u)
#define PACK_TYPE_MASK UINT32_C(0x7)
#define PACK_TYPE_MAX UINT32_C(4)
#define PACK_FLAG_TIMESTAMPS UINT32_C(0x40)
#define PACK_BLOB_LIVE UINT32_C(0x50464834)

struct rome2_pack_blob {
    uint32_t state;                          /* PACK_BLOB_LIVE or 0 */
    uint32_t reserved;
    const rome2_pack_blob *self;             /* address binding */
    void *raw;                               /* exact allocate() result */
    size_t raw_bytes;                        /* exact request */
    size_t payload_bytes;                    /* private copy of the size */
    rome2_owned_string_allocator allocator;  /* captured by value */
    rome2_pack_blob_view view;               /* published, never trusted */
};

_Static_assert(sizeof(rome2_pack_blob) % 8u == 0, "payload follows 8-aligned");

typedef struct pack_header {
    uint32_t flags;
    uint32_t dependency_count;
    uint32_t dependency_bytes;
    uint32_t file_count;
    uint32_t file_bytes;
} pack_header;

typedef struct pack_target {
    uint64_t offset;
    uint32_t size;
} pack_target;

static const unsigned char pack_empty_sentinel[1] = {0};

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void *align8(void *raw)
{
    const size_t residue = (size_t)((uintptr_t)raw % 8u);
    return (unsigned char *)raw + (residue == 0 ? 0 : 8u - residue);
}

static size_t blob_request(size_t payload_bytes)
{
    return sizeof(rome2_pack_blob) + 7u + payload_bytes;
}

static bool live(const rome2_pack_blob *b)
{
    return b != NULL && b->state == PACK_BLOB_LIVE && b->reserved == 0 &&
        b->self == b && b->raw != NULL && align8(b->raw) == (const void *)b &&
        b->payload_bytes <= UINT32_MAX &&
        b->raw_bytes == blob_request(b->payload_bytes) &&
        b->allocator.allocate != NULL && b->allocator.release != NULL;
}

/* ASCII A..Z fold to a..z and '\\' equals '/'; every other byte is exact. */
static unsigned char fold(unsigned char c)
{
    if (c >= 0x41u && c <= 0x5au) { return (unsigned char)(c + 0x20u); }
    return c == 0x5cu ? (unsigned char)0x2fu : c;
}

static bool names_equal(const unsigned char *entry, size_t entry_length,
    const char *name, size_t name_length)
{
    size_t i;
    if (entry_length != name_length) { return false; }
    for (i = 0; i < entry_length; ++i) {
        if (fold(entry[i]) != fold((unsigned char)name[i])) { return false; }
    }
    return true;
}

static rome2_pack_status file_length(FILE *file, uint64_t *size)
{
    __int64 end;
    if (_fseeki64(file, 0, SEEK_END) != 0) { return ROME2_PACK_IO_ERROR; }
    end = _ftelli64(file);
    if (end < 0 || _fseeki64(file, 0, SEEK_SET) != 0) { return ROME2_PACK_IO_ERROR; }
    *size = (uint64_t)end;
    return ROME2_PACK_OK;
}

/* Exact consumption of one nonempty NUL-terminated name inside [*cursor, end). */
static bool take_name(const unsigned char *index, size_t *cursor, size_t end,
    const unsigned char **name, size_t *length)
{
    const unsigned char *begin = index + *cursor;
    const unsigned char *nul;
    if (*cursor >= end) { return false; }
    nul = memchr(begin, 0, end - *cursor);
    if (nul == NULL || nul == begin) { return false; }
    *name = begin;
    *length = (size_t)(nul - begin);
    *cursor += *length + 1u;
    return true;
}

static rome2_pack_status scan_index(const unsigned char *index, const pack_header *h,
    uint64_t file_size, const char *name, size_t name_length, pack_target *target)
{
    const size_t fixed = (h->flags & PACK_FLAG_TIMESTAMPS) != 0 ? 8u : 4u;
    size_t cursor = 0, end = h->dependency_bytes, length;
    uint64_t offset = (uint64_t)PACK_HEADER_BYTES + h->dependency_bytes + h->file_bytes;
    const unsigned char *path;
    bool found = false;
    uint32_t i;
    for (i = 0; i < h->dependency_count; ++i) {
        if (!take_name(index, &cursor, end, &path, &length)) { return ROME2_PACK_CORRUPT; }
    }
    if (cursor != end) { return ROME2_PACK_CORRUPT; }
    end += h->file_bytes;
    /* Invariant: offset <= file_size (the caller proved the index fits). */
    for (i = 0; i < h->file_count; ++i) {
        uint32_t size;
        if (end - cursor < fixed) { return ROME2_PACK_CORRUPT; }
        size = le32(index + cursor);
        cursor += fixed;
        if (!take_name(index, &cursor, end, &path, &length)) { return ROME2_PACK_CORRUPT; }
        if ((uint64_t)size > file_size - offset) { return ROME2_PACK_CORRUPT; }
        if (names_equal(path, length, name, name_length)) {
            if (found) { return ROME2_PACK_CORRUPT; }
            found = true;
            target->offset = offset;
            target->size = size;
        }
        offset += size;
    }
    if (cursor != end) { return ROME2_PACK_CORRUPT; }
    return found ? ROME2_PACK_OK : ROME2_PACK_NOT_FOUND;
}

static rome2_pack_status locate(FILE *file, const char *name, size_t name_length,
    size_t maximum_bytes, const rome2_owned_string_allocator *a, pack_target *target)
{
    unsigned char header[PACK_HEADER_BYTES];
    pack_header h;
    uint64_t file_size, index_bytes, entry_minimum;
    void *raw;
    rome2_pack_status status = file_length(file, &file_size);
    if (status != ROME2_PACK_OK) { return status; }
    if (file_size < PACK_HEADER_BYTES) { return ROME2_PACK_CORRUPT; }
    if (fread(header, 1, sizeof header, file) != sizeof header) { return ROME2_PACK_IO_ERROR; }
    if (memcmp(header, "PFH4", 4) != 0) { return ROME2_PACK_UNSUPPORTED; }
    h.flags = le32(header + 4);
    h.dependency_count = le32(header + 8);
    h.dependency_bytes = le32(header + 12);
    h.file_count = le32(header + 16);
    h.file_bytes = le32(header + 20);
    if ((h.flags & ~(PACK_TYPE_MASK | PACK_FLAG_TIMESTAMPS)) != 0 ||
        (h.flags & PACK_TYPE_MASK) > PACK_TYPE_MAX) {
        return ROME2_PACK_UNSUPPORTED;
    }
    index_bytes = (uint64_t)h.dependency_bytes + h.file_bytes;
    if (index_bytes > PACK_INDEX_LIMIT) { return ROME2_PACK_LIMIT_EXCEEDED; }
    entry_minimum = (h.flags & PACK_FLAG_TIMESTAMPS) != 0 ? 10u : 6u;
    if ((uint64_t)h.dependency_count * 2u > h.dependency_bytes ||
        (uint64_t)h.file_count * entry_minimum > h.file_bytes ||
        index_bytes > file_size - PACK_HEADER_BYTES) {
        return ROME2_PACK_CORRUPT;
    }
    if (index_bytes == 0) { return ROME2_PACK_NOT_FOUND; } /* no deps, no files */
    raw = a->allocate(a->context, (size_t)index_bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (raw == NULL) { return ROME2_PACK_ALLOCATION_FAILED; }
    if (fread(raw, 1, (size_t)index_bytes, file) != (size_t)index_bytes) {
        status = ROME2_PACK_IO_ERROR;
    } else {
        status = scan_index(raw, &h, file_size, name, name_length, target);
    }
    a->release(a->context, raw, (size_t)index_bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (status == ROME2_PACK_OK && (size_t)target->size > maximum_bytes) {
        status = ROME2_PACK_LIMIT_EXCEEDED;
    }
    return status;
}

static rome2_pack_status load(FILE *file, const pack_target *target,
    const rome2_owned_string_allocator *a, rome2_pack_blob **result)
{
    const size_t payload_bytes = target->size;
    const size_t bytes = blob_request(payload_bytes);
    rome2_pack_blob *b;
    unsigned char *payload;
    void *raw;
    if (_fseeki64(file, (__int64)target->offset, SEEK_SET) != 0) { return ROME2_PACK_IO_ERROR; }
    raw = a->allocate(a->context, bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
    if (raw == NULL) { return ROME2_PACK_ALLOCATION_FAILED; }
    b = align8(raw);
    payload = (unsigned char *)b + sizeof *b;
    if (payload_bytes != 0 && fread(payload, 1, payload_bytes, file) != payload_bytes) {
        a->release(a->context, raw, bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
        return ROME2_PACK_IO_ERROR;
    }
    memset(b, 0, sizeof *b);
    b->state = PACK_BLOB_LIVE;
    b->self = b;
    b->raw = raw;
    b->raw_bytes = bytes;
    b->payload_bytes = payload_bytes;
    b->allocator = *a;
    b->view.data = payload_bytes == 0 ? pack_empty_sentinel : payload;
    b->view.size = payload_bytes;
    b->view.archive_offset = target->offset;
    *result = b;
    return ROME2_PACK_OK;
}

rome2_pack_status rome2_pack_read_file(rome2_pack_blob **out,
    const uint16_t *archive_path, const char *virtual_path, size_t maximum_bytes,
    const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator captured;
    rome2_pack_blob *result = NULL;
    pack_target target = {0, 0};
    FILE *file = NULL;
    rome2_pack_status status;
    if (out == NULL || *out != NULL || archive_path == NULL || archive_path[0] == 0 ||
        virtual_path == NULL || virtual_path[0] == '\0') {
        return ROME2_PACK_BAD_ARGUMENT;
    }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_PACK_INVALID_ALLOCATOR;
    }
    captured = *allocator;
    if (_wfopen_s(&file, archive_path, L"rbN") != 0 || file == NULL) {
        return ROME2_PACK_IO_ERROR;
    }
    status = locate(file, virtual_path, strlen(virtual_path), maximum_bytes, &captured, &target);
    if (status == ROME2_PACK_OK) { status = load(file, &target, &captured, &result); }
    (void)fclose(file);
    if (status == ROME2_PACK_OK) { *out = result; }
    return status;
}

const rome2_pack_blob_view *rome2_pack_blob_get(const rome2_pack_blob *blob)
{
    return live(blob) ? &blob->view : NULL;
}

rome2_pack_status rome2_pack_blob_destroy(rome2_pack_blob **blob)
{
    rome2_owned_string_allocator captured;
    rome2_pack_blob *b;
    size_t bytes;
    void *raw;
    if (blob == NULL) { return ROME2_PACK_BAD_ARGUMENT; }
    b = *blob;
    if (b == NULL) { return ROME2_PACK_OK; }
    if (!live(b)) { return ROME2_PACK_BAD_ARGUMENT; }
    *blob = NULL;
    captured = b->allocator;
    raw = b->raw;
    bytes = b->raw_bytes;
    memset(b, 0, sizeof *b); /* consumed before the release callback runs */
    captured.release(captured.context, raw, bytes, ROME2_OWNED_STRING_ALLOCATION_CLASS);
    return ROME2_PACK_OK;
}
