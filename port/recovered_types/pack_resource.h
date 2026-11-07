#ifndef ROME2_RECOVERED_PACK_RESOURCE_H
#define ROME2_RECOVERED_PACK_RESOURCE_H

#include "owned_string.h"

/* Host PFH4 adapter, not an overlay of the game's archive manager. Supports
 * plain PFH4 types 0..4, optionally with 0x40 per-entry timestamps. Encrypted,
 * extended and unknown flags are explicitly unsupported. Paths compare with
 * ASCII case folding and slash normalization; no files are extracted to disk.
 * Duplicate matching paths or malformed indices/payload ranges are rejected.
 * All entries are validated before the requested payload is published.
 * The caller explicitly selects archive precedence outside this API. */
typedef struct rome2_pack_blob rome2_pack_blob;
typedef struct rome2_pack_blob_view {
    const unsigned char *data;
    size_t size;
    uint64_t archive_offset;
} rome2_pack_blob_view;
typedef enum rome2_pack_status {
    ROME2_PACK_OK = 0,
    ROME2_PACK_BAD_ARGUMENT,
    ROME2_PACK_INVALID_ALLOCATOR,
    ROME2_PACK_IO_ERROR,
    ROME2_PACK_UNSUPPORTED,
    ROME2_PACK_CORRUPT,
    ROME2_PACK_NOT_FOUND,
    ROME2_PACK_LIMIT_EXCEEDED,
    ROME2_PACK_ALLOCATION_FAILED
} rome2_pack_status;

/* out must point to a NULL handle. On error it stays unchanged. index limit is
 * 64 MiB; payload limit is supplied by the caller. Paths are NUL-terminated
 * UTF-16 (archive) and UTF-8 (virtual). No process locale changes. Captured
 * class-zero allocator, arbitrary raw alignment, exact releases; no string
 * observer for archive metadata or raw bytes. destroy consumes the handle.
 * No callback reentry or concurrent mutation; see owned_string.h. */
rome2_pack_status rome2_pack_read_file(rome2_pack_blob **out,
    const uint16_t *archive_path, const char *virtual_path, size_t maximum_bytes,
    const rome2_owned_string_allocator *allocator);
const rome2_pack_blob_view *rome2_pack_blob_get(const rome2_pack_blob *blob);
rome2_pack_status rome2_pack_blob_destroy(rome2_pack_blob **blob);

#endif
