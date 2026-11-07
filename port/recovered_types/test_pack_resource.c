#include "pack_resource.h"
#include <windows.h>
#include <winioctl.h>
#include "test_support.h"

#include <direct.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <share.h>
#include <sys/stat.h>
#include <wchar.h>

/* Synthetic PFH4 fixtures only; no game archive is read.  Fixtures live in
 * <scratch>\run-<pid>, where <scratch> is argv[1] or, by default, the repo's
 * out\type-layer4-20261103\pack-worker derived from this source path. */

#define PATH_CHARS 600
#define HDR_FLAGS 4u
#define HDR_DEP_COUNT 8u
#define HDR_DEP_BYTES 12u
#define HDR_FILE_COUNT 16u
#define HDR_FILE_BYTES 20u
#define MAX_ENTRIES 16
#define MIB (UINT32_C(1024) * 1024u)

typedef struct image {
    unsigned char bytes[2048];
    size_t size;
} image;
typedef struct entry {
    const char *path;
    const void *data;
    uint32_t size;
} entry;
typedef struct layout {
    size_t index, file_index, data, end;
    size_t entry_at[MAX_ENTRIES];
    size_t payload_at[MAX_ENTRIES];
} layout;
typedef struct recorder {
    test_heap heap;
    size_t sizes[8];
    size_t count;
} recorder;
typedef union handle_storage {
    uint64_t align;
    unsigned char bytes[256];
} handle_storage;

static wchar_t g_dir[PATH_CHARS];
static unsigned g_serial;
static const unsigned char *g_sentinel;

/* ---- fixtures ---------------------------------------------------------- */

static void put(image *m, const void *data, size_t n)
{
    CHECK(n <= sizeof m->bytes - m->size);
    if (n != 0) { memcpy(m->bytes + m->size, data, n); }
    m->size += n;
}

static void put32(image *m, uint32_t v)
{
    const unsigned char b[4] = {(unsigned char)v, (unsigned char)(v >> 8),
        (unsigned char)(v >> 16), (unsigned char)(v >> 24)};
    put(m, b, sizeof b);
}

static void patch32(image *m, size_t at, uint32_t v)
{
    CHECK(at + 4u <= m->size);
    m->bytes[at] = (unsigned char)v;
    m->bytes[at + 1] = (unsigned char)(v >> 8);
    m->bytes[at + 2] = (unsigned char)(v >> 16);
    m->bytes[at + 3] = (unsigned char)(v >> 24);
}

static uint32_t peek32(const image *m, size_t at)
{
    CHECK(at + 4u <= m->size);
    return (uint32_t)m->bytes[at] | ((uint32_t)m->bytes[at + 1] << 8) |
        ((uint32_t)m->bytes[at + 2] << 16) | ((uint32_t)m->bytes[at + 3] << 24);
}

static void build(image *m, layout *l, const char *magic, uint32_t flags,
    const char *const *deps, size_t dep_count, const entry *entries, size_t count,
    const char *trailer)
{
    size_t i;
    memset(m, 0, sizeof *m);
    memset(l, 0, sizeof *l);
    CHECK(count <= MAX_ENTRIES);
    put(m, magic, 4);
    put32(m, flags);
    put32(m, (uint32_t)dep_count);
    put32(m, 0);
    put32(m, (uint32_t)count);
    put32(m, 0);
    put32(m, UINT32_C(0x5eed0004));
    l->index = m->size;
    for (i = 0; i < dep_count; ++i) { put(m, deps[i], strlen(deps[i]) + 1u); }
    patch32(m, HDR_DEP_BYTES, (uint32_t)(m->size - l->index));
    l->file_index = m->size;
    for (i = 0; i < count; ++i) {
        l->entry_at[i] = m->size;
        put32(m, entries[i].size);
        /* Timestamps contain NUL and 'A' bytes; they must be skipped. */
        if ((flags & 0x40u) != 0) { put32(m, i == 0 ? 0 : UINT32_C(0x00410000) + (uint32_t)i); }
        put(m, entries[i].path, strlen(entries[i].path) + 1u);
    }
    patch32(m, HDR_FILE_BYTES, (uint32_t)(m->size - l->file_index));
    l->data = m->size;
    for (i = 0; i < count; ++i) {
        l->payload_at[i] = m->size;
        put(m, entries[i].data, entries[i].size);
    }
    l->end = m->size;
    if (trailer != NULL) { put(m, trailer, strlen(trailer)); }
}

static const char fauna_bytes[] = "<fauna>\0</fauna>";
static const unsigned char accent_bytes[] = {0xc3, 0x89, 0x00, 0xff};
static const entry main_entries[] = {
    {"data/readme.txt", "R1", 2},
    {"Script\\Fauna_Config.XML", fauna_bytes, (uint32_t)(sizeof fauna_bytes - 1u)},
    {"empty.bin", "", 0},
    {"art/\xc3\x89t\xc3\xa9.dds", accent_bytes, (uint32_t)sizeof accent_bytes},
    {"last.txt", "tail", 4},
};
#define MAIN_COUNT (sizeof main_entries / sizeof main_entries[0])
static const char *const main_deps[] = {"base.pack", "Patch\\x.pack"};

typedef struct lookup {
    const char *name;
    int entry;
} lookup;
static const lookup main_lookups[] = {
    {"data/readme.txt", 0}, {"DATA\\README.TXT", 0}, {"Data/ReadMe.Txt", 0},
    {"script/fauna_config.xml", 1}, {"SCRIPT/FAUNA_CONFIG.XML", 1},
    {"script\\fauna_config.xml", 1}, {"Script\\Fauna_Config.XML", 1},
    {"empty.bin", 2}, {"EMPTY.BIN", 2},
    {"art/\xc3\x89t\xc3\xa9.dds", 3}, {"ART\\\xc3\x89T\xc3\xa9.DDS", 3},
    {"last.txt", 4}, {"LAST.txt", 4},
    {"art/\xc3\xa9t\xc3\xa9.dds", -1}, {"art/\xc3\x89t\xc3\x89.dds", -1},
    {"missing.txt", -1}, {"data/readme.tx", -1}, {"data/readme.txt/", -1},
    {"./data/readme.txt", -1}, {"data//readme.txt", -1}, {"data/./readme.txt", -1},
    {"data/x/../readme.txt", -1}, {"/data/readme.txt", -1}, {"data/readme.txt ", -1},
    {"base.pack", -1}, {"Patch\\x.pack", -1}, {"script/fauna_config.xml\x01", -1},
};

static void build_main(image *m, layout *l, uint32_t flags, const char *trailer)
{
    build(m, l, "PFH4", flags, main_deps, 2, main_entries, MAIN_COUNT, trailer);
}

/* ---- files ------------------------------------------------------------- */

static void make_dir(const wchar_t *path)
{
    if (_wmkdir(path) != 0) { CHECK(errno == EEXIST); }
}

static void init_dir(int argc, wchar_t **argv)
{
    wchar_t base[PATH_CHARS];
    if (argc > 1) {
        CHECK(wcscpy_s(base, PATH_CHARS, argv[1]) == 0);
    } else {
        int strip;
        CHECK(wcscpy_s(base, PATH_CHARS, _CRT_WIDE(__FILE__)) == 0);
        for (strip = 0; strip < 3; ++strip) {
            wchar_t *back = wcsrchr(base, L'\\'), *slash = wcsrchr(base, L'/');
            wchar_t *cut = back;
            if (cut == NULL || (slash != NULL && wcslen(slash) < wcslen(cut))) { cut = slash; }
            if (cut == NULL) {
                fprintf(stderr, "relative __FILE__; pass a scratch directory as argv[1]\n");
                exit(1);
            }
            *cut = L'\0';
        }
        CHECK(wcscat_s(base, PATH_CHARS, L"\\out") == 0);
        make_dir(base);
        CHECK(wcscat_s(base, PATH_CHARS, L"\\type-layer4-20261103") == 0);
        make_dir(base);
        CHECK(wcscat_s(base, PATH_CHARS, L"\\pack-worker") == 0);
    }
    make_dir(base);
    CHECK(swprintf_s(g_dir, PATH_CHARS, L"%ls\\run-%d", base, _getpid()) > 0);
    make_dir(g_dir);
}

static void next_path(wchar_t *path)
{
    CHECK(swprintf_s(path, PATH_CHARS, L"%ls\\f%04u.pack", g_dir, ++g_serial) > 0);
}

static void write_bytes(const wchar_t *path, const void *bytes, size_t n)
{
    FILE *f = NULL;
    CHECK(_wfopen_s(&f, path, L"wb") == 0 && f != NULL);
    if (n != 0) { CHECK(fwrite(bytes, 1, n, f) == n); }
    CHECK(fclose(f) == 0);
}

static void write_image(wchar_t *path, const image *m, size_t n)
{
    CHECK(n <= m->size);
    next_path(path);
    write_bytes(path, m->bytes, n);
}

/* Succeeds only when no other handle (for example a leaked FILE) is open. */
static void check_closed(const wchar_t *path)
{
    int fd = -1;
    CHECK(_wsopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYRW, 0) == 0);
    CHECK(_close(fd) == 0);
}

static void remove_file(const wchar_t *path)
{
    CHECK(_wremove(path) == 0); /* also fails if a handle leaked */
}

/* ---- allocator --------------------------------------------------------- */

static void *record_allocate(void *context, size_t bytes, uint32_t allocation_class)
{
    recorder *r = context;
    if (r->count < 8) { r->sizes[r->count] = bytes; }
    ++r->count;
    return test_allocate(&r->heap, bytes, allocation_class);
}

static void record_release(void *context, void *raw, size_t bytes, uint32_t allocation_class)
{
    recorder *r = context;
    test_release(&r->heap, raw, bytes, allocation_class);
}

static rome2_owned_string_allocator record_policy(recorder *r)
{
    rome2_owned_string_allocator p = {record_allocate, record_release, r, test_observer, &r->heap};
    return p;
}

static void recorder_init(recorder *r, unsigned residue, size_t fail_at)
{
    memset(r, 0, sizeof *r);
    r->heap.residue = residue;
    r->heap.fail_at = fail_at;
}

static const test_grant *only_grant(const test_heap *h)
{
    const test_grant *found = NULL;
    size_t i;
    CHECK(h->live == 1);
    for (i = 0; i < 128; ++i) {
        if (h->grants[i].actual != NULL) { CHECK(found == NULL); found = &h->grants[i]; }
    }
    CHECK(found != NULL);
    return found;
}

static bool inside(const test_grant *g, const void *p, size_t n)
{
    const uintptr_t a = (uintptr_t)p, base = (uintptr_t)g->raw;
    return a >= base && n <= g->bytes && a - base <= g->bytes - n;
}

/* ---- expectations ------------------------------------------------------ */

/* Every allocation failure point (index grant, result grant), then success,
 * for raw residues 0..7.  Verifies payload, placement, captured allocator
 * authority, published-view independence and exact release. */
static void expect_payload(const wchar_t *path, const char *name, size_t maximum,
    const void *expected, size_t size, uint64_t offset, size_t index_bytes)
{
    unsigned residue;
    for (residue = 0; residue < 8; ++residue) {
        size_t fail_at;
        for (fail_at = 1; fail_at <= 3; ++fail_at) {
            recorder r, other;
            rome2_owned_string_allocator p;
            rome2_pack_blob *blob = NULL;
            const rome2_pack_blob_view *view;
            rome2_pack_blob_view *published;
            const test_grant *grant;
            uintptr_t grant_raw;
            rome2_pack_status status;
            recorder_init(&r, residue, fail_at);
            recorder_init(&other, residue, 0);
            p = record_policy(&r);
            status = rome2_pack_read_file(&blob, path, name, maximum, &p);
            check_closed(path);
            CHECK(r.heap.observations == 0);
            CHECK(r.count >= 1 && r.sizes[0] == index_bytes);
            if (fail_at < 3) {
                CHECK(status == ROME2_PACK_ALLOCATION_FAILED && blob == NULL);
                CHECK(r.heap.allocations == fail_at && r.heap.live == 0);
                CHECK(r.heap.releases == fail_at - 1u);
                continue;
            }
            CHECK(status == ROME2_PACK_OK && blob != NULL);
            CHECK(r.count == 2 && r.heap.allocations == 2 && r.heap.releases == 1);
            CHECK(r.heap.peak == 1); /* index released before the result grant */
            grant = only_grant(&r.heap);
            grant_raw = (uintptr_t)grant->raw;
            CHECK(grant->bytes == r.sizes[1] && r.sizes[1] >= size + 7u);
            view = rome2_pack_blob_get(blob);
            CHECK(view != NULL && view == rome2_pack_blob_get(blob));
            CHECK(inside(grant, blob, 8) && (uintptr_t)blob % 8u == 0);
            CHECK(inside(grant, view, sizeof *view) && (uintptr_t)view % 8u == 0);
            CHECK(view->size == size && view->archive_offset == offset && view->data != NULL);
            if (size == 0) {
                CHECK(view->data[0] == 0 && !inside(grant, view->data, 1));
                if (g_sentinel == NULL) { g_sentinel = view->data; }
                CHECK(view->data == g_sentinel);
            } else {
                CHECK(inside(grant, view->data, size) && (uintptr_t)view->data % 8u == 0);
                CHECK(memcmp(view->data, expected, size) == 0);
                CHECK((uintptr_t)view->data >= (uintptr_t)(view + 1) ||
                    (uintptr_t)view >= (uintptr_t)view->data + size);
            }
            if (residue == 0) {
                /* A byte copy at another address carries no authority. */
                handle_storage copy;
                rome2_pack_blob *alias = (rome2_pack_blob *)(void *)copy.bytes;
                const size_t handle_bytes = r.sizes[1] - 7u - size;
                CHECK(handle_bytes % 8u == 0 && handle_bytes <= sizeof copy.bytes);
                memcpy(copy.bytes, blob, handle_bytes);
                CHECK(rome2_pack_blob_get(alias) == NULL);
                CHECK(rome2_pack_blob_destroy(&alias) == ROME2_PACK_BAD_ARGUMENT);
                CHECK(alias == (rome2_pack_blob *)(void *)copy.bytes && r.heap.releases == 1);
            }
            /* Neither the caller's allocator object nor the published view
             * can redirect cleanup. */
            p = record_policy(&other);
            published = (rome2_pack_blob_view *)view;
            published->data = (const unsigned char *)&other;
            published->size = SIZE_MAX;
            published->archive_offset = UINT64_MAX;
            CHECK(rome2_pack_blob_get(blob) == view);
            CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_OK && blob == NULL);
            CHECK(r.heap.live == 0 && r.heap.releases == 2 && r.heap.observations == 0);
            CHECK(r.heap.last_release == grant_raw && r.heap.last_release_bytes == r.sizes[1]);
            CHECK(other.count == 0 && other.heap.releases == 0 && other.heap.observations == 0);
            CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_OK && blob == NULL);
            CHECK(r.heap.releases == 2);
        }
    }
}

/* Expected non-OK outcome after exactly `allocations` grants, plus the
 * ALLOCATION_FAILED outcome at every one of those grants. */
static void expect_status_path(const wchar_t *path, const char *name, size_t maximum,
    rome2_pack_status expected, size_t allocations)
{
    unsigned residue;
    CHECK(expected != ROME2_PACK_OK && allocations <= 1);
    for (residue = 0; residue < 8; residue += 7) {
        size_t fail_at;
        for (fail_at = 0; fail_at <= allocations; ++fail_at) {
            recorder r;
            rome2_owned_string_allocator p;
            rome2_pack_blob *blob = NULL;
            rome2_pack_status status;
            recorder_init(&r, residue, fail_at);
            p = record_policy(&r);
            status = rome2_pack_read_file(&blob, path, name, maximum, &p);
            check_closed(path);
            CHECK(blob == NULL && r.heap.live == 0 && r.heap.observations == 0);
            if (fail_at != 0) {
                CHECK(status == ROME2_PACK_ALLOCATION_FAILED);
                CHECK(r.heap.allocations == fail_at && r.heap.releases == fail_at - 1u);
            } else {
                if (status != expected) {
                    fprintf(stderr, "name '%s': status %d, expected %d\n", name, (int)status, (int)expected);
                }
                CHECK(status == expected);
                CHECK(r.heap.allocations == allocations && r.heap.releases == allocations);
            }
        }
    }
}

static void expect_image(const image *m, size_t n, const char *name, size_t maximum,
    rome2_pack_status expected, size_t allocations)
{
    wchar_t path[PATH_CHARS];
    write_image(path, m, n);
    expect_status_path(path, name, maximum, expected, allocations);
    remove_file(path);
}

static void expect_entry(const wchar_t *path, const layout *l, const entry *entries,
    size_t index, const char *name, size_t maximum)
{
    expect_payload(path, name, maximum, entries[index].data, entries[index].size,
        l->payload_at[index], l->data - l->index);
}

/* ---- scenarios --------------------------------------------------------- */

static void test_variants(void)
{
    uint32_t type, timestamps;
    for (timestamps = 0; timestamps <= 0x40u; timestamps += 0x40u) {
        for (type = 0; type <= 4; ++type) {
            wchar_t path[PATH_CHARS];
            image m;
            layout l;
            size_t i;
            build_main(&m, &l, type | timestamps, "TRAILER\0");
            write_image(path, &m, m.size);
            for (i = 0; i < sizeof main_lookups / sizeof main_lookups[0]; ++i) {
                const lookup *k = &main_lookups[i];
                if (k->entry < 0) {
                    expect_status_path(path, k->name, SIZE_MAX, ROME2_PACK_NOT_FOUND, 1);
                } else {
                    expect_entry(path, &l, main_entries, (size_t)k->entry, k->name, SIZE_MAX);
                }
            }
            remove_file(path);
        }
    }
}

static void test_fold_boundaries(void)
{
    static const entry entries[] = {
        {"@[]^_.a", "1", 1}, {"`{}~.b", "2", 1}, {"Z.z", "3", 1},
        {"\xc1.bin", "4", 1}, {"mix\\ED/sep", "5", 1},
    };
    static const lookup lookups[] = {
        {"@[]^_.A", 0}, {"`{}~.B", 1}, {"z.Z", 2}, {"\xc1.BIN", 3},
        {"MIX/ed\\SEP", 4}, {"mix/ed/sep", 4}, {"mix\\ed\\sep", 4},
        {"`[]^_.a", -1}, {"@{]^_.a", -1}, {"@[]~_.a", -1}, {"\xe1.bin", -1},
        {"mix|ed/sep", -1},
    };
    wchar_t path[PATH_CHARS];
    image m;
    layout l;
    size_t i;
    build(&m, &l, "PFH4", 3, NULL, 0, entries, sizeof entries / sizeof entries[0], NULL);
    write_image(path, &m, m.size);
    for (i = 0; i < sizeof lookups / sizeof lookups[0]; ++i) {
        if (lookups[i].entry < 0) {
            expect_status_path(path, lookups[i].name, 1, ROME2_PACK_NOT_FOUND, 1);
        } else {
            expect_entry(path, &l, entries, (size_t)lookups[i].entry, lookups[i].name, 1);
        }
    }
    remove_file(path);
}

static void test_payload_limit(void)
{
    wchar_t path[PATH_CHARS];
    image m;
    layout l;
    build_main(&m, &l, 0x42u, NULL);
    write_image(path, &m, m.size); /* payload ends exactly at EOF */
    expect_entry(path, &l, main_entries, 1, "script/fauna_config.xml", 16);
    expect_status_path(path, "script/fauna_config.xml", 15, ROME2_PACK_LIMIT_EXCEEDED, 1);
    expect_status_path(path, "script/fauna_config.xml", 0, ROME2_PACK_LIMIT_EXCEEDED, 1);
    expect_entry(path, &l, main_entries, 2, "empty.bin", 0);
    expect_entry(path, &l, main_entries, 4, "last.txt", 4);
    expect_status_path(path, "last.txt", 3, ROME2_PACK_LIMIT_EXCEEDED, 1);
    remove_file(path);
    /* Validation precedes the payload limit. */
    patch32(&m, l.entry_at[MAIN_COUNT - 1], 5);
    expect_image(&m, m.size, "script/fauna_config.xml", 0, ROME2_PACK_CORRUPT, 1);
}

static void test_header(void)
{
    static const char *const magics[] = {"PFH5", "PFH3", "PFH2", "PFH0", "pfh4", "PFH6", "\0\0\0\0", "4HFP"};
    image m, base;
    layout l;
    size_t i;
    uint32_t bit, type;
    build_main(&base, &l, 1, NULL);
    /* Short files, including a zero-byte file, are CORRUPT before magic. */
    expect_image(&base, 0, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    expect_image(&base, 1, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    expect_image(&base, 4, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    expect_image(&base, 27, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    m = base; memcpy(m.bytes, "PFH5", 4);
    expect_image(&m, 27, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    for (i = 0; i < sizeof magics / sizeof magics[0]; ++i) {
        m = base; memcpy(m.bytes, magics[i], 4);
        expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_UNSUPPORTED, 0);
        expect_image(&m, 28, "last.txt", SIZE_MAX, ROME2_PACK_UNSUPPORTED, 0);
    }
    for (type = 5; type <= 7; ++type) {
        m = base; patch32(&m, HDR_FLAGS, type);
        expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_UNSUPPORTED, 0);
        patch32(&m, HDR_FLAGS, type | 0x40u);
        expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_UNSUPPORTED, 0);
    }
    for (bit = 3; bit < 32; ++bit) {
        if (bit == 6) { continue; }
        m = base; patch32(&m, HDR_FLAGS, UINT32_C(1) | (UINT32_C(1) << bit));
        expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_UNSUPPORTED, 0);
        patch32(&m, HDR_FLAGS, UINT32_C(0x41) | (UINT32_C(1) << bit));
        expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_UNSUPPORTED, 0);
    }
    /* Exactly 28 bytes: a valid empty archive. */
    build(&m, &l, "PFH4", 0, NULL, 0, NULL, 0, NULL);
    CHECK(m.size == 28);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_NOT_FOUND, 0);
    /* Aggregate 64 MiB index cap precedes every file-size check. */
    patch32(&m, HDR_DEP_BYTES, 64u * MIB);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_CORRUPT, 0); /* within cap */
    patch32(&m, HDR_DEP_BYTES, 64u * MIB + 1u);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_LIMIT_EXCEEDED, 0);
    patch32(&m, HDR_DEP_BYTES, 32u * MIB);
    patch32(&m, HDR_FILE_BYTES, 32u * MIB);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    patch32(&m, HDR_FILE_BYTES, 32u * MIB + 1u);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_LIMIT_EXCEEDED, 0);
    patch32(&m, HDR_DEP_BYTES, UINT32_MAX);
    patch32(&m, HDR_FILE_BYTES, UINT32_MAX);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_LIMIT_EXCEEDED, 0);
    patch32(&m, HDR_DEP_BYTES, 0);
    patch32(&m, HDR_FILE_BYTES, 64u * MIB + 1u);
    expect_image(&m, m.size, "x", SIZE_MAX, ROME2_PACK_LIMIT_EXCEEDED, 0);
    /* Count/size contradictions are rejected before any index read. */
    m = base; patch32(&m, HDR_DEP_COUNT, UINT32_C(0x80000000));
    expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    m = base; patch32(&m, HDR_DEP_COUNT, peek32(&base, HDR_DEP_BYTES) / 2u + 1u);
    expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    m = base; patch32(&m, HDR_FILE_COUNT, UINT32_MAX);
    expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    m = base; patch32(&m, HDR_FILE_COUNT, peek32(&base, HDR_FILE_BYTES) / 6u + 1u);
    expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    build_main(&m, &l, 0x41u, NULL);
    patch32(&m, HDR_FILE_COUNT, peek32(&m, HDR_FILE_BYTES) / 10u + 1u);
    CHECK((uint64_t)peek32(&m, HDR_FILE_COUNT) * 6u <= peek32(&m, HDR_FILE_BYTES));
    expect_image(&m, m.size, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    /* Declared index beyond EOF. */
    build_main(&m, &l, 1, NULL);
    expect_image(&m, l.data - 1u, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
    expect_image(&m, 28, "last.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 0);
}

static void test_index(void)
{
    static const char *const empty_dep[] = {"", "abc"};
    static const entry empty_path_after_target[] = {
        {"target", "T", 1}, {"", "x", 1}, {"after", "A", 1},
    };
    uint32_t timestamps;
    for (timestamps = 0; timestamps <= 0x40u; timestamps += 0x40u) {
        image m, base;
        layout l;
        const uint32_t flags = 2u | timestamps;
        uint32_t dep_count, dep_bytes, file_count, file_bytes;
        build_main(&base, &l, flags, "trailing");
        dep_count = peek32(&base, HDR_DEP_COUNT);
        dep_bytes = peek32(&base, HDR_DEP_BYTES);
        file_count = peek32(&base, HDR_FILE_COUNT);
        file_bytes = peek32(&base, HDR_FILE_BYTES);
        m = base; patch32(&m, HDR_DEP_COUNT, dep_count + 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_DEP_COUNT, dep_count - 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_DEP_BYTES, dep_bytes + 1u); patch32(&m, HDR_FILE_BYTES, file_bytes - 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_DEP_BYTES, dep_bytes - 1u); patch32(&m, HDR_FILE_BYTES, file_bytes + 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_FILE_COUNT, file_count + 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_FILE_COUNT, file_count - 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_FILE_BYTES, file_bytes + 1u);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, HDR_FILE_BYTES, file_bytes - 1u); /* unterminated last path */
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        /* Entry fixed fields cut by the index end. */
        m = base; patch32(&m, HDR_FILE_BYTES, (uint32_t)(l.entry_at[MAIN_COUNT - 1] - l.file_index + 2u));
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        /* Empty dependency name passes the count pre-check but not the scan. */
        build(&m, &l, "PFH4", flags, empty_dep, 2, main_entries, MAIN_COUNT, NULL);
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        /* Every entry is validated even after the target was found. */
        build(&m, &l, "PFH4", flags, NULL, 0, empty_path_after_target, 3, NULL);
        expect_image(&m, m.size, "target", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        /* Payload bounds: truncated last payload, target first. */
        build_main(&m, &l, flags, NULL);
        expect_image(&m, l.end - 1u, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, l.entry_at[MAIN_COUNT - 1], UINT32_C(4) + 9u); /* 1 byte past EOF */
        expect_image(&m, m.size, "data/readme.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
        m = base; patch32(&m, l.entry_at[MAIN_COUNT - 1], UINT32_C(4) + 8u); /* exactly EOF */
        {
            wchar_t path[PATH_CHARS];
            write_image(path, &m, m.size);
            expect_payload(path, "last.txt", SIZE_MAX, "tailtrailing", 12,
                l.payload_at[MAIN_COUNT - 1], l.data - l.index);
            remove_file(path);
        }
    }
}

static void test_offset_overflow(void)
{
    static const entry entries[] = {{"a", "a", 1}, {"b", "b", 1}, {"t", "T", 1}};
    image m;
    layout l;
    build(&m, &l, "PFH4", 0, NULL, 0, entries, 3, "padding-padding-padding");
    /* 32-bit sums would wrap to small offsets; 64-bit sums exceed the file. */
    patch32(&m, l.entry_at[0], UINT32_MAX);
    patch32(&m, l.entry_at[1], 1);
    expect_image(&m, m.size, "t", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
    expect_image(&m, m.size, "a", 0, ROME2_PACK_CORRUPT, 1);
    patch32(&m, l.entry_at[0], UINT32_MAX);
    patch32(&m, l.entry_at[1], UINT32_MAX);
    patch32(&m, l.entry_at[2], 3);
    expect_image(&m, m.size, "b", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
}

static void test_duplicates(void)
{
    static const entry entries[] = {
        {"dir/Name.txt", "x", 1}, {"other", "o", 1}, {"same", "s", 1},
        {"DIR\\name.TXT", "y", 1}, {"same", "S", 1}, {"unique", "u", 1},
    };
    wchar_t path[PATH_CHARS];
    image m;
    layout l;
    build(&m, &l, "PFH4", 0x44u, NULL, 0, entries, 6, NULL);
    write_image(path, &m, m.size);
    expect_status_path(path, "dir/name.txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
    expect_status_path(path, "Dir\\Name.Txt", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
    expect_status_path(path, "same", SIZE_MAX, ROME2_PACK_CORRUPT, 1);
    /* Duplicates are only diagnosed for the requested path. */
    expect_entry(path, &l, entries, 1, "other", SIZE_MAX);
    expect_entry(path, &l, entries, 5, "UNIQUE", SIZE_MAX);
    remove_file(path);
}

static void test_empty_archives(void)
{
    static const char *const deps[] = {"only.pack"};
    image m;
    layout l;
    build(&m, &l, "PFH4", 0x40u, NULL, 0, NULL, 0, "junk");
    expect_image(&m, m.size, "anything", SIZE_MAX, ROME2_PACK_NOT_FOUND, 0);
    build(&m, &l, "PFH4", 4, deps, 1, NULL, 0, NULL);
    expect_image(&m, m.size, "only.pack", SIZE_MAX, ROME2_PACK_NOT_FOUND, 1);
}

static void test_arguments(void)
{
    static const wchar_t missing[] = L"Z:\\definitely\\missing\\archive.pack";
    recorder r;
    rome2_owned_string_allocator p, bad;
    rome2_pack_blob *blob = NULL;
    handle_storage fake;
    rome2_pack_blob *const occupied = (rome2_pack_blob *)(void *)fake.bytes;
    wchar_t path[PATH_CHARS];
    image m;
    layout l;
    memset(&fake, 0, sizeof fake);
    recorder_init(&r, 3, 0);
    p = record_policy(&r);
    build_main(&m, &l, 1, NULL);
    write_image(path, &m, m.size);
    CHECK(rome2_pack_read_file(NULL, path, "last.txt", 9, &p) == ROME2_PACK_BAD_ARGUMENT);
    blob = occupied;
    CHECK(rome2_pack_read_file(&blob, path, "last.txt", 9, &p) == ROME2_PACK_BAD_ARGUMENT);
    CHECK(blob == occupied);
    blob = NULL;
    CHECK(rome2_pack_read_file(&blob, NULL, "last.txt", 9, &p) == ROME2_PACK_BAD_ARGUMENT);
    CHECK(rome2_pack_read_file(&blob, L"", "last.txt", 9, &p) == ROME2_PACK_BAD_ARGUMENT);
    CHECK(rome2_pack_read_file(&blob, path, NULL, 9, &p) == ROME2_PACK_BAD_ARGUMENT);
    CHECK(rome2_pack_read_file(&blob, path, "", 9, &p) == ROME2_PACK_BAD_ARGUMENT);
    CHECK(rome2_pack_read_file(NULL, path, "last.txt", 9, NULL) == ROME2_PACK_BAD_ARGUMENT);
    /* Allocator validation precedes any file effect (missing path). */
    CHECK(rome2_pack_read_file(&blob, missing, "last.txt", 9, NULL) == ROME2_PACK_INVALID_ALLOCATOR);
    bad = p; bad.allocate = NULL;
    CHECK(rome2_pack_read_file(&blob, missing, "last.txt", 9, &bad) == ROME2_PACK_INVALID_ALLOCATOR);
    bad = p; bad.release = NULL;
    CHECK(rome2_pack_read_file(&blob, path, "last.txt", 9, &bad) == ROME2_PACK_INVALID_ALLOCATOR);
    CHECK(blob == NULL && r.count == 0 && r.heap.allocations == 0);
    /* The observer is optional and never used. */
    bad = p; bad.release_observer = NULL; bad.observer_context = NULL;
    CHECK(rome2_pack_read_file(&blob, path, "last.txt", 4, &bad) == ROME2_PACK_OK);
    CHECK(memcmp(rome2_pack_blob_get(blob)->data, "tail", 4) == 0);
    CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_OK && blob == NULL);
    CHECK(r.heap.live == 0 && r.heap.observations == 0);
    check_closed(path);
    remove_file(path);
    /* Handle API. */
    CHECK(rome2_pack_blob_get(NULL) == NULL);
    CHECK(rome2_pack_blob_destroy(NULL) == ROME2_PACK_BAD_ARGUMENT);
    CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_OK && blob == NULL);
    CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_OK && blob == NULL);
    blob = occupied;
    CHECK(rome2_pack_blob_get(occupied) == NULL);
    CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_BAD_ARGUMENT && blob == occupied);
    CHECK(r.heap.allocations == 2 && r.heap.releases == 2);
}

static void test_io(void)
{
    wchar_t path[PATH_CHARS], absent[PATH_CHARS];
    recorder r;
    rome2_owned_string_allocator p;
    rome2_pack_blob *blob = NULL;
    image m;
    layout l;
    int fd = -1;
    recorder_init(&r, 5, 0);
    p = record_policy(&r);
    next_path(absent);
    CHECK(rome2_pack_read_file(&blob, absent, "last.txt", 9, &p) == ROME2_PACK_IO_ERROR);
    CHECK(swprintf_s(absent, PATH_CHARS, L"%ls\\no-such-dir\\x.pack", g_dir) > 0);
    CHECK(rome2_pack_read_file(&blob, absent, "last.txt", 9, &p) == ROME2_PACK_IO_ERROR);
    CHECK(rome2_pack_read_file(&blob, g_dir, "last.txt", 9, &p) == ROME2_PACK_IO_ERROR);
    build_main(&m, &l, 1, NULL);
    write_image(path, &m, m.size);
    CHECK(_wsopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYRW, 0) == 0);
    CHECK(rome2_pack_read_file(&blob, path, "last.txt", 9, &p) == ROME2_PACK_IO_ERROR);
    CHECK(_close(fd) == 0);
    CHECK(blob == NULL && r.heap.allocations == 0);
    /* The payload is a copy: it outlives the archive file. */
    CHECK(rome2_pack_read_file(&blob, path, "SCRIPT\\FAUNA_CONFIG.xml", 16, &p) == ROME2_PACK_OK);
    remove_file(path);
    CHECK(rome2_pack_blob_get(blob)->size == 16);
    CHECK(memcmp(rome2_pack_blob_get(blob)->data, fauna_bytes, 16) == 0);
    CHECK(rome2_pack_blob_destroy(&blob) == ROME2_PACK_OK);
    CHECK(r.heap.live == 0 && r.heap.releases == r.heap.allocations && r.heap.observations == 0);
}

static void test_independent_results(void)
{
    wchar_t path[PATH_CHARS];
    recorder r;
    rome2_owned_string_allocator p;
    rome2_pack_blob *a = NULL, *b = NULL, *e1 = NULL, *e2 = NULL;
    image m;
    layout l;
    recorder_init(&r, 1, 0);
    p = record_policy(&r);
    build_main(&m, &l, 0x40u, NULL);
    write_image(path, &m, m.size);
    CHECK(rome2_pack_read_file(&a, path, "last.txt", 4, &p) == ROME2_PACK_OK);
    CHECK(rome2_pack_read_file(&b, path, "LAST.TXT", 4, &p) == ROME2_PACK_OK);
    CHECK(rome2_pack_read_file(&e1, path, "empty.bin", 0, &p) == ROME2_PACK_OK);
    CHECK(rome2_pack_read_file(&e2, path, "Empty.Bin", 0, &p) == ROME2_PACK_OK);
    CHECK(a != b && rome2_pack_blob_get(a)->data != rome2_pack_blob_get(b)->data);
    CHECK(memcmp(rome2_pack_blob_get(a)->data, rome2_pack_blob_get(b)->data, 4) == 0);
    CHECK(e1 != e2 && rome2_pack_blob_get(e1)->data == rome2_pack_blob_get(e2)->data);
    CHECK(rome2_pack_blob_get(e1)->data[0] == 0 && rome2_pack_blob_get(e1)->size == 0);
    CHECK(r.heap.live == 4 && r.heap.peak == 4);
    CHECK(rome2_pack_blob_destroy(&b) == ROME2_PACK_OK);
    CHECK(memcmp(rome2_pack_blob_get(a)->data, "tail", 4) == 0);
    CHECK(rome2_pack_blob_destroy(&e2) == ROME2_PACK_OK);
    CHECK(rome2_pack_blob_get(e1)->data[0] == 0);
    CHECK(rome2_pack_blob_destroy(&e1) == ROME2_PACK_OK);
    CHECK(rome2_pack_blob_destroy(&a) == ROME2_PACK_OK);
    CHECK(r.heap.live == 0 && r.heap.allocations == 8 && r.heap.releases == 8);
    CHECK(r.heap.observations == 0);
    remove_file(path);
}

/* Payload offsets beyond 4 GiB, via an NTFS sparse file (skipped if the
 * volume cannot create one).  Only a few KiB are ever allocated on disk. */
static void test_sparse_offset(void)
{
    static const entry entries[] = {{"huge0.bin", "", 0}, {"gap.bin", "", 0}, {"high.bin", "", 0}};
    static const unsigned char zeros[16] = {0};
    wchar_t path[PATH_CHARS];
    image m;
    layout l;
    HANDLE h;
    DWORD done = 0, high_part = 0;
    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER at;
    uint64_t gap_offset, high_offset, allocated;
    build(&m, &l, "PFH4", 0x41u, NULL, 0, entries, 3, NULL);
    patch32(&m, l.entry_at[0], UINT32_MAX);
    patch32(&m, l.entry_at[1], 16);
    patch32(&m, l.entry_at[2], 5);
    gap_offset = (uint64_t)l.data + UINT32_MAX;
    high_offset = gap_offset + 16u;
    CHECK(high_offset > UINT64_C(0x100000000));
    next_path(path);
    h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    memset(&info, 0, sizeof info);
    if (!DeviceIoControl(h, FSCTL_SET_SPARSE, NULL, 0, NULL, 0, &done, NULL) ||
        !GetFileInformationByHandle(h, &info) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) == 0) {
        CHECK(CloseHandle(h));
        remove_file(path);
        printf("test_pack_resource: sparse >4 GiB offset SKIPPED (no sparse support)\n");
        return;
    }
    CHECK(WriteFile(h, m.bytes, (DWORD)l.data, &done, NULL) && done == l.data);
    at.QuadPart = (LONGLONG)high_offset;
    CHECK(SetFilePointerEx(h, at, NULL, FILE_BEGIN));
    CHECK(WriteFile(h, "HIGH!Z", 6, &done, NULL) && done == 6);
    CHECK(CloseHandle(h));
    allocated = GetCompressedFileSizeW(path, &high_part);
    allocated |= (uint64_t)high_part << 32;
    CHECK(allocated < UINT64_C(64) * MIB);
    expect_payload(path, "high.bin", 5, "HIGH!", 5, high_offset, l.data - l.index);
    expect_payload(path, "GAP.BIN", 16, zeros, 16, gap_offset, l.data - l.index);
    expect_status_path(path, "huge0.bin", MIB, ROME2_PACK_LIMIT_EXCEEDED, 1);
    /* Truncate by one byte inside the last payload: every entry fails. */
    h = CreateFileW(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    at.QuadPart = (LONGLONG)(high_offset + 4u);
    CHECK(SetFilePointerEx(h, at, NULL, FILE_BEGIN) && SetEndOfFile(h));
    CHECK(CloseHandle(h));
    expect_status_path(path, "high.bin", 5, ROME2_PACK_CORRUPT, 1);
    expect_status_path(path, "huge0.bin", MIB, ROME2_PACK_CORRUPT, 1);
    expect_status_path(path, "gap.bin", 16, ROME2_PACK_CORRUPT, 1);
    remove_file(path);
}

int wmain(int argc, wchar_t **argv)
{
    init_dir(argc, argv);
    test_arguments();
    test_io();
    test_header();
    test_index();
    test_offset_overflow();
    test_duplicates();
    test_empty_archives();
    test_fold_boundaries();
    test_payload_limit();
    test_independent_results();
    test_variants();
    test_sparse_offset();
    (void)_wrmdir(g_dir);
    printf("pack_resource tests: %zu checks passed\n", checks);
    return 0;
}
