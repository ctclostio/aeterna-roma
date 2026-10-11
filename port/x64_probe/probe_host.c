#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define ROME2_ARRAY_COUNT(value) (sizeof(value) / sizeof((value)[0]))
#define ROME2_PATH_CAPACITY ((size_t)32768)
#define ROME2_LITERAL_UNITS ((size_t)22)
#define ROME2_LITERAL_BYTES ((size_t)44)
#define ROME2_POLICY_SENTINEL UINT32_C(0xa5a55a5a)
#define ROME2_INFRASTRUCTURE_EXIT 77

#define ROME2_STATUS_OK UINT32_C(0)
#define ROME2_STATUS_BAD_ARGUMENT UINT32_C(1)
#define ROME2_STATUS_NULL_ADDRESS UINT32_C(2)
#define ROME2_STATUS_RANGE_OVERFLOW UINT32_C(3)
#define ROME2_STATUS_OUT_OF_RANGE UINT32_C(4)

#define ROME2_POLICY_INSTALL_HANDLER UINT32_C(0)
#define ROME2_POLICY_SKIP_HANDLER UINT32_C(1)
#define ROME2_PROBE_ABI_VERSION UINT64_C(0x00010000)

typedef uint64_t (__cdecl *rome2_probe_abi_version_fn)(void);
typedef uint32_t (__cdecl *rome2_probe_select_fn)(
    const uint8_t *host_base,
    uint32_t guest_base,
    uint64_t byte_count,
    uint32_t command_line,
    uint32_t *policy_out);

typedef enum rome2_load_mode {
    ROME2_LOAD_ABSOLUTE = 0,
    ROME2_LOAD_RELATIVE = 1
} rome2_load_mode;

typedef struct rome2_loaded_probe {
    HMODULE module;
    rome2_probe_abi_version_fn abi_version;
    rome2_probe_select_fn select_policy;
} rome2_loaded_probe;

typedef int (*rome2_case_fn)(const wchar_t *dll_path);

typedef struct rome2_case_descriptor {
    const wchar_t *name;
    const char *check_id;
    rome2_case_fn run;
} rome2_case_descriptor;

static const uint16_t rome2_frozen_literal[ROME2_LITERAL_UNITS] = {
    UINT16_C(0x002d), UINT16_C(0x006e), UINT16_C(0x006f), UINT16_C(0x005f),
    UINT16_C(0x0065), UINT16_C(0x0078), UINT16_C(0x0063), UINT16_C(0x0065),
    UINT16_C(0x0070), UINT16_C(0x0074), UINT16_C(0x0069), UINT16_C(0x006f),
    UINT16_C(0x006e), UINT16_C(0x005f), UINT16_C(0x0068), UINT16_C(0x0061),
    UINT16_C(0x006e), UINT16_C(0x0064), UINT16_C(0x006c), UINT16_C(0x0065),
    UINT16_C(0x0072), UINT16_C(0x0000)
};

_Static_assert(sizeof(void *) == 8, "the probe host must be built for x64");
_Static_assert(sizeof(rome2_probe_abi_version_fn) == sizeof(FARPROC),
    "GetProcAddress and the ABI function pointer must have equal widths");
_Static_assert(sizeof(rome2_probe_select_fn) == sizeof(FARPROC),
    "GetProcAddress and the selector function pointer must have equal widths");

static uint16_t rome2_read_u16_le(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t rome2_read_u32_le(const uint8_t *bytes)
{
    return
        (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static void rome2_store_u16_le(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)(value & UINT16_C(0x00ff));
    destination[1] = (uint8_t)(value >> 8);
}

static void rome2_store_literal(uint8_t *destination)
{
    size_t index;

    for (index = 0; index < ROME2_LITERAL_UNITS; ++index) {
        rome2_store_u16_le(destination + index * 2, rome2_frozen_literal[index]);
    }
}

static int rome2_report_failure(const char *label, const char *detail)
{
    fprintf(stderr, "FAIL %s: %s\n", label, detail);
    return 1;
}

static int rome2_expect_u32(
    const char *label,
    const char *field,
    uint32_t actual,
    uint32_t expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: %s=%lu expected=%lu\n", label, field,
        (unsigned long)actual, (unsigned long)expected);
    return 1;
}

static int rome2_expect_u64(
    const char *label,
    const char *field,
    uint64_t actual,
    uint64_t expected)
{
    if (actual == expected) {
        return 0;
    }
    fprintf(stderr, "FAIL %s: %s=%llu expected=%llu\n", label, field,
        (unsigned long long)actual, (unsigned long long)expected);
    return 1;
}

static const wchar_t *rome2_path_basename(const wchar_t *path)
{
    const wchar_t *backslash = wcsrchr(path, L'\\');
    const wchar_t *slash = wcsrchr(path, L'/');
    const wchar_t *last = backslash;

    if (last == NULL || (slash != NULL && slash > last)) {
        last = slash;
    }
    return last == NULL ? path : last + 1;
}

static int rome2_read_file_region(
    HANDLE file,
    uint64_t offset,
    uint8_t *destination,
    DWORD byte_count)
{
    LARGE_INTEGER position;
    DWORD bytes_read = 0;

    position.QuadPart = (LONGLONG)offset;
    if (SetFilePointerEx(file, position, NULL, FILE_BEGIN) == 0) {
        return 0;
    }
    if (ReadFile(file, destination, byte_count, &bytes_read, NULL) == 0) {
        return 0;
    }
    return bytes_read == byte_count;
}

/*
 * This is deliberately only a load-safety preflight. The supervisor-owned
 * independent PE gate performs the complete export/import/hardening audit.
 */
static int rome2_validate_candidate_image(const wchar_t *dll_path)
{
    uint8_t dos_header[64];
    uint8_t nt_prefix[26];
    uint32_t pe_offset;
    uint16_t machine;
    uint16_t optional_size;
    uint16_t characteristics;
    uint16_t optional_magic;
    HANDLE file;
    int valid = 0;

    if (_wcsicmp(rome2_path_basename(dll_path),
            L"rome2_guest32_probe64.dll") != 0) {
        return rome2_report_failure("image-preflight",
            "candidate filename is not rome2_guest32_probe64.dll");
    }

    file = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return rome2_report_failure("image-preflight",
            "candidate DLL cannot be opened");
    }

    if (!rome2_read_file_region(file, UINT64_C(0), dos_header,
            (DWORD)sizeof(dos_header)) || dos_header[0] != 'M' ||
        dos_header[1] != 'Z') {
        rome2_report_failure("image-preflight", "missing DOS signature");
        goto finished;
    }
    pe_offset = rome2_read_u32_le(dos_header + 0x3c);
    if (pe_offset < sizeof(dos_header) ||
        !rome2_read_file_region(file, pe_offset, nt_prefix,
            (DWORD)sizeof(nt_prefix))) {
        rome2_report_failure("image-preflight", "invalid PE header offset");
        goto finished;
    }
    if (memcmp(nt_prefix, "PE\0\0", 4) != 0) {
        rome2_report_failure("image-preflight", "missing PE signature");
        goto finished;
    }

    machine = rome2_read_u16_le(nt_prefix + 4);
    optional_size = rome2_read_u16_le(nt_prefix + 20);
    characteristics = rome2_read_u16_le(nt_prefix + 22);
    optional_magic = rome2_read_u16_le(nt_prefix + 24);
    if (machine != UINT16_C(0x8664) || optional_magic != UINT16_C(0x020b) ||
        optional_size < UINT16_C(112) ||
        (characteristics & UINT16_C(0x2000)) == 0) {
        rome2_report_failure("image-preflight",
            "candidate is not an AMD64 PE32+ DLL");
        goto finished;
    }
    valid = 1;

finished:
    CloseHandle(file);
    return valid ? 0 : 1;
}

static int rome2_normalize_candidate_path(
    const wchar_t *input,
    wchar_t *absolute_path,
    size_t capacity)
{
    DWORD length;
    DWORD attributes;

    if (capacity > (size_t)MAXDWORD) {
        return rome2_report_failure("path", "internal path capacity is invalid");
    }
    length = GetFullPathNameW(input, (DWORD)capacity, absolute_path, NULL);
    if (length == 0 || (size_t)length >= capacity) {
        return rome2_report_failure("path", "candidate path is not resolvable");
    }
    attributes = GetFileAttributesW(absolute_path);
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return rome2_report_failure("path", "candidate DLL is not a file");
    }
    return rome2_validate_candidate_image(absolute_path);
}

static int rome2_assign_probe_symbols(rome2_loaded_probe *probe)
{
    FARPROC raw_abi;
    FARPROC raw_select;

    raw_abi = GetProcAddress(probe->module, "Rome2Guest32ProbeAbiVersion");
    raw_select = GetProcAddress(probe->module,
        "Rome2Guest32ProbeSelectEntryPolicy");
    if (raw_abi == NULL || raw_select == NULL) {
        return rome2_report_failure("load",
            "one or both frozen named exports are missing");
    }
    memcpy(&probe->abi_version, &raw_abi, sizeof(probe->abi_version));
    memcpy(&probe->select_policy, &raw_select, sizeof(probe->select_policy));
    return 0;
}

static int rome2_load_probe(
    const wchar_t *dll_path,
    rome2_load_mode mode,
    rome2_loaded_probe *probe)
{
    DWORD load_error = ERROR_SUCCESS;

    memset(probe, 0, sizeof(*probe));
    if (mode == ROME2_LOAD_ABSOLUTE) {
        probe->module = LoadLibraryExW(dll_path, NULL,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (probe->module == NULL) {
            load_error = GetLastError();
        }
    }
    else {
        wchar_t relative_path[32768];
        wchar_t previous_directory[32768];
        wchar_t *separator;
        wchar_t *filename;
        DWORD previous_length;

        if (wcscpy_s(relative_path, ROME2_ARRAY_COUNT(relative_path),
                dll_path) != 0) {
            return rome2_report_failure("relative-load",
                "candidate path exceeds the relative-load buffer");
        }
        separator = wcsrchr(relative_path, L'\\');
        if (separator == NULL) {
            separator = wcsrchr(relative_path, L'/');
        }
        if (separator == NULL || separator[1] == L'\0') {
            return rome2_report_failure("relative-load",
                "candidate path has no directory and filename");
        }
        filename = separator + 1;
        *separator = L'\0';

        previous_length = GetCurrentDirectoryW(
            (DWORD)ROME2_ARRAY_COUNT(previous_directory), previous_directory);
        if (previous_length == 0 ||
            previous_length >= (DWORD)ROME2_ARRAY_COUNT(previous_directory)) {
            return rome2_report_failure("relative-load",
                "cannot save the current directory");
        }
        if (SetCurrentDirectoryW(relative_path) == 0) {
            return rome2_report_failure("relative-load",
                "cannot enter the candidate directory");
        }
        probe->module = LoadLibraryExW(filename, NULL, 0);
        if (probe->module == NULL) {
            load_error = GetLastError();
        }
        if (SetCurrentDirectoryW(previous_directory) == 0) {
            if (probe->module != NULL) {
                FreeLibrary(probe->module);
                probe->module = NULL;
            }
            return rome2_report_failure("relative-load",
                "cannot restore the current directory");
        }
    }

    if (probe->module == NULL) {
        fprintf(stderr, "FAIL load: LoadLibraryExW error=%lu\n",
            (unsigned long)load_error);
        return 1;
    }
    if (rome2_assign_probe_symbols(probe) != 0) {
        FreeLibrary(probe->module);
        memset(probe, 0, sizeof(*probe));
        return 1;
    }
    return 0;
}

static int rome2_unload_probe(rome2_loaded_probe *probe)
{
    int failures = 0;

    if (probe->module != NULL && FreeLibrary(probe->module) == 0) {
        failures += rome2_report_failure("unload", "FreeLibrary failed");
    }
    memset(probe, 0, sizeof(*probe));
    return failures;
}

static int rome2_call_and_check(
    rome2_loaded_probe *probe,
    const char *label,
    const uint8_t *host_base,
    uint32_t guest_base,
    uint64_t byte_count,
    uint32_t command_line,
    uint32_t expected_status,
    uint32_t expected_policy,
    const uint8_t *preserved_input,
    size_t preserved_size)
{
    uint8_t *snapshot = NULL;
    uint32_t policy = ROME2_POLICY_SENTINEL;
    uint32_t status;
    int failures = 0;

    if (preserved_size != 0) {
        if (preserved_input == NULL) {
            return rome2_report_failure(label,
                "internal preservation input is null");
        }
        snapshot = (uint8_t *)malloc(preserved_size);
        if (snapshot == NULL) {
            return ROME2_INFRASTRUCTURE_EXIT;
        }
        memcpy(snapshot, preserved_input, preserved_size);
    }

    status = probe->select_policy(host_base, guest_base, byte_count,
        command_line, &policy);
    failures += rome2_expect_u32(label, "status", status, expected_status);
    failures += rome2_expect_u32(label, "policy", policy, expected_policy);
    if (snapshot != NULL &&
        memcmp(snapshot, preserved_input, preserved_size) != 0) {
        failures += rome2_report_failure(label, "input bytes were modified");
    }
    free(snapshot);
    return failures;
}

static int rome2_finish_case(
    rome2_loaded_probe *probe,
    int failures)
{
    int unload_failures = rome2_unload_probe(probe);

    if (failures == ROME2_INFRASTRUCTURE_EXIT) {
        return failures;
    }
    return failures + unload_failures;
}

static int rome2_case_abi(const wchar_t *dll_path)
{
    uint8_t literal[ROME2_LITERAL_BYTES];
    uint8_t mismatch[2] = { 0x21, 0x00 };
    uint8_t short_input[1] = { 0x2d };
    rome2_loaded_probe probe;
    int failures = 0;

    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }
    failures += rome2_expect_u64("abi-version", "value",
        probe.abi_version(), ROME2_PROBE_ABI_VERSION);
    rome2_store_literal(literal);
    failures += rome2_call_and_check(&probe, "abi-policy-skip", literal,
        UINT32_C(0x2000), ROME2_LITERAL_BYTES, UINT32_C(0x2000),
        ROME2_STATUS_OK, ROME2_POLICY_SKIP_HANDLER, literal, sizeof(literal));
    failures += rome2_call_and_check(&probe, "abi-policy-install", mismatch,
        UINT32_C(0x2100), sizeof(mismatch), UINT32_C(0x2100),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER,
        mismatch, sizeof(mismatch));
    failures += rome2_call_and_check(&probe, "abi-status-bad-argument", NULL,
        UINT32_C(0x2200), UINT64_C(2), UINT32_C(0x2200),
        ROME2_STATUS_BAD_ARGUMENT, ROME2_POLICY_SENTINEL, NULL, 0);
    failures += rome2_call_and_check(&probe, "abi-status-null-address", literal,
        UINT32_C(0x2000), ROME2_LITERAL_BYTES, UINT32_C(0),
        ROME2_STATUS_NULL_ADDRESS, ROME2_POLICY_SENTINEL,
        literal, sizeof(literal));
    failures += rome2_call_and_check(&probe, "abi-status-range-overflow",
        literal, UINT32_C(0x2000), UINT64_C(0x100000001),
        UINT32_C(0x2000), ROME2_STATUS_RANGE_OVERFLOW,
        ROME2_POLICY_SENTINEL, literal, sizeof(literal));
    failures += rome2_call_and_check(&probe, "abi-status-out-of-range",
        short_input, UINT32_C(0x2300), sizeof(short_input), UINT32_C(0x2300),
        ROME2_STATUS_OUT_OF_RANGE, ROME2_POLICY_SENTINEL,
        short_input, sizeof(short_input));
    return rome2_finish_case(&probe, failures);
}

static int rome2_case_semantics(const wchar_t *dll_path)
{
    uint8_t bytes[64];
    rome2_loaded_probe probe;
    size_t index;
    int failures = 0;

    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }

    memset(bytes, 0, sizeof(bytes));
    rome2_store_literal(bytes);
    failures += rome2_call_and_check(&probe, "semantic-exact", bytes,
        UINT32_C(0x3000), ROME2_LITERAL_BYTES, UINT32_C(0x3000),
        ROME2_STATUS_OK, ROME2_POLICY_SKIP_HANDLER, bytes, ROME2_LITERAL_BYTES);

    memset(bytes, 0, sizeof(bytes));
    failures += rome2_call_and_check(&probe, "semantic-empty", bytes,
        UINT32_C(0x3100), UINT64_C(2), UINT32_C(0x3100),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, 2);

    memset(bytes, 0, sizeof(bytes));
    for (index = 0; index < 3; ++index) {
        rome2_store_u16_le(bytes + index * 2, rome2_frozen_literal[index]);
    }
    failures += rome2_call_and_check(&probe, "semantic-prefix", bytes,
        UINT32_C(0x3200), UINT64_C(8), UINT32_C(0x3200),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, 8);

    memset(bytes, 0, sizeof(bytes));
    rome2_store_literal(bytes);
    rome2_store_u16_le(bytes + 42, UINT16_C(0x0078));
    rome2_store_u16_le(bytes + 44, UINT16_C(0));
    failures += rome2_call_and_check(&probe, "semantic-suffix", bytes,
        UINT32_C(0x3300), UINT64_C(46), UINT32_C(0x3300),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, 46);

    rome2_store_literal(bytes);
    rome2_store_u16_le(bytes + 2, UINT16_C(0x004e));
    failures += rome2_call_and_check(&probe, "semantic-case", bytes,
        UINT32_C(0x3400), ROME2_LITERAL_BYTES, UINT32_C(0x3400),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, ROME2_LITERAL_BYTES);

    memset(bytes, 0, sizeof(bytes));
    rome2_store_u16_le(bytes, UINT16_C(0x0020));
    rome2_store_literal(bytes + 2);
    failures += rome2_call_and_check(&probe, "semantic-leading-space", bytes,
        UINT32_C(0x3500), UINT64_C(46), UINT32_C(0x3500),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, 46);

    memset(bytes, 0, sizeof(bytes));
    rome2_store_literal(bytes);
    rome2_store_u16_le(bytes + 42, UINT16_C(0x0020));
    rome2_store_u16_le(bytes + 44, UINT16_C(0));
    failures += rome2_call_and_check(&probe, "semantic-trailing-space", bytes,
        UINT32_C(0x3600), UINT64_C(46), UINT32_C(0x3600),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, 46);

    memset(bytes, 0, sizeof(bytes));
    rome2_store_u16_le(bytes, UINT16_C(0x0022));
    for (index = 0; index < ROME2_LITERAL_UNITS - 1; ++index) {
        rome2_store_u16_le(bytes + (index + 1) * 2,
            rome2_frozen_literal[index]);
    }
    rome2_store_u16_le(bytes + 44, UINT16_C(0x0022));
    rome2_store_u16_le(bytes + 46, UINT16_C(0));
    failures += rome2_call_and_check(&probe, "semantic-quoted", bytes,
        UINT32_C(0x3700), UINT64_C(48), UINT32_C(0x3700),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, bytes, 48);

    return rome2_finish_case(&probe, failures);
}

static int rome2_case_early_stop(const wchar_t *dll_path)
{
    SYSTEM_INFO system_info;
    DWORD old_protection = 0;
    uint8_t *allocation;
    uint8_t *first;
    uint8_t *later;
    SIZE_T allocation_size;
    rome2_loaded_probe probe;
    size_t index;
    int failures = 0;

    GetSystemInfo(&system_info);
    if (system_info.dwPageSize < 64) {
        return ROME2_INFRASTRUCTURE_EXIT;
    }
    allocation_size = (SIZE_T)system_info.dwPageSize * 2;
    allocation = (uint8_t *)VirtualAlloc(NULL, allocation_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (allocation == NULL) {
        return ROME2_INFRASTRUCTURE_EXIT;
    }
    if (VirtualProtect(allocation + system_info.dwPageSize,
            system_info.dwPageSize, PAGE_NOACCESS, &old_protection) == 0) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        return ROME2_INFRASTRUCTURE_EXIT;
    }
    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        return 1;
    }

    first = allocation + system_info.dwPageSize - 2;
    first[0] = 0x21;
    first[1] = 0x00;
    failures += rome2_call_and_check(&probe, "early-first-mismatch", first,
        UINT32_C(0x4000), UINT64_C(2), UINT32_C(0x4000),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, first, 2);

    later = allocation + system_info.dwPageSize - 22;
    for (index = 0; index < 10; ++index) {
        rome2_store_u16_le(later + index * 2, rome2_frozen_literal[index]);
    }
    rome2_store_u16_le(later + 20, UINT16_C(0x005a));
    failures += rome2_call_and_check(&probe, "early-later-mismatch", later,
        UINT32_C(0x4100), UINT64_C(22), UINT32_C(0x4100),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER, later, 22);

    failures = rome2_finish_case(&probe, failures);
    if (VirtualFree(allocation, 0, MEM_RELEASE) == 0) {
        failures += rome2_report_failure("early-stop", "VirtualFree failed");
    }
    return failures;
}

static int rome2_case_truncation(const wchar_t *dll_path)
{
    uint8_t literal[ROME2_LITERAL_BYTES];
    rome2_loaded_probe probe;
    int failures = 0;

    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }
    rome2_store_literal(literal);
    failures += rome2_call_and_check(&probe, "missing-terminator", literal,
        UINT32_C(0x5000), UINT64_C(42), UINT32_C(0x5000),
        ROME2_STATUS_OUT_OF_RANGE, ROME2_POLICY_SENTINEL, literal, 42);
    failures += rome2_call_and_check(&probe, "one-byte-final-unit", literal,
        UINT32_C(0x5100), UINT64_C(43), UINT32_C(0x5100),
        ROME2_STATUS_OUT_OF_RANGE, ROME2_POLICY_SENTINEL, literal, 43);
    failures += rome2_call_and_check(&probe, "truncated-interior-unit", literal,
        UINT32_C(0x5200), UINT64_C(15), UINT32_C(0x5200),
        ROME2_STATUS_OUT_OF_RANGE, ROME2_POLICY_SENTINEL, literal, 15);
    return rome2_finish_case(&probe, failures);
}

static int rome2_case_memory_errors(const wchar_t *dll_path)
{
    uint8_t literal[ROME2_LITERAL_BYTES];
    uint8_t literal_snapshot[ROME2_LITERAL_BYTES];
    uint8_t high_bytes[64];
    uint32_t status;
    rome2_loaded_probe probe;
    int failures = 0;

    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }
    rome2_store_literal(literal);
    memcpy(literal_snapshot, literal, sizeof(literal));

    failures += rome2_call_and_check(&probe, "null-host", NULL,
        UINT32_C(0x6000), ROME2_LITERAL_BYTES, UINT32_C(0x6000),
        ROME2_STATUS_BAD_ARGUMENT, ROME2_POLICY_SENTINEL, NULL, 0);

    status = probe.select_policy(literal, UINT32_C(0x6000),
        ROME2_LITERAL_BYTES, UINT32_C(0x6000), NULL);
    failures += rome2_expect_u32("null-output", "status", status,
        ROME2_STATUS_BAD_ARGUMENT);
    if (memcmp(literal, literal_snapshot, sizeof(literal)) != 0) {
        failures += rome2_report_failure("null-output",
            "input bytes were modified");
    }

    failures += rome2_call_and_check(&probe, "null-command", literal,
        UINT32_C(0x6000), ROME2_LITERAL_BYTES, UINT32_C(0),
        ROME2_STATUS_NULL_ADDRESS, ROME2_POLICY_SENTINEL,
        literal, sizeof(literal));
    failures += rome2_call_and_check(&probe, "extent-too-wide", literal,
        UINT32_C(0x6000), UINT64_C(0x100000001), UINT32_C(0x6000),
        ROME2_STATUS_RANGE_OVERFLOW, ROME2_POLICY_SENTINEL,
        literal, sizeof(literal));
    failures += rome2_call_and_check(&probe, "extent-end-overflow", literal,
        UINT32_C(0xfffffff0), UINT64_C(17), UINT32_C(0xfffffff0),
        ROME2_STATUS_RANGE_OVERFLOW, ROME2_POLICY_SENTINEL,
        literal, sizeof(literal));
    failures += rome2_call_and_check(&probe, "numeric-host-overflow",
        (const uint8_t *)(uintptr_t)(UINTPTR_MAX - (uintptr_t)2),
        UINT32_C(0x6000), ROME2_LITERAL_BYTES, UINT32_C(0x6000),
        ROME2_STATUS_RANGE_OVERFLOW, ROME2_POLICY_SENTINEL, NULL, 0);

    memset(high_bytes, 0, sizeof(high_bytes));
    rome2_store_u16_le(high_bytes + 62, UINT16_C(0x002d));
    failures += rome2_call_and_check(&probe, "checked-address-overflow",
        high_bytes, UINT32_C(0xffffffc0), UINT64_C(64),
        UINT32_C(0xfffffffe), ROME2_STATUS_RANGE_OVERFLOW,
        ROME2_POLICY_SENTINEL, high_bytes, sizeof(high_bytes));
    failures += rome2_call_and_check(&probe, "command-below-base", literal,
        UINT32_C(0x6000), ROME2_LITERAL_BYTES, UINT32_C(0x5fff),
        ROME2_STATUS_OUT_OF_RANGE, ROME2_POLICY_SENTINEL,
        literal, sizeof(literal));
    return rome2_finish_case(&probe, failures);
}

static int rome2_case_memory_boundaries(const wchar_t *dll_path)
{
    uint8_t unaligned[ROME2_LITERAL_BYTES + 1];
    uint8_t high_extent[64];
    rome2_loaded_probe probe;
    int failures = 0;

    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }
    memset(unaligned, 0xcc, sizeof(unaligned));
    rome2_store_literal(unaligned + 1);
    failures += rome2_call_and_check(&probe, "unaligned-command", unaligned,
        UINT32_C(0x7000), sizeof(unaligned), UINT32_C(0x7001),
        ROME2_STATUS_OK, ROME2_POLICY_SKIP_HANDLER,
        unaligned, sizeof(unaligned));

    memset(high_extent, 0xcc, sizeof(high_extent));
    rome2_store_literal(high_extent);
    failures += rome2_call_and_check(&probe, "extent-ending-at-2pow32",
        high_extent, UINT32_C(0xffffffc0), UINT64_C(64),
        UINT32_C(0xffffffc0), ROME2_STATUS_OK,
        ROME2_POLICY_SKIP_HANDLER, high_extent, sizeof(high_extent));
    return rome2_finish_case(&probe, failures);
}

static int rome2_case_high_native(const wchar_t *dll_path)
{
    static const SIZE_T allocation_size = (SIZE_T)0x100000;
    static const uintptr_t hints[] = {
        (uintptr_t)UINT64_C(0x0000010000000000),
        (uintptr_t)UINT64_C(0x0000020000000000),
        (uintptr_t)UINT64_C(0x0000000200000000),
        (uintptr_t)UINT64_C(0x0000000100010000)
    };
    uint8_t *allocation = NULL;
    uint8_t *command;
    rome2_loaded_probe probe;
    size_t index;
    int failures = 0;

    for (index = 0; index < ROME2_ARRAY_COUNT(hints); ++index) {
        allocation = (uint8_t *)VirtualAlloc((LPVOID)hints[index],
            allocation_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (allocation != NULL &&
            (uintptr_t)allocation > (uintptr_t)UINT32_MAX) {
            break;
        }
        if (allocation != NULL) {
            VirtualFree(allocation, 0, MEM_RELEASE);
            allocation = NULL;
        }
    }
    if (allocation == NULL) {
        allocation = (uint8_t *)VirtualAlloc(NULL, allocation_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (allocation == NULL ||
        (uintptr_t)allocation <= (uintptr_t)UINT32_MAX) {
        if (allocation != NULL) {
            VirtualFree(allocation, 0, MEM_RELEASE);
        }
        fprintf(stderr, "INFRA high-native: allocation above 4 GiB unavailable\n");
        return ROME2_INFRASTRUCTURE_EXIT;
    }
    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        VirtualFree(allocation, 0, MEM_RELEASE);
        return 1;
    }

    command = allocation + 0x40;
    rome2_store_literal(command);
    failures += rome2_call_and_check(&probe, "high-native-exact", command,
        UINT32_C(0x40000000), ROME2_LITERAL_BYTES, UINT32_C(0x40000000),
        ROME2_STATUS_OK, ROME2_POLICY_SKIP_HANDLER,
        command, ROME2_LITERAL_BYTES);
    command[0] = 0x58;
    failures += rome2_call_and_check(&probe, "high-native-mismatch", command,
        UINT32_C(0x40000000), ROME2_LITERAL_BYTES, UINT32_C(0x40000000),
        ROME2_STATUS_OK, ROME2_POLICY_INSTALL_HANDLER,
        command, ROME2_LITERAL_BYTES);

    failures = rome2_finish_case(&probe, failures);
    if (VirtualFree(allocation, 0, MEM_RELEASE) == 0) {
        failures += rome2_report_failure("high-native", "VirtualFree failed");
    }
    return failures;
}

static int rome2_case_load_common(
    const wchar_t *dll_path,
    rome2_load_mode mode,
    const char *label)
{
    uint8_t literal[ROME2_LITERAL_BYTES];
    rome2_loaded_probe probe;
    int failures = 0;

    if (rome2_load_probe(dll_path, mode, &probe) != 0) {
        return 1;
    }
    failures += rome2_expect_u64(label, "abi-version", probe.abi_version(),
        ROME2_PROBE_ABI_VERSION);
    rome2_store_literal(literal);
    failures += rome2_call_and_check(&probe, label, literal,
        UINT32_C(0x8000), ROME2_LITERAL_BYTES, UINT32_C(0x8000),
        ROME2_STATUS_OK, ROME2_POLICY_SKIP_HANDLER,
        literal, sizeof(literal));
    return rome2_finish_case(&probe, failures);
}

static int rome2_case_load_absolute(const wchar_t *dll_path)
{
    return rome2_case_load_common(dll_path, ROME2_LOAD_ABSOLUTE,
        "load-absolute");
}

static int rome2_case_load_relative(const wchar_t *dll_path)
{
    return rome2_case_load_common(dll_path, ROME2_LOAD_RELATIVE,
        "load-relative");
}

static int rome2_case_invalid_resolution(const wchar_t *dll_path)
{
    static const char *forbidden_names[] = {
        "Rome2EntryPoint",
        "Rome2Guest32ProbeAbiVersionW",
        "Rome2Guest32ProbeSelectEntryPolicyA",
        "Rome2Guest32ProbeSelectEntryPolicy@20",
        "_Rome2Guest32ProbeSelectEntryPolicy"
    };
    rome2_loaded_probe probe;
    size_t index;
    int failures = 0;

    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }
    for (index = 0; index < ROME2_ARRAY_COUNT(forbidden_names); ++index) {
        if (GetProcAddress(probe.module, forbidden_names[index]) != NULL) {
            fprintf(stderr, "FAIL invalid-resolution: unexpected export %s\n",
                forbidden_names[index]);
            ++failures;
        }
    }
    return rome2_finish_case(&probe, failures);
}

static int rome2_case_load_cycles(const wchar_t *dll_path)
{
    uint8_t literal[ROME2_LITERAL_BYTES];
    unsigned int cycle;
    int failures = 0;

    rome2_store_literal(literal);
    for (cycle = 0; cycle < 64; ++cycle) {
        rome2_loaded_probe probe;
        rome2_load_mode mode = cycle < 32 ?
            ROME2_LOAD_ABSOLUTE : ROME2_LOAD_RELATIVE;

        if (rome2_load_probe(dll_path, mode, &probe) != 0) {
            ++failures;
            break;
        }
        failures += rome2_expect_u64("load-cycle", "abi-version",
            probe.abi_version(), ROME2_PROBE_ABI_VERSION);
        failures += rome2_call_and_check(&probe, "load-cycle-call", literal,
            UINT32_C(0x8100), ROME2_LITERAL_BYTES, UINT32_C(0x8100),
            ROME2_STATUS_OK, ROME2_POLICY_SKIP_HANDLER,
            literal, sizeof(literal));
        failures += rome2_unload_probe(&probe);
        if (failures != 0) {
            break;
        }
    }
    return failures;
}

static int rome2_case_repeat(const wchar_t *dll_path)
{
    uint8_t exact[ROME2_LITERAL_BYTES];
    uint8_t exact_snapshot[ROME2_LITERAL_BYTES];
    uint8_t mismatch[2] = { 0x21, 0x00 };
    uint8_t truncated[42];
    uint8_t truncated_snapshot[42];
    rome2_loaded_probe probe;
    unsigned int iteration;
    int failures = 0;

    rome2_store_literal(exact);
    memcpy(exact_snapshot, exact, sizeof(exact));
    memcpy(truncated, exact, sizeof(truncated));
    memcpy(truncated_snapshot, truncated, sizeof(truncated));
    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }

    for (iteration = 0; iteration < 10000; ++iteration) {
        uint32_t policy = ROME2_POLICY_SENTINEL;
        uint32_t status;

        if (iteration % 3 == 0) {
            status = probe.select_policy(exact, UINT32_C(0x9000),
                ROME2_LITERAL_BYTES, UINT32_C(0x9000), &policy);
            if (status != ROME2_STATUS_OK ||
                policy != ROME2_POLICY_SKIP_HANDLER) {
                failures = rome2_report_failure("repeat-exact",
                    "nondeterministic status or policy");
                break;
            }
        }
        else if (iteration % 3 == 1) {
            status = probe.select_policy(mismatch, UINT32_C(0x9100),
                sizeof(mismatch), UINT32_C(0x9100), &policy);
            if (status != ROME2_STATUS_OK ||
                policy != ROME2_POLICY_INSTALL_HANDLER) {
                failures = rome2_report_failure("repeat-mismatch",
                    "nondeterministic status or policy");
                break;
            }
        }
        else {
            status = probe.select_policy(truncated, UINT32_C(0x9200),
                sizeof(truncated), UINT32_C(0x9200), &policy);
            if (status != ROME2_STATUS_OUT_OF_RANGE ||
                policy != ROME2_POLICY_SENTINEL) {
                failures = rome2_report_failure("repeat-failure",
                    "nondeterministic status or output mutation");
                break;
            }
        }
    }
    if (memcmp(exact, exact_snapshot, sizeof(exact)) != 0 ||
        memcmp(truncated, truncated_snapshot, sizeof(truncated)) != 0 ||
        mismatch[0] != 0x21 || mismatch[1] != 0x00) {
        failures += rome2_report_failure("repeat", "input bytes were modified");
    }
    return rome2_finish_case(&probe, failures);
}

typedef struct rome2_thread_context {
    rome2_probe_select_fn select_policy;
    unsigned int thread_index;
    unsigned int iterations;
    LONG failures;
} rome2_thread_context;

static DWORD WINAPI rome2_concurrency_thread(LPVOID parameter)
{
    rome2_thread_context *context = (rome2_thread_context *)parameter;
    uint8_t exact[ROME2_LITERAL_BYTES];
    uint8_t exact_snapshot[ROME2_LITERAL_BYTES];
    uint8_t mismatch[2] = { 0x21, 0x00 };
    uint8_t truncated[42];
    uint8_t truncated_snapshot[42];
    unsigned int iteration;

    rome2_store_literal(exact);
    memcpy(exact_snapshot, exact, sizeof(exact));
    memcpy(truncated, exact, sizeof(truncated));
    memcpy(truncated_snapshot, truncated, sizeof(truncated));

    for (iteration = 0; iteration < context->iterations; ++iteration) {
        unsigned int selector = (iteration + context->thread_index) % 3;
        uint32_t policy = ROME2_POLICY_SENTINEL;
        uint32_t status;

        if (selector == 0) {
            status = context->select_policy(exact, UINT32_C(0xa000),
                ROME2_LITERAL_BYTES, UINT32_C(0xa000), &policy);
            if (status != ROME2_STATUS_OK ||
                policy != ROME2_POLICY_SKIP_HANDLER) {
                ++context->failures;
                break;
            }
        }
        else if (selector == 1) {
            status = context->select_policy(mismatch, UINT32_C(0xa100),
                sizeof(mismatch), UINT32_C(0xa100), &policy);
            if (status != ROME2_STATUS_OK ||
                policy != ROME2_POLICY_INSTALL_HANDLER) {
                ++context->failures;
                break;
            }
        }
        else {
            status = context->select_policy(truncated, UINT32_C(0xa200),
                sizeof(truncated), UINT32_C(0xa200), &policy);
            if (status != ROME2_STATUS_OUT_OF_RANGE ||
                policy != ROME2_POLICY_SENTINEL) {
                ++context->failures;
                break;
            }
        }
        if (memcmp(exact, exact_snapshot, sizeof(exact)) != 0 ||
            memcmp(truncated, truncated_snapshot, sizeof(truncated)) != 0 ||
            mismatch[0] != 0x21 || mismatch[1] != 0x00) {
            ++context->failures;
            break;
        }
    }
    return (DWORD)context->failures;
}

static int rome2_case_concurrency(const wchar_t *dll_path)
{
    enum { thread_count = 16, iterations_per_thread = 2000 };
    HANDLE threads[thread_count];
    rome2_thread_context contexts[thread_count];
    rome2_loaded_probe probe;
    DWORD wait_result;
    unsigned int index;
    unsigned int created = 0;
    int failures = 0;

    memset(threads, 0, sizeof(threads));
    memset(contexts, 0, sizeof(contexts));
    if (rome2_load_probe(dll_path, ROME2_LOAD_ABSOLUTE, &probe) != 0) {
        return 1;
    }

    for (index = 0; index < thread_count; ++index) {
        contexts[index].select_policy = probe.select_policy;
        contexts[index].thread_index = index;
        contexts[index].iterations = iterations_per_thread;
        threads[index] = CreateThread(NULL, 0, rome2_concurrency_thread,
            &contexts[index], 0, NULL);
        if (threads[index] == NULL) {
            failures += rome2_report_failure("concurrency",
                "CreateThread failed");
            break;
        }
        ++created;
    }
    if (created == 0) {
        rome2_unload_probe(&probe);
        return ROME2_INFRASTRUCTURE_EXIT;
    }

    /*
     * CTest owns the wall-clock timeout for this process.  Never return while
     * a worker can still reference contexts[] or the loaded probe.
     */
    wait_result = WaitForMultipleObjects(created, threads, TRUE, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        failures += rome2_report_failure("concurrency",
            "worker threads did not finish cleanly");
        for (index = 0; index < created; ++index) {
            if (WaitForSingleObject(threads[index], INFINITE) !=
                    WAIT_OBJECT_0) {
                failures += rome2_report_failure("concurrency",
                    "cannot join a worker thread");
            }
        }
    }

    for (index = 0; index < created; ++index) {
        DWORD thread_exit = 0;

        if (GetExitCodeThread(threads[index], &thread_exit) == 0) {
            failures += rome2_report_failure("concurrency",
                "GetExitCodeThread failed");
        }
        else if (thread_exit != 0 || contexts[index].failures != 0) {
            failures += rome2_report_failure("concurrency",
                "a worker observed nondeterministic behavior");
        }
        CloseHandle(threads[index]);
    }
    return rome2_finish_case(&probe, failures);
}

static const rome2_case_descriptor rome2_cases[] = {
    { L"abi", "H-ABI-01", rome2_case_abi },
    { L"semantics", "H-SEM-01", rome2_case_semantics },
    { L"early-stop", "H-SEM-02", rome2_case_early_stop },
    { L"truncation", "H-SEM-02", rome2_case_truncation },
    { L"memory-errors", "H-MEM-01", rome2_case_memory_errors },
    { L"memory-boundaries", "H-MEM-02", rome2_case_memory_boundaries },
    { L"high-native", "H-MEM-03", rome2_case_high_native },
    { L"load-absolute", "H-LOAD-01", rome2_case_load_absolute },
    { L"load-relative", "H-LOAD-01", rome2_case_load_relative },
    { L"invalid-resolution", "H-LOAD-02", rome2_case_invalid_resolution },
    { L"load-cycles", "H-LOAD-02", rome2_case_load_cycles },
    { L"repeat", "H-CONC-01", rome2_case_repeat },
    { L"concurrency", "H-CONC-01", rome2_case_concurrency }
};

static const rome2_case_descriptor *rome2_find_case(const wchar_t *name)
{
    size_t index;

    for (index = 0; index < ROME2_ARRAY_COUNT(rome2_cases); ++index) {
        if (wcscmp(name, rome2_cases[index].name) == 0) {
            return &rome2_cases[index];
        }
    }
    return NULL;
}

static void rome2_print_usage(const wchar_t *program)
{
    size_t index;

    fwprintf(stderr,
        L"usage: %ls <absolute-or-relative-probe-dll>\n"
        L"       %ls --case <name> <probe-dll>\n",
        program, program);
    fwprintf(stderr, L"cases:");
    for (index = 0; index < ROME2_ARRAY_COUNT(rome2_cases); ++index) {
        fwprintf(stderr, L" %ls", rome2_cases[index].name);
    }
    fwprintf(stderr, L"\n");
}

int wmain(int argc, wchar_t **argv)
{
    wchar_t dll_path[32768];
    const rome2_case_descriptor *single_case = NULL;
    const wchar_t *input_path;
    size_t index;
    int failures = 0;
    int infrastructure_failures = 0;

    if (argc == 2) {
        input_path = argv[1];
    }
    else if (argc == 4 && wcscmp(argv[1], L"--case") == 0) {
        single_case = rome2_find_case(argv[2]);
        if (single_case == NULL) {
            rome2_print_usage(argv[0]);
            return 2;
        }
        input_path = argv[3];
    }
    else {
        rome2_print_usage(argv[0]);
        return 2;
    }

    if (rome2_normalize_candidate_path(input_path, dll_path,
            ROME2_ARRAY_COUNT(dll_path)) != 0) {
        return 1;
    }

    if (single_case != NULL) {
        int result = single_case->run(dll_path);

        return result == ROME2_INFRASTRUCTURE_EXIT ? 2 : result;
    }

    for (index = 0; index < ROME2_ARRAY_COUNT(rome2_cases); ++index) {
        const rome2_case_descriptor *descriptor = &rome2_cases[index];
        int result = descriptor->run(dll_path);

        if (result == ROME2_INFRASTRUCTURE_EXIT) {
            ++infrastructure_failures;
            fprintf(stderr, "INFRA %s/%ls\n", descriptor->check_id,
                descriptor->name);
        }
        else if (result != 0) {
            ++failures;
            fprintf(stderr, "FAIL %s/%ls\n", descriptor->check_id,
                descriptor->name);
        }
        else {
            printf("PASS %s/%ls\n", descriptor->check_id,
                descriptor->name);
        }
    }
    if (infrastructure_failures != 0) {
        fprintf(stderr, "probe runtime paused: %d infrastructure case(s)\n",
            infrastructure_failures);
        return 2;
    }
    if (failures != 0) {
        fprintf(stderr, "probe runtime failed: %d case(s)\n", failures);
        return 1;
    }
    printf("probe runtime passed: %zu cases\n",
        ROME2_ARRAY_COUNT(rome2_cases));
    return 0;
}
