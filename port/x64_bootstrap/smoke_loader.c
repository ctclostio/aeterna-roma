#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bootstrap_contract.h"
#include "canonical_identity.h"

typedef uint64_t (*abi_version_fn)(void);
typedef const char *(*string_probe_fn)(void);
typedef int (*legacy_entry_fn)(
    HINSTANCE,
    HINSTANCE,
    const wchar_t *,
    uint32_t,
    void **,
    uint32_t,
    uint32_t,
    int32_t,
    void *);

_Static_assert(sizeof(void *) == 8, "the smoke loader must be compiled for x64");

static char *make_absolute_path(const char *path)
{
    DWORD required;
    DWORD written;
    char *absolute;

    required = GetFullPathNameA(path, 0, NULL, NULL);
    if (required == 0) {
        return NULL;
    }
    absolute = (char *)malloc((size_t)required);
    if (absolute == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    written = GetFullPathNameA(path, required, absolute, NULL);
    if (written == 0 || written >= required) {
        DWORD error = GetLastError();
        free(absolute);
        SetLastError(error != ERROR_SUCCESS ? error : ERROR_INSUFFICIENT_BUFFER);
        return NULL;
    }
    return absolute;
}

static FARPROC require_export(HMODULE module, const char *name)
{
    FARPROC address = GetProcAddress(module, name);
    if (address == NULL) {
        fprintf(stderr, "missing export %s (GetLastError=%lu)\n", name,
            (unsigned long)GetLastError());
    }
    return address;
}

static int export_matches_ordinal(HMODULE module, FARPROC named, WORD ordinal)
{
    FARPROC ordinal_address = GetProcAddress(module, MAKEINTRESOURCEA(ordinal));
    if (ordinal_address == NULL) {
        fprintf(stderr, "missing export ordinal %u (GetLastError=%lu)\n",
            (unsigned int)ordinal, (unsigned long)GetLastError());
        return 0;
    }
    if (ordinal_address != named) {
        fprintf(stderr, "named export and ordinal %u resolve differently\n",
            (unsigned int)ordinal);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    HMODULE module;
    FARPROC raw_export;
    FARPROC entry_by_name;
    FARPROC entry_by_ordinal;
    abi_version_fn abi_version = NULL;
    string_probe_fn fingerprint = NULL;
    string_probe_fn status = NULL;
    legacy_entry_fn legacy_entry = NULL;
    const char *actual_fingerprint;
    const char *actual_status;
    char *absolute_dll_path;
    int result = 1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <empire.retail.dll>\n", argv[0]);
        return 2;
    }

    absolute_dll_path = make_absolute_path(argv[1]);
    if (absolute_dll_path == NULL) {
        fprintf(stderr, "could not resolve DLL path %s (GetLastError=%lu)\n",
            argv[1], (unsigned long)GetLastError());
        return 1;
    }

    module = LoadLibraryExA(
        absolute_dll_path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR);
    if (module == NULL) {
        DWORD error = GetLastError();
        fprintf(stderr, "LoadLibraryExA failed for %s (GetLastError=%lu)\n",
            absolute_dll_path, (unsigned long)error);
        free(absolute_dll_path);
        return 1;
    }
    free(absolute_dll_path);

    _Static_assert(sizeof(raw_export) == sizeof(abi_version),
        "Windows function pointers must have one representation");

    entry_by_name = require_export(module, "entry_point");
    entry_by_ordinal = GetProcAddress(
        module, MAKEINTRESOURCEA(ROME2_LEGACY_ENTRY_ORDINAL));
    if (entry_by_ordinal == NULL) {
        fprintf(stderr, "missing export ordinal %u (GetLastError=%lu)\n",
            (unsigned int)ROME2_LEGACY_ENTRY_ORDINAL,
            (unsigned long)GetLastError());
    }
    if (entry_by_name == NULL || entry_by_ordinal == NULL) {
        goto cleanup;
    }
    if (entry_by_name != entry_by_ordinal) {
        fprintf(stderr, "entry_point name and ordinal %u resolve differently\n",
            (unsigned int)ROME2_LEGACY_ENTRY_ORDINAL);
        goto cleanup;
    }
    memcpy(&legacy_entry, &entry_by_name, sizeof(legacy_entry));
    if (legacy_entry(NULL, NULL, L"", 0, NULL, 0, 0, 0, NULL) !=
        ROME2_LEGACY_ENTRY_RESULT) {
        fprintf(stderr, "inert entry_point returned an unexpected result\n");
        goto cleanup;
    }

    raw_export = require_export(module, "Rome2PortAbiVersion");
    if (raw_export == NULL || !export_matches_ordinal(
            module, raw_export, ROME2_ABI_VERSION_ORDINAL)) {
        goto cleanup;
    }
    memcpy(&abi_version, &raw_export, sizeof(abi_version));

    raw_export = require_export(module, "Rome2PortCanonicalFingerprint");
    if (raw_export == NULL || !export_matches_ordinal(
            module, raw_export, ROME2_FINGERPRINT_ORDINAL)) {
        goto cleanup;
    }
    memcpy(&fingerprint, &raw_export, sizeof(fingerprint));

    raw_export = require_export(module, "Rome2PortStatus");
    if (raw_export == NULL || !export_matches_ordinal(
            module, raw_export, ROME2_STATUS_ORDINAL)) {
        goto cleanup;
    }
    memcpy(&status, &raw_export, sizeof(status));

    if (abi_version() != ROME2_PORT_ABI_VERSION) {
        fprintf(stderr, "unexpected port ABI version\n");
        goto cleanup;
    }
    actual_fingerprint = fingerprint();
    actual_status = status();
    if (actual_fingerprint == NULL || actual_status == NULL) {
        fprintf(stderr, "bootstrap returned a null identity/status string\n");
        goto cleanup;
    }
    if (strcmp(actual_fingerprint, ROME2_CANONICAL_FINGERPRINT) != 0) {
        fprintf(stderr, "bootstrap fingerprint does not match the canonical stage\n");
        goto cleanup;
    }
    if (strcmp(actual_status, ROME2_PORT_STATUS) != 0) {
        fprintf(stderr, "bootstrap status does not match the scaffold contract\n");
        goto cleanup;
    }

    printf("loaded x64 bootstrap: abi=0x%llx fingerprint=%s status=%s\n",
        (unsigned long long)abi_version(), actual_fingerprint, actual_status);
    result = 0;

cleanup:
    if (!FreeLibrary(module)) {
        fprintf(stderr, "FreeLibrary failed (GetLastError=%lu)\n",
            (unsigned long)GetLastError());
        result = 1;
    }
    return result;
}
