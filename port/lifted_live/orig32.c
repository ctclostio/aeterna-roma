/*
 * orig32.c - 32-bit observer of the original DLL's start-up: the reference
 * side of scripts/lift/compare_orig.py.
 *
 * Loads the game's own empire.retail.dll in a 32-bit process and writes
 *   <prefix>.trace  every call the DLL makes through its import table while
 *                   its entry runs DLL_PROCESS_ATTACH, as pairs of dwords:
 *                   RVA of the import-table slot, return address (rebased to
 *                   the preferred image base)
 *   <prefix>.mem    its writable sections when the entry returns and, for every
 *                   aligned dword in them, what kind of address its value is
 *   <prefix>.valloc its VirtualAlloc calls with their results
 *   <prefix>.env    this process's executable path, command line, stack base
 *                   and ESP at the DLL entry, which the lifted run is given
 *                   so both see the same strings and stack addresses
 *
 * The DLL's code is unmodified; its import table points at stubs that record
 * the call and jump to the real function. The process ends without running
 * DLL_PROCESS_DETACH.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define PREFERRED 0x10000000u
#define MAX_SLOTS 4096u
#define MAX_CALLS (16u << 20)
#define STUB 10u

typedef struct call_rec {
    uint32_t slot, ret;
} call_rec;

static uint8_t *g_base, *g_entry, *g_stubs, g_saved[5];
static uint32_t g_image_size, g_tid, g_nslots, g_skipped, g_ncalls, g_other_thread, g_result = 0xffffffffu;
static void *g_orig[MAX_SLOTS];
static uint32_t g_slot_rva[MAX_SLOTS];
static call_rec *g_calls;
static int g_logging;

static IMAGE_NT_HEADERS32 *nt_headers(void) { return (IMAGE_NT_HEADERS32 *)(g_base + ((IMAGE_DOS_HEADER *)g_base)->e_lfanew); }

/* VirtualAlloc is also recorded with its arguments and result (<prefix>.valloc: address, size, type, protection,
 * result per call), so the lifted run can be given the same address layout. */
#define MAX_VA 8192u
static uint8_t g_capture[MAX_SLOTS];
static uint32_t g_va[MAX_VA][5], g_nva, g_shadow[16], g_depth;

/* Integer code only (/arch:IA32) and no API calls: the caller's floating-point state and last error stay as they
 * are. Returns nonzero when the call's result is to be recorded too. */
static int __cdecl log_call(uint32_t slot, uint32_t ret, const uint32_t *args) {
    if (!g_logging) {
        return 0;
    }
    if (__readfsdword(0x24) != g_tid) {
        ++g_other_thread;
        return 0;
    }
    if (g_ncalls < MAX_CALLS) {
        g_calls[g_ncalls].slot = g_slot_rva[slot];
        g_calls[g_ncalls].ret = ret - (uint32_t)(uintptr_t)g_base + PREFERRED;
    }
    ++g_ncalls;
    if (!g_capture[slot] || g_nva == MAX_VA || g_depth == 16u) {
        return 0;
    }
    g_va[g_nva][0] = args[0];
    g_va[g_nva][1] = args[1];
    g_va[g_nva][2] = args[2];
    g_va[g_nva][3] = args[3];
    g_shadow[g_depth++] = ret;
    return 1;
}
static uint32_t __cdecl pop_return(uint32_t result) {
    g_va[g_nva++][4] = result;
    return g_shadow[--g_depth];
}

/* Where a recorded call returns to: notes the result, then goes on to the caller. */
static __declspec(naked) void after_return(void) {
    __asm {
        sub esp, 4
        pushad
        pushfd
        push eax
        call pop_return
        add esp, 4
        mov [esp + 36], eax
        popfd
        popad
        ret
    }
}

/* Entered from a stub with the slot number pushed above the caller's return address. */
static __declspec(naked) void common(void) {
    __asm {
        pushad
        pushfd
        lea ecx, [esp + 44]
        mov eax, [esp + 36]
        mov edx, [esp + 40]
        push ecx
        push edx
        push eax
        call log_call
        add esp, 12
        test eax, eax
        jz pass
        mov dword ptr [esp + 40], offset after_return
    pass:
        popfd
        popad
        xchg eax, [esp]
        mov eax, g_orig[eax * 4]
        xchg eax, [esp]
        ret
    }
}

static void hook_imports(void) {
    IMAGE_DATA_DIRECTORY dir = nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *d = (IMAGE_IMPORT_DESCRIPTOR *)(g_base + dir.VirtualAddress);
    g_stubs = VirtualAlloc(NULL, MAX_SLOTS * STUB, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    for (; g_stubs != NULL && d->Name != 0u; ++d) {
        uint32_t *iat = (uint32_t *)(g_base + d->FirstThunk);
        const uint32_t *name = d->OriginalFirstThunk != 0u ? (const uint32_t *)(g_base + d->OriginalFirstThunk) : NULL;
        for (; *iat != 0u; ++iat, name += name != NULL) {
            MEMORY_BASIC_INFORMATION mbi;
            uint8_t *s = g_stubs + STUB * g_nslots;
            uint32_t rel = (uint32_t)((uint8_t *)common - (s + STUB));
            DWORD old;
            /* A slot that does not hold the address of code (a data import) is left alone. */
            if (g_nslots == MAX_SLOTS || VirtualQuery((void *)(uintptr_t)*iat, &mbi, sizeof mbi) == 0u || (mbi.Protect & 0xf0u) == 0u) {
                ++g_skipped;
                continue;
            }
            g_orig[g_nslots] = (void *)(uintptr_t)*iat;
            g_slot_rva[g_nslots] = (uint32_t)((uint8_t *)iat - g_base);
            g_capture[g_nslots] = name != NULL && (*name & 0x80000000u) == 0u
                                  && strcmp((const char *)(g_base + *name + 2u), "VirtualAlloc") == 0;
            s[0] = 0x68u; /* push imm32 */
            memcpy(s + 1, &g_nslots, 4u);
            s[5] = 0xe9u; /* jmp rel32 */
            memcpy(s + 6, &rel, 4u);
            VirtualProtect(iat, 4u, PAGE_READWRITE, &old);
            *iat = (uint32_t)(uintptr_t)s;
            VirtualProtect(iat, 4u, old, &old);
            ++g_nslots;
        }
    }
}

typedef BOOL(WINAPI *dll_entry)(HINSTANCE, DWORD, LPVOID);
static char g_mem_path[MAX_PATH + 8];
static int g_mem_written;
static uint32_t g_entry_esp;
static int write_mem(const char *path);

static void poke_entry(const uint8_t *bytes) {
    DWORD old;
    VirtualProtect(g_entry, 5u, PAGE_EXECUTE_READWRITE, &old);
    memcpy(g_entry, bytes, 5u);
    VirtualProtect(g_entry, 5u, old, &old);
    FlushInstructionCache(GetCurrentProcess(), g_entry, 5u);
}

/* Runs in place of the DLL's entry the first time the loader calls it. */
static BOOL WINAPI hook_entry(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    BOOL r;
    poke_entry(g_saved);
    if (reason != DLL_PROCESS_ATTACH) {
        return ((dll_entry)g_entry)(inst, reason, reserved);
    }
    hook_imports();
    g_entry_esp = (uint32_t)(uintptr_t)&inst - 4u; /* where the loader's return address is */
    g_tid = GetCurrentThreadId();
    g_logging = 1;
    r = ((dll_entry)g_entry)(inst, reason, reserved);
    g_logging = 0;
    g_result = (uint32_t)r;
    /* Here, under the loader lock: a thread that starts later runs the DLL's thread-attach code and changes the data. */
    g_mem_written = write_mem(g_mem_path);
    return r;
}

/* ntdll's loader notification: called once a DLL is mapped, before its imports are bound and its entry runs. */
typedef struct ustr {
    USHORT Length, MaximumLength;
    PWSTR Buffer;
} ustr;
typedef struct ldr_note {
    ULONG Flags;
    const ustr *FullDllName, *BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} ldr_note;
typedef VOID(CALLBACK *ldr_fn)(ULONG reason, const ldr_note *data, PVOID context);
typedef LONG(NTAPI *ldr_register)(ULONG flags, ldr_fn fn, PVOID context, PVOID *cookie);

static void CALLBACK on_dll(ULONG reason, const ldr_note *d, PVOID context) {
    static const wchar_t name[] = L"empire.retail.dll";
    uint8_t jmp[5] = {0xe9u};
    uint32_t rel;
    (void)context;
    if (reason != 1u || g_base != NULL || d->BaseDllName->Length != sizeof name - sizeof name[0]
        || _wcsnicmp(d->BaseDllName->Buffer, name, sizeof name / sizeof name[0] - 1u) != 0) {
        return;
    }
    g_base = d->DllBase;
    g_image_size = d->SizeOfImage;
    g_entry = g_base + nt_headers()->OptionalHeader.AddressOfEntryPoint;
    memcpy(g_saved, g_entry, 5u);
    rel = (uint32_t)((uint8_t *)hook_entry - (g_entry + 5));
    memcpy(jmp + 1, &rel, 4u);
    poke_entry(jmp);
}

/* 0 not an address, 1 this image, 2 other committed memory (heap, stack, thread block), 3 another module. */
static uint8_t addr_class(uint32_t v) {
    static uint32_t lo, hi;
    static uint8_t cls;
    MEMORY_BASIC_INFORMATION mbi;
    if (v < 0x10000u) {
        return 0u;
    }
    if (v - (uint32_t)(uintptr_t)g_base < g_image_size) {
        return 1u;
    }
    if (v - (uint32_t)(uintptr_t)g_stubs < MAX_SLOTS * STUB) {
        return 3u; /* an import's address as this process's import table holds it */
    }
    if (v >= lo && v < hi) {
        return cls;
    }
    if (VirtualQuery((void *)(uintptr_t)v, &mbi, sizeof mbi) == 0u) {
        return 0u;
    }
    lo = (uint32_t)(uintptr_t)mbi.BaseAddress;
    hi = lo + (uint32_t)mbi.RegionSize;
    cls = mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0u ? 0u : mbi.Type == MEM_IMAGE ? 3u : 2u;
    return cls;
}

static void put32(FILE *f, uint32_t v) { fwrite(&v, 4u, 1u, f); }

/* A memory record: header, n (key, size) pairs, then each region's bytes followed by one class per dword. */
static int write_regions(const char *path, uint32_t n, const uint32_t *key, uint8_t *const *at, const uint32_t *size) {
    FILE *f = fopen(path, "wb");
    uint32_t i, a;
    if (f == NULL) {
        return 0;
    }
    fwrite("LMEM", 4u, 1u, f);
    put32(f, (uint32_t)(uintptr_t)g_base);
    put32(f, g_result);
    put32(f, GetCurrentProcessId());
    put32(f, g_tid);
    put32(f, n);
    for (i = 0u; i < n; ++i) {
        put32(f, key[i]);
        put32(f, size[i]);
    }
    for (i = 0u; i < n; ++i) {
        fwrite(at[i], 1u, size[i], f);
        for (a = 0u; a < size[i]; a += 4u) {
            uint32_t v;
            memcpy(&v, at[i] + a, 4u);
            fputc(addr_class(v), f);
        }
    }
    return fclose(f) == 0;
}

/* <prefix>.mem: the writable sections, keyed by RVA. <prefix>.heap: what VirtualAlloc returned, keyed by address. */
static int write_mem(const char *path) {
    static uint32_t key[MAX_VA], size[MAX_VA];
    static uint8_t *at[MAX_VA];
    IMAGE_NT_HEADERS32 *nt = nt_headers();
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    char heap[MAX_PATH + 8];
    uint32_t i, n = 0u;
    for (i = 0u; i < nt->FileHeader.NumberOfSections; ++i) {
        if ((s[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0u) {
            key[n] = s[i].VirtualAddress;
            at[n] = g_base + s[i].VirtualAddress;
            size[n++] = s[i].Misc.VirtualSize & ~3u;
        }
    }
    if (!write_regions(path, n, key, at, size)) {
        return 0;
    }
    for (i = n = 0u; i < g_nva; ++i) {
        if (g_va[i][0] == 0u && g_va[i][4] != 0u && (g_va[i][2] & MEM_COMMIT) != 0u) {
            key[n] = g_va[i][4];
            at[n] = (uint8_t *)(uintptr_t)g_va[i][4];
            size[n++] = (g_va[i][1] + 0xfffu) & ~0xfffu;
        }
    }
    snprintf(heap, sizeof heap, "%.*s.heap", (int)strlen(path) - 4, path);
    return write_regions(heap, n, key, at, size);
}

int main(int argc, char **argv) {
    char prefix[MAX_PATH], path[MAX_PATH + 8], exe[MAX_PATH];
    ldr_register reg = (ldr_register)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification");
    PVOID cookie = NULL;
    HMODULE dll;
    DWORD error;
    FILE *f;
    if (argc != 3 || GetFullPathNameA(argv[2], sizeof prefix, prefix, NULL) == 0u || !SetCurrentDirectoryA(argv[1])) {
        fprintf(stderr, "usage: orig32 <game directory> <output prefix>\n");
        return 2;
    }
    g_calls = VirtualAlloc(NULL, MAX_CALLS * sizeof *g_calls, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (reg == NULL || g_calls == NULL || reg(0u, on_dll, NULL, &cookie) != 0) {
        fprintf(stderr, "orig32: cannot set up\n");
        return 2;
    }
    GetModuleFileNameA(NULL, exe, sizeof exe);
    snprintf(g_mem_path, sizeof g_mem_path, "%s.mem", prefix);

    dll = LoadLibraryA("empire.retail.dll");
    error = GetLastError();
    snprintf(path, sizeof path, "%s.env", prefix);
    if ((f = fopen(path, "wb")) != NULL) {
        fprintf(f, "%s\n%s\n%x %x\n", exe, GetCommandLineA(), (unsigned)__readfsdword(4), g_entry_esp);
        fclose(f);
    }
    printf("original: module %p (error %lu), image base %p, entry returned %u\n", (void *)dll, dll != NULL ? 0ul : error,
           (void *)g_base, g_result);
    printf("original: %u import slots observed, %u left alone, %u calls recorded, %u from other threads\n", g_nslots, g_skipped,
           g_ncalls, g_other_thread);
    if (g_base == NULL || g_result == 0xffffffffu || g_ncalls > MAX_CALLS) {
        fprintf(stderr, "orig32: the DLL entry was not observed, or the call log overflowed\n");
        fflush(NULL);
        TerminateProcess(GetCurrentProcess(), 3u);
    }
    snprintf(path, sizeof path, "%s.trace", prefix);
    if ((f = fopen(path, "wb")) == NULL || fwrite(g_calls, sizeof *g_calls, g_ncalls, f) != g_ncalls || fclose(f) != 0) {
        fprintf(stderr, "orig32: cannot write %s\n", path);
    }
    snprintf(path, sizeof path, "%s.valloc", prefix);
    if ((f = fopen(path, "wb")) == NULL || fwrite(g_va, sizeof g_va[0], g_nva, f) != g_nva || fclose(f) != 0) {
        fprintf(stderr, "orig32: cannot write %s\n", path);
    }
    if (!g_mem_written) {
        fprintf(stderr, "orig32: cannot write %s\n", g_mem_path);
    }
    fflush(NULL);
    TerminateProcess(GetCurrentProcess(), 0u); /* no DLL_PROCESS_DETACH: the game's shutdown code is not what is observed */
    return 0;
}
