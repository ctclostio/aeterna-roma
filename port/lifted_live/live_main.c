/*
 * live_main.c - live runner for the lifted engine code.
 *
 *   live.exe --image <image.bin> [--game-dir <dir>] [--max-insns <n>] [--trace <n>]
 *
 * Loads the mapped game image into a flat 4 GiB guest address space, binds
 * every import slot to a host implementation (shim) where one exists, and
 * runs the DLL's initialisation entry on the lifted functions in lifted.dll.
 * Calls between lifted functions, guest memory and the shimmed Win32 calls
 * are real. The run stops at the first thing that is missing (an import
 * without a shim, an address with no lifted code, a guest fault) and prints
 * what it was and how far execution got.
 *
 * Guest pointers stay 32 bits wide: guest address a is host address
 * g_mem + a. One guest thread.
 */
#include "live.h"

#include <intrin.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#define CINTERFACE
#include <windows.h>
#include <mmsystem.h>
#include <objbase.h>
#include <oleauto.h>
#include <gameux.h>
#include <shlobj.h>
#include <shlwapi.h>

#pragma warning(disable : 4996) /* GetVersion, GetVersionEx: the guest asks for them */
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "winmm.lib")

/* Guest address space: the 2 GiB user range of a 32-bit process. */
#define VM_LO 0x00010000u
#define VM_HI 0x7ffe0000u
#define FS_BASE 0x7efdd000u
#define SYSTEM_LO 0x70000000u /* import slots, module handles, TEB: never handed out */
#define STACK_TOP 0x70000000u
#define STACK_LIMIT 0x6fe00000u
#define TLS_ARRAY 0x6fd00000u
#define PEB_ADDR 0x6fc00000u
#define HEAP_LO 0x60000000u /* process-heap blocks (HeapAlloc) */
#define HEAP_HI 0x6f000000u
#define IMPORT_BASE 0x70000000u
#define IMPORT_STEP 16u
#define MAX_IMPORTS 8192u
#define RET_SENTINEL 0x7ffe0000u
#define FAKE_EXE 0x00400000u
#define FAKE_MODULE 0x7d000000u /* + 0x10000 per registered module name */
#define SELF_DLL "empire.retail.dll"
#define TEB_LAST_ERROR 0x34u
#define TLS_SLOTS 1088u
#define RING 32u

static uint8_t *g_mem;
static lift_ctx *g_c;
static const live_core *g_core;
static char g_stop[512];
static char g_game_dir[MAX_PATH] = "Total War Rome II";
static uint64_t g_trace;

#define GP(a) (g_mem + (uint32_t)(a))
#define PTR(a) ((a) != 0u ? (void *)GP(a) : NULL)
#define H(x) ((HANDLE)(intptr_t)(int32_t)(x))

static uint32_t rd32(uint32_t a) {
    uint32_t v;
    memcpy(&v, GP(a), 4u);
    return v;
}
static void wr32(uint32_t a, uint32_t v) {
    memcpy(GP(a), &v, 4u);
}
static void stop(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (g_stop[0] == '\0') {
        vsnprintf(g_stop, sizeof g_stop, fmt, ap);
    }
    va_end(ap);
}
static void die(const char *what) {
    fprintf(stderr, "live: %s\n", what);
    exit(2);
}

/* ---- guest virtual memory ---------------------------------------------------------
 * Page states as VirtualAlloc, VirtualFree and VirtualQuery see them. Only
 * committed pages are backed by host memory and mapped for lifted code, so
 * touching a reserved or free page is a guest access violation. */

enum { PG_FREE = 0, PG_RESERVED = 1, PG_COMMITTED = 2 };
#define KEEP_BASE 0xffffffffu
static uint8_t *g_pstate;  /* per page */
static uint32_t *g_pbase;  /* per page: first page number of its allocation */
static uint64_t g_vm_reserved, g_vm_committed; /* pages */

static void vm_set(uint32_t lo, uint32_t hi, int state, uint32_t base) {
    uint32_t pn;
    if (lo >= hi) {
        return;
    }
    if (state == PG_COMMITTED) {
        if (VirtualAlloc(GP(lo), (SIZE_T)hi - lo, MEM_COMMIT, PAGE_READWRITE) == NULL) {
            die("host cannot commit guest memory");
        }
    } else {
        VirtualFree(GP(lo), (SIZE_T)hi - lo, MEM_DECOMMIT);
    }
    for (pn = lo >> 12; pn < hi >> 12; ++pn) {
        g_vm_reserved += (uint64_t)(state != PG_FREE) - (g_pstate[pn] != PG_FREE);
        g_vm_committed += (uint64_t)(state == PG_COMMITTED) - (g_pstate[pn] == PG_COMMITTED);
        g_pstate[pn] = (uint8_t)state;
        g_c->pt[pn] = state == PG_COMMITTED ? GP(pn << 12) : NULL;
        if (base != KEEP_BASE) {
            g_pbase[pn] = base;
        }
    }
}

/* Pages from pn on that share its state and allocation, up to limit. */
static uint32_t vm_run(uint32_t pn, uint32_t limit) {
    uint32_t n = 1u;
    while (pn + n < limit && g_pstate[pn + n] == g_pstate[pn] && (g_pstate[pn] == PG_FREE || g_pbase[pn + n] == g_pbase[pn])) {
        ++n;
    }
    return n;
}

static uint32_t vm_alloc(uint32_t addr, uint32_t size, uint32_t type) {
    uint32_t lo, hi, pn;
    if (size == 0u || size > VM_HI - VM_LO) {
        return 0u;
    }
    if (addr == 0u || ((type & MEM_RESERVE) != 0u && g_pstate[addr >> 12] == PG_FREE)) {
        /* New allocation, 64 KiB aligned: at addr, or first fit from the bottom (from the top for MEM_TOP_DOWN). */
        uint32_t pages = (uint32_t)(((uint64_t)size + (addr & 0xffffu) + 0xffffu) >> 16) << 4, run = 0u;
        if (addr != 0u) {
            lo = addr & ~0xffffu;
            if (lo < VM_LO || lo >= SYSTEM_LO || (lo >> 12) + pages > SYSTEM_LO >> 12 || g_pstate[lo >> 12] != PG_FREE
                || vm_run(lo >> 12, SYSTEM_LO >> 12) < pages) {
                return 0u;
            }
        } else if ((type & MEM_TOP_DOWN) != 0u) {
            for (pn = SYSTEM_LO >> 12; pn > VM_LO >> 12 && run < pages; pn -= 16u) {
                run = g_pstate[pn - 16u] == PG_FREE && vm_run(pn - 16u, pn) == 16u ? run + 16u : 0u;
            }
            if (run < pages) {
                return 0u;
            }
            lo = pn << 12;
        } else {
            for (pn = VM_LO >> 12; pn < SYSTEM_LO >> 12 && run < pages; pn += 16u) {
                run = g_pstate[pn] == PG_FREE && vm_run(pn, pn + 16u) == 16u ? run + 16u : 0u;
            }
            if (run < pages) {
                return 0u;
            }
            lo = (pn - pages) << 12;
        }
        vm_set(lo, lo + (pages << 12), PG_RESERVED, lo >> 12);
        if ((type & MEM_COMMIT) != 0u) {
            hi = addr != 0u ? (uint32_t)(((uint64_t)addr + size + 0xfffu) & ~0xfffull) : lo + ((size + 0xfffu) & ~0xfffu);
            vm_set(addr != 0u ? addr & ~0xfffu : lo, hi, PG_COMMITTED, KEEP_BASE);
        }
        return lo;
    }
    /* Commit inside an existing allocation. */
    lo = addr & ~0xfffu;
    hi = (uint32_t)(((uint64_t)addr + size + 0xfffu) & ~0xfffull);
    if ((type & MEM_COMMIT) == 0u || hi <= lo || hi > SYSTEM_LO) {
        return 0u;
    }
    for (pn = lo >> 12; pn < hi >> 12; ++pn) {
        if (g_pstate[pn] == PG_FREE || g_pbase[pn] != g_pbase[lo >> 12]) {
            return 0u;
        }
    }
    for (pn = lo >> 12; pn < hi >> 12; ++pn) {
        if (g_pstate[pn] == PG_RESERVED) { /* committed pages keep their contents */
            vm_set(pn << 12, (pn + 1u) << 12, PG_COMMITTED, KEEP_BASE);
        }
    }
    return lo;
}

static int vm_free(uint32_t addr, uint32_t size, uint32_t type) {
    uint32_t pn = addr >> 12, n;
    if (addr < VM_LO || addr >= SYSTEM_LO || g_pstate[pn] == PG_FREE) {
        return 0;
    }
    if ((type & MEM_RELEASE) != 0u) {
        if (size != 0u || g_pbase[pn] != pn) {
            return 0;
        }
        for (n = 1u; pn + n < SYSTEM_LO >> 12 && g_pstate[pn + n] != PG_FREE && g_pbase[pn + n] == pn; ++n) {
        }
        vm_set(addr, addr + (n << 12), PG_FREE, 0u);
        return 1;
    }
    if ((type & MEM_DECOMMIT) != 0u) {
        uint32_t hi = size != 0u ? (uint32_t)(((uint64_t)addr + size + 0xfffu) & ~0xfffull) : 0u;
        if (size == 0u) {
            for (n = 0u; pn + n < SYSTEM_LO >> 12 && g_pstate[pn + n] != PG_FREE && g_pbase[pn + n] == g_pbase[pn]; ++n) {
            }
            hi = (pn + n) << 12;
        }
        vm_set(addr & ~0xfffu, hi, PG_RESERVED, KEEP_BASE);
        return 1;
    }
    return 0;
}

/* MEMORY_BASIC_INFORMATION, 32-bit layout (28 bytes). */
static void vm_query(uint32_t addr, uint32_t mbi) {
    uint32_t pn = addr >> 12, n = vm_run(pn, VM_HI >> 12), state = g_pstate[pn];
    uint32_t image = state != PG_FREE && g_pbase[pn] == LM_IMAGE_BASE >> 12;
    uint32_t out[7];
    out[0] = pn << 12;
    out[1] = state != PG_FREE ? g_pbase[pn] << 12 : 0u;
    out[2] = state != PG_FREE ? (image ? PAGE_EXECUTE_WRITECOPY : PAGE_READWRITE) : 0u;
    out[3] = n << 12;
    out[4] = state == PG_COMMITTED ? MEM_COMMIT : state == PG_RESERVED ? MEM_RESERVE : MEM_FREE;
    out[5] = state == PG_COMMITTED ? (image ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE) : state == PG_FREE ? PAGE_NOACCESS : 0u;
    out[6] = state == PG_FREE ? 0u : image ? MEM_IMAGE : MEM_PRIVATE;
    memcpy(GP(mbi), out, sizeof out);
}

/* ---- guest heap ------------------------------------------------------------------
 * Power-of-two size classes with free lists, carved from [HEAP_LO, HEAP_HI).
 * Block: dword requested size, dword class | magic, then the user bytes
 * (8-byte aligned, as the 32-bit process heap gives). */

#define BLK_LIVE 0xa110c000u
#define BLK_FREE 0xf4ee0000u
static uint32_t g_heap_top = HEAP_LO;
static uint32_t g_free[32];
static uint64_t g_heap_live, g_heap_allocs;

static uint32_t galloc(uint32_t size, int zero) {
    uint32_t cls = 4u, a;
    if (size > 0x20000000u) {
        return 0u;
    }
    while ((1u << cls) < size + 8u) {
        ++cls;
    }
    a = g_free[cls];
    if (a != 0u) {
        g_free[cls] = rd32(a + 8u);
    } else {
        if ((1u << cls) > HEAP_HI - g_heap_top) {
            return 0u;
        }
        a = g_heap_top;
        g_heap_top += 1u << cls;
    }
    wr32(a, size);
    wr32(a + 4u, BLK_LIVE | cls);
    if (zero) {
        memset(GP(a + 8u), 0, size);
    }
    g_heap_live += size;
    ++g_heap_allocs;
    return a + 8u;
}
static uint32_t blk_class(uint32_t p, const char *who) {
    uint32_t tag = (p >= HEAP_LO + 8u && p < g_heap_top) ? rd32(p - 4u) : 0u;
    if ((tag & 0xffffff00u) != BLK_LIVE) {
        stop("%s: %08x is not a live heap block", who, p);
        return 0u;
    }
    return tag & 0xffu;
}
static void gfree(uint32_t p) {
    uint32_t cls;
    if (p == 0u || (cls = blk_class(p, "free")) == 0u) {
        return;
    }
    g_heap_live -= rd32(p - 8u);
    wr32(p - 4u, BLK_FREE | cls);
    wr32(p, g_free[cls]);
    g_free[cls] = p - 8u;
}
static uint32_t gdup(const void *src, uint32_t n) {
    uint32_t p = galloc(n, 0);
    if (p == 0u) {
        die("guest heap exhausted");
    }
    memcpy(GP(p), src, n);
    return p;
}

/* ---- modules and imports ----------------------------------------------------------- */

typedef uint32_t (*shim_fn)(lift_ctx *c, const uint32_t *a);
typedef struct shim {
    const char *name;
    uint32_t nargs; /* stack dwords the callee removes (stdcall) */
    shim_fn fn;
} shim;
typedef struct import {
    char dll[64], name[96];
    const shim *sh;
    uint64_t calls;
} import;

static import g_imp[MAX_IMPORTS];
static uint32_t g_nimp, g_static_imports;
static char g_mod[128][64];
static uint32_t g_nmod;
static const shim *find_shim(const char *name);
static uint32_t export_addr(const char *name);

static uint32_t import_addr(const char *dll, const char *name) {
    uint32_t i;
    for (i = 0u; i < g_nimp; ++i) {
        if (strcmp(g_imp[i].name, name) == 0 && _stricmp(g_imp[i].dll, dll) == 0) {
            return IMPORT_BASE + i * IMPORT_STEP;
        }
    }
    if (g_nimp == MAX_IMPORTS) {
        die("import table full");
    }
    snprintf(g_imp[i].dll, sizeof g_imp[i].dll, "%s", dll);
    snprintf(g_imp[i].name, sizeof g_imp[i].name, "%s", name);
    g_imp[i].sh = find_shim(name);
    ++g_nimp;
    return IMPORT_BASE + i * IMPORT_STEP;
}

/* Module handle for a file name; the path and a missing ".dll" do not matter. */
static uint32_t module_handle(const char *path) {
    char name[64];
    const char *base = path, *p;
    uint32_t i;
    for (p = path; *p != '\0'; ++p) {
        if (*p == '\\' || *p == '/') {
            base = p + 1;
        }
    }
    snprintf(name, sizeof name, strchr(base, '.') != NULL ? "%s" : "%s.dll", base);
    _strlwr(name);
    if (strcmp(name, SELF_DLL) == 0) {
        return LM_IMAGE_BASE;
    }
    for (i = 0u; i < g_nmod; ++i) {
        if (strcmp(g_mod[i], name) == 0) {
            return FAKE_MODULE + (i << 16);
        }
    }
    if (g_nmod == 128u) {
        die("module table full");
    }
    strcpy(g_mod[g_nmod], name);
    return FAKE_MODULE + (g_nmod++ << 16);
}
static const char *module_name(uint32_t h) {
    uint32_t i = (h - FAKE_MODULE) >> 16;
    return h == LM_IMAGE_BASE ? SELF_DLL : (h >= FAKE_MODULE && i < g_nmod) ? g_mod[i] : NULL;
}
static void narrow(uint32_t wide, char *out, int cap) {
    out[0] = '\0';
    WideCharToMultiByte(CP_ACP, 0, (const wchar_t *)GP(wide), -1, out, cap, NULL, NULL);
    out[cap - 1] = '\0';
}

/* ---- shims: KERNEL32 ------------------------------------------------------------------ */

#define SHIM(n) static uint32_t sh_##n(lift_ctx *c, const uint32_t *a)
#define LAST_ERROR() wr32(FS_BASE + TEB_LAST_ERROR, GetLastError())

static uint32_t g_tls[TLS_SLOTS], g_tls_next = 1u;
static uint32_t g_cmdline_a, g_cmdline_w, g_unhandled_filter;

SHIM(GetLastError) { return rd32(FS_BASE + TEB_LAST_ERROR); }
SHIM(SetLastError) { wr32(FS_BASE + TEB_LAST_ERROR, a[0]); return 0u; }
SHIM(GetSystemTimeAsFileTime) { GetSystemTimeAsFileTime((FILETIME *)GP(a[0])); return 0u; }
SHIM(GetCurrentProcessId) { return GetCurrentProcessId(); }
SHIM(GetCurrentThreadId) { return GetCurrentThreadId(); }
SHIM(GetCurrentProcess) { return 0xffffffffu; }
SHIM(GetCurrentThread) { return 0xfffffffeu; }
SHIM(GetTickCount) { return GetTickCount(); }
SHIM(QueryPerformanceCounter) { return (uint32_t)QueryPerformanceCounter((LARGE_INTEGER *)GP(a[0])); }
SHIM(QueryPerformanceFrequency) { return (uint32_t)QueryPerformanceFrequency((LARGE_INTEGER *)GP(a[0])); }
SHIM(GetVersion) { return GetVersion(); }
SHIM(GetVersionExA) { return (uint32_t)GetVersionExA((OSVERSIONINFOA *)GP(a[0])); }
SHIM(GetVersionExW) { return (uint32_t)GetVersionExW((OSVERSIONINFOW *)GP(a[0])); }
SHIM(IsProcessorFeaturePresent) { return (uint32_t)IsProcessorFeaturePresent(a[0]); }
SHIM(IsDebuggerPresent) { return 0u; }
SHIM(Sleep) { Sleep(a[0]); return 0u; }
SHIM(EncodePointer) { return a[0]; }
SHIM(DecodePointer) { return a[0]; }
SHIM(SetUnhandledExceptionFilter) { uint32_t old = g_unhandled_filter; g_unhandled_filter = a[0]; return old; }
SHIM(OutputDebugStringA) { fprintf(stderr, "guest: %s", (const char *)GP(a[0])); return 0u; }
SHIM(ExitProcess) { stop("guest called ExitProcess(%u)", a[0]); return 0u; }
SHIM(TerminateProcess) { stop("guest called TerminateProcess(%08x, %u)", a[0], a[1]); return 0u; }

/* Heap: one guest heap serves every heap handle. */
SHIM(GetProcessHeap) { return 0x00010000u; }
SHIM(HeapCreate) { static uint32_t n; return 0x00020000u + (++n << 4); }
SHIM(HeapDestroy) { return 1u; }
SHIM(HeapSetInformation) { return 1u; }
SHIM(HeapValidate) { return 1u; }
SHIM(HeapAlloc) {
    uint32_t p = galloc(a[2], (a[1] & HEAP_ZERO_MEMORY) != 0u);
    if (p == 0u) {
        wr32(FS_BASE + TEB_LAST_ERROR, ERROR_NOT_ENOUGH_MEMORY);
    }
    return p;
}
SHIM(HeapFree) { gfree(a[2]); return 1u; }
SHIM(HeapSize) { return blk_class(a[2], "HeapSize") != 0u ? rd32(a[2] - 8u) : 0xffffffffu; }
SHIM(HeapReAlloc) {
    uint32_t p = a[2], size = a[3], cls = blk_class(p, "HeapReAlloc"), old, q;
    if (cls == 0u) {
        return 0u;
    }
    old = rd32(p - 8u);
    if (size + 8u <= (1u << cls) && size <= 0x20000000u) {
        wr32(p - 8u, size);
        g_heap_live += (uint64_t)size - old;
        q = p;
    } else if ((a[1] & HEAP_REALLOC_IN_PLACE_ONLY) != 0u || (q = galloc(size, 0)) == 0u) {
        wr32(FS_BASE + TEB_LAST_ERROR, ERROR_NOT_ENOUGH_MEMORY);
        return 0u;
    } else {
        memcpy(GP(q), GP(p), old < size ? old : size);
        gfree(p);
    }
    if ((a[1] & HEAP_ZERO_MEMORY) != 0u && size > old) {
        memset(GP(q + old), 0, size - old);
    }
    return q;
}
/* Virtual memory. Page protections are not enforced: a committed page is readable and writable. */
SHIM(VirtualAlloc) {
    uint32_t p = vm_alloc(a[0], a[1], a[2]);
    if (p == 0u) {
        wr32(FS_BASE + TEB_LAST_ERROR, a[0] != 0u ? ERROR_INVALID_ADDRESS : ERROR_NOT_ENOUGH_MEMORY);
    }
    return p;
}
SHIM(VirtualFree) {
    uint32_t ok = (uint32_t)vm_free(a[0], a[1], a[2]);
    if (!ok) {
        wr32(FS_BASE + TEB_LAST_ERROR, ERROR_INVALID_ADDRESS);
    }
    return ok;
}
SHIM(VirtualQuery) {
    if (a[2] < 28u) {
        return 0u;
    }
    vm_query(a[0], a[1]);
    return 28u;
}
SHIM(VirtualProtect) {
    if (a[3] != 0u) {
        wr32(a[3], PAGE_READWRITE);
    }
    return 1u;
}

/* Thread-local and fiber-local slots (one guest thread). */
SHIM(TlsAlloc) { return g_tls_next < TLS_SLOTS ? g_tls_next++ : 0xffffffffu; }
SHIM(TlsFree) { return 1u; }
SHIM(TlsGetValue) { wr32(FS_BASE + TEB_LAST_ERROR, 0u); return a[0] < TLS_SLOTS ? g_tls[a[0]] : 0u; }
SHIM(TlsSetValue) { if (a[0] >= TLS_SLOTS) { return 0u; } g_tls[a[0]] = a[1]; return 1u; }
SHIM(FlsAlloc) { return g_tls_next < TLS_SLOTS ? g_tls_next++ : 0xffffffffu; }
SHIM(FlsSetValue) { if (a[0] >= TLS_SLOTS) { return 0u; } g_tls[a[0]] = a[1]; return 1u; }

/* Critical sections keep the 32-bit layout in guest memory:
 * DebugInfo, LockCount, RecursionCount, OwningThread, LockSemaphore, SpinCount. */
SHIM(InitializeCriticalSection) {
    memset(GP(a[0]), 0, 24u);
    wr32(a[0] + 4u, 0xffffffffu);
    return 1u;
}
SHIM(InitializeCriticalSectionAndSpinCount) {
    sh_InitializeCriticalSection(c, a);
    wr32(a[0] + 20u, a[1]);
    return 1u;
}
SHIM(EnterCriticalSection) {
    wr32(a[0] + 4u, rd32(a[0] + 4u) + 1u);
    wr32(a[0] + 8u, rd32(a[0] + 8u) + 1u);
    wr32(a[0] + 12u, GetCurrentThreadId());
    return 1u;
}
SHIM(LeaveCriticalSection) {
    uint32_t depth = rd32(a[0] + 8u) - 1u;
    wr32(a[0] + 4u, rd32(a[0] + 4u) - 1u);
    wr32(a[0] + 8u, depth);
    if (depth == 0u) {
        wr32(a[0] + 12u, 0u);
    }
    return 0u;
}
SHIM(DeleteCriticalSection) { memset(GP(a[0]), 0, 24u); return 0u; }

SHIM(InterlockedIncrement) { return (uint32_t)_InterlockedIncrement((long *)GP(a[0])); }
SHIM(InterlockedDecrement) { return (uint32_t)_InterlockedDecrement((long *)GP(a[0])); }
SHIM(InterlockedExchange) { return (uint32_t)_InterlockedExchange((long *)GP(a[0]), (long)a[1]); }
SHIM(InterlockedExchangeAdd) { return (uint32_t)_InterlockedExchangeAdd((long *)GP(a[0]), (long)a[1]); }
SHIM(InterlockedCompareExchange) {
    return (uint32_t)_InterlockedCompareExchange((long *)GP(a[0]), (long)a[1], (long)a[2]);
}

/* Condition variables and slim locks. With one guest thread nobody can be
 * waiting and a lock is never contended; a wait that would need another
 * thread to end it stops the run. */
SHIM(InitializeConditionVariable) { wr32(a[0], 0u); return 0u; }
SHIM(WakeConditionVariable) { return 0u; }
SHIM(SleepConditionVariableCS) { stop("SleepConditionVariableCS: no second guest thread to wake the first"); return 0u; }
SHIM(AcquireSRWLock) {
    if (rd32(a[0]) != 0u) {
        stop("slim lock %08x acquired twice by the only guest thread", a[0]);
    }
    wr32(a[0], 1u);
    return 1u;
}
SHIM(ReleaseSRWLock) { wr32(a[0], 0u); return 0u; }

/* Interlocked singly linked lists, 32-bit header: Next, Depth (word), Sequence (word). */
SHIM(InitializeSListHead) { memset(GP(a[0]), 0, 8u); return 0u; }
SHIM(InterlockedPushEntrySList) {
    uint32_t old = rd32(a[0]);
    wr32(a[1], old);
    wr32(a[0], a[1]);
    wr32(a[0] + 4u, rd32(a[0] + 4u) + 0x00010001u);
    return old;
}
SHIM(InterlockedPopEntrySList) {
    uint32_t e = rd32(a[0]);
    if (e != 0u) {
        wr32(a[0], rd32(e));
        wr32(a[0] + 4u, rd32(a[0] + 4u) + 0x0000ffffu);
    }
    return e;
}
SHIM(InterlockedFlushSList) {
    uint32_t e = rd32(a[0]);
    wr32(a[0], 0u);
    wr32(a[0] + 4u, rd32(a[0] + 4u) & 0xffff0000u);
    return e;
}
SHIM(QueryDepthSList) { return rd32(a[0] + 4u) & 0xffffu; }

/* Process start-up data. */
SHIM(GetStartupInfoA) { memset(GP(a[0]), 0, 68u); wr32(a[0], 68u); return 0u; }
SHIM(GetStdHandle) { return (uint32_t)(uintptr_t)GetStdHandle(a[0]); }
SHIM(GetFileType) { return GetFileType(H(a[0])); }
SHIM(SetHandleCount) { return a[0]; }
SHIM(GetCommandLineA) { return g_cmdline_a; }
SHIM(GetCommandLineW) { return g_cmdline_w; }
SHIM(GetEnvironmentStringsW) {
    wchar_t *env = GetEnvironmentStringsW();
    const wchar_t *p = env;
    uint32_t g;
    while (*p != L'\0') {
        p += wcslen(p) + 1u;
    }
    g = gdup(env, (uint32_t)((p + 1 - env) * sizeof *p));
    FreeEnvironmentStringsW(env);
    return g;
}
SHIM(FreeEnvironmentStringsW) { gfree(a[0]); return 1u; }

/* Code pages and locale: the buffers have the same layout at both widths. */
SHIM(GetACP) { return GetACP(); }
SHIM(GetOEMCP) { return GetOEMCP(); }
SHIM(IsValidCodePage) { return (uint32_t)IsValidCodePage(a[0]); }
SHIM(GetCPInfo) { return (uint32_t)GetCPInfo(a[0], (CPINFO *)GP(a[1])); }
SHIM(GetUserDefaultLCID) { return GetUserDefaultLCID(); }
SHIM(IsValidLocale) { return (uint32_t)IsValidLocale(a[0], a[1]); }
SHIM(WideCharToMultiByte) {
    uint32_t r = (uint32_t)WideCharToMultiByte(a[0], a[1], PTR(a[2]), (int)a[3], PTR(a[4]), (int)a[5], PTR(a[6]), PTR(a[7]));
    LAST_ERROR();
    return r;
}
SHIM(MultiByteToWideChar) {
    uint32_t r = (uint32_t)MultiByteToWideChar(a[0], a[1], PTR(a[2]), (int)a[3], PTR(a[4]), (int)a[5]);
    LAST_ERROR();
    return r;
}
SHIM(GetStringTypeW) { return (uint32_t)GetStringTypeW(a[0], PTR(a[1]), (int)a[2], PTR(a[3])); }
SHIM(LCMapStringW) {
    uint32_t r = (uint32_t)LCMapStringW(a[0], a[1], PTR(a[2]), (int)a[3], PTR(a[4]), (int)a[5]);
    LAST_ERROR();
    return r;
}
SHIM(GetLocaleInfoW) { return (uint32_t)GetLocaleInfoW(a[0], a[1], PTR(a[2]), (int)a[3]); }
SHIM(LCMapStringEx) {
    uint32_t r = (uint32_t)LCMapStringEx(PTR(a[0]), a[1], PTR(a[2]), (int)a[3], PTR(a[4]), (int)a[5], PTR(a[6]), NULL, 0);
    LAST_ERROR();
    return r;
}
SHIM(CompareStringEx) {
    uint32_t r = (uint32_t)CompareStringEx(PTR(a[0]), a[1], PTR(a[2]), (int)a[3], PTR(a[4]), (int)a[5], PTR(a[6]), NULL, 0);
    LAST_ERROR();
    return r;
}
SHIM(CompareStringW) { return (uint32_t)CompareStringW(a[0], a[1], PTR(a[2]), (int)a[3], PTR(a[4]), (int)a[5]); }
SHIM(GetLocaleInfoA) { return (uint32_t)GetLocaleInfoA(a[0], a[1], PTR(a[2]), (int)a[3]); }
SHIM(GetLocaleInfoEx) { return (uint32_t)GetLocaleInfoEx(PTR(a[0]), a[1], PTR(a[2]), (int)a[3]); }
SHIM(GetUserDefaultLocaleName) { return (uint32_t)GetUserDefaultLocaleName(PTR(a[0]), (int)a[1]); }
SHIM(IsValidLocaleName) { return (uint32_t)IsValidLocaleName(PTR(a[0])); }
SHIM(LCIDToLocaleName) { return (uint32_t)LCIDToLocaleName(a[0], PTR(a[1]), (int)a[2], a[3]); }
SHIM(LocaleNameToLCID) { return LocaleNameToLCID(PTR(a[0]), a[1]); }
SHIM(AreFileApisANSI) { return (uint32_t)AreFileApisANSI(); }
SHIM(GetSystemTimePreciseAsFileTime) { GetSystemTimePreciseAsFileTime((FILETIME *)GP(a[0])); return 0u; }
SHIM(GetTickCount64) {
    uint64_t t = GetTickCount64();
    c->r[LM_EDX] = (uint32_t)(t >> 32);
    return (uint32_t)t;
}

/* Modules. Handles other than the game DLL stand for a name; GetProcAddress
 * hands out an import slot, so an unimplemented function stops the run only
 * when it is called. */
SHIM(GetModuleHandleA) { return a[0] == 0u ? FAKE_EXE : module_handle((const char *)GP(a[0])); }
SHIM(GetModuleHandleW) {
    char name[MAX_PATH];
    if (a[0] == 0u) {
        return FAKE_EXE;
    }
    narrow(a[0], name, sizeof name);
    return module_handle(name);
}
SHIM(LoadLibraryA) { return module_handle((const char *)GP(a[0])); }
SHIM(LoadLibraryW) { return sh_GetModuleHandleW(c, a); }
SHIM(LoadLibraryExA) { return module_handle((const char *)GP(a[0])); }
SHIM(LoadLibraryExW) { return sh_GetModuleHandleW(c, a); }
SHIM(FreeLibrary) { return 1u; }
SHIM(GetProcAddress) {
    const char *dll = module_name(a[0]);
    char ordinal[16];
    if (a[0] == LM_IMAGE_BASE && a[1] >= 0x10000u) {
        return export_addr((const char *)GP(a[1]));
    }
    if (dll == NULL || a[0] == LM_IMAGE_BASE) {
        stop("GetProcAddress on module %08x is not implemented", a[0]);
        return 0u;
    }
    if (a[1] < 0x10000u) {
        snprintf(ordinal, sizeof ordinal, "#%u", a[1]);
        return import_addr(dll, ordinal);
    }
    return import_addr(dll, (const char *)GP(a[1]));
}
static void module_path(uint32_t h, char *out, size_t cap) {
    const char *name = h == 0u || h == FAKE_EXE ? "Rome2.exe" : module_name(h);
    snprintf(out, cap, "%s\\%s", g_game_dir, name != NULL ? name : "unknown.dll");
}
SHIM(GetModuleFileNameA) {
    char path[MAX_PATH];
    module_path(a[0], path, sizeof path);
    if (a[2] == 0u) {
        return 0u;
    }
    snprintf((char *)GP(a[1]), a[2], "%s", path);
    return (uint32_t)strlen((const char *)GP(a[1]));
}
SHIM(GetModuleFileNameW) {
    char path[MAX_PATH];
    int n;
    module_path(a[0], path, sizeof path);
    n = MultiByteToWideChar(CP_ACP, 0, path, -1, (wchar_t *)GP(a[1]), (int)a[2]);
    return n > 0 ? (uint32_t)n - 1u : 0u;
}

/* System description. The guest sees a 32-bit x86 process: 4 KiB pages, a 2 GiB user range. */
SHIM(GetSystemInfo) {
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    memset(GP(a[0]), 0, 36u);
    wr32(a[0] + 4u, 4096u);
    wr32(a[0] + 8u, 0x00010000u);
    wr32(a[0] + 12u, 0x7ffeffffu);
    wr32(a[0] + 16u, (uint32_t)si.dwActiveProcessorMask);
    wr32(a[0] + 20u, si.dwNumberOfProcessors > 32u ? 32u : si.dwNumberOfProcessors);
    wr32(a[0] + 24u, 586u);
    wr32(a[0] + 28u, 0x00010000u);
    wr32(a[0] + 32u, (uint32_t)si.wProcessorLevel | ((uint32_t)si.wProcessorRevision << 16));
    return 0u;
}
SHIM(GlobalMemoryStatusEx) {
    MEMORYSTATUSEX *ms = (MEMORYSTATUSEX *)GP(a[0]);
    BOOL ok = GlobalMemoryStatusEx(ms); /* physical and page-file figures are the host's */
    ms->ullTotalVirtual = VM_HI;
    ms->ullAvailVirtual = VM_HI - VM_LO - (g_vm_reserved << 12);
    ms->ullAvailExtendedVirtual = 0u;
    return (uint32_t)ok;
}
SHIM(GetProcessAffinityMask) {
    DWORD_PTR process = 0u, system = 0u;
    BOOL ok = GetProcessAffinityMask(GetCurrentProcess(), &process, &system);
    wr32(a[1], (uint32_t)process);
    wr32(a[2], (uint32_t)system);
    return (uint32_t)ok;
}
SHIM(GetLocalTime) { GetLocalTime((SYSTEMTIME *)GP(a[0])); return 0u; }
SHIM(GetSystemTime) { GetSystemTime((SYSTEMTIME *)GP(a[0])); return 0u; }
SHIM(timeGetTime) { return timeGetTime(); }
SHIM(GetEnvironmentVariableA) { uint32_t r = GetEnvironmentVariableA(PTR(a[0]), PTR(a[1]), a[2]); LAST_ERROR(); return r; }
SHIM(GetEnvironmentVariableW) { uint32_t r = GetEnvironmentVariableW(PTR(a[0]), PTR(a[1]), a[2]); LAST_ERROR(); return r; }
SHIM(GetCurrentDirectoryA) { return GetCurrentDirectoryA(a[0], PTR(a[1])); }
SHIM(GetCurrentDirectoryW) { return GetCurrentDirectoryW(a[0], PTR(a[1])); }

/* Kernel objects are the host's; a handle value fits 32 bits. */
#define HANDLE32(h) ((uint32_t)(uintptr_t)(h))
SHIM(CloseHandle) { uint32_t r = (uint32_t)CloseHandle(H(a[0])); LAST_ERROR(); return r; }
SHIM(CreateEventA) { uint32_t r = HANDLE32(CreateEventA(NULL, (BOOL)a[1], (BOOL)a[2], PTR(a[3]))); LAST_ERROR(); return r; }
SHIM(CreateEventW) { uint32_t r = HANDLE32(CreateEventW(NULL, (BOOL)a[1], (BOOL)a[2], PTR(a[3]))); LAST_ERROR(); return r; }
SHIM(SetEvent) { return (uint32_t)SetEvent(H(a[0])); }
SHIM(ResetEvent) { return (uint32_t)ResetEvent(H(a[0])); }
SHIM(CreateMutexA) { uint32_t r = HANDLE32(CreateMutexA(NULL, (BOOL)a[1], PTR(a[2]))); LAST_ERROR(); return r; }
SHIM(CreateMutexW) { uint32_t r = HANDLE32(CreateMutexW(NULL, (BOOL)a[1], PTR(a[2]))); LAST_ERROR(); return r; }
SHIM(ReleaseMutex) { return (uint32_t)ReleaseMutex(H(a[0])); }
SHIM(CreateSemaphoreA) { uint32_t r = HANDLE32(CreateSemaphoreA(NULL, (LONG)a[1], (LONG)a[2], PTR(a[3]))); LAST_ERROR(); return r; }
SHIM(CreateSemaphoreW) { uint32_t r = HANDLE32(CreateSemaphoreW(NULL, (LONG)a[1], (LONG)a[2], PTR(a[3]))); LAST_ERROR(); return r; }
SHIM(ReleaseSemaphore) { return (uint32_t)ReleaseSemaphore(H(a[0]), (LONG)a[1], PTR(a[2])); }
SHIM(WaitForSingleObject) { uint32_t r = WaitForSingleObject(H(a[0]), a[1]); LAST_ERROR(); return r; }

/* ---- shims: files ------------------------------------------------------------------------------
 * Files are the host's. Opening for write, creating and deleting stop the
 * run unless --allow-writes is given, so a fault in the port cannot damage
 * the installed game or its saved settings while it is being brought up. */

static int g_allow_writes;
static char g_profile[MAX_PATH]; /* stands for the user's application-data folders; writes below it are allowed */
static HANDLE g_find[256];

static int write_allowed(const char *what, const char *path_a, const wchar_t *path_w) {
    char narrow_path[MAX_PATH] = "", full[MAX_PATH] = "";
    if (path_a == NULL) {
        WideCharToMultiByte(CP_ACP, 0, path_w, -1, narrow_path, sizeof narrow_path, NULL, NULL);
        path_a = narrow_path;
    }
    GetFullPathNameA(path_a, sizeof full, full, NULL);
    if (g_allow_writes || (g_profile[0] != '\0' && _strnicmp(full, g_profile, strlen(g_profile)) == 0)) {
        return 1;
    }
    stop("%s wants to write %s (outside --profile; pass --allow-writes 1 to permit)", what, full);
    return 0;
}
static int is_write(uint32_t access, uint32_t disposition) {
    return (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE)) != 0u || disposition != OPEN_EXISTING;
}
SHIM(CreateFileA) {
    uint32_t r;
    if (is_write(a[1], a[4]) && !write_allowed("CreateFileA", PTR(a[0]), NULL)) {
        return 0xffffffffu;
    }
    r = HANDLE32(CreateFileA(PTR(a[0]), a[1], a[2], NULL, a[4], a[5], NULL));
    LAST_ERROR();
    return r;
}
SHIM(CreateFileW) {
    uint32_t r;
    if (is_write(a[1], a[4]) && !write_allowed("CreateFileW", NULL, PTR(a[0]))) {
        return 0xffffffffu;
    }
    r = HANDLE32(CreateFileW(PTR(a[0]), a[1], a[2], NULL, a[4], a[5], NULL));
    LAST_ERROR();
    return r;
}
SHIM(ReadFile) {
    DWORD n = 0u;
    BOOL ok;
    if (a[4] != 0u) {
        stop("ReadFile with OVERLAPPED is not implemented");
        return 0u;
    }
    ok = ReadFile(H(a[0]), PTR(a[1]), a[2], &n, NULL);
    LAST_ERROR();
    if (a[3] != 0u) {
        wr32(a[3], n);
    }
    return (uint32_t)ok;
}
SHIM(WriteFile) {
    DWORD n = 0u;
    BOOL ok;
    if (a[4] != 0u) {
        stop("WriteFile with OVERLAPPED is not implemented");
        return 0u;
    }
    ok = WriteFile(H(a[0]), PTR(a[1]), a[2], &n, NULL); /* the handle was opened under the write rule, or is a console */
    LAST_ERROR();
    if (a[3] != 0u) {
        wr32(a[3], n);
    }
    return (uint32_t)ok;
}
SHIM(GetFileSize) { uint32_t r = GetFileSize(H(a[0]), PTR(a[1])); LAST_ERROR(); return r; }
SHIM(GetFileSizeEx) { uint32_t r = (uint32_t)GetFileSizeEx(H(a[0]), (LARGE_INTEGER *)GP(a[1])); LAST_ERROR(); return r; }
SHIM(SetFilePointer) { uint32_t r = SetFilePointer(H(a[0]), (LONG)a[1], PTR(a[2]), a[3]); LAST_ERROR(); return r; }
SHIM(SetFilePointerEx) {
    LARGE_INTEGER to;
    uint32_t r;
    to.QuadPart = (LONGLONG)(((uint64_t)a[2] << 32) | a[1]);
    r = (uint32_t)SetFilePointerEx(H(a[0]), to, PTR(a[3]), a[4]);
    LAST_ERROR();
    return r;
}
SHIM(GetFileAttributesA) { uint32_t r = GetFileAttributesA(PTR(a[0])); LAST_ERROR(); return r; }
SHIM(GetFileAttributesW) { uint32_t r = GetFileAttributesW(PTR(a[0])); LAST_ERROR(); return r; }
SHIM(GetFileAttributesExA) { uint32_t r = (uint32_t)GetFileAttributesExA(PTR(a[0]), a[1], PTR(a[2])); LAST_ERROR(); return r; }
SHIM(GetFileAttributesExW) { uint32_t r = (uint32_t)GetFileAttributesExW(PTR(a[0]), a[1], PTR(a[2])); LAST_ERROR(); return r; }
SHIM(FileTimeToSystemTime) { return (uint32_t)FileTimeToSystemTime(PTR(a[0]), PTR(a[1])); }
SHIM(SystemTimeToFileTime) { return (uint32_t)SystemTimeToFileTime(PTR(a[0]), PTR(a[1])); }
SHIM(FileTimeToLocalFileTime) { return (uint32_t)FileTimeToLocalFileTime(PTR(a[0]), PTR(a[1])); }
SHIM(GetFullPathNameA) {
    char *part = NULL;
    uint32_t r = GetFullPathNameA(PTR(a[0]), a[1], PTR(a[2]), &part);
    LAST_ERROR();
    if (a[3] != 0u) {
        wr32(a[3], part != NULL ? (uint32_t)((uint8_t *)part - g_mem) : 0u);
    }
    return r;
}
SHIM(GetFullPathNameW) {
    wchar_t *part = NULL;
    uint32_t r = GetFullPathNameW(PTR(a[0]), a[1], PTR(a[2]), &part);
    LAST_ERROR();
    if (a[3] != 0u) {
        wr32(a[3], part != NULL ? (uint32_t)((uint8_t *)part - g_mem) : 0u);
    }
    return r;
}
/* A search handle is a host pointer, so the guest gets a table index. The find-data buffers have no pointers. */
static uint32_t find_open(HANDLE h) {
    uint32_t i;
    LAST_ERROR();
    if (h == INVALID_HANDLE_VALUE) {
        return 0xffffffffu;
    }
    for (i = 0u; i < 256u; ++i) {
        if (g_find[i] == NULL) {
            g_find[i] = h;
            return 0x00f00000u + (i << 2);
        }
    }
    FindClose(h);
    stop("too many open file searches");
    return 0xffffffffu;
}
static HANDLE *find_slot(uint32_t h) {
    uint32_t i = (h - 0x00f00000u) >> 2;
    return h >= 0x00f00000u && i < 256u && g_find[i] != NULL ? &g_find[i] : NULL;
}
SHIM(FindFirstFileA) { return find_open(FindFirstFileA(PTR(a[0]), PTR(a[1]))); }
SHIM(FindFirstFileW) { return find_open(FindFirstFileW(PTR(a[0]), PTR(a[1]))); }
SHIM(FindNextFileA) { HANDLE *s = find_slot(a[0]); uint32_t r = s != NULL ? (uint32_t)FindNextFileA(*s, PTR(a[1])) : 0u; LAST_ERROR(); return r; }
SHIM(FindNextFileW) { HANDLE *s = find_slot(a[0]); uint32_t r = s != NULL ? (uint32_t)FindNextFileW(*s, PTR(a[1])) : 0u; LAST_ERROR(); return r; }
SHIM(FindClose) {
    HANDLE *s = find_slot(a[0]);
    if (s == NULL) {
        return 0u;
    }
    FindClose(*s);
    *s = NULL;
    return 1u;
}

/* ---- shims: COM ----------------------------------------------------------------------------------
 * COM is initialised on the host thread for real. An interface pointer is a
 * host object with a 64-bit vtable, so the guest cannot call it directly:
 * each interface needs a bridge, and creating a class that has none stops
 * the run and names it. */

typedef struct com_iface {
    const char *name;
    GUID iid;
    uint32_t n_methods;
    uint32_t vtbl; /* guest vtable of import slots "<name>#<method>", built on first use */
} com_iface;
static com_iface g_ifaces[] = {
    {"IGameExplorer", {0xe7b2fb72u, 0xd728u, 0x49b3u, {0xa5u, 0xf2u, 0x18u, 0xebu, 0xf5u, 0xf1u, 0x34u, 0x9eu}}, 7u, 0u},
};
static struct {
    uint32_t guest; /* guest object: one dword, the vtable pointer */
    IUnknown *host;
    com_iface *iface;
} g_proxy[256];

/* Guest object standing for a host interface pointer; 0 when the interface has no bridge. */
static uint32_t com_wrap(IUnknown *host, const GUID *iid) {
    size_t k;
    uint32_t i, m;
    for (k = 0u; k < sizeof g_ifaces / sizeof g_ifaces[0]; ++k) {
        com_iface *f = &g_ifaces[k];
        if (memcmp(&f->iid, iid, sizeof *iid) != 0) {
            continue;
        }
        for (i = 0u; i < 256u && g_proxy[i].host != NULL; ++i) {
        }
        if (i == 256u) {
            return 0u;
        }
        if (f->vtbl == 0u) {
            f->vtbl = galloc(4u * f->n_methods, 1);
            for (m = 0u; m < f->n_methods; ++m) {
                char method[64];
                snprintf(method, sizeof method, "%s#%u", f->name, m);
                wr32(f->vtbl + 4u * m, import_addr("com", method));
            }
        }
        g_proxy[i].guest = galloc(8u, 1);
        g_proxy[i].host = host;
        g_proxy[i].iface = f;
        wr32(g_proxy[i].guest, f->vtbl);
        return g_proxy[i].guest;
    }
    return 0u;
}
static int com_index(uint32_t guest) {
    int i;
    for (i = 0; i < 256; ++i) {
        if (g_proxy[i].host != NULL && g_proxy[i].guest == guest) {
            return i;
        }
    }
    stop("%08x is not a bridged COM object", guest);
    return -1;
}

static void guid_text(uint32_t g, char out[40]) {
    const uint8_t *p = GP(g);
    snprintf(out, 40, "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", rd32(g), p[4] | p[5] << 8, p[6] | p[7] << 8, p[8],
             p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}
SHIM(CoInitialize) { return (uint32_t)CoInitializeEx(NULL, COINIT_APARTMENTTHREADED); }
SHIM(CoInitializeEx) { return (uint32_t)CoInitializeEx(NULL, a[1]); }
SHIM(CoUninitialize) { CoUninitialize(); return 0u; }
SHIM(CoCreateInstance) {
    char clsid[40], iid[40];
    IUnknown *object = NULL;
    HRESULT hr = CoCreateInstance((const CLSID *)GP(a[0]), NULL, a[2], (const IID *)GP(a[3]), (void **)&object);
    wr32(a[4], 0u);
    if (FAILED(hr)) {
        return (uint32_t)hr; /* the class is not available on this system: the guest gets the real answer */
    }
    wr32(a[4], com_wrap(object, (const GUID *)GP(a[3])));
    if (rd32(a[4]) == 0u) {
        object->lpVtbl->Release(object);
        guid_text(a[0], clsid);
        guid_text(a[3], iid);
        stop("CoCreateInstance(class %s, interface %s) succeeded on the host: this interface needs a COM bridge", clsid, iid);
        return (uint32_t)E_NOTIMPL;
    }
    return (uint32_t)hr;
}

/* IUnknown, for every bridged interface. */
SHIM(com_QueryInterface) {
    int i = com_index(a[0]);
    IUnknown *out = NULL;
    HRESULT hr;
    char iid[40];
    if (i < 0) {
        return (uint32_t)E_FAIL;
    }
    hr = g_proxy[i].host->lpVtbl->QueryInterface(g_proxy[i].host, (const IID *)GP(a[1]), (void **)&out);
    wr32(a[2], SUCCEEDED(hr) ? com_wrap(out, (const GUID *)GP(a[1])) : 0u);
    if (SUCCEEDED(hr) && rd32(a[2]) == 0u) {
        out->lpVtbl->Release(out);
        guid_text(a[1], iid);
        stop("QueryInterface(%s) on %s succeeded on the host: this interface needs a COM bridge", iid, g_proxy[i].iface->name);
    }
    return (uint32_t)hr;
}
SHIM(com_AddRef) {
    int i = com_index(a[0]);
    return i >= 0 ? g_proxy[i].host->lpVtbl->AddRef(g_proxy[i].host) : 0u;
}
SHIM(com_Release) {
    int i = com_index(a[0]);
    uint32_t left = i >= 0 ? g_proxy[i].host->lpVtbl->Release(g_proxy[i].host) : 0u;
    if (i >= 0 && left == 0u) {
        gfree(g_proxy[i].guest);
        g_proxy[i].guest = 0u;
        g_proxy[i].host = NULL;
    }
    return left;
}

/* IGameExplorer (Windows Game Explorer). */
SHIM(IGameExplorer_VerifyAccess) {
    int i = com_index(a[0]);
    IGameExplorer *ge;
    BOOL has_access = FALSE;
    BSTR path;
    HRESULT hr;
    if (i < 0) {
        return (uint32_t)E_FAIL;
    }
    ge = (IGameExplorer *)g_proxy[i].host;
    path = SysAllocStringLen(PTR(a[1]), a[1] != 0u ? rd32(a[1] - 4u) / 2u : 0u);
    hr = ge->lpVtbl->VerifyAccess(ge, path, &has_access);
    SysFreeString(path);
    if (a[2] != 0u) {
        wr32(a[2], (uint32_t)has_access);
    }
    return (uint32_t)hr;
}
SHIM(IGameExplorer_change) {
    stop("IGameExplorer: adding, updating or removing the game's Windows registration is not done by this runner");
    return (uint32_t)E_ACCESSDENIED;
}

/* BSTR (OLEAUT32 ordinals 2, 4, 6, 7): byte length, then UTF-16 text and a terminator, in the guest heap. */
static uint32_t bstr_alloc(const void *text, uint32_t chars) {
    uint32_t p = galloc(4u + 2u * chars + 2u, 1);
    if (p == 0u) {
        return 0u;
    }
    wr32(p, 2u * chars);
    if (text != NULL) {
        memcpy(GP(p + 4u), text, 2u * chars);
    }
    return p + 4u;
}
SHIM(SysAllocString) { return a[0] != 0u ? bstr_alloc(GP(a[0]), (uint32_t)wcslen((const wchar_t *)GP(a[0]))) : 0u; }
SHIM(SysAllocStringLen) { return bstr_alloc(PTR(a[0]), a[1]); }
SHIM(SysFreeString) { if (a[0] != 0u) { gfree(a[0] - 4u); } return 0u; }
SHIM(SysStringLen) { return a[0] != 0u ? rd32(a[0] - 4u) / 2u : 0u; }

/* ---- shims: SHELL32, SHLWAPI ----------------------------------------------------------------- */

SHIM(SHGetFolderPathW) {
    int folder = (int)(a[1] & 0xffu);
    if (g_profile[0] != '\0' && (folder == CSIDL_APPDATA || folder == CSIDL_LOCAL_APPDATA || folder == CSIDL_PERSONAL
                                 || folder == CSIDL_COMMON_APPDATA)) {
        MultiByteToWideChar(CP_ACP, 0, g_profile, -1, PTR(a[4]), MAX_PATH);
        return 0u;
    }
    return (uint32_t)SHGetFolderPathW(NULL, (int)a[1], NULL, a[3], PTR(a[4]));
}
SHIM(SHCreateDirectoryExW) {
    return write_allowed("SHCreateDirectoryExW", NULL, PTR(a[1])) ? (uint32_t)SHCreateDirectoryExW(NULL, PTR(a[1]), NULL)
                                                                   : (uint32_t)ERROR_ACCESS_DENIED;
}
SHIM(PathAppendW) { return (uint32_t)PathAppendW(PTR(a[0]), PTR(a[1])); }

/* ---- shims: steam_api (cdecl) ------------------------------------------------------------------
 * No Steam client is attached. Callback objects are recorded as the library
 * records them; nothing dispatches them. */

static struct {
    uint32_t object, id;
} g_steam_callbacks[1024];
static uint32_t g_steam_ncallbacks;

SHIM(SteamAPI_RegisterCallback) {
    if (g_steam_ncallbacks == 1024u) {
        stop("Steam callback table full");
        return 0u;
    }
    g_steam_callbacks[g_steam_ncallbacks].object = a[0];
    g_steam_callbacks[g_steam_ncallbacks++].id = a[1];
    return 0u;
}
SHIM(SteamAPI_UnregisterCallback) {
    uint32_t i;
    for (i = 0u; i < g_steam_ncallbacks; ++i) {
        if (g_steam_callbacks[i].object == a[0]) {
            g_steam_callbacks[i] = g_steam_callbacks[--g_steam_ncallbacks];
            break;
        }
    }
    return 0u;
}

/* ---- shims: ADVAPI32 (registry, read side) ----------------------------------------------- */

#define HK(x) ((HKEY)(intptr_t)(int32_t)(x))
SHIM(RegOpenKeyExW) {
    HKEY key = NULL;
    LSTATUS r = RegOpenKeyExW(HK(a[0]), PTR(a[1]), a[2], a[3], &key);
    wr32(a[4], (uint32_t)(uintptr_t)key);
    return (uint32_t)r;
}
SHIM(RegOpenKeyExA) {
    HKEY key = NULL;
    LSTATUS r = RegOpenKeyExA(HK(a[0]), PTR(a[1]), a[2], a[3], &key);
    wr32(a[4], (uint32_t)(uintptr_t)key);
    return (uint32_t)r;
}
SHIM(RegQueryValueExW) { return (uint32_t)RegQueryValueExW(HK(a[0]), PTR(a[1]), NULL, PTR(a[3]), PTR(a[4]), PTR(a[5])); }
SHIM(RegQueryValueExA) { return (uint32_t)RegQueryValueExA(HK(a[0]), PTR(a[1]), NULL, PTR(a[3]), PTR(a[4]), PTR(a[5])); }
SHIM(RegCloseKey) { return (uint32_t)RegCloseKey(HK(a[0])); }

#define S(name, nargs) {#name, nargs, sh_##name}
static const shim g_shims[] = {
    S(GetLastError, 0), S(SetLastError, 1), S(GetSystemTimeAsFileTime, 1), S(GetCurrentProcessId, 0),
    S(GetCurrentThreadId, 0), S(GetCurrentProcess, 0), S(GetCurrentThread, 0), S(GetTickCount, 0),
    S(QueryPerformanceCounter, 1), S(QueryPerformanceFrequency, 1), S(GetVersion, 0), S(GetVersionExA, 1),
    S(GetVersionExW, 1), S(IsProcessorFeaturePresent, 1), S(IsDebuggerPresent, 0), S(Sleep, 1), S(EncodePointer, 1),
    S(DecodePointer, 1), S(SetUnhandledExceptionFilter, 1), S(OutputDebugStringA, 1), S(ExitProcess, 1),
    S(TerminateProcess, 2), S(GetProcessHeap, 0), S(HeapCreate, 3), S(HeapDestroy, 1), S(HeapSetInformation, 4),
    S(HeapValidate, 3), S(HeapAlloc, 3), S(HeapFree, 3), S(HeapSize, 3), S(HeapReAlloc, 4), S(VirtualAlloc, 4),
    S(VirtualFree, 3), S(VirtualQuery, 3), S(VirtualProtect, 4), S(TlsAlloc, 0), S(TlsFree, 1), S(TlsGetValue, 1), S(TlsSetValue, 2), S(FlsAlloc, 1),
    {"FlsFree", 1, sh_TlsFree}, {"FlsGetValue", 1, sh_TlsGetValue}, S(FlsSetValue, 2),
    S(InitializeCriticalSection, 1), S(InitializeCriticalSectionAndSpinCount, 2),
    {"InitializeCriticalSectionEx", 3, sh_InitializeCriticalSectionAndSpinCount}, S(EnterCriticalSection, 1),
    S(LeaveCriticalSection, 1), S(DeleteCriticalSection, 1), S(InterlockedIncrement, 1), S(InterlockedDecrement, 1),
    S(InterlockedExchange, 2), S(InterlockedExchangeAdd, 2), S(InterlockedCompareExchange, 3), S(GetStartupInfoA, 1),
    S(InitializeConditionVariable, 1), S(WakeConditionVariable, 1), {"WakeAllConditionVariable", 1, sh_WakeConditionVariable},
    S(SleepConditionVariableCS, 3), {"InitializeSRWLock", 1, sh_InitializeConditionVariable},
    {"AcquireSRWLockExclusive", 1, sh_AcquireSRWLock}, {"ReleaseSRWLockExclusive", 1, sh_ReleaseSRWLock},
    S(InitializeSListHead, 1), S(InterlockedPushEntrySList, 2), S(InterlockedPopEntrySList, 1),
    S(InterlockedFlushSList, 1), S(QueryDepthSList, 1),
    {"GetStartupInfoW", 1, sh_GetStartupInfoA}, S(GetStdHandle, 1), S(GetFileType, 1), S(SetHandleCount, 1),
    S(GetCommandLineA, 0), S(GetCommandLineW, 0), S(GetEnvironmentStringsW, 0), S(FreeEnvironmentStringsW, 1),
    S(GetACP, 0), S(GetOEMCP, 0), S(IsValidCodePage, 1), S(GetCPInfo, 2), S(GetUserDefaultLCID, 0), S(IsValidLocale, 2),
    S(WideCharToMultiByte, 8), S(MultiByteToWideChar, 6), S(GetStringTypeW, 4), S(LCMapStringW, 6), S(GetLocaleInfoW, 4),
    S(LCMapStringEx, 9), S(CompareStringEx, 9), S(CompareStringW, 6), S(GetLocaleInfoEx, 4), S(GetLocaleInfoA, 4),
    S(GetUserDefaultLocaleName, 2), S(IsValidLocaleName, 1), S(LCIDToLocaleName, 4), S(LocaleNameToLCID, 2),
    S(AreFileApisANSI, 0), S(GetSystemTimePreciseAsFileTime, 1), S(GetTickCount64, 0),
    S(RegOpenKeyExW, 5), S(RegOpenKeyExA, 5), S(RegQueryValueExW, 6), S(RegQueryValueExA, 6), S(RegCloseKey, 1),
    S(GetSystemInfo, 1), {"GetNativeSystemInfo", 1, sh_GetSystemInfo}, S(GlobalMemoryStatusEx, 1),
    S(GetProcessAffinityMask, 3), S(GetLocalTime, 1), S(GetSystemTime, 1), S(timeGetTime, 0),
    S(GetEnvironmentVariableA, 3), S(GetEnvironmentVariableW, 3), S(GetCurrentDirectoryA, 2), S(GetCurrentDirectoryW, 2),
    S(CloseHandle, 1), S(CreateEventA, 4), S(CreateEventW, 4), S(SetEvent, 1), S(ResetEvent, 1), S(CreateMutexA, 3),
    S(CreateMutexW, 3), S(ReleaseMutex, 1), S(CreateSemaphoreA, 4), S(CreateSemaphoreW, 4), S(ReleaseSemaphore, 3),
    S(WaitForSingleObject, 2), S(SHGetFolderPathW, 5), S(SHCreateDirectoryExW, 3), S(PathAppendW, 2),
    S(SteamAPI_RegisterCallback, 0), S(SteamAPI_UnregisterCallback, 0),
    S(CoInitialize, 1), S(CoInitializeEx, 2), S(CoUninitialize, 0), S(CoCreateInstance, 5),
    {"#2", 1, sh_SysAllocString}, {"#4", 2, sh_SysAllocStringLen}, {"#6", 1, sh_SysFreeString}, {"#7", 1, sh_SysStringLen},
    {"IGameExplorer#0", 3, sh_com_QueryInterface}, {"IGameExplorer#1", 1, sh_com_AddRef}, {"IGameExplorer#2", 1, sh_com_Release},
    {"IGameExplorer#3", 5, sh_IGameExplorer_change}, {"IGameExplorer#4", 5, sh_IGameExplorer_change},
    {"IGameExplorer#5", 5, sh_IGameExplorer_change}, {"IGameExplorer#6", 3, sh_IGameExplorer_VerifyAccess},
    S(CreateFileA, 7), S(CreateFileW, 7), S(ReadFile, 5), S(WriteFile, 5), S(GetFileSize, 2), S(GetFileSizeEx, 2),
    S(SetFilePointer, 4), S(SetFilePointerEx, 5), S(GetFileAttributesA, 1), S(GetFileAttributesW, 1),
    S(GetFileAttributesExA, 3), S(GetFileAttributesExW, 3), S(FileTimeToSystemTime, 2), S(SystemTimeToFileTime, 2),
    S(FileTimeToLocalFileTime, 2), S(GetFullPathNameA, 4), S(GetFullPathNameW, 4), S(FindFirstFileA, 2),
    S(FindFirstFileW, 2), S(FindNextFileA, 2), S(FindNextFileW, 2), S(FindClose, 1),
    S(GetModuleHandleA, 1), S(GetModuleHandleW, 1), S(LoadLibraryA, 1), S(LoadLibraryW, 1), S(LoadLibraryExA, 3),
    S(LoadLibraryExW, 3), S(FreeLibrary, 1), S(GetProcAddress, 2), S(GetModuleFileNameA, 3), S(GetModuleFileNameW, 3),
};

static const shim *find_shim(const char *name) {
    size_t i;
    for (i = 0u; i < sizeof g_shims / sizeof g_shims[0]; ++i) {
        if (strcmp(g_shims[i].name, name) == 0) {
            return &g_shims[i];
        }
    }
    return NULL;
}

/* ---- survey ---------------------------------------------------------------------------------
 * A development aid, not execution: with --survey <table of name, stack bytes>
 * an import without a shim returns 0 with the right number of argument bytes
 * removed, and the run goes on so that one run lists the imports the next
 * stretch of code needs. Whatever happens after the first such call did not
 * happen in the real program; the report says so. The table also checks the
 * argument counts of the shims. */

static struct sig {
    char name[96];
    uint32_t bytes;
} *g_sig;
static uint32_t g_nsig, g_survey_hits[256], g_nsurvey;
static uint64_t g_survey_calls;

static int sig_bytes(const import *im) {
    static const char *const cdecl_dlls[] = {"steam_api.dll", "LIBEAY32.dll", "SSLEAY32.dll", "twitchsdk_32_release.dll"};
    const char *at = strrchr(im->name, '@');
    uint32_t i;
    if (at != NULL && at[1] != '\0') {
        return atoi(at + 1); /* decorated stdcall name carries its size */
    }
    for (i = 0u; i < sizeof cdecl_dlls / sizeof cdecl_dlls[0]; ++i) {
        if (_stricmp(im->dll, cdecl_dlls[i]) == 0) {
            return 0;
        }
    }
    for (i = 0u; i < g_nsig; ++i) {
        if (strcmp(g_sig[i].name, im->name) == 0) {
            return (int)g_sig[i].bytes;
        }
    }
    return -1;
}

static void load_signatures(const char *path) {
    FILE *f = fopen(path, "r");
    uint32_t cap = 0u;
    size_t i;
    if (f == NULL) {
        die("cannot read the stack-bytes table");
    }
    for (;;) {
        if (g_nsig == cap) {
            cap = cap != 0u ? cap * 2u : 4096u;
            g_sig = realloc(g_sig, cap * sizeof *g_sig);
            if (g_sig == NULL) {
                die("out of memory");
            }
        }
        if (fscanf(f, "%95s %u", g_sig[g_nsig].name, &g_sig[g_nsig].bytes) != 2) {
            break;
        }
        ++g_nsig;
    }
    fclose(f);
    for (i = 0u; i < sizeof g_shims / sizeof g_shims[0]; ++i) {
        import probe = {"", "", NULL, 0u};
        int bytes;
        snprintf(probe.name, sizeof probe.name, "%s", g_shims[i].name);
        bytes = sig_bytes(&probe);
        if (bytes >= 0 && (uint32_t)bytes != 4u * g_shims[i].nargs) {
            printf("SHIM ARGUMENT COUNT: %s removes %u bytes, the SDK says %d\n", g_shims[i].name, 4u * g_shims[i].nargs, bytes);
        }
    }
}

/* ---- dispatch ------------------------------------------------------------------------------- */

static uint8_t *g_cov;       /* one byte per instruction of every function, set when executed */
static uint32_t *g_cov_off;  /* first coverage byte of each function */
static uint32_t *g_entered;  /* times control entered each function at any address */
static uint64_t g_transfers;
static uint32_t g_ring[RING];
static struct {
    uint32_t eip;
    int fn;
} g_cache[1u << 16];

static int find_fn(uint32_t eip) {
    uint32_t slot = (eip ^ (eip >> 16)) & 0xffffu, lo = 0u, hi = g_core->n_fns;
    int fn = -1;
    if (g_cache[slot].eip == eip) {
        return g_cache[slot].fn;
    }
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2u;
        if (g_core->fns[mid].entry < eip) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    if (lo < g_core->n_fns && g_core->fns[lo].entry == eip) {
        fn = (int)lo;
    } else {
        lo = 0u;
        hi = g_core->n_ranges;
        while (lo < hi) {
            uint32_t mid = lo + (hi - lo) / 2u;
            if (g_core->ranges[mid].hi <= eip) {
                lo = mid + 1u;
            } else {
                hi = mid;
            }
        }
        if (lo < g_core->n_ranges && g_core->ranges[lo].lo <= eip) {
            fn = (int)g_core->ranges[lo].fn;
        }
    }
    g_cache[slot].eip = eip;
    g_cache[slot].fn = fn;
    return fn;
}

static void describe_stop(const lift_ctx *c) {
    if (c->status == LM_S_UNSUPPORTED) {
        stop("untranslated instruction at %08x", c->ta);
    } else if (c->status == LM_S_BUDGET) {
        stop("instruction budget reached at %08x", c->ta);
    } else if (c->status != LM_S_OK) {
        stop("host exception while executing %08x", c->eip);
    } else if (c->tkind == LM_T_FAULT) {
        stop("guest access violation at %08x, address %08x", c->ta, c->tb);
    } else {
        stop("guest exception class %u at %08x", c->tb, c->ta);
    }
}

/* Runs lifted code from c->eip until it returns to RET_SENTINEL (0) or something stops it (1). */
static int run(void) {
    lift_ctx *c = g_c;
    static uint32_t last_eip;
    static uint64_t last_steps;
    int jumped = setjmp(c->jb);
    /* A zero frame makes longjmp restore registers without unwinding. */
    ((_JUMP_BUFFER *)c->jb)->Frame = 0u;
    if (jumped == LIVE_JMP_STOP) {
        describe_stop(c);
        return 1;
    }
    last_eip = 0u;
    for (;;) {
        uint32_t eip = c->eip, k = (eip - IMPORT_BASE) / IMPORT_STEP;
        int fn;
        g_ring[g_transfers++ % RING] = eip;
        if (g_trace != 0u) {
            --g_trace;
            printf("-> %08x esp=%08x eax=%08x\n", eip, c->r[LM_ESP], c->r[LM_EAX]);
        }
        if (eip == RET_SENTINEL) {
            return 0;
        }
        if (eip >= IMPORT_BASE && k < g_nimp && (eip - IMPORT_BASE) % IMPORT_STEP == 0u) {
            import *im = &g_imp[k];
            uint32_t esp = c->r[LM_ESP];
            if (im->sh == NULL) {
                int bytes = g_sig != NULL ? sig_bytes(im) : -1;
                if (bytes < 0 || g_nsurvey == 256u) {
                    stop("import without a shim: %s!%s (called from %08x)", im->dll, im->name, rd32(esp));
                    return 1;
                }
                if (im->calls++ == 0u) {
                    g_survey_hits[g_nsurvey++] = k;
                }
                ++g_survey_calls;
                wr32(FS_BASE + TEB_LAST_ERROR, ERROR_CALL_NOT_IMPLEMENTED);
                c->r[LM_EAX] = 0u;
                c->eip = rd32(esp);
                c->r[LM_ESP] = esp + 4u + (uint32_t)bytes;
                continue;
            }
            ++im->calls;
            c->r[LM_EAX] = im->sh->fn(c, (const uint32_t *)GP(esp + 4u));
            if (g_stop[0] != '\0') {
                return 1;
            }
            c->eip = rd32(esp);
            c->r[LM_ESP] = esp + 4u + 4u * im->sh->nargs;
            continue;
        }
        fn = find_fn(eip);
        if (fn < 0) {
            stop("no lifted code at %08x", eip);
            return 1;
        }
        if (eip == last_eip && c->steps == last_steps) {
            stop("%08x is not an instruction of the function that owns it (%08x)", eip, g_core->fns[fn].entry);
            return 1;
        }
        last_eip = eip;
        last_steps = c->steps;
        ++g_entered[fn];
        c->cov = g_cov + g_cov_off[fn];
        g_core->fns[fn].fn(c);
        stop("lifted function %08x returned to the dispatcher", g_core->fns[fn].entry);
        return 1;
    }
}

/* Calls a stdcall guest function from the host. */
static int guest_call(uint32_t entry, uint32_t nargs, const uint32_t *args) {
    lift_ctx *c = g_c;
    uint32_t i, esp = c->r[LM_ESP];
    int stopped;
    for (i = nargs; i-- > 0u;) {
        c->r[LM_ESP] -= 4u;
        wr32(c->r[LM_ESP], args[i]);
    }
    c->r[LM_ESP] -= 4u;
    wr32(c->r[LM_ESP], RET_SENTINEL);
    c->eip = entry;
    stopped = run();
    if (!stopped) {
        c->r[LM_ESP] = esp; /* a cdecl callee leaves its arguments */
    }
    return stopped;
}

/* ---- loader ---------------------------------------------------------------------------------- */

static uint32_t load_image(const char *path) {
    FILE *f = fopen(path, "rb");
    long size;
    uint32_t image_size;
    if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        die("cannot read the image");
    }
    image_size = ((uint32_t)size + LM_PAGE - 1u) & ~(LM_PAGE - 1u);
    lift_set_image(g_c, GP(LM_IMAGE_BASE), image_size);
    lift_set_env(g_c, FS_BASE, NULL, NULL, 0u);
    g_pstate = calloc(1u << 20, sizeof *g_pstate);
    g_pbase = calloc(1u << 20, sizeof *g_pbase);
    if (g_pstate == NULL || g_pbase == NULL) {
        die("out of memory");
    }
    vm_set(0u, VM_LO, PG_RESERVED, 0u);
    vm_set(FAKE_EXE, FAKE_EXE + 0x100000u, PG_RESERVED, FAKE_EXE >> 12);
    vm_set(LM_IMAGE_BASE, LM_IMAGE_BASE + image_size, PG_COMMITTED, LM_IMAGE_BASE >> 12);
    vm_set(HEAP_LO, HEAP_HI, PG_COMMITTED, HEAP_LO >> 12);
    vm_set(PEB_ADDR, STACK_TOP, PG_COMMITTED, PEB_ADDR >> 12); /* PEB, TLS array, stack */
    vm_set(SYSTEM_LO, 0x80000000u, PG_RESERVED, SYSTEM_LO >> 12);
    vm_set(FS_BASE, FS_BASE + LM_PAGE, PG_COMMITTED, KEEP_BASE);
    if (fread(GP(LM_IMAGE_BASE), 1u, (size_t)size, f) != (size_t)size) {
        die("short read of the image");
    }
    fclose(f);
    return image_size;
}

/* Data directory entry n of the PE32 optional header: address (VA) or 0. */
static uint32_t data_dir(uint32_t n) {
    uint32_t opt = LM_IMAGE_BASE + rd32(LM_IMAGE_BASE + 0x3cu) + 24u, rva = rd32(opt + 96u + 8u * n);
    return rva != 0u ? LM_IMAGE_BASE + rva : 0u;
}

static uint32_t export_addr(const char *name) {
    uint32_t d = data_dir(0u), i, n = d != 0u ? rd32(d + 24u) : 0u;
    for (i = 0u; i < n; ++i) {
        if (strcmp((const char *)GP(LM_IMAGE_BASE + rd32(LM_IMAGE_BASE + rd32(d + 32u) + 4u * i)), name) == 0) {
            uint16_t ordinal;
            memcpy(&ordinal, GP(LM_IMAGE_BASE + rd32(d + 36u) + 2u * i), 2u);
            return LM_IMAGE_BASE + rd32(LM_IMAGE_BASE + rd32(d + 28u) + 4u * ordinal);
        }
    }
    return 0u;
}

/* What Rome2.exe's WinMain (0x402250) does around its call of the DLL's
 * entry_point: reserve 0x14a00000 bytes, then the largest free region below
 * 0x7d000000 less 1 MiB (at most 1 GiB and at most the total virtual size
 * less the first block), and call
 *   entry_point(hInstance, hPrevInstance, lpCmdLine, blocks + 1, &block[0],
 *               size of block[1] (low, high), 0, &relaunch)        cdecl
 * A nonzero result makes the launcher start itself again. */
static int launch(void) {
    uint32_t entry = export_addr("entry_point"), size = VM_HI - 0x14a00000u, largest = 0u, mode = 1u, pn, n;
    uint32_t blocks = galloc(16u, 1), relaunch = galloc(4u, 1), args[9];
    if (entry == 0u || blocks == 0u || relaunch == 0u) {
        stop("launcher: no entry_point export or no memory");
        return 1;
    }
    wr32(blocks, vm_alloc(0u, 0x14a00000u, MEM_RESERVE));
    if (size > 0x40000000u) {
        size = 0x40000000u;
    }
    for (pn = 0u; pn < VM_HI >> 12; pn += n) {
        n = vm_run(pn, VM_HI >> 12);
        if (g_pstate[pn] == PG_FREE && pn << 12 < 0x7d000000u && n << 12 > largest) {
            largest = n << 12;
        }
    }
    if (largest > 0x500000u) {
        if (size > largest - 0x100000u) {
            size = largest - 0x100000u;
        }
        wr32(blocks + 4u, vm_alloc(0u, size, MEM_RESERVE));
        mode = 2u;
    } else {
        size = 0u;
    }
    printf("launcher: blocks %08x (0x14a00000 bytes), %08x (0x%x bytes)\n", rd32(blocks), rd32(blocks + 4u), size);
    args[0] = FAKE_EXE;
    args[1] = 0u;
    args[2] = gdup("", 1u);
    args[3] = mode + 1u;
    args[4] = blocks;
    args[5] = size;
    args[6] = 0u;
    args[7] = 0u;
    args[8] = relaunch;
    return guest_call(entry, 9u, args);
}

static void bind_imports(void) {
    uint32_t d = data_dir(1u);
    for (; d != 0u && rd32(d + 12u) != 0u; d += 20u) {
        const char *dll = (const char *)GP(LM_IMAGE_BASE + rd32(d + 12u));
        uint32_t names = LM_IMAGE_BASE + (rd32(d) != 0u ? rd32(d) : rd32(d + 16u)), iat = LM_IMAGE_BASE + rd32(d + 16u), v;
        for (; (v = rd32(names)) != 0u; names += 4u, iat += 4u) {
            char ordinal[16];
            snprintf(ordinal, sizeof ordinal, "#%u", v & 0xffffu);
            wr32(iat, import_addr(dll, (v & 0x80000000u) != 0u ? ordinal : (const char *)GP(LM_IMAGE_BASE + v + 2u)));
        }
    }
    g_static_imports = g_nimp;
}

static void init_thread(void) {
    uint32_t tls = data_dir(9u);
    wr32(FS_BASE + 0x00u, 0xffffffffu); /* empty exception handler chain */
    wr32(FS_BASE + 0x04u, STACK_TOP);
    wr32(FS_BASE + 0x08u, STACK_LIMIT);
    wr32(FS_BASE + 0x18u, FS_BASE);
    wr32(FS_BASE + 0x20u, GetCurrentProcessId());
    wr32(FS_BASE + 0x24u, GetCurrentThreadId());
    wr32(FS_BASE + 0x2cu, TLS_ARRAY);
    wr32(FS_BASE + 0x30u, PEB_ADDR);
    if (tls != 0u) {
        /* Static thread-local storage: this module is index 0. */
        uint32_t start = rd32(tls), end = rd32(tls + 4u), block = galloc(end - start + rd32(tls + 16u), 1);
        memcpy(GP(block), GP(start), end - start);
        wr32(TLS_ARRAY, block);
        wr32(rd32(tls + 8u), 0u);
        if (rd32(tls + 12u) != 0u && rd32(rd32(tls + 12u)) != 0u) {
            fprintf(stderr, "live: TLS callbacks present and not run\n");
        }
    }
    g_c->r[LM_ESP] = STACK_TOP - 0x1000u;
    g_c->mode = 0u;
    g_c->status = LM_S_OK;
    live_fp_enter(g_c);
}

static void report(int stopped) {
    uint32_t i, fns = 0u, shimmed = 0u;
    uint64_t insns = 0u, total = g_cov_off[g_core->n_fns];
    for (i = 0u; i < g_core->n_fns; ++i) {
        fns += g_entered[i] != 0u;
    }
    for (i = 0u; i < total; ++i) {
        insns += g_cov[i];
    }
    for (i = 0u; i < g_static_imports; ++i) {
        shimmed += g_imp[i].sh != NULL;
    }
    if (stopped) {
        printf("STOP: %s\n", g_stop);
        printf("  eip=%08x eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x\n", g_c->eip,
               g_c->r[0], g_c->r[1], g_c->r[2], g_c->r[3], g_c->r[4], g_c->r[5], g_c->r[6], g_c->r[7]);
        printf("  last transfers:");
        for (i = 0u; i < RING && i < g_transfers; ++i) {
            printf(" %08x", g_ring[(g_transfers - 1u - i) % RING]);
        }
        printf("\n");
    }
    printf("instructions executed:        %llu\n", (unsigned long long)g_c->steps);
    printf("control transfers:            %llu\n", (unsigned long long)g_transfers);
    printf("functions executed:           %u of %u\n", fns, g_core->n_fns);
    printf("distinct instructions reached: %llu of %llu\n", (unsigned long long)insns, (unsigned long long)total);
    printf("static imports with a shim:   %u of %u\n", shimmed, g_static_imports);
    printf("guest heap:                   %llu allocations, %llu bytes live\n", (unsigned long long)g_heap_allocs,
           (unsigned long long)g_heap_live);
    printf("guest virtual memory:         %llu MiB reserved, %llu MiB committed\n", (unsigned long long)(g_vm_reserved >> 8),
           (unsigned long long)(g_vm_committed >> 8));
    if (g_nsurvey != 0u) {
        printf("SURVEY RUN, NOT EXECUTION: %llu calls to %u imports without a shim returned 0. In first-call order:\n",
               (unsigned long long)g_survey_calls, g_nsurvey);
        for (i = 0u; i < g_nsurvey; ++i) {
            const import *im = &g_imp[g_survey_hits[i]];
            printf("  %s!%s x%llu\n", im->dll, im->name, (unsigned long long)im->calls);
        }
    }
    printf("imports called:");
    for (i = 0u; i < g_nimp; ++i) {
        if (g_imp[i].calls != 0u && g_imp[i].sh != NULL) {
            printf(" %s=%llu", g_imp[i].name, (unsigned long long)g_imp[i].calls);
        }
    }
    printf("\n");
}

int main(int argc, char **argv) {
    const char *image = NULL;
    uint64_t max_insns = 20000000000ull;
    uint32_t i, off = 0u, entry, args[3] = {LM_IMAGE_BASE, DLL_PROCESS_ATTACH, 0u};
    wchar_t wide[MAX_PATH + 16];
    char cmd[MAX_PATH + 16];
    int stopped;

    for (i = 1; i + 1u < (uint32_t)argc; i += 2u) {
        if (strcmp(argv[i], "--image") == 0) {
            image = argv[i + 1];
        } else if (strcmp(argv[i], "--game-dir") == 0) {
            snprintf(g_game_dir, sizeof g_game_dir, "%s", argv[i + 1]);
        } else if (strcmp(argv[i], "--max-insns") == 0) {
            max_insns = strtoull(argv[i + 1], NULL, 0);
        } else if (strcmp(argv[i], "--trace") == 0) {
            g_trace = strtoull(argv[i + 1], NULL, 0);
        } else if (strcmp(argv[i], "--survey") == 0) {
            load_signatures(argv[i + 1]);
        } else if (strcmp(argv[i], "--allow-writes") == 0) {
            g_allow_writes = atoi(argv[i + 1]);
        } else if (strcmp(argv[i], "--profile") == 0) {
            CreateDirectoryA(argv[i + 1], NULL);
            GetFullPathNameA(argv[i + 1], sizeof g_profile, g_profile, NULL);
        }
    }
    if (image == NULL) {
        die("usage: live --image <image.bin> [--game-dir <dir>] [--max-insns <n>] [--trace <n>]");
    }
    if (GetFullPathNameA(g_game_dir, sizeof cmd, cmd, NULL) != 0u) {
        strcpy(g_game_dir, cmd);
    }

    g_core = live_core_get();
    g_mem = VirtualAlloc(NULL, 1ull << 32, MEM_RESERVE, PAGE_NOACCESS);
    if (g_mem == NULL) {
        die("cannot reserve the guest address space");
    }
    g_c = lift_ctx_create();
    lift_set_thunks(g_c, g_core->thunks, g_core->n_thunks);
    load_image(image);
    g_cov_off = calloc(g_core->n_fns + 1u, sizeof *g_cov_off);
    g_entered = calloc(g_core->n_fns, sizeof *g_entered);
    for (i = 0u; i < g_core->n_fns; ++i) {
        g_cov_off[i] = off;
        off += g_core->fns[i].n_insn;
    }
    g_cov_off[g_core->n_fns] = off;
    g_cov = calloc(off + 1u, 1u);
    if (g_cov_off == NULL || g_entered == NULL || g_cov == NULL) {
        die("out of memory");
    }
    g_c->limit = g_c->budget = max_insns;

    snprintf(cmd, sizeof cmd, "\"%s\\Rome2.exe\"", g_game_dir);
    g_cmdline_a = gdup(cmd, (uint32_t)strlen(cmd) + 1u);
    i = (uint32_t)MultiByteToWideChar(CP_ACP, 0, cmd, -1, wide, MAX_PATH + 16);
    g_cmdline_w = gdup(wide, i * (uint32_t)sizeof wide[0]);
    bind_imports();
    init_thread();
    /* The launcher runs in the game directory; relative paths the engine opens are relative to it. */
    if (!SetCurrentDirectoryA(g_game_dir)) {
        die("cannot enter the game directory");
    }

    entry = LM_IMAGE_BASE + rd32(LM_IMAGE_BASE + rd32(LM_IMAGE_BASE + 0x3cu) + 24u + 16u);
    printf("image %s, %u lifted functions, DLL entry %08x\n", image, g_core->n_fns, entry);
    stopped = guest_call(entry, 3u, args);
    if (!stopped) {
        printf("REACHED: DLL entry returned %u for DLL_PROCESS_ATTACH (CRT start-up and static initializers ran)\n",
               g_c->r[LM_EAX]);
        stopped = launch();
        if (!stopped) {
            printf("REACHED: entry_point returned %u\n", g_c->r[LM_EAX] & 0xffu);
        }
    }
    report(stopped);
    return stopped;
}
