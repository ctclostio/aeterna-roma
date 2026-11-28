/*
 * live_profile.c - where a live run spends its time.
 *
 *     live_profile <samples.tsv> <lifted.dll> <live.exe> [arguments for live.exe]
 *
 * Starts live.exe and, every few milliseconds, looks at each of its threads
 * that has run since the last look: stops it, walks its stack, lets it go.
 * One line per look goes to samples.tsv:
 *
 *     milliseconds since the start <tab> thread id <tab> kind <tab> name <tab> cycles
 *
 * cycles is the processor time the thread used since its last line: the
 * weight of the line. A look costs the thread a little time itself (it is
 * stopped through the kernel even when it waits), so a thread is looked at
 * only after it has used MIN_CYCLES, and a waiting thread hardly ever.
 *
 *     G  a lifted function, executing its own code; name is its guest address
 *     H  the same, executing a helper it called (a memory access, the flags of
 *        an addition, an x87 or SSE instruction): what inlining would remove
 *     R  the runner: the function of live.exe nearest the top of the stack (a
 *        shim with everything it calls, the dispatch loop)
 *     M  anything else; name is the module the thread was in
 *
 * The lifted functions are found by their host addresses: this program loads
 * the same lifted.dll and reads the table it exports (live_core_get), and a
 * function's extent comes from the DLL's unwind tables. live.exe's functions
 * are named from live.pdb, next to it. scripts/lift/profile_live.py builds
 * this, runs it on a copy of the last build and sums the lines up.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <dbghelp.h>
#include <psapi.h>
#include <tlhelp32.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "live.h"

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

#define INTERVAL_MS 4u
#define MIN_CYCLES 200000u
#define MAX_THREADS 256u
#define MAX_DEPTH 64u

typedef struct watched {
    DWORD tid;
    HANDLE h;
    ULONG64 cycles;
    int seen; /* in the last thread listing */
} watched;

typedef struct host_fn {
    uint32_t rva, entry;
} host_fn;

static watched g_thread[MAX_THREADS];
static uint32_t g_nthreads;
static HANDLE g_proc;
static const uint8_t *g_local; /* lifted.dll as loaded here */
static host_fn *g_fn;          /* ascending by rva */
static uint32_t g_nfn;
static uint64_t g_lifted_lo, g_lifted_hi, g_exe_lo, g_exe_hi; /* in the child */
static FILE *g_out;

static void die(const char *what) {
    fprintf(stderr, "live_profile: %s (error %lu)\n", what, GetLastError());
    exit(2);
}

static int by_rva(const void *a, const void *b) {
    const uint32_t x = ((const host_fn *)a)->rva, y = ((const host_fn *)b)->rva;
    return x < y ? -1 : x > y;
}

static void load_table(const char *dll) {
    typedef const live_core *(*get_core)(void);
    const HMODULE lib = LoadLibraryA(dll);
    const get_core get = lib != NULL ? (get_core)(uintptr_t)GetProcAddress(lib, "live_core_get") : NULL;
    const live_core *core;
    uint32_t i;
    if (get == NULL) {
        die("cannot load lifted.dll or it has no live_core_get");
    }
    core = get();
    g_local = (const uint8_t *)lib;
    g_nfn = core->n_fns;
    g_fn = malloc((size_t)g_nfn * sizeof *g_fn);
    if (g_fn == NULL) {
        die("out of memory");
    }
    for (i = 0u; i < g_nfn; ++i) {
        g_fn[i].rva = (uint32_t)((const uint8_t *)(uintptr_t)core->fns[i].fn - g_local);
        g_fn[i].entry = core->fns[i].entry;
    }
    qsort(g_fn, g_nfn, sizeof *g_fn, by_rva);
}

/* The guest address of the lifted function that owns this address of lifted.dll, 0 when none does (a helper,
 * a thunk, the lifted runtime). */
static uint32_t lifted_entry(uint64_t child_pc) {
    DWORD64 base = 0u;
    const RUNTIME_FUNCTION *rf = RtlLookupFunctionEntry((DWORD64)(uintptr_t)(g_local + (child_pc - g_lifted_lo)), &base, NULL);
    uint32_t lo = 0u, hi = g_nfn;
    if (rf == NULL) {
        return 0u;
    }
    for (;;) { /* a function in several pieces: the later ones chain to the first */
        const uint8_t *info = g_local + rf->UnwindData;
        if (((info[0] >> 3) & UNW_FLAG_CHAININFO) == 0u) {
            break;
        }
        rf = (const RUNTIME_FUNCTION *)(info + 4u + 2u * ((info[2] + 1u) & ~1u));
    }
    while (lo < hi) {
        const uint32_t mid = lo + (hi - lo) / 2u;
        if (g_fn[mid].rva < rf->BeginAddress) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo < g_nfn && g_fn[lo].rva == rf->BeginAddress ? g_fn[lo].entry : 0u;
}

static void find_modules(void) {
    HMODULE mods[1024];
    DWORD bytes = 0u, i;
    if (!EnumProcessModules(g_proc, mods, sizeof mods, &bytes)) {
        return;
    }
    for (i = 0u; i < bytes / sizeof mods[0] && i < 1024u; ++i) {
        char name[MAX_PATH];
        MODULEINFO mi;
        if (GetModuleBaseNameA(g_proc, mods[i], name, sizeof name) == 0u || !GetModuleInformation(g_proc, mods[i], &mi, sizeof mi)) {
            continue;
        }
        if (_stricmp(name, "lifted.dll") == 0) {
            g_lifted_lo = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
            g_lifted_hi = g_lifted_lo + mi.SizeOfImage;
        } else if (i == 0u) {
            g_exe_lo = (uint64_t)(uintptr_t)mi.lpBaseOfDll;
            g_exe_hi = g_exe_lo + mi.SizeOfImage;
        }
    }
    SymRefreshModuleList(g_proc);
}

static void list_threads(DWORD pid) {
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0u);
    THREADENTRY32 te;
    uint32_t i, kept = 0u;
    if (snap == INVALID_HANDLE_VALUE) {
        return;
    }
    for (i = 0u; i < g_nthreads; ++i) {
        g_thread[i].seen = 0;
    }
    te.dwSize = sizeof te;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }
            for (i = 0u; i < g_nthreads && g_thread[i].tid != te.th32ThreadID; ++i) {
            }
            if (i == g_nthreads && g_nthreads < MAX_THREADS) {
                g_thread[i].h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (g_thread[i].h == NULL) {
                    continue;
                }
                g_thread[i].tid = te.th32ThreadID;
                g_thread[i].cycles = 0u;
                QueryThreadCycleTime(g_thread[i].h, &g_thread[i].cycles); /* what it used before it was seen is not sampled */
                ++g_nthreads;
            }
            if (i < g_nthreads) {
                g_thread[i].seen = 1;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    for (i = 0u; i < g_nthreads; ++i) {
        if (g_thread[i].seen) {
            g_thread[kept++] = g_thread[i];
        } else {
            CloseHandle(g_thread[i].h);
        }
    }
    g_nthreads = kept;
}

static void look(watched *w, DWORD ms) {
    CONTEXT ctx;
    STACKFRAME64 f;
    ULONG64 cycles = 0u, used;
    uint64_t first = 0u;
    uint32_t depth, entry = 0u;
    char name[sizeof(SYMBOL_INFO) + 256u], module[MAX_PATH];
    const char *kind = "M", *text = "?";
    if (!QueryThreadCycleTime(w->h, &cycles) || cycles - w->cycles < MIN_CYCLES) {
        return; /* has not run since the last look, or only for the look itself */
    }
    used = cycles - w->cycles;
    w->cycles = cycles;
    if (SuspendThread(w->h) == (DWORD)-1) {
        return;
    }
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (GetThreadContext(w->h, &ctx)) {
        memset(&f, 0, sizeof f);
        f.AddrPC.Offset = ctx.Rip;
        f.AddrFrame.Offset = ctx.Rbp;
        f.AddrStack.Offset = ctx.Rsp;
        f.AddrPC.Mode = f.AddrFrame.Mode = f.AddrStack.Mode = AddrModeFlat;
        first = ctx.Rip;
        for (depth = 0u; depth < MAX_DEPTH; ++depth) {
            const uint64_t pc = depth == 0u ? first : f.AddrPC.Offset;
            if (pc >= g_lifted_lo && pc < g_lifted_hi && (entry = lifted_entry(pc)) != 0u) {
                kind = depth == 0u ? "G" : "H";
                break;
            }
            if (pc >= g_exe_lo && pc < g_exe_hi) {
                SYMBOL_INFO *sym = (SYMBOL_INFO *)name;
                DWORD64 off = 0u;
                sym->SizeOfStruct = sizeof(SYMBOL_INFO);
                sym->MaxNameLen = 255u;
                kind = "R";
                text = SymFromAddr(g_proc, pc, &off, sym) ? sym->Name : "live.exe";
                break;
            }
            if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, g_proc, w->h, &f, &ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)
                || f.AddrPC.Offset == 0u) {
                break;
            }
        }
    }
    ResumeThread(w->h);
    if (first == 0u) {
        return;
    }
    if (entry != 0u) {
        fprintf(g_out, "%lu\t%lu\t%s\t%08x\t%llu\n", ms, w->tid, kind, entry, used);
        return;
    }
    if (kind[0] == 'M') {
        HMODULE mod = NULL;
        MEMORY_BASIC_INFORMATION mbi;
        text = "?";
        if (VirtualQueryEx(g_proc, (LPCVOID)(uintptr_t)first, &mbi, sizeof mbi) != 0u && (mod = (HMODULE)mbi.AllocationBase) != NULL
            && GetModuleBaseNameA(g_proc, mod, module, sizeof module) != 0u) {
            text = module;
        }
    }
    fprintf(g_out, "%lu\t%lu\t%s\t%s\t%llu\n", ms, w->tid, kind, text, used);
}

int main(int argc, char **argv) {
    static char cmd[32768];
    STARTUPINFOA si = {sizeof si};
    PROCESS_INFORMATION pi;
    DWORD start, code = 0u, tick = 0u;
    size_t n = 0u;
    int i;
    if (argc < 4) {
        fprintf(stderr, "usage: live_profile <samples.tsv> <lifted.dll> <live.exe> [arguments for live.exe]\n");
        return 2;
    }
    load_table(argv[2]);
    g_out = fopen(argv[1], "wb");
    if (g_out == NULL) {
        die("cannot write the samples file");
    }
    for (i = 3; i < argc; ++i) {
        n += (size_t)snprintf(cmd + n, sizeof cmd - n, "%s\"%s\"", i == 3 ? "" : " ", argv[i]);
        if (n >= sizeof cmd) {
            die("command line too long");
        }
    }
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0u, NULL, NULL, &si, &pi)) {
        die("cannot start live.exe");
    }
    g_proc = pi.hProcess;
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
    SymInitialize(g_proc, NULL, FALSE);
    start = GetTickCount();
    while (WaitForSingleObject(g_proc, INTERVAL_MS) == WAIT_TIMEOUT) {
        const DWORD ms = GetTickCount() - start;
        uint32_t k;
        if (tick++ % 64u == 0u) {
            list_threads(pi.dwProcessId);
            find_modules();
        }
        if (g_lifted_lo == 0u) {
            continue; /* still loading */
        }
        for (k = 0u; k < g_nthreads; ++k) {
            look(&g_thread[k], ms);
        }
    }
    GetExitCodeProcess(g_proc, &code);
    fclose(g_out);
    return (int)code;
}
