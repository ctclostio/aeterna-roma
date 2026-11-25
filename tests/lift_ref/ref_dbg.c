/*
 * ref_dbg.c - reference side of the lifted-tier differential test.
 *
 * For every (function, seed) trial in a job file this program runs the
 * function's original bytes on the host CPU and writes the terminal record
 * and digest defined by port/lifted_runtime/lift_model.h. The lifted runner
 * writes the same lines from generated C and the driver compares them.
 *
 * Guest code never runs in this process. A 32-bit child (ref_child.exe) is
 * started under the debug API, its initial thread is taken at the loader
 * breakpoint, and from then on that thread only executes guest code: every
 * resume starts from a context written here and every stop is a debug event
 * handled here. No exception is ever passed back to the child. Before the
 * first trial everything in the child that is not model memory is made
 * non-executable, and inaccessible wherever the system allows it, so guest
 * code can only execute bytes of the function under test.
 *
 * See docs/lifted_tier.md, "Reference side".
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lift_model.h"

#define PAGE_OF(a) ((uint32_t)(a) & ~(LM_PAGE - 1u))
#define ARENA_SIZE (LM_ARENA_HI - LM_ARENA_LO)
#define ARENA_PAGE_COUNT (ARENA_SIZE / LM_PAGE)

#define GUEST_CONTEXT (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_EXTENDED_REGISTERS)
#define EFLAGS_TF 0x00000100u
#define AV_EXECUTE 8u

#define CODE_BREAKPOINT 0x80000003u
#define CODE_WX86_BREAKPOINT 0x4000001fu
#define CODE_SINGLE_STEP 0x80000004u
#define CODE_WX86_SINGLE_STEP 0x4000001eu
#define CODE_ACCESS_VIOLATION 0xc0000005u

/* Never mapped (first 64 KiB): the guest thread is sent here to stop it at a
 * known execute fault between trials. */
#define PARK_ADDR 0x0000f00du

/* Memory the child keeps for itself that cannot be made inaccessible (system
 * views, PEB/TEB block, shared user data) must lie in these zones. The
 * environment file reports as foreign the whole high zone, which holds the
 * model's TEB page, and those parts of the low zone in which a child of this
 * run really had accessible memory (see g_foreign). Everything else in the
 * low zone faults in the child exactly as the model says. */
#define ZONE_LOW_LO 0x00010000u
#define ZONE_LOW_HI 0x01000000u
#define ZONE_HIGH_LO 0x7e000000u
#define ZONE_HIGH_HI 0x80000000u

/* The model's TEB page. A child's real TEB is at a different address on every
 * start and holds pointers into memory the guest cannot use, so the model has
 * its own: a fixed address and fixed contents (see init_model_teb). The
 * contents are written over the real TEB page, which is where FS-relative
 * guest accesses land. The model address itself is only reserved in the
 * child; a guest access to it by flat address cannot be served and discards
 * the trial. The page lies inside the high foreign zone, so an FS-relative
 * access that misses the page by less than the zone is, for the lifted
 * runner, an access to foreign memory, whatever the child has next to its
 * real TEB. */
#define MODEL_TEB 0x7efdd000u
#define MODEL_TEB_RESERVE_LO 0x7efd0000u
#define MODEL_TEB_RESERVE_SIZE 0x00010000u
#define MODEL_TLS_ARRAY 0x5fd00000u /* fs:[0x2c], in the arena */
#define MODEL_PEB 0x5fc00000u       /* fs:[0x30], in the arena */

#define SPAWN_ATTEMPTS 8
#define SPAWN_WAIT_MS 10000u
#define PARK_WAIT_MS 2000u
#define STEP_WAIT_MS 5000u
#define READ_RUN_PAGES 16u

/* ---- job data ------------------------------------------------------------ */

typedef struct range {
    uint32_t lo, hi; /* hi exclusive */
} range;

typedef struct call_site {
    uint32_t ret, pop_bytes, fp_ret;
} call_site;

typedef struct insn_stub {
    uint32_t addr, len, kind;
} insn_stub;

typedef struct trial {
    uint32_t seed, mode, budget;
} trial;

typedef struct function {
    uint32_t entry;
    int valid;
    range *ranges;
    size_t n_ranges, cap_ranges;
    call_site *calls;
    size_t n_calls, cap_calls;
    insn_stub *stubs;
    size_t n_stubs, cap_stubs;
    range *windows;
    size_t n_windows, cap_windows;
    trial *trials;
    size_t n_trials, cap_trials;
} function;

typedef struct outcome {
    uint32_t status, tkind, a, b, steps;
    uint64_t digest;
} outcome;

/* ---- process state -------------------------------------------------------- */

enum { PG_LAZY = 0, PG_TOUCHED = 1, PG_VIEW = 2 };
enum { K_TEB, K_VIEW, K_IMAGE, K_ARENA };
enum { TOUCH_NEW, TOUCH_PRESENT, TOUCH_INVALID, TOUCH_ERROR };
enum { EV_GUEST, EV_TIMEOUT, EV_DEAD };

typedef struct page_ref {
    uint32_t addr; /* model address of the page */
    uint32_t kind; /* K_* */
    uint32_t aux;  /* K_VIEW: index into the view; K_ARENA: index into the fill cache */
} page_ref;

typedef struct child {
    HANDLE process, thread;
    DWORD pid, tid;
    int alive;
    int at_event;     /* the guest thread is stopped in a debug event that has not been continued */
    uint32_t teb;     /* address of the thread's real 32-bit TEB page */
    CONTEXT base_ctx; /* context at the loader breakpoint; source of the segment registers */
} child;

typedef struct trial_state {
    const function *fn;
    uint32_t seed;
    int step_mode;
    int tracing;
    uint32_t budget;
    uint32_t n_stub; /* stub events so far (calls and stubbed instructions) */
    DWORD set_flags; /* context parts changed since they were last written to the thread */
    lm_hash h;
    outcome out;
} trial_state;

static struct {
    const char *image_path, *jobs_path, *out_path, *env_path;
    DWORD timeout_ms;
    int trace;
    uint32_t trace_entry, trace_seed;
} g_opt;

static char g_child_path[MAX_PATH];
static LONGLONG g_qpc_freq;

static uint8_t *g_image;       /* pristine image, env.image_size bytes */
static lm_env g_env;           /* model environment, as written to the environment file */
static uint8_t g_teb[LM_PAGE]; /* model contents of the TEB page */

static child g_child;
static int g_spawn_failed; /* a respawn failed for good; remaining trials are harness failures */
static unsigned g_spawn_count;

static uint8_t *g_image_state; /* PG_* per image page */
static uint8_t *g_arena_state; /* 1 when the arena page is committed */

static page_ref *g_touched; /* pages materialised by the current trial */
static size_t g_n_touched, g_cap_touched;
static uint8_t *g_fills; /* pristine contents of the touched arena pages */
static size_t g_n_fills, g_cap_fills;
static page_ref *g_work;
static size_t g_cap_work;

/* Exec view: the pages of the function under test as the child sees them. */
static struct {
    int installed;
    uint32_t mode;
    uint32_t *pages; /* ascending */
    size_t n_pages, cap_pages;
    uint8_t *bytes; /* n_pages * LM_PAGE */
    size_t cap_bytes;
} g_view;

static uint8_t g_read_buf[READ_RUN_PAGES * LM_PAGE];

/* Low-zone memory that a child of this run kept accessible, merged over all
 * children: ascending and disjoint. */
static range *g_foreign;
static size_t g_n_foreign, g_cap_foreign;

/* ---- small helpers -------------------------------------------------------- */

static void die(const char *what, const char *detail) {
    fprintf(stderr, "ref_dbg: %s%s%s\n", what, detail[0] != '\0' ? " " : "", detail);
    exit(1);
}

static void *grow(void *p, size_t *cap, size_t need, size_t elem) {
    size_t n = *cap;
    if (need <= n) {
        return p;
    }
    n = n < 16u ? 16u : n * 2u;
    if (n < need) {
        n = need;
    }
    p = realloc(p, n * elem);
    if (p == NULL) {
        die("out of memory", "");
    }
    *cap = n;
    return p;
}

static LONGLONG qpc_now(void) {
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    return t.QuadPart;
}

static LONGLONG qpc_after_ms(DWORD ms) {
    return qpc_now() + (LONGLONG)ms * g_qpc_freq / 1000;
}

static DWORD ms_until(LONGLONG deadline) {
    LONGLONG left = deadline - qpc_now();
    if (left <= 0) {
        return 0u;
    }
    return (DWORD)((left * 1000 + g_qpc_freq - 1) / g_qpc_freq);
}

static int is_breakpoint_code(uint32_t code) {
    return code == CODE_BREAKPOINT || code == CODE_WX86_BREAKPOINT;
}

static int is_single_step_code(uint32_t code) {
    return code == CODE_SINGLE_STEP || code == CODE_WX86_SINGLE_STEP;
}

static int is_executable(DWORD protect) {
    switch (protect & 0xffu) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return 1;
    default:
        return 0;
    }
}

static int is_accessible(DWORD protect) {
    return (protect & 0xffu) != PAGE_NOACCESS;
}

/* Same access without execute. */
static DWORD without_execute(DWORD protect) {
    DWORD modifiers = protect & ~0xffu;
    switch (protect & 0xffu) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
        return PAGE_READONLY | modifiers;
    case PAGE_EXECUTE_READWRITE:
        return PAGE_READWRITE | modifiers;
    case PAGE_EXECUTE_WRITECOPY:
        return PAGE_WRITECOPY | modifiers;
    default:
        return protect;
    }
}

static int in_image(uint32_t addr) {
    return (uint32_t)(addr - LM_IMAGE_BASE) < g_env.image_size;
}

static int in_arena(uint32_t addr) {
    return (uint32_t)(addr - LM_ARENA_LO) < ARENA_SIZE;
}

/* [lo, hi) lies in one of the foreign zones. */
static int in_zone(uint32_t lo, uint32_t hi) {
    return lo < hi && ((lo >= ZONE_LOW_LO && hi <= ZONE_LOW_HI) || (lo >= ZONE_HIGH_LO && hi <= ZONE_HIGH_HI));
}

/* Adds [lo, hi) to the foreign ranges, merging with what it touches. */
static void add_foreign(uint32_t lo, uint32_t hi) {
    size_t i = 0u, j;
    while (i < g_n_foreign && g_foreign[i].hi < lo) {
        ++i;
    }
    for (j = i; j < g_n_foreign && g_foreign[j].lo <= hi; ++j) {
        if (g_foreign[j].lo < lo) {
            lo = g_foreign[j].lo;
        }
        if (g_foreign[j].hi > hi) {
            hi = g_foreign[j].hi;
        }
    }
    if (j == i) {
        g_foreign = grow(g_foreign, &g_cap_foreign, g_n_foreign + 1u, sizeof *g_foreign);
        memmove(&g_foreign[i + 1u], &g_foreign[i], (g_n_foreign - i) * sizeof *g_foreign);
        ++g_n_foreign;
    } else if (j > i + 1u) {
        memmove(&g_foreign[i + 1u], &g_foreign[j], (g_n_foreign - j) * sizeof *g_foreign);
        g_n_foreign -= j - i - 1u;
    }
    g_foreign[i].lo = lo;
    g_foreign[i].hi = hi;
}

/* Contents of the model's TEB page: zero except for the fields 32-bit code
 * reads through FS. The chain of exception handlers is empty, the stack
 * bounds enclose the guest stack, and the thread-local storage array and the
 * PEB are in the arena, so what they point at is shaped per seed like any
 * other arena memory. */
static void init_model_teb(void) {
    memset(g_teb, 0, sizeof g_teb);
    lm_put32(g_teb + 0x00u, 0xffffffffu);                /* ExceptionList */
    lm_put32(g_teb + 0x04u, LM_ARENA_HI);                /* StackBase */
    lm_put32(g_teb + 0x08u, LM_STACK_TOP - 0x00100000u); /* StackLimit */
    lm_put32(g_teb + 0x18u, MODEL_TEB);                  /* Self */
    lm_put32(g_teb + 0x20u, 0x00001000u);                /* ClientId.UniqueProcess */
    lm_put32(g_teb + 0x24u, 0x00001004u);                /* ClientId.UniqueThread */
    lm_put32(g_teb + 0x2cu, MODEL_TLS_ARRAY);            /* ThreadLocalStoragePointer */
    lm_put32(g_teb + 0x30u, MODEL_PEB);                  /* ProcessEnvironmentBlock */
    g_env.fs_base = MODEL_TEB;
}

/* ---- child memory --------------------------------------------------------- */

static int child_read(uint32_t addr, void *buf, size_t len) {
    SIZE_T got = 0;
    return ReadProcessMemory(g_child.process, (LPCVOID)(uintptr_t)addr, buf, len, &got) && got == len;
}

static int child_write(uint32_t addr, const void *buf, size_t len) {
    SIZE_T put = 0;
    return WriteProcessMemory(g_child.process, (LPVOID)(uintptr_t)addr, buf, len, &put) && put == len;
}

static int child_protect(uint32_t addr, size_t len, DWORD protect) {
    DWORD old;
    return VirtualProtectEx(g_child.process, (LPVOID)(uintptr_t)addr, len, protect, &old) != 0;
}

/* Where a model address lives in the child: the model's TEB page is the
 * child's real TEB page, everything else is where the model says. */
static uint32_t real_addr(uint32_t model_addr) {
    if (PAGE_OF(model_addr) == MODEL_TEB) {
        return g_child.teb + (model_addr & (LM_PAGE - 1u));
    }
    return model_addr;
}

/* ---- debug events --------------------------------------------------------- */

static void close_event_handles(const DEBUG_EVENT *ev) {
    if (ev->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev->u.CreateProcessInfo.hFile != NULL) {
        CloseHandle(ev->u.CreateProcessInfo.hFile);
    } else if (ev->dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev->u.LoadDll.hFile != NULL) {
        CloseHandle(ev->u.LoadDll.hFile);
    }
}

/* A thread other than the guest thread must never run: it would execute the
 * child's own code. Such threads are suspended for good. */
static void freeze_thread(DWORD tid) {
    HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (h != NULL) {
        SuspendThread(h);
        CloseHandle(h);
    }
}

/* Waits for the next exception raised by the guest thread. Everything else
 * the child reports is absorbed here. */
static int next_guest_event(DEBUG_EVENT *ev, LONGLONG deadline) {
    for (;;) {
        if (!WaitForDebugEvent(ev, ms_until(deadline))) {
            return GetLastError() == ERROR_SEM_TIMEOUT ? EV_TIMEOUT : EV_DEAD;
        }
        close_event_handles(ev);
        if (ev->dwProcessId == g_child.pid) {
            switch (ev->dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                if (ev->dwThreadId == g_child.tid) {
                    g_child.at_event = 1;
                    return EV_GUEST;
                }
                freeze_thread(ev->dwThreadId);
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                SuspendThread(ev->u.CreateThread.hThread);
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                if (ev->dwThreadId == g_child.tid) {
                    ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
                    return EV_DEAD;
                }
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
                g_child.alive = 0;
                return EV_DEAD;
            default:
                break;
            }
        }
        ContinueDebugEvent(ev->dwProcessId, ev->dwThreadId, DBG_CONTINUE);
    }
}

static int resume_guest(void) {
    if (!ContinueDebugEvent(g_child.pid, g_child.tid, DBG_CONTINUE)) {
        return 0;
    }
    g_child.at_event = 0;
    return 1;
}

static int is_execute_fault_at(const DEBUG_EVENT *ev, uint32_t addr) {
    const EXCEPTION_RECORD *rec = &ev->u.Exception.ExceptionRecord;
    return rec->ExceptionCode == CODE_ACCESS_VIOLATION && rec->NumberParameters >= 2u &&
           rec->ExceptionInformation[0] == AV_EXECUTE && (uint32_t)rec->ExceptionInformation[1] == addr;
}

/* Brings the guest thread to a debug event at PARK_ADDR, whatever it was
 * doing. `running` is set when the thread may be executing guest code (a
 * timeout); it is then suspended first. Events that were already on their way
 * are discarded: the context is rewritten after each one until the execute
 * fault at PARK_ADDR arrives. */
static int park_guest(int running) {
    CONTEXT ctx = g_child.base_ctx;
    int suspended = 0;
    int tries;

    if (running) {
        if (SuspendThread(g_child.thread) == (DWORD)-1) {
            return 0;
        }
        suspended = 1;
    }
    for (tries = 0; tries < 16; ++tries) {
        DEBUG_EVENT ev;
        ctx.ContextFlags = CONTEXT_CONTROL;
        ctx.Eip = PARK_ADDR;
        ctx.Esp = LM_STACK_TOP;
        ctx.EFlags = LM_EFLAGS_INIT;
        if (!SetThreadContext(g_child.thread, &ctx)) {
            return 0;
        }
        if (suspended) {
            if (ResumeThread(g_child.thread) == (DWORD)-1) {
                return 0;
            }
            suspended = 0;
        }
        if (g_child.at_event && !resume_guest()) {
            return 0;
        }
        if (next_guest_event(&ev, qpc_after_ms(PARK_WAIT_MS)) != EV_GUEST) {
            return 0;
        }
        if (is_execute_fault_at(&ev, PARK_ADDR)) {
            return 1;
        }
    }
    return 0;
}

static void kill_child(void) {
    int i;
    if (g_child.process == NULL) {
        return;
    }
    TerminateProcess(g_child.process, 1u);
    if (g_child.at_event) {
        ContinueDebugEvent(g_child.pid, g_child.tid, DBG_CONTINUE);
    }
    for (i = 0; i < 64 && g_child.alive; ++i) {
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, 1000u)) {
            break;
        }
        close_event_handles(&ev);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && ev.dwProcessId == g_child.pid) {
            break;
        }
    }
    CloseHandle(g_child.thread);
    CloseHandle(g_child.process);
    memset(&g_child, 0, sizeof g_child);
    g_view.installed = 0;
}

/* ---- child set-up --------------------------------------------------------- */

static int context_round_trip(void) {
    CONTEXT ctx;
    ctx.ContextFlags = GUEST_CONTEXT;
    return GetThreadContext(g_child.thread, &ctx) && SetThreadContext(g_child.thread, &ctx);
}

/* Takes access away from one range of the child's own memory. The system
 * reads a small part of the 64-bit stack when it gets or sets the context of
 * a WOW64 thread, so a range whose loss breaks context access is given back
 * read-only. Returns 0 when the range is left executable. */
static int lock_range(uint32_t lo, uint32_t size, DWORD protect) {
    if (child_protect(lo, size, PAGE_NOACCESS)) {
        if (context_round_trip()) {
            return 1;
        }
        if (child_protect(lo, size, PAGE_READONLY) && context_round_trip()) {
            return 1;
        }
        return child_protect(lo, size, without_execute(protect)) && context_round_trip();
    }
    if (!is_executable(protect)) {
        return 1; /* protection is fixed by the system; checked against the zones later */
    }
    return child_protect(lo, size, without_execute(protect));
}

/* Makes everything the child owns non-executable and, where possible,
 * inaccessible. The image and arena ranges and the TEB page are ours. */
static int lock_down(void) {
    MEMORY_BASIC_INFORMATION mbi;
    uint32_t addr = 0u;

    while (VirtualQueryEx(g_child.process, (LPCVOID)(uintptr_t)addr, &mbi, sizeof mbi) == sizeof mbi) {
        uint32_t lo = (uint32_t)(uintptr_t)mbi.BaseAddress;
        uint32_t size = (uint32_t)mbi.RegionSize;
        uint32_t hi = lo + size;
        if (mbi.State == MEM_COMMIT && is_accessible(mbi.Protect) && !in_image(lo) && !in_arena(lo)) {
            if (lo <= g_child.teb && g_child.teb < hi) {
                if (g_child.teb > lo && !lock_range(lo, g_child.teb - lo, mbi.Protect)) {
                    return 0;
                }
                if (hi > g_child.teb + LM_PAGE &&
                    !lock_range(g_child.teb + LM_PAGE, hi - g_child.teb - LM_PAGE, mbi.Protect)) {
                    return 0;
                }
            } else if (!lock_range(lo, size, mbi.Protect)) {
                return 0;
            }
        }
        if (hi <= addr) {
            break;
        }
        addr = hi;
    }
    return 1;
}

/* Checks the whole address space of the child: no executable page outside the
 * exec view, image pages protected according to their state, and nothing of
 * the child's own accessible outside the foreign zones. What is accessible in
 * the low zone is recorded as foreign. */
static int verify_layout(void) {
    MEMORY_BASIC_INFORMATION mbi;
    uint32_t addr = 0u;

    while (VirtualQueryEx(g_child.process, (LPCVOID)(uintptr_t)addr, &mbi, sizeof mbi) == sizeof mbi) {
        uint32_t lo = (uint32_t)(uintptr_t)mbi.BaseAddress;
        uint32_t hi = lo + (uint32_t)mbi.RegionSize;
        if (mbi.State == MEM_COMMIT) {
            if (in_image(lo)) {
                uint32_t p;
                for (p = lo; p != hi && in_image(p); p += LM_PAGE) {
                    uint8_t state = g_image_state[(p - LM_IMAGE_BASE) / LM_PAGE];
                    DWORD want = state == PG_VIEW ? PAGE_EXECUTE_READWRITE
                                                  : state == PG_TOUCHED ? PAGE_READWRITE : PAGE_NOACCESS;
                    if (mbi.Protect != want) {
                        fprintf(stderr, "ref_dbg: image page %08x has protection %lx, expected %lx\n", p, mbi.Protect,
                                want);
                        return 0;
                    }
                }
            } else if (is_executable(mbi.Protect)) {
                fprintf(stderr, "ref_dbg: executable memory left at %08x..%08x\n", lo, hi);
                return 0;
            } else if (in_arena(lo)) {
                if (mbi.Protect != PAGE_READWRITE) {
                    return 0;
                }
            } else if (is_accessible(mbi.Protect)) {
                if (!in_zone(lo, hi)) {
                    fprintf(stderr, "ref_dbg: child memory at %08x..%08x lies outside the foreign zones\n", lo, hi);
                    return 0;
                }
                if (lo < ZONE_LOW_HI) {
                    add_foreign(lo, hi);
                }
            }
        }
        if (hi <= addr) {
            break;
        }
        addr = hi;
    }
    return 1;
}

/* DEP check: a committed, non-executable page of int3 bytes. With DEP the
 * jump raises an execute fault; without it the int3 would run and report a
 * breakpoint. Nothing else can execute either way. */
static int probe_dep(void) {
    static uint8_t filler[LM_PAGE];
    CONTEXT ctx = g_child.base_ctx;
    DEBUG_EVENT ev;
    uint32_t page = LM_ARENA_LO;
    int ok;

    memset(filler, 0xcc, sizeof filler);
    if (VirtualAllocEx(g_child.process, (LPVOID)(uintptr_t)page, LM_PAGE, MEM_COMMIT, PAGE_READWRITE) == NULL ||
        !child_write(page, filler, LM_PAGE)) {
        return 0;
    }
    ctx.ContextFlags = CONTEXT_CONTROL;
    ctx.Eip = page;
    ctx.Esp = LM_STACK_TOP;
    ctx.EFlags = LM_EFLAGS_INIT;
    ok = SetThreadContext(g_child.thread, &ctx) && resume_guest() &&
         next_guest_event(&ev, qpc_after_ms(PARK_WAIT_MS)) == EV_GUEST && is_execute_fault_at(&ev, page);
    if (!ok) {
        fprintf(stderr, "ref_dbg: DEP is not active in the child\n");
    }
    return VirtualFreeEx(g_child.process, (LPVOID)(uintptr_t)page, LM_PAGE, MEM_DECOMMIT) && ok;
}

/* The FXSAVE fields the model hashes. */
static int fx_model_equal(const uint8_t *a, const uint8_t *b) {
    uint32_t i;
    if (memcmp(a + LM_FX_FCW, b + LM_FX_FCW, 2u) != 0 || memcmp(a + LM_FX_FSW, b + LM_FX_FSW, 2u) != 0 ||
        a[LM_FX_FTW] != b[LM_FX_FTW] || memcmp(a + LM_FX_MXCSR, b + LM_FX_MXCSR, 4u) != 0 ||
        memcmp(a + LM_FX_XMM, b + LM_FX_XMM, 128u) != 0) {
        return 0;
    }
    for (i = 0u; i < 8u; ++i) {
        if (memcmp(a + LM_FX_ST + 16u * i, b + LM_FX_ST + 16u * i, 10u) != 0) {
            return 0;
        }
    }
    return 1;
}

/* x87 and SSE state must survive a set, a resume and a get bit for bit, using
 * the FXSAVE image alone. */
static int probe_fx(void) {
    uint8_t fx[LM_FX_SIZE];
    CONTEXT ctx = g_child.base_ctx;
    CONTEXT back;
    uint32_t i, k;

    memset(fx, 0, sizeof fx);
    lm_put16(fx + LM_FX_FCW, 0x0c7fu);
    lm_put16(fx + LM_FX_FSW, 0x2800u); /* top = 5 */
    fx[LM_FX_FTW] = 0xe0u;
    lm_put32(fx + LM_FX_MXCSR, 0x5f80u);
    for (i = 0u; i < 8u; ++i) {
        for (k = 0u; k < 10u; ++k) {
            fx[LM_FX_ST + 16u * i + k] = (uint8_t)(0x11u * (i + 1u) + k);
        }
        fx[LM_FX_ST + 16u * i + 7u] |= 0x80u;
        for (k = 0u; k < 16u; ++k) {
            fx[LM_FX_XMM + 16u * i + k] = (uint8_t)(0xa0u + 0x10u * i + k);
        }
    }
    ctx.ContextFlags = GUEST_CONTEXT;
    ctx.Eip = PARK_ADDR;
    ctx.Esp = LM_STACK_TOP;
    ctx.EFlags = LM_EFLAGS_INIT;
    memcpy(ctx.ExtendedRegisters, fx, sizeof fx);
    back.ContextFlags = GUEST_CONTEXT;
    if (!SetThreadContext(g_child.thread, &ctx) || !GetThreadContext(g_child.thread, &back) ||
        !fx_model_equal(back.ExtendedRegisters, fx)) {
        return 0;
    }
    if (!park_guest(0)) {
        return 0;
    }
    memset(&back, 0, sizeof back);
    back.ContextFlags = GUEST_CONTEXT;
    return GetThreadContext(g_child.thread, &back) && fx_model_equal(back.ExtendedRegisters, fx);
}

static uint32_t selector_base(DWORD selector) {
    LDT_ENTRY e;
    if (!GetThreadSelectorEntry(g_child.thread, selector, &e)) {
        return 0u;
    }
    return (uint32_t)e.BaseLow | ((uint32_t)e.HighWord.Bytes.BaseMid << 16) |
           ((uint32_t)e.HighWord.Bytes.BaseHi << 24);
}

/* Starts a child and prepares it for trials. Returns 0, with the child gone,
 * when anything about it is not as required. */
static int spawn_child(void) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DEBUG_EVENT ev;
    uint32_t teb = 0u;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    if (!CreateProcessA(g_child_path, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, NULL, NULL,
                        &si, &pi)) {
        fprintf(stderr, "ref_dbg: cannot start %s (error %lu)\n", g_child_path, GetLastError());
        return 0;
    }
    ++g_spawn_count;
    memset(&g_child, 0, sizeof g_child);
    g_child.process = pi.hProcess;
    g_child.thread = pi.hThread;
    g_child.pid = pi.dwProcessId;
    g_child.tid = pi.dwThreadId;
    g_child.alive = 1;
    g_view.installed = 0;

    /* Run the loader up to its breakpoint. That event is never continued with
     * the loader's context: the thread is ours from here on. */
    for (;;) {
        if (!WaitForDebugEvent(&ev, SPAWN_WAIT_MS)) {
            goto fail;
        }
        close_event_handles(&ev);
        if (ev.dwProcessId == g_child.pid) {
            if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                break;
            }
            if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                teb = (uint32_t)(uintptr_t)ev.u.CreateProcessInfo.lpThreadLocalBase;
            } else if (ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                SuspendThread(ev.u.CreateThread.hThread);
            } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                g_child.alive = 0;
                goto fail;
            }
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }
    if (ev.dwThreadId != g_child.tid) {
        freeze_thread(ev.dwThreadId);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
        goto fail;
    }
    g_child.at_event = 1;
    if (!is_breakpoint_code(ev.u.Exception.ExceptionRecord.ExceptionCode)) {
        goto fail;
    }
    g_child.base_ctx.ContextFlags = GUEST_CONTEXT;
    if (!GetThreadContext(g_child.thread, &g_child.base_ctx)) {
        goto fail;
    }
    if (teb == 0u || (teb & (LM_PAGE - 1u)) != 0u || selector_base(g_child.base_ctx.SegFs) != teb ||
        selector_base(g_child.base_ctx.SegDs) != 0u || selector_base(g_child.base_ctx.SegSs) != 0u ||
        selector_base(g_child.base_ctx.SegGs) != 0u) {
        goto fail;
    }
    g_child.teb = teb;

    /* Claim the guest's address ranges; this fails when the child has anything
     * there. The model's TEB address is only reserved, so it always faults. */
    if (VirtualAllocEx(g_child.process, (LPVOID)(uintptr_t)LM_IMAGE_BASE, g_env.image_size, MEM_RESERVE | MEM_COMMIT,
                       PAGE_READWRITE) == NULL ||
        VirtualAllocEx(g_child.process, (LPVOID)(uintptr_t)LM_ARENA_LO, ARENA_SIZE, MEM_RESERVE, PAGE_NOACCESS) ==
            NULL ||
        VirtualAllocEx(g_child.process, (LPVOID)(uintptr_t)MODEL_TEB_RESERVE_LO, MODEL_TEB_RESERVE_SIZE, MEM_RESERVE,
                       PAGE_NOACCESS) == NULL) {
        goto fail;
    }
    memset(g_image_state, PG_LAZY, g_env.image_size / LM_PAGE);
    memset(g_arena_state, 0, ARENA_PAGE_COUNT);
    g_n_touched = 0u;
    g_n_fills = 0u;

    if (!lock_down() || !park_guest(0) || !probe_dep() || !probe_fx()) {
        goto fail;
    }
    if (!child_write(teb, g_teb, LM_PAGE) || !child_write(LM_IMAGE_BASE, g_image, g_env.image_size) ||
        !child_protect(LM_IMAGE_BASE, g_env.image_size, PAGE_NOACCESS) || !verify_layout()) {
        goto fail;
    }
    return 1;

fail:
    kill_child();
    return 0;
}

static int ensure_child(void) {
    int attempt;
    if (g_child.alive) {
        return 1;
    }
    if (g_child.process != NULL) {
        kill_child();
    }
    if (g_spawn_failed) {
        return 0;
    }
    for (attempt = 0; attempt < SPAWN_ATTEMPTS; ++attempt) {
        if (spawn_child()) {
            return 1;
        }
    }
    g_spawn_failed = 1;
    fprintf(stderr, "ref_dbg: could not prepare a child after %d attempts\n", SPAWN_ATTEMPTS);
    return 0;
}

/* ---- function lookups ------------------------------------------------------ */

static int in_body(const function *fn, uint32_t addr) {
    size_t i;
    for (i = 0u; i < fn->n_ranges; ++i) {
        if ((uint32_t)(addr - fn->ranges[i].lo) < fn->ranges[i].hi - fn->ranges[i].lo) {
            return 1;
        }
    }
    return 0;
}

static const call_site *find_call(const function *fn, uint32_t ret) {
    size_t lo = 0u, hi = fn->n_calls;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (fn->calls[mid].ret < ret) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo < fn->n_calls && fn->calls[lo].ret == ret ? &fn->calls[lo] : NULL;
}

static const insn_stub *find_stub(const function *fn, uint32_t addr) {
    size_t lo = 0u, hi = fn->n_stubs;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        if (fn->stubs[mid].addr < addr) {
            lo = mid + 1u;
        } else {
            hi = mid;
        }
    }
    return lo < fn->n_stubs && fn->stubs[lo].addr == addr ? &fn->stubs[lo] : NULL;
}

/* PUSHF/PUSHFD at addr, after any prefixes. Read from the pristine image. */
static int insn_is_pushf(uint32_t addr) {
    uint32_t i;
    for (i = 0u; i < 15u && in_image(addr + i); ++i) {
        uint8_t b = g_image[addr + i - LM_IMAGE_BASE];
        switch (b) {
        case 0x26u:
        case 0x2eu:
        case 0x36u:
        case 0x3eu:
        case 0x64u:
        case 0x65u:
        case 0x66u:
        case 0x67u:
        case 0xf0u:
        case 0xf2u:
        case 0xf3u:
            break;
        default:
            return b == 0x9cu;
        }
    }
    return 0;
}

/* ---- exec view ------------------------------------------------------------- */

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static void copy_into_view(uint32_t lo, uint32_t hi) {
    size_t i;
    for (i = 0u; i < g_view.n_pages; ++i) {
        uint32_t page = g_view.pages[i];
        uint32_t a = lo > page ? lo : page;
        uint32_t b = hi < page + LM_PAGE ? hi : page + LM_PAGE;
        if (a < b) {
            memcpy(g_view.bytes + i * LM_PAGE + (a - page), g_image + (a - LM_IMAGE_BASE), b - a);
        }
    }
}

/* Builds the page contents the child sees while `fn` runs. Fast mode: image
 * bytes inside the body ranges and data windows, int3 everywhere else, so
 * control that leaves the body on these pages stops at once. Step mode: the
 * whole page, because every step is checked here anyway. In both modes the
 * first byte of each stubbed instruction is int3. */
static void build_view(const function *fn, uint32_t mode) {
    size_t i, n = 0u;
    uint32_t p;

    g_view.n_pages = 0u;
    for (i = 0u; i < fn->n_ranges; ++i) {
        for (p = PAGE_OF(fn->ranges[i].lo); p < fn->ranges[i].hi; p += LM_PAGE) {
            g_view.pages = grow(g_view.pages, &g_view.cap_pages, g_view.n_pages + 1u, sizeof *g_view.pages);
            g_view.pages[g_view.n_pages++] = p;
        }
    }
    qsort(g_view.pages, g_view.n_pages, sizeof *g_view.pages, cmp_u32);
    for (i = 0u; i < g_view.n_pages; ++i) {
        if (n == 0u || g_view.pages[n - 1u] != g_view.pages[i]) {
            g_view.pages[n++] = g_view.pages[i];
        }
    }
    g_view.n_pages = n;
    g_view.bytes = grow(g_view.bytes, &g_view.cap_bytes, n * LM_PAGE, 1u);
    if (mode != 0u) {
        for (i = 0u; i < n; ++i) {
            memcpy(g_view.bytes + i * LM_PAGE, g_image + (g_view.pages[i] - LM_IMAGE_BASE), LM_PAGE);
        }
    } else {
        memset(g_view.bytes, 0xcc, n * LM_PAGE);
        for (i = 0u; i < fn->n_ranges; ++i) {
            copy_into_view(fn->ranges[i].lo, fn->ranges[i].hi);
        }
        for (i = 0u; i < fn->n_windows; ++i) {
            copy_into_view(fn->windows[i].lo, fn->windows[i].hi);
        }
    }
    for (i = 0u; i < fn->n_stubs; ++i) {
        uint32_t page = PAGE_OF(fn->stubs[i].addr);
        const uint32_t *hit = bsearch(&page, g_view.pages, n, sizeof *g_view.pages, cmp_u32);
        if (hit != NULL) {
            g_view.bytes[(size_t)(hit - g_view.pages) * LM_PAGE + (fn->stubs[i].addr & (LM_PAGE - 1u))] = 0xccu;
        }
    }
}

/* Length of the run of consecutive view pages starting at index i. */
static size_t view_run(size_t i) {
    size_t j = i + 1u;
    while (j < g_view.n_pages && g_view.pages[j] == g_view.pages[j - 1u] + LM_PAGE) {
        ++j;
    }
    return j - i;
}

static int remove_view(void) {
    size_t i, k, n;
    if (!g_view.installed) {
        return 1;
    }
    g_view.installed = 0;
    for (i = 0u; i < g_view.n_pages; i += n) {
        uint32_t page = g_view.pages[i];
        n = view_run(i);
        if (!child_write(page, g_image + (page - LM_IMAGE_BASE), n * LM_PAGE) ||
            !child_protect(page, n * LM_PAGE, PAGE_NOACCESS)) {
            return 0;
        }
        for (k = 0u; k < n; ++k) {
            g_image_state[(page - LM_IMAGE_BASE) / LM_PAGE + k] = PG_LAZY;
        }
    }
    return 1;
}

/* Makes the exec view of (fn, mode) current and checks the child's layout.
 * The caller removes the view before moving on to another function, so an
 * installed view always belongs to `fn` and only its mode can differ. */
static int install_view(const function *fn, uint32_t mode) {
    size_t i, k, n;
    int same_pages = g_view.installed;

    if (same_pages && g_view.mode == mode) {
        return 1;
    }
    build_view(fn, mode);
    for (i = 0u; i < g_view.n_pages; i += n) {
        uint32_t page = g_view.pages[i];
        n = view_run(i);
        if ((!same_pages && !child_protect(page, n * LM_PAGE, PAGE_EXECUTE_READWRITE)) ||
            !child_write(page, g_view.bytes + i * LM_PAGE, n * LM_PAGE)) {
            return 0;
        }
        for (k = 0u; k < n; ++k) {
            g_image_state[(page - LM_IMAGE_BASE) / LM_PAGE + k] = PG_VIEW;
        }
    }
    g_view.mode = mode;
    g_view.installed = 1;
    return verify_layout();
}

/* ---- guest memory as the model sees it ------------------------------------ */

static void add_touched(uint32_t page, uint32_t kind, uint32_t aux) {
    g_touched = grow(g_touched, &g_cap_touched, g_n_touched + 1u, sizeof *g_touched);
    g_touched[g_n_touched].addr = page;
    g_touched[g_n_touched].kind = kind;
    g_touched[g_n_touched].aux = aux;
    ++g_n_touched;
}

/* First access to a page: image pages become readable and writable, arena
 * pages are committed and filled. */
static int touch_page(const trial_state *ts, uint32_t addr) {
    uint32_t page = PAGE_OF(addr);

    if (in_image(page)) {
        uint8_t *state = &g_image_state[(page - LM_IMAGE_BASE) / LM_PAGE];
        if (*state != PG_LAZY) {
            return TOUCH_PRESENT;
        }
        if (!child_protect(page, LM_PAGE, PAGE_READWRITE)) {
            return TOUCH_ERROR;
        }
        *state = PG_TOUCHED;
        add_touched(page, K_IMAGE, 0u);
    } else if (in_arena(page)) {
        uint8_t *state = &g_arena_state[(page - LM_ARENA_LO) / LM_PAGE];
        uint8_t *fill;
        if (*state != 0u) {
            return TOUCH_PRESENT;
        }
        g_fills = grow(g_fills, &g_cap_fills, (g_n_fills + 1u) * LM_PAGE, 1u);
        fill = g_fills + g_n_fills * LM_PAGE;
        lm_fill_page(ts->seed, page, fill);
        if (VirtualAllocEx(g_child.process, (LPVOID)(uintptr_t)page, LM_PAGE, MEM_COMMIT, PAGE_READWRITE) == NULL) {
            return TOUCH_ERROR;
        }
        *state = 1u;
        add_touched(page, K_ARENA, (uint32_t)g_n_fills);
        ++g_n_fills;
        if (!child_write(page, fill, LM_PAGE)) {
            return TOUCH_ERROR;
        }
    } else if (page == MODEL_TEB) {
        return TOUCH_PRESENT;
    } else {
        return TOUCH_INVALID;
    }
    if (ts->tracing) {
        printf("page %08x\n", page);
    }
    return TOUCH_NEW;
}

/* Reads a guest dword as a guest access would, materialising its pages.
 * Returns 1, 0 when the dword is not entirely on model-valid pages, or -1 on
 * a harness failure. */
static int guest_read32(const trial_state *ts, uint32_t addr, uint32_t *out) {
    uint8_t b[4];
    uint32_t fault_addr;
    uint32_t first = LM_PAGE - (addr & (LM_PAGE - 1u));

    if (lm_access_fault(&g_env, addr, 4u, &fault_addr)) {
        return 0;
    }
    if (first > 4u) {
        first = 4u;
    }
    if (touch_page(ts, addr) == TOUCH_ERROR || !child_read(real_addr(addr), b, first)) {
        return -1;
    }
    if (first < 4u &&
        (touch_page(ts, addr + first) == TOUCH_ERROR || !child_read(real_addr(addr + first), b + first, 4u - first))) {
        return -1;
    }
    *out = lm_get32(b);
    return 1;
}

/* ---- trace ------------------------------------------------------------------ */

static void ctx_regs(const CONTEXT *ctx, uint32_t r[LM_GPR_COUNT]) {
    r[LM_EAX] = ctx->Eax;
    r[LM_ECX] = ctx->Ecx;
    r[LM_EDX] = ctx->Edx;
    r[LM_EBX] = ctx->Ebx;
    r[LM_ESP] = ctx->Esp;
    r[LM_EBP] = ctx->Ebp;
    r[LM_ESI] = ctx->Esi;
    r[LM_EDI] = ctx->Edi;
}

static void trace_regs(const uint32_t r[LM_GPR_COUNT], uint32_t eflags) {
    printf(" eax=%08x ecx=%08x edx=%08x ebx=%08x esp=%08x ebp=%08x esi=%08x edi=%08x df=%u", r[LM_EAX], r[LM_ECX],
           r[LM_EDX], r[LM_EBX], r[LM_ESP], r[LM_EBP], r[LM_ESI], r[LM_EDI], (eflags & LM_EFLAGS_DF) != 0u);
}

static void trace_hex(const char *name, uint32_t index, const uint8_t *p, uint32_t n) {
    uint32_t i;
    printf("%s%u ", name, index);
    for (i = 0u; i < n; ++i) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

static void trace_fx(const uint8_t *fx) {
    uint32_t i;
    printf("fx fcw=%04x fsw=%04x ftw=%02x mxcsr=%08x\n", lm_get16(fx + LM_FX_FCW), lm_get16(fx + LM_FX_FSW),
           fx[LM_FX_FTW], lm_get32(fx + LM_FX_MXCSR));
    for (i = 0u; i < 8u; ++i) {
        trace_hex("st", i, fx + LM_FX_ST + 16u * i, 10u);
    }
    for (i = 0u; i < 8u; ++i) {
        trace_hex("xmm", i, fx + LM_FX_XMM + 16u * i, 16u);
    }
}

/* ---- trial ------------------------------------------------------------------ */

static void set_terminal(trial_state *ts, uint32_t kind, uint32_t a, uint32_t b, const CONTEXT *ctx) {
    uint32_t r[LM_GPR_COUNT];
    ctx_regs(ctx, r);
    lm_hash_terminal(&ts->h, kind, a, b, r, ctx->EFlags, ctx->ExtendedRegisters);
    ts->out.tkind = kind;
    ts->out.a = a;
    ts->out.b = b;
    if (ts->tracing) {
        printf("term kind=%u a=%08x b=%08x", kind, a, b);
        trace_regs(r, ctx->EFlags);
        printf("\n");
        trace_fx(ctx->ExtendedRegisters);
    }
}

static int get_guest_context(CONTEXT *ctx) {
    ctx->ContextFlags = GUEST_CONTEXT;
    /* A code selector other than the 32-bit one means the thread is no longer
     * running what this program put there. */
    return GetThreadContext(g_child.thread, ctx) && ctx->SegCs == g_child.base_ctx.SegCs;
}

/* Control is about to continue at `target`, outside the body. Rule 2 of the
 * trial protocol: a call site on top of the stack makes this a call event and
 * the stub is applied to `ctx`; anything else ends the trial. Returns 1 when
 * the trial goes on from ctx, 0 when it ended, -1 on a harness failure. */
static int leave_body(trial_state *ts, CONTEXT *ctx, uint32_t target) {
    uint32_t esp = ctx->Esp;
    uint32_t words[1u + LM_CALL_STACK_WORDS];
    uint32_t r[LM_GPR_COUNT];
    uint32_t i, eax, ecx, edx;
    const call_site *site;
    int have_all = 0;
    int rc;

    if ((esp & (LM_PAGE - 1u)) + sizeof words <= LM_PAGE && lm_valid_page(&g_env, esp)) {
        uint8_t raw[sizeof words];
        if (touch_page(ts, esp) == TOUCH_ERROR || !child_read(real_addr(esp), raw, sizeof raw)) {
            return -1;
        }
        for (i = 0u; i < 1u + LM_CALL_STACK_WORDS; ++i) {
            words[i] = lm_get32(raw + 4u * i);
        }
        have_all = 1;
        rc = 1;
    } else {
        rc = guest_read32(ts, esp, &words[0]);
        if (rc < 0) {
            return -1;
        }
    }
    site = rc > 0 ? find_call(ts->fn, words[0]) : NULL;
    if (site == NULL) {
        set_terminal(ts, LM_T_LEAVE, target, 0u, ctx);
        return 0;
    }
    for (i = 1u; !have_all && i <= LM_CALL_STACK_WORDS; ++i) {
        rc = guest_read32(ts, esp + 4u * i, &words[i]);
        if (rc < 0) {
            return -1;
        }
        if (rc == 0) {
            words[i] = LM_PEEK_INVALID;
        }
    }
    ctx_regs(ctx, r);
    lm_hash_call(&ts->h, target, site->ret, r, ctx->EFlags, ctx->ExtendedRegisters, words + 1);
    if (ts->tracing) {
        lm_hash fxh;
        lm_hash_init(&fxh);
        lm_hash_fx(&fxh, ctx->ExtendedRegisters);
        printf("call %u target=%08x site=%08x", ts->n_stub, target, site->ret);
        trace_regs(r, ctx->EFlags);
        printf(" fx=%016llx stack=", (unsigned long long)fxh.h);
        for (i = 1u; i <= LM_CALL_STACK_WORDS; ++i) {
            printf("%s%08x", i > 1u ? "," : "", words[i]);
        }
        printf("\n");
    }
    lm_stub_call_regs(ts->seed, ts->n_stub, &eax, &ecx, &edx);
    ctx->Eax = eax;
    ctx->Ecx = ecx;
    ctx->Edx = edx;
    ctx->Esp = esp + 4u + site->pop_bytes;
    ctx->Eip = site->ret;
    ts->set_flags |= CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (site->fp_ret) {
        lm_fx_push(ctx->ExtendedRegisters, lm_stub_call_st0(ts->seed, ts->n_stub));
        ts->set_flags |= CONTEXT_EXTENDED_REGISTERS;
    }
    ++ts->n_stub;
    return 1;
}

/* Replaces a stubbed instruction (rule 3). Same return convention as leave_body. */
static int apply_insn_stub(trial_state *ts, CONTEXT *ctx, const insn_stub *stub) {
    uint32_t v[4];

    if (stub->kind == LM_INSN_TRAP) {
        set_terminal(ts, LM_T_EXC, stub->addr, LM_X_TRAP, ctx);
        return 0;
    }
    lm_hash_insn(&ts->h, stub->kind, stub->addr);
    if (ts->tracing) {
        printf("insn %u kind=%u addr=%08x\n", ts->n_stub, stub->kind, stub->addr);
    }
    lm_stub_insn_regs(ts->seed, ts->n_stub, v);
    ctx->Eax = v[0];
    ctx->Edx = v[3];
    if (stub->kind == LM_INSN_CPUID) {
        ctx->Ebx = v[1];
        ctx->Ecx = v[2];
    } else if (stub->kind == LM_INSN_RDTSCP) {
        ctx->Ecx = v[2];
    }
    ctx->Eip = stub->addr + stub->len;
    ts->set_flags |= CONTEXT_CONTROL | CONTEXT_INTEGER;
    ++ts->n_stub;
    return 1;
}

/* Step mode, with `ctx` holding the state after a step (or the initial
 * state): handle leaving the body until control is inside it again, then
 * apply the budget. Same return convention as leave_body. */
static int step_settle(trial_state *ts, CONTEXT *ctx, int stepped) {
    while (!in_body(ts->fn, ctx->Eip)) {
        int rc = leave_body(ts, ctx, ctx->Eip);
        if (rc <= 0) {
            return rc;
        }
    }
    if (stepped && ts->out.steps >= ts->budget) {
        set_terminal(ts, LM_T_STEP, ctx->Eip, 0u, ctx);
        return 0;
    }
    return 1;
}

static void trace_step(const trial_state *ts, const CONTEXT *ctx) {
    uint32_t r[LM_GPR_COUNT];
    ctx_regs(ctx, r);
    printf("step %u %08x", ts->out.steps, ctx->Eip);
    trace_regs(r, ctx->EFlags);
    printf("\n");
}

/* Runs one trial up to its terminal record. Returns 0 when the trial has an
 * outcome and the guest thread is parked at a debug event, -1 when the child
 * can no longer be trusted. */
static int run_guest(trial_state *ts) {
    const function *fn = ts->fn;
    CONTEXT ctx = g_child.base_ctx;
    uint32_t r[LM_GPR_COUNT];
    LONGLONG deadline = 0;
    int pushf_step = 0;
    int rc;

    lm_hash_init(&ts->h);
    lm_init_gpr(ts->seed, r);
    ctx.Eax = r[LM_EAX];
    ctx.Ecx = r[LM_ECX];
    ctx.Edx = r[LM_EDX];
    ctx.Ebx = r[LM_EBX];
    ctx.Esp = r[LM_ESP];
    ctx.Ebp = r[LM_EBP];
    ctx.Esi = r[LM_ESI];
    ctx.Edi = r[LM_EDI];
    ctx.Eip = fn->entry;
    ctx.EFlags = LM_EFLAGS_INIT;
    lm_init_fx(ts->seed, ctx.ExtendedRegisters);

    if (ts->step_mode) {
        rc = step_settle(ts, &ctx, 0);
        if (rc <= 0) {
            return rc;
        }
        if (ts->tracing) {
            trace_step(ts, &ctx);
        }
        pushf_step = insn_is_pushf(ctx.Eip);
        ctx.EFlags |= EFLAGS_TF;
    } else {
        deadline = qpc_after_ms(g_opt.timeout_ms);
    }
    ctx.ContextFlags = GUEST_CONTEXT;
    if (!SetThreadContext(g_child.thread, &ctx)) {
        return -1;
    }

    for (;;) {
        DEBUG_EVENT ev;
        const EXCEPTION_RECORD *rec;
        const insn_stub *stub;
        uint32_t code, xaddr;
        int stepped = 0;
        int e;

        if (!ts->step_mode && qpc_now() >= deadline) {
            ts->out.status = LM_S_TIMEOUT;
            return 0;
        }
        if (!resume_guest()) {
            return -1;
        }
        e = next_guest_event(&ev, ts->step_mode ? qpc_after_ms(STEP_WAIT_MS) : deadline);
        if (e == EV_TIMEOUT && !ts->step_mode) {
            ts->out.status = LM_S_TIMEOUT;
            return park_guest(1) ? 0 : -1;
        }
        if (e != EV_GUEST) {
            return -1;
        }
        rec = &ev.u.Exception.ExceptionRecord;
        code = rec->ExceptionCode;
        xaddr = (uint32_t)(uintptr_t)rec->ExceptionAddress;
        ts->set_flags = 0u;

        if (code == CODE_ACCESS_VIOLATION) {
            uint32_t access = rec->NumberParameters >= 2u ? (uint32_t)rec->ExceptionInformation[0] : 0u;
            uint32_t addr = rec->NumberParameters >= 2u ? (uint32_t)rec->ExceptionInformation[1] : 0xffffffffu;
            if (access != AV_EXECUTE) {
                int t = touch_page(ts, addr);
                if (t == TOUCH_NEW) {
                    continue; /* lazy page: the instruction runs again */
                }
                if (t == TOUCH_PRESENT && PAGE_OF(addr) == MODEL_TEB) {
                    /* Flat access to the model's TEB address; only FS-relative accesses reach the TEB. */
                    ts->out.status = LM_S_HARNESS;
                    return 0;
                }
                if (t != TOUCH_INVALID) {
                    return -1;
                }
            }
            if (!get_guest_context(&ctx)) {
                return -1;
            }
            if (access != AV_EXECUTE || ctx.Eip != addr) {
                set_terminal(ts, LM_T_FAULT, ctx.Eip, addr, &ctx);
                return 0;
            }
            rc = leave_body(ts, &ctx, addr);
        } else if (is_breakpoint_code(code)) {
            if (!get_guest_context(&ctx)) {
                return -1;
            }
            stub = find_stub(fn, xaddr);
            if (stub != NULL) {
                rc = apply_insn_stub(ts, &ctx, stub);
                if (rc > 0 && ts->step_mode) {
                    ++ts->out.steps;
                    stepped = 1;
                }
            } else if (in_body(fn, xaddr)) {
                set_terminal(ts, LM_T_EXC, xaddr, LM_X_BKPT, &ctx);
                return 0;
            } else {
                ctx.Eip = xaddr; /* filler: control left the body and stopped before executing anything */
                rc = leave_body(ts, &ctx, xaddr);
            }
        } else if (is_single_step_code(code)) {
            if (!ts->step_mode) {
                /* The guest set TF itself (POPFD). The trap is absorbed and the flag cleared. */
                ctx.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(g_child.thread, &ctx)) {
                    return -1;
                }
                ctx.EFlags &= ~EFLAGS_TF;
                if (!SetThreadContext(g_child.thread, &ctx)) {
                    return -1;
                }
                continue;
            }
            ++ts->out.steps;
            stepped = 1;
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (!GetThreadContext(g_child.thread, &ctx) || ctx.SegCs != g_child.base_ctx.SegCs) {
                return -1;
            }
            if (pushf_step) {
                /* The flags image PUSHF just stored has the harness's TF in it (bit 8). */
                uint8_t b;
                if (!child_read(real_addr(ctx.Esp + 1u), &b, 1u)) {
                    return -1;
                }
                b &= 0xfeu;
                if (!child_write(real_addr(ctx.Esp + 1u), &b, 1u)) {
                    return -1;
                }
            }
            if (in_body(fn, ctx.Eip) && ts->out.steps < ts->budget && !ts->tracing) {
                /* Common case: nothing to decide, take the next step. */
                pushf_step = insn_is_pushf(ctx.Eip);
                ctx.EFlags |= EFLAGS_TF;
                if (!SetThreadContext(g_child.thread, &ctx)) {
                    return -1;
                }
                continue;
            }
            if (!get_guest_context(&ctx)) {
                return -1;
            }
            rc = 1;
        } else {
            if (!get_guest_context(&ctx)) {
                return -1;
            }
            set_terminal(ts, LM_T_EXC, ctx.Eip, lm_exc_class(code), &ctx);
            return 0;
        }

        if (rc <= 0) {
            return rc;
        }
        if (ts->step_mode) {
            rc = step_settle(ts, &ctx, stepped);
            if (rc <= 0) {
                return rc;
            }
            if (ts->tracing) {
                trace_step(ts, &ctx);
            }
            pushf_step = insn_is_pushf(ctx.Eip);
            ctx.EFlags |= EFLAGS_TF;
            ts->set_flags |= CONTEXT_CONTROL;
        } else {
            /* A stub can hand control to an address outside the body (a call
             * that is the last instruction before a jump table returns into
             * the table). Rule 2 applies there before anything executes; the
             * exec view would run a data window's bytes instead. */
            while (!in_body(fn, ctx.Eip)) {
                rc = leave_body(ts, &ctx, ctx.Eip);
                if (rc <= 0) {
                    return rc;
                }
            }
        }
        ctx.ContextFlags = ts->set_flags;
        if (!SetThreadContext(g_child.thread, &ctx)) {
            return -1;
        }
    }
}

static int cmp_page_ref(const void *a, const void *b) {
    uint32_t x = ((const page_ref *)a)->addr, y = ((const page_ref *)b)->addr;
    return x < y ? -1 : x > y;
}

/* Hashes (when `record`) every byte of `cur` that the guest left different
 * from its pristine value and puts the page back in order. `shown` is what
 * the child held before the trial, `pristine` what the model says the page
 * holds; they differ only for exec view filler. */
static int settle_page(trial_state *ts, const page_ref *pg, const uint8_t *cur, int record, uint32_t *count) {
    const uint8_t *shown, *pristine;
    uint32_t i;

    switch (pg->kind) {
    case K_TEB:
        shown = pristine = g_teb;
        break;
    case K_VIEW:
        shown = g_view.bytes + (size_t)pg->aux * LM_PAGE;
        pristine = g_image + (pg->addr - LM_IMAGE_BASE);
        break;
    case K_IMAGE:
        shown = pristine = g_image + (pg->addr - LM_IMAGE_BASE);
        break;
    default:
        shown = pristine = g_fills + (size_t)pg->aux * LM_PAGE;
        break;
    }
    if (memcmp(cur, shown, LM_PAGE) == 0) {
        return 1;
    }
    for (i = 0u; record && i < LM_PAGE; ++i) {
        if (cur[i] != shown[i] && cur[i] != pristine[i]) {
            lm_hash_mem_byte(&ts->h, pg->addr + i, cur[i]);
            ++*count;
            if (ts->tracing) {
                printf("mem %08x %02x\n", pg->addr + i, cur[i]);
            }
        }
    }
    /* Arena pages are decommitted afterwards; everything else gets its contents back. */
    return pg->kind == K_ARENA || child_write(real_addr(pg->addr), shown, LM_PAGE);
}

/* Ends a trial's use of memory: the memory record (when `record`), then the
 * child's memory is returned to its state before the trial. Pages are visited
 * in ascending model address. */
static int settle_memory(trial_state *ts, int record) {
    size_t n, i, j, k;
    uint32_t count = 0u;

    g_work = grow(g_work, &g_cap_work, g_n_touched + g_view.n_pages + 1u, sizeof *g_work);
    for (n = 0u; n < g_n_touched; ++n) {
        g_work[n] = g_touched[n];
    }
    for (i = 0u; i < g_view.n_pages; ++i) {
        g_work[n].addr = g_view.pages[i];
        g_work[n].kind = K_VIEW;
        g_work[n].aux = (uint32_t)i;
        ++n;
    }
    g_work[n].addr = MODEL_TEB;
    g_work[n].kind = K_TEB;
    g_work[n].aux = 0u;
    ++n;
    qsort(g_work, n, sizeof *g_work, cmp_page_ref);

    if (record) {
        lm_hash_mem_begin(&ts->h);
    }
    for (i = 0u; i < n; i = j) {
        j = i + 1u;
        if (g_work[i].kind != K_TEB) {
            while (j < n && j - i < READ_RUN_PAGES && g_work[j].kind != K_TEB &&
                   g_work[j].addr == g_work[j - 1u].addr + LM_PAGE) {
                ++j;
            }
        }
        if (!child_read(real_addr(g_work[i].addr), g_read_buf, (j - i) * LM_PAGE)) {
            return 0;
        }
        for (k = i; k < j; ++k) {
            if (!settle_page(ts, &g_work[k], g_read_buf + (k - i) * LM_PAGE, record, &count)) {
                return 0;
            }
        }
    }
    if (record) {
        lm_hash_mem_end(&ts->h, count);
    }

    /* Touched image pages go back to no-access, arena pages are decommitted. */
    for (i = 0u; i < n; i = j) {
        uint32_t kind = g_work[i].kind;
        uint32_t lo = g_work[i].addr;
        j = i + 1u;
        if (kind != K_IMAGE && kind != K_ARENA) {
            continue;
        }
        while (j < n && g_work[j].kind == kind && g_work[j].addr == g_work[j - 1u].addr + LM_PAGE) {
            ++j;
        }
        if (kind == K_IMAGE) {
            if (!child_protect(lo, (j - i) * LM_PAGE, PAGE_NOACCESS)) {
                return 0;
            }
            memset(g_image_state + (lo - LM_IMAGE_BASE) / LM_PAGE, PG_LAZY, j - i);
        } else {
            if (!VirtualFreeEx(g_child.process, (LPVOID)(uintptr_t)lo, (j - i) * LM_PAGE, MEM_DECOMMIT)) {
                return 0;
            }
            memset(g_arena_state + (lo - LM_ARENA_LO) / LM_PAGE, 0, j - i);
        }
    }
    g_n_touched = 0u;
    g_n_fills = 0u;
    return 1;
}

static void run_trial(const function *fn, const trial *t, outcome *out) {
    trial_state ts;
    int ok;

    memset(&ts, 0, sizeof ts);
    ts.fn = fn;
    ts.seed = t->seed;
    ts.step_mode = t->mode != 0u;
    ts.budget = t->budget;
    ts.tracing = g_opt.trace;
    if (ts.tracing) {
        printf("trial %08x %08x %u\n", fn->entry, t->seed, t->mode);
    }
    if (!fn->valid || !ensure_child()) {
        ts.out.status = LM_S_HARNESS;
    } else if (!install_view(fn, t->mode)) {
        ts.out.status = LM_S_HARNESS;
        kill_child();
    } else {
        ok = run_guest(&ts) == 0;
        if (ok) {
            ok = settle_memory(&ts, ts.out.status == LM_S_OK);
        }
        if (!ok) {
            ts.out.status = LM_S_HARNESS;
            kill_child();
        }
    }
    if (ts.out.status == LM_S_OK) {
        ts.out.digest = ts.h.h;
    } else {
        ts.out.tkind = ts.out.a = ts.out.b = ts.out.steps = 0u;
        ts.out.digest = 0u;
    }
    if (ts.tracing) {
        printf("end status=%u digest=%016llx steps=%u\n", ts.out.status, (unsigned long long)ts.out.digest,
               ts.out.steps);
    }
    *out = ts.out;
}

/* ---- files ------------------------------------------------------------------ */

static void load_image(const char *path) {
    FILE *f = fopen(path, "rb");
    long size = -1;
    if (f == NULL) {
        die("cannot open image", path);
    }
    if (fseek(f, 0, SEEK_END) == 0) {
        size = ftell(f);
    }
    if (size <= 0 || fseek(f, 0, SEEK_SET) != 0 || (unsigned long)size > LM_ARENA_LO - LM_IMAGE_BASE) {
        die("bad image file", path);
    }
    g_env.image_size = ((uint32_t)size + LM_PAGE - 1u) & ~(LM_PAGE - 1u);
    g_image = calloc(g_env.image_size, 1u);
    g_image_state = calloc(g_env.image_size / LM_PAGE, 1u);
    g_arena_state = calloc(ARENA_PAGE_COUNT, 1u);
    if (g_image == NULL || g_image_state == NULL || g_arena_state == NULL) {
        die("out of memory", "");
    }
    if (fread(g_image, 1u, (size_t)size, f) != (size_t)size) {
        die("cannot read image", path);
    }
    fclose(f);
}

static void write_env(const char *path) {
    FILE *f = fopen(path, "wb");
    uint32_t i;
    if (f == NULL) {
        die("cannot write", path);
    }
    fprintf(f, "fs_base %x\nimage_size %x\nteb ", g_env.fs_base, g_env.image_size);
    for (i = 0u; i < LM_PAGE; ++i) {
        fprintf(f, "%02x", g_teb[i]);
    }
    fprintf(f, "\n");
    for (i = 0u; i < g_n_foreign; ++i) {
        fprintf(f, "foreign %x %x\n", g_foreign[i].lo, g_foreign[i].hi);
    }
    fprintf(f, "foreign %x %x\n", ZONE_HIGH_LO, ZONE_HIGH_HI);
    if (fclose(f) != 0) {
        die("cannot write", path);
    }
}

static int cmp_range(const void *a, const void *b) {
    uint32_t x = ((const range *)a)->lo, y = ((const range *)b)->lo;
    return x < y ? -1 : x > y;
}

static int cmp_call(const void *a, const void *b) {
    uint32_t x = ((const call_site *)a)->ret, y = ((const call_site *)b)->ret;
    return x < y ? -1 : x > y;
}

static int cmp_stub(const void *a, const void *b) {
    uint32_t x = ((const insn_stub *)a)->addr, y = ((const insn_stub *)b)->addr;
    return x < y ? -1 : x > y;
}

/* A function is runnable when its body lies in the image and every stubbed
 * instruction lies in its body. */
static void finish_function(function *fn) {
    size_t i;
    qsort(fn->ranges, fn->n_ranges, sizeof *fn->ranges, cmp_range);
    qsort(fn->calls, fn->n_calls, sizeof *fn->calls, cmp_call);
    qsort(fn->stubs, fn->n_stubs, sizeof *fn->stubs, cmp_stub);
    fn->valid = fn->n_ranges > 0u;
    for (i = 0u; i < fn->n_ranges; ++i) {
        const range *r = &fn->ranges[i];
        if (r->lo >= r->hi || r->lo < LM_IMAGE_BASE || r->hi - LM_IMAGE_BASE > g_env.image_size) {
            fn->valid = 0;
        }
    }
    for (i = 0u; i < fn->n_windows; ++i) {
        const range *r = &fn->windows[i];
        if (r->lo >= r->hi || r->lo < LM_IMAGE_BASE || r->hi - LM_IMAGE_BASE > g_env.image_size) {
            fn->valid = 0;
        }
    }
    for (i = 0u; i < fn->n_stubs; ++i) {
        if (!in_body(fn, fn->stubs[i].addr)) {
            fn->valid = 0;
        }
    }
    if (!fn->valid) {
        fprintf(stderr, "ref_dbg: function %x has an unusable description; its trials are harness failures\n",
                fn->entry);
    }
}

typedef struct totals {
    unsigned long trials, by_status[6];
} totals;

static void run_function(function *fn, FILE *out, totals *tot) {
    size_t i;
    finish_function(fn);
    for (i = 0u; i < fn->n_trials; ++i) {
        const trial *t = &fn->trials[i];
        outcome o;
        /* --trace selects one function and seed; entry 0 traces every trial. */
        if (g_opt.trace && g_opt.trace_entry != 0u &&
            (fn->entry != g_opt.trace_entry || t->seed != g_opt.trace_seed)) {
            continue;
        }
        run_trial(fn, t, &o);
        fprintf(out, "%x %x %u %u %u %x %x %016llx %u\n", fn->entry, t->seed, t->mode, o.status, o.tkind, o.a, o.b,
                (unsigned long long)o.digest, o.steps);
        ++tot->trials;
        ++tot->by_status[o.status < 6u ? o.status : 5u];
    }
    fflush(out);
    if (g_child.alive && !remove_view()) {
        kill_child();
    }
}

static void run_jobs(FILE *jobs, FILE *out, totals *tot) {
    static function fn;
    char line[256];
    unsigned long line_no = 0;
    int open = 0;

    while (fgets(line, sizeof line, jobs) != NULL) {
        unsigned a = 0, b = 0, c = 0, d = 0, e = 0;
        int ok = 1;
        ++line_no;
        switch (line[0]) {
        case 'F':
            ok = !open && sscanf(line + 1, "%x %u %u %u %u", &a, &b, &c, &d, &e) == 5;
            fn.entry = a;
            fn.n_ranges = fn.n_calls = fn.n_stubs = fn.n_windows = fn.n_trials = 0u;
            open = 1;
            break;
        case 'R':
        case 'W': {
            range r;
            ok = open && sscanf(line + 1, "%x %x", &a, &b) == 2;
            r.lo = a;
            r.hi = b;
            if (line[0] == 'R') {
                fn.ranges = grow(fn.ranges, &fn.cap_ranges, fn.n_ranges + 1u, sizeof r);
                fn.ranges[fn.n_ranges++] = r;
            } else {
                fn.windows = grow(fn.windows, &fn.cap_windows, fn.n_windows + 1u, sizeof r);
                fn.windows[fn.n_windows++] = r;
            }
            break;
        }
        case 'C': {
            call_site s;
            ok = open && sscanf(line + 1, "%x %u %u", &a, &b, &c) == 3;
            s.ret = a;
            s.pop_bytes = b;
            s.fp_ret = c;
            fn.calls = grow(fn.calls, &fn.cap_calls, fn.n_calls + 1u, sizeof s);
            fn.calls[fn.n_calls++] = s;
            break;
        }
        case 'I': {
            insn_stub s;
            ok = open && sscanf(line + 1, "%x %u %u", &a, &b, &c) == 3;
            s.addr = a;
            s.len = b;
            s.kind = c;
            fn.stubs = grow(fn.stubs, &fn.cap_stubs, fn.n_stubs + 1u, sizeof s);
            fn.stubs[fn.n_stubs++] = s;
            break;
        }
        case 'T': {
            trial t;
            ok = open && sscanf(line + 1, "%x %u %u", &a, &b, &c) == 3;
            t.seed = a;
            t.mode = b;
            t.budget = c;
            fn.trials = grow(fn.trials, &fn.cap_trials, fn.n_trials + 1u, sizeof t);
            fn.trials[fn.n_trials++] = t;
            break;
        }
        case 'E':
            ok = open;
            if (ok) {
                run_function(&fn, out, tot);
            }
            open = 0;
            break;
        case '\r':
        case '\n':
        case '#':
            break;
        default:
            ok = 0;
            break;
        }
        if (!ok) {
            fprintf(stderr, "ref_dbg: %s:%lu: malformed job line\n", g_opt.jobs_path, line_no);
            exit(1);
        }
    }
    if (open) {
        fprintf(stderr, "ref_dbg: %s: last function is not closed\n", g_opt.jobs_path);
        exit(1);
    }
}

/* On a hybrid CPU the core classes differ in details the model leaves to the
 * host (observed: the address reported for an access that wraps past 4 GiB).
 * A run therefore keeps to one class, the most capable among the processors
 * this process may use; the child inherits the restriction. */
static void keep_to_one_core_class(void) {
    SYSTEM_CPU_SET_INFORMATION *sets;
    GROUP_AFFINITY group;
    DWORD_PTR allowed, system_mask, chosen = 0u;
    ULONG size = 0u, offset = 0u;
    BYTE best = 0u;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &allowed, &system_mask) ||
        !GetThreadGroupAffinity(GetCurrentThread(), &group)) {
        return;
    }
    GetSystemCpuSetInformation(NULL, 0u, &size, GetCurrentProcess(), 0u);
    sets = size != 0u ? (SYSTEM_CPU_SET_INFORMATION *)malloc(size) : NULL;
    if (sets == NULL || !GetSystemCpuSetInformation(sets, size, &size, GetCurrentProcess(), 0u)) {
        free(sets);
        return;
    }
    while (offset < size) {
        const SYSTEM_CPU_SET_INFORMATION *set = (const SYSTEM_CPU_SET_INFORMATION *)((const char *)sets + offset);
        if (set->Size == 0u) {
            break;
        }
        offset += set->Size;
        if (set->Type == CpuSetInformation && set->CpuSet.Group == group.Group &&
            set->CpuSet.LogicalProcessorIndex < 8u * sizeof(DWORD_PTR)) {
            DWORD_PTR bit = (DWORD_PTR)1u << set->CpuSet.LogicalProcessorIndex;
            if ((allowed & bit) != 0u) {
                if (chosen == 0u || set->CpuSet.EfficiencyClass > best) {
                    best = set->CpuSet.EfficiencyClass;
                    chosen = bit;
                } else if (set->CpuSet.EfficiencyClass == best) {
                    chosen |= bit;
                }
            }
        }
    }
    free(sets);
    if (chosen != 0u && chosen != allowed) {
        SetProcessAffinityMask(GetCurrentProcess(), chosen);
    }
}

static void usage(void) {
    fprintf(stderr, "usage: ref_dbg --image <flat image> --jobs <job file> --out <result file> --env <env file>\n"
                    "               [--timeout-ms N] [--trace <entry hex> <seed hex>]\n");
    exit(1);
}

int main(int argc, char **argv) {
    LARGE_INTEGER freq;
    LONGLONG start;
    FILE *jobs, *out;
    totals tot;
    char *slash;
    double seconds;
    int i;

    g_opt.timeout_ms = 50u;
    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "--trace") == 0 && i + 2 < argc) {
            g_opt.trace = 1;
            g_opt.trace_entry = (uint32_t)strtoul(argv[i + 1], NULL, 16);
            g_opt.trace_seed = (uint32_t)strtoul(argv[i + 2], NULL, 16);
            i += 2;
        } else if (i + 1 >= argc) {
            usage();
        } else if (strcmp(arg, "--image") == 0) {
            g_opt.image_path = argv[++i];
        } else if (strcmp(arg, "--jobs") == 0) {
            g_opt.jobs_path = argv[++i];
        } else if (strcmp(arg, "--out") == 0) {
            g_opt.out_path = argv[++i];
        } else if (strcmp(arg, "--env") == 0) {
            g_opt.env_path = argv[++i];
        } else if (strcmp(arg, "--timeout-ms") == 0) {
            g_opt.timeout_ms = (DWORD)strtoul(argv[++i], NULL, 10);
        } else {
            usage();
        }
    }
    if (g_opt.image_path == NULL || g_opt.jobs_path == NULL || g_opt.out_path == NULL || g_opt.env_path == NULL ||
        g_opt.timeout_ms == 0u) {
        usage();
    }

    QueryPerformanceFrequency(&freq);
    g_qpc_freq = freq.QuadPart;
    if (GetModuleFileNameA(NULL, g_child_path, MAX_PATH) == 0u) {
        die("cannot locate ref_child.exe", "");
    }
    slash = strrchr(g_child_path, '\\');
    if (slash == NULL || (size_t)(slash - g_child_path) + sizeof "\\ref_child.exe" > MAX_PATH) {
        die("cannot locate ref_child.exe", "");
    }
    strcpy(slash + 1, "ref_child.exe");

    load_image(g_opt.image_path);
    jobs = fopen(g_opt.jobs_path, "rb");
    if (jobs == NULL) {
        die("cannot open", g_opt.jobs_path);
    }
    out = fopen(g_opt.out_path, "wb");
    if (out == NULL) {
        die("cannot write", g_opt.out_path);
    }

    keep_to_one_core_class();
    init_model_teb();
    if (!ensure_child()) {
        return 2;
    }

    memset(&tot, 0, sizeof tot);
    start = qpc_now();
    run_jobs(jobs, out, &tot);
    seconds = (double)(qpc_now() - start) / (double)g_qpc_freq;
    kill_child();
    /* Written last: the foreign ranges cover every child the run used. */
    write_env(g_opt.env_path);
    fclose(jobs);
    if (fclose(out) != 0) {
        die("cannot write", g_opt.out_path);
    }
    fprintf(stderr,
            "ref_dbg: %lu trials in %.3f s (%.0f/s); ok %lu, timeout %lu, harness %lu; children started %u\n",
            tot.trials, seconds, seconds > 0.0 ? (double)tot.trials / seconds : 0.0, tot.by_status[LM_S_OK],
            tot.by_status[LM_S_TIMEOUT], tot.by_status[LM_S_HARNESS], g_spawn_count);
    return 0;
}
