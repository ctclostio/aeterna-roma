/*
 * test_d3d11_bridge.c - the Direct3D 11 bridge end to end, on the WARP software rasterizer.
 *
 * The test plays the 32-bit guest. Its "guest memory" is a block of the host's low 4 GiB, used at its
 * own address. Every interface call goes the way guest code goes: read the vtable dword of the guest
 * object, read the slot, and enter the bridge function registered for that address with the dwords a
 * 32-bit caller would push. Structures are written in their 32-bit layout, as raw dwords, so the test
 * does not share the bridge's idea of them. A call is refused when the number of dwords differs from
 * what the bridge registered for the slot.
 *
 * It renders a triangle and reads exact pixel values back, then checks object identity and lifetime,
 * the swap chain, the compiler entry points, several guest threads and the cases that must stop the run.
 *
 * The test is built twice. On its own it links d3d11_bridge.c as a second source and is the bridge's host
 * through d3d11_bridge_host_t. With TEST_LIVE it stands in for live_main.c: it defines the runner's shim
 * table, import records, lock and guest_call under the runner's names, includes d3d11_bridge.c the way
 * live_main.c does, and reaches every bridge function through a row of D3D11_BRIDGE_SHIMS.
 *
 *     python scripts/lift/gen_d3d11_bridge.py --test
 */
#define COBJMACROS
#define CINTERFACE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <initguid.h>

#pragma warning(push)
#pragma warning(disable : 4201)
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#pragma warning(pop)

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "d3d11_bridge.h"

#pragma comment(lib, "user32.lib") /* the swap-chain test needs a window */

DEFINE_GUID(IID_Reflection42, 0x17f27486, 0xa342, 0x4d10, 0x88, 0x42, 0xab, 0x08, 0x74, 0xe7, 0xf6, 0x70);

static uint32_t g_checks;
static char g_stop[512]; /* the last message the bridge stopped the run with */
static int g_stops;
#define CHECK(cond) \
    do { \
        ++g_checks; \
        if (!(cond)) { \
            printf("FAIL %s:%d: %s\n%s%s", __FILE__, __LINE__, #cond, g_stop, g_stops != 0 ? "\n" : ""); \
            exit(1); \
        } \
    } while (0)
/* A harness invariant, not a finding about the bridge: not counted. */
#define MUST(cond) \
    do { \
        if (!(cond)) { \
            printf("FAIL %s:%d: %s\n%s%s", __FILE__, __LINE__, #cond, g_stop, g_stops != 0 ? "\n" : ""); \
            exit(1); \
        } \
    } while (0)
#define CHECK_HR(expr) \
    do { \
        uint32_t hr_ = (expr); \
        ++g_checks; \
        if (hr_ != 0u) { \
            printf("FAIL %s:%d: %s returned %08x\n%s%s", __FILE__, __LINE__, #expr, hr_, g_stop, g_stops != 0 ? "\n" : ""); \
            exit(1); \
        } \
    } while (0)

/* ---- the runner's side ---------------------------------------------------------------------------- */

/* The CPU state of a guest thread, as much of it as the bridge's glue reads. The bridge itself only passes
 * the pointer on. */
enum { LM_EAX, LM_ECX, LM_EDX, LM_EBX, LM_ESP, LM_EBP, LM_ESI, LM_EDI, LM_GPR_COUNT };
typedef struct lift_ctx {
    uint32_t r[LM_GPR_COUNT];
} lift_ctx;
static __declspec(thread) lift_ctx g_cpu;

#define GUEST_SIZE (64u << 20)
#define GP(a) ((void *)(uintptr_t)(uint32_t)(a))

typedef struct block {
    uint32_t addr, size;
    int by_bridge, zero, live;
} block;
static block g_blocks[16384];
static uint32_t g_nblocks, g_lo, g_top, g_hi;
static CRITICAL_SECTION g_lock; /* the harness's own tables */
/* Set while this thread is inside a bridge function. The bridge may use the host callbacks only then:
 * a callback from a thread Direct3D owns, or after the bridge function returned, fails the test. */
static __declspec(thread) int g_in_bridge;

static int in_guest(uint32_t a) { return a >= g_lo && a < g_top; }
static uint32_t G(const void *p) {
    MUST((uintptr_t)p >= g_lo && (uintptr_t)p < g_top);
    return (uint32_t)(uintptr_t)p;
}
static uint32_t rd32(uint32_t a) {
    MUST(in_guest(a));
    return *(uint32_t *)GP(a);
}

/* Never reuses an address and poisons what is freed, so a stale guest object cannot pass for a live one. */
static uint32_t guest_alloc(uint32_t size, int zero, int by_bridge) {
    uint32_t addr;
    block *b;
    EnterCriticalSection(&g_lock);
    addr = g_top;
    b = &g_blocks[g_nblocks];
    MUST(g_nblocks < sizeof g_blocks / sizeof g_blocks[0]);
    MUST(size <= g_hi - g_top);
    g_top += (size + 31u) & ~15u;
    memset(GP(addr), zero ? 0 : 0xcd, size);
    b->addr = addr;
    b->size = size;
    b->by_bridge = by_bridge;
    b->zero = zero;
    b->live = 1;
    ++g_nblocks;
    LeaveCriticalSection(&g_lock);
    return addr;
}
static block *block_at(uint32_t p) {
    block *found = NULL;
    uint32_t i;
    EnterCriticalSection(&g_lock);
    for (i = 0u; i < g_nblocks && found == NULL; ++i) {
        if (g_blocks[i].addr == p) {
            found = &g_blocks[i];
        }
    }
    LeaveCriticalSection(&g_lock);
    return found;
}
/* The two heap callbacks of the bridge. */
static uint32_t galloc(uint32_t size, int zero) {
    MUST(g_in_bridge);
    return guest_alloc(size, zero, 1);
}
static void gfree(uint32_t p) {
    block *b = block_at(p);
    MUST(g_in_bridge);
    EnterCriticalSection(&g_lock);
    MUST(b != NULL && b->live && b->by_bridge); /* freed once, and only what the bridge allocated */
    memset(GP(p), 0xdd, b->size);
    b->live = 0;
    LeaveCriticalSection(&g_lock);
}
/* The guest's own allocations. */
static void *gmem(uint32_t size) { return GP(guest_alloc(size, 1, 0)); }
static uint32_t gput(const void *data, uint32_t size) {
    uint32_t p = guest_alloc(size, 0, 0);
    memcpy(GP(p), data, size);
    return p;
}
static uint32_t gstr(const char *s) { return gput(s, (uint32_t)strlen(s) + 1u); }
#define GI(iid) gput(&iid, sizeof(GUID)) /* an IID the guest passes is in guest memory too */

/* What the guest can call: a "thunk address" for a name. A name has one address, whoever asks and
 * however often; asking again must name the same function and argument count. */
#define THUNK_BASE 0xf0000000u
typedef struct thunk {
    char name[96];
    uint32_t nargs;
    d3d11_bridge_fn fn;
} thunk;
static thunk g_thunks[1024];
static uint32_t g_nthunks, g_asked_again;

static uint32_t thunk_addr(const char *name, uint32_t nargs, d3d11_bridge_fn fn) {
    uint32_t i;
    EnterCriticalSection(&g_lock);
    for (i = 0u; i < g_nthunks && strcmp(g_thunks[i].name, name) != 0; ++i) {
    }
    if (i < g_nthunks) {
        MUST(g_thunks[i].nargs == nargs && g_thunks[i].fn == fn);
        ++g_asked_again;
    } else {
        MUST(g_nthunks < sizeof g_thunks / sizeof g_thunks[0] && fn != NULL && strlen(name) < sizeof g_thunks[0].name);
        strcpy(g_thunks[i].name, name);
        g_thunks[i].nargs = nargs;
        g_thunks[i].fn = fn;
        ++g_nthunks;
    }
    LeaveCriticalSection(&g_lock);
    return THUNK_BASE + 16u * i;
}

static void stop(const char *fmt, ...) {
    va_list ap;
    MUST(g_in_bridge);
    EnterCriticalSection(&g_lock);
    va_start(ap, fmt);
    vsnprintf(g_stop, sizeof g_stop, fmt, ap);
    va_end(ap);
    ++g_stops;
    LeaveCriticalSection(&g_lock);
}
/* The call just made must have stopped the run with a message containing text. */
static void expect_stop(const char *text) {
    if (g_stops != 1 || strstr(g_stop, text) == NULL) {
        printf("FAIL: expected one stop containing \"%s\", got %d: %s\n", text, g_stops, g_stop);
        exit(1);
    }
    ++g_checks;
    g_stops = 0;
    g_stop[0] = '\0';
}
static void no_stop(void) {
    if (g_stops != 0) {
        printf("FAIL: the bridge stopped the run: %s\n", g_stop);
        exit(1);
    }
}

/* The guest's ID3DInclude: two "guest functions" the bridge has the runner call. */
#define FN_INCLUDE_OPEN 0xe0000010u
#define FN_INCLUDE_CLOSE 0xe0000020u
static uint32_t g_include_obj, g_include_text, g_opens, g_closes, g_src;
static uint32_t guest_code(uint32_t entry, uint32_t nargs, const uint32_t *args) {
    static const char text[] = "static const float4 bias = float4(0, 0, BLUE, 0);\n";
    MUST(g_in_bridge);
    if (entry == FN_INCLUDE_OPEN) {
        CHECK(nargs == 6u && args[0] == g_include_obj && args[1] == (uint32_t)D3D_INCLUDE_LOCAL);
        CHECK(in_guest(args[2]) && strcmp(GP(args[2]), "bias.hlsl") == 0);
        CHECK(args[3] == 0u || args[3] == g_src); /* the including file: the source the guest passed */
        CHECK(in_guest(args[4]) && in_guest(args[5]));
        g_include_text = gstr(text);
        *(uint32_t *)GP(args[4]) = g_include_text;
        *(uint32_t *)GP(args[5]) = (uint32_t)sizeof text - 1u;
        ++g_opens;
        return 0u;
    }
    CHECK(entry == FN_INCLUDE_CLOSE && nargs == 2u && args[0] == g_include_obj && args[1] == g_include_text);
    ++g_closes;
    return 0u;
}

#ifdef TEST_LIVE
/* ---- as live_main.c: the names and types the bridge's glue uses there ----------------------------- */

#define SH_FREE 1u
typedef uint32_t (*shim_fn)(lift_ctx *c, const uint32_t *a);
typedef struct shim {
    const char *dll;
    const char *name;
    uint32_t nargs;
    shim_fn fn;
    uint32_t flags;
} shim;
static const shim *find_shim(const char *dll, const char *name);

/* The address of an import: live_main.c edits its import table here, under g_lock. */
static uint32_t import_addr(const char *dll, const char *name, uint32_t iat) {
    const shim *sh = find_shim(dll, name);
    (void)iat;
    MUST(g_lock.OwningThread == (HANDLE)(uintptr_t)GetCurrentThreadId());
    if (sh == NULL) {
        printf("FAIL: no shim row for %s!%s\n", dll, name);
        exit(1);
    }
    MUST(sh->flags == SH_FREE);
    return thunk_addr(name, sh->nargs, sh->fn);
}

/* Runs guest code on the calling thread; the callee's EAX is left in that thread's state. */
static int guest_call(uint32_t entry, uint32_t nargs, const uint32_t *args) {
    MUST(g_lock.OwningThread != (HANDLE)(uintptr_t)GetCurrentThreadId()); /* no host lock across guest code */
    g_cpu.r[LM_EAX] = guest_code(entry, nargs, args);
    return 0;
}

#define D3D11_BRIDGE_LIVE
#include "d3d11_bridge.c"

static const shim g_shims[] = {
    D3D11_BRIDGE_SHIMS
};
static const shim *find_shim(const char *dll, const char *name) {
    size_t i;
    for (i = 0u; i < sizeof g_shims / sizeof g_shims[0]; ++i) {
        if (_stricmp(g_shims[i].dll, dll) == 0 && strcmp(g_shims[i].name, name) == 0) {
            return &g_shims[i];
        }
    }
    return NULL;
}

#else
/* ---- as a host of its own, through d3d11_bridge_host_t -------------------------------------------- */

static uint32_t register_method(const char *iface, uint32_t idx, uint32_t nargs, d3d11_bridge_fn fn) {
    char name[96];
    MUST(g_in_bridge);
    snprintf(name, sizeof name, "%s#%u", iface, idx);
    return thunk_addr(name, nargs, fn);
}
static uint32_t call_guest(struct lift_ctx *c, uint32_t entry, uint32_t nargs, const uint32_t *args) {
    MUST(c == &g_cpu); /* the state the D3DCompile call was entered with */
    return guest_code(entry, nargs, args);
}

#endif

/* ---- calling the bridge the way the guest does -------------------------------------------------- */

static uint32_t g_seen_vtbl[64], g_nseen, g_calls;

static uint32_t gcall(const char *what, uint32_t obj, uint32_t slot, const uint32_t *args, size_t nargs) {
    uint32_t vtbl = rd32(obj), va = rd32(vtbl + 4u * slot), i = (va - THUNK_BASE) / 16u, r;
    d3d11_bridge_fn fn;
    EnterCriticalSection(&g_lock);
    if (va < THUNK_BASE || (va - THUNK_BASE) % 16u != 0u || i >= g_nthunks) {
        printf("FAIL: %s: object %08x slot %u holds %08x, not a registered method\n", what, obj, slot, va);
        exit(1);
    }
    if (g_thunks[i].nargs != nargs) {
        printf("FAIL: %s: the guest pushes %u dwords, the bridge registered %u\n", what, (unsigned)nargs, g_thunks[i].nargs);
        exit(1);
    }
    for (i = 0u; i < g_nseen && g_seen_vtbl[i] != vtbl; ++i) {
    }
    if (i == g_nseen) {
        MUST(g_nseen < 64u);
        g_seen_vtbl[g_nseen++] = vtbl;
    }
    ++g_calls;
    fn = g_thunks[(va - THUNK_BASE) / 16u].fn;
    LeaveCriticalSection(&g_lock);
    g_in_bridge = 1;
    r = fn(&g_cpu, args);
    g_in_bridge = 0;
    return r;
}
#define SLOT(I, M) ((uint32_t)(offsetof(I##Vtbl, M) / sizeof(void *)))
#define CALL(obj, I, M, ...) \
    gcall(#I "::" #M, obj, SLOT(I, M), (uint32_t[]){obj, __VA_ARGS__}, sizeof((uint32_t[]){obj, __VA_ARGS__}) / sizeof(uint32_t))
#define CALL0(obj, I, M) gcall(#I "::" #M, obj, SLOT(I, M), (uint32_t[]){obj}, 1u)
#define RELEASE(obj) CALL0(obj, IUnknown, Release)

/* An entry point, found the way the guest finds it: by the name of the DLL and of the export. */
static uint32_t ecall_n(const char *name, const uint32_t *args, size_t nargs) {
    uint32_t i, r;
    for (i = 0u; i < d3d11_bridge_export_count; ++i) {
        if (strcmp(d3d11_bridge_exports[i].name, name) == 0) {
            d3d11_bridge_fn fn = d3d11_bridge_exports[i].fn;
            CHECK(d3d11_bridge_exports[i].nargs == nargs);
#ifdef TEST_LIVE
            {
                const shim *sh = find_shim(d3d11_bridge_exports[i].dll, name);
                CHECK(sh != NULL && sh->nargs == nargs && sh->fn == fn);
                fn = sh->fn;
            }
#endif
            g_in_bridge = 1;
            r = fn(&g_cpu, args);
            g_in_bridge = 0;
            return r;
        }
    }
    printf("FAIL: %s is not exported by the bridge\n", name);
    exit(1);
}
#define ECALL(name, ...) ecall_n(#name, (uint32_t[]){__VA_ARGS__}, sizeof((uint32_t[]){__VA_ARGS__}) / sizeof(uint32_t))

/* The bridge's other functions, entered the same way. */
static void *host_object(uint32_t guest) {
    void *p;
    g_in_bridge = 1;
    p = d3d11_bridge_host_object(guest);
    g_in_bridge = 0;
    return p;
}
static uint32_t wrap(void *host_iface, const GUID *iid) {
    uint32_t g;
    g_in_bridge = 1;
    g = d3d11_bridge_wrap(host_iface, iid);
    g_in_bridge = 0;
    return g;
}
static uint32_t live_objects(void) {
    uint32_t n;
    g_in_bridge = 1;
    n = d3d11_bridge_live_objects();
    g_in_bridge = 0;
    return n;
}
static uint32_t live_maps(void) {
    uint32_t n;
    g_in_bridge = 1;
    n = d3d11_bridge_live_maps();
    g_in_bridge = 0;
    return n;
}
#ifndef TEST_LIVE
static void bridge_init(const d3d11_bridge_host_t *host) {
    g_in_bridge = 1;
    d3d11_bridge_init(host);
    g_in_bridge = 0;
}
#endif

static uint32_t fbits(float f) {
    uint32_t u;
    memcpy(&u, &f, sizeof u);
    return u;
}

/* Four bytes after a structure the bridge writes: they must survive. */
#define SENTINEL 0x5ca1ab1eu

static uint32_t *g_out; /* a guest dword for out parameters */
static uint32_t g_dev, g_ctx, g_fl;

/* ---- DXGI --------------------------------------------------------------------------------------- */

static void test_dxgi(void) {
    uint32_t factory, adapter, parent, output, *desc = gmem(296u + 4u), base = live_objects();
    uint32_t hr;
    CHECK_HR(ECALL(CreateDXGIFactory1, GI(IID_IDXGIFactory1), G(g_out)));
    factory = *g_out;
    CHECK(in_guest(factory));
    CHECK(live_objects() == base + 1u);
    CHECK(host_object(factory) != NULL && host_object(G(desc)) == NULL);

    CHECK_HR(CALL(factory, IDXGIFactory1, EnumAdapters1, 0u, G(g_out)));
    adapter = *g_out;
    /* DXGI_ADAPTER_DESC1 is 296 bytes for the guest (three 4-byte SIZE_Ts), 304 on the host. */
    desc[296u / 4u] = SENTINEL;
    CHECK_HR(CALL(adapter, IDXGIAdapter1, GetDesc1, G(desc)));
    CHECK(desc[296u / 4u] == SENTINEL && ((WCHAR *)desc)[0] != 0);
    printf("adapter 0: %ls, vendor %04x, %u MiB dedicated video memory, flags %u\n", (WCHAR *)desc, desc[64], desc[68] >> 20, desc[73]);
    {
        /* The same adapter through the host, to compare every field the bridge converts. */
        IDXGIAdapter1 *host = host_object(adapter);
        DXGI_ADAPTER_DESC1 d;
        CHECK(SUCCEEDED(IDXGIAdapter1_GetDesc1(host, &d)));
        CHECK(memcmp(desc, d.Description, 256u) == 0 && desc[64] == d.VendorId && desc[65] == d.DeviceId && desc[66] == d.SubSysId);
        CHECK(desc[67] == d.Revision && desc[68] == (d.DedicatedVideoMemory > 0xffffffffu ? 0xffffffffu : (uint32_t)d.DedicatedVideoMemory));
        CHECK(desc[69] == (d.DedicatedSystemMemory > 0xffffffffu ? 0xffffffffu : (uint32_t)d.DedicatedSystemMemory));
        CHECK(desc[70] == (d.SharedSystemMemory > 0xffffffffu ? 0xffffffffu : (uint32_t)d.SharedSystemMemory));
        CHECK(desc[71] == d.AdapterLuid.LowPart && desc[72] == (uint32_t)d.AdapterLuid.HighPart && desc[73] == d.Flags);
    }
    /* IDXGIAdapter::GetDesc through the derived object: 292 bytes. */
    desc[292u / 4u] = SENTINEL;
    CHECK_HR(CALL(adapter, IDXGIAdapter, GetDesc, G(desc)));
    CHECK(desc[292u / 4u] == SENTINEL);

    /* GetParent names the interface it wants and gets the object the guest already holds. */
    CHECK_HR(CALL(adapter, IDXGIObject, GetParent, GI(IID_IDXGIFactory1), G(g_out)));
    parent = *g_out;
    CHECK(parent == factory);
    CHECK(RELEASE(parent) >= 1u);
    CHECK_HR(CALL(factory, IUnknown, QueryInterface, GI(IID_IDXGIFactory), G(g_out)));
    CHECK(*g_out == factory);
    RELEASE(factory);
    CHECK(CALL0(factory, IDXGIFactory1, IsCurrent) <= 1u);

    hr = CALL(adapter, IDXGIAdapter, EnumOutputs, 0u, G(g_out));
    if (hr == 0u) {
        uint32_t *od = gmem(92u + 4u), modes = 0u, *n = gmem(4u);
        output = *g_out;
        od[92u / 4u] = SENTINEL;
        CHECK_HR(CALL(output, IDXGIOutput, GetDesc, G(od)));
        CHECK(od[92u / 4u] == SENTINEL);
        {
            DXGI_OUTPUT_DESC d;
            CHECK(SUCCEEDED(IDXGIOutput_GetDesc((IDXGIOutput *)host_object(output), &d)));
            CHECK(memcmp(od, d.DeviceName, 64u) == 0 && memcmp(&od[16], &d.DesktopCoordinates, 16u) == 0);
            CHECK(od[20] == (uint32_t)d.AttachedToDesktop && od[21] == (uint32_t)d.Rotation && od[22] == (uint32_t)(uintptr_t)d.Monitor);
            CHECK((HMONITOR)(intptr_t)(int32_t)od[22] == d.Monitor);
        }
        CHECK_HR(CALL(output, IDXGIOutput, GetDisplayModeList, DXGI_FORMAT_R8G8B8A8_UNORM, 0u, G(n), 0u));
        modes = *n;
        printf("output 0: %ls, %u display modes\n", (WCHAR *)od, modes);
        CHECK(RELEASE(output) == 0u);
    } else {
        CHECK(hr == (uint32_t)DXGI_ERROR_NOT_FOUND);
        printf("adapter 0 has no output: IDXGIOutput not exercised\n");
    }
    CHECK(RELEASE(adapter) == 0u);
    CHECK(RELEASE(factory) == 0u);
    CHECK(live_objects() == base);

    /* CreateDXGIFactory, and D3D11CreateDevice on an adapter object the guest passes: the software one. */
    CHECK_HR(ECALL(CreateDXGIFactory, GI(IID_IDXGIFactory), G(g_out)));
    CHECK(in_guest(*g_out) && RELEASE(*g_out) == 0u);
    CHECK_HR(ECALL(CreateDXGIFactory1, GI(IID_IDXGIFactory1), G(g_out)));
    factory = *g_out;
    {
        uint32_t i, made = 0u, *ctx = gmem(4u), *dev = gmem(4u);
        for (i = 0u; CALL(factory, IDXGIFactory1, EnumAdapters1, i, G(g_out)) == 0u; ++i) {
            adapter = *g_out;
            CHECK_HR(CALL(adapter, IDXGIAdapter1, GetDesc1, G(desc)));
            if ((desc[73] & DXGI_ADAPTER_FLAG_SOFTWARE) != 0u && made == 0u) {
                CHECK_HR(ECALL(D3D11CreateDevice, adapter, D3D_DRIVER_TYPE_UNKNOWN, 0u, 0u, 0u, 0u, D3D11_SDK_VERSION, G(dev), 0u, G(ctx)));
                CHECK(in_guest(*dev) && in_guest(*ctx));
                RELEASE(*ctx);
                CHECK(RELEASE(*dev) == 0u);
                made = 1u;
            }
            RELEASE(adapter);
        }
        CHECK(i >= 1u && made == 1u && *g_out == 0u); /* the failed EnumAdapters1 cleared the out pointer */
    }
    /* A bridged object of the wrong interface where an adapter is expected stops the run. */
    CHECK(ECALL(D3D11CreateDevice, factory, D3D_DRIVER_TYPE_UNKNOWN, 0u, 0u, 0u, 0u, D3D11_SDK_VERSION, G(g_out), 0u, 0u) == (uint32_t)E_INVALIDARG);
    expect_stop("IDXGIAdapter is expected");
    CHECK(RELEASE(factory) == 0u);
    CHECK(live_objects() == base);
    no_stop();
}

/* ---- device, identity --------------------------------------------------------------------------- */

static void test_device(void) {
    uint32_t *level = gmem(4u), *got = gmem(4u), *ctx = gmem(4u), dxgi, adapter, same;
    *level = D3D_FEATURE_LEVEL_11_0;
    CHECK_HR(ECALL(D3D11CreateDevice, 0u, D3D_DRIVER_TYPE_WARP, 0u, 0u, G(level), 1u, D3D11_SDK_VERSION, G(g_out), G(got), G(ctx)));
    g_dev = *g_out;
    g_ctx = *ctx;
    g_fl = *got;
    CHECK(in_guest(g_dev) && in_guest(g_ctx) && g_dev != g_ctx && g_fl == D3D_FEATURE_LEVEL_11_0);
    CHECK((uintptr_t)host_object(g_dev) != g_dev); /* the guest never sees the host pointer */
    CHECK(CALL0(g_dev, ID3D11Device, GetFeatureLevel) == D3D_FEATURE_LEVEL_11_0);
    CHECK(CALL0(g_ctx, ID3D11DeviceContext, GetType) == D3D11_DEVICE_CONTEXT_IMMEDIATE);

    /* The same host pointer is always the same guest object. */
    CALL(g_dev, ID3D11Device, GetImmediateContext, G(g_out));
    CHECK(*g_out == g_ctx);
    RELEASE(g_ctx);
    CALL(g_ctx, ID3D11DeviceChild, GetDevice, G(g_out));
    CHECK(*g_out == g_dev);
    RELEASE(g_dev);

    /* Another interface of the device is another guest object, and leads back. */
    CHECK_HR(CALL(g_dev, IUnknown, QueryInterface, GI(IID_IDXGIDevice1), G(g_out)));
    dxgi = *g_out;
    CHECK(in_guest(dxgi) && dxgi != g_dev);
    CHECK_HR(CALL(dxgi, IDXGIDevice1, SetMaximumFrameLatency, 2u));
    CHECK_HR(CALL(dxgi, IDXGIDevice1, GetMaximumFrameLatency, G(got)));
    CHECK(*got == 2u);
    CHECK_HR(CALL(dxgi, IUnknown, QueryInterface, GI(IID_ID3D11Device), G(g_out)));
    same = *g_out;
    CHECK(same == g_dev);
    RELEASE(same);
    CHECK_HR(CALL(dxgi, IDXGIDevice, GetAdapter, G(g_out)));
    adapter = *g_out;
    CHECK_HR(CALL(adapter, IDXGIObject, GetParent, GI(IID_IDXGIFactory1), G(g_out)));
    CHECK(in_guest(*g_out));
    RELEASE(*g_out);
    RELEASE(adapter);
    /* COM identity: IUnknown asked of either interface of the device is one pointer, so one guest object. */
    {
        uint32_t unknown;
        CHECK_HR(CALL(g_dev, IUnknown, QueryInterface, GI(IID_IUnknown), G(g_out)));
        unknown = *g_out;
        CHECK_HR(CALL(dxgi, IUnknown, QueryInterface, GI(IID_IUnknown), G(g_out)));
        CHECK(in_guest(unknown) && *g_out == unknown);
        RELEASE(unknown);
        RELEASE(unknown);
    }
    RELEASE(dxgi);

    /* AddRef and Release are the host object's. */
    {
        ID3D11Device *host = host_object(g_dev);
        uint32_t n = CALL0(g_dev, IUnknown, AddRef);
        ID3D11Device_AddRef(host);
        CHECK(ID3D11Device_Release(host) == n);
        CHECK(RELEASE(g_dev) == n - 1u);
    }

    /* An interface the host does not have is the host's answer, not a stop: the game asks for these two. */
    *g_out = 0x12345678u;
    CHECK(CALL(g_dev, IUnknown, QueryInterface, GI(IID_ID3D11Debug), G(g_out)) == (uint32_t)E_NOINTERFACE && *g_out == 0u);
    CHECK(CALL(g_dev, IUnknown, QueryInterface, GI(IID_ID3D11InfoQueue), G(g_out)) == (uint32_t)E_NOINTERFACE && *g_out == 0u);

    /* Pass-through structures. */
    {
        D3D11_FEATURE_DATA_THREADING *t = gmem(sizeof *t);
        uint32_t *q = gmem(4u);
        CHECK_HR(CALL(g_dev, ID3D11Device, CheckFeatureSupport, D3D11_FEATURE_THREADING, G(t), sizeof *t));
        CHECK_HR(CALL(g_dev, ID3D11Device, CheckFormatSupport, DXGI_FORMAT_R8G8B8A8_UNORM, G(q)));
        CHECK((*q & D3D11_FORMAT_SUPPORT_RENDER_TARGET) != 0u);
        CHECK_HR(CALL(g_dev, ID3D11Device, CheckMultisampleQualityLevels, DXGI_FORMAT_R8G8B8A8_UNORM, 1u, G(q)));
        CHECK(*q >= 1u);
    }
    no_stop();
}

/* ---- compile, draw, read back ------------------------------------------------------------------- */

static const char VS_SRC[] =
    "cbuffer C : register(b0) { float4 tint; };\n"
    "struct I { float3 pos : POSITION; float4 col : COLOR; };\n"
    "struct O { float4 pos : SV_Position; float4 col : COLOR; };\n"
    "O main(I i) { O o; o.pos = float4(i.pos, 1); o.col = i.col * tint; return o; }\n";
static const char PS_SRC[] =
    "#include \"bias.hlsl\"\n"
    "Texture2D tex : register(t0);\n"
    "float4 main(float4 pos : SV_Position, float4 col : COLOR) : SV_Target { return col * tex.Load(int3(0, 0, 0)) + bias; }\n";

static uint32_t blob_ptr(uint32_t blob) {
    uint32_t p = CALL0(blob, ID3D10Blob, GetBufferPointer), n = CALL0(blob, ID3D10Blob, GetBufferSize);
    CHECK(in_guest(p) && n != 0u && in_guest(p + n - 1u));
    return p;
}

static uint32_t compile(const char *src, const char *target, uint32_t defines, uint32_t include) {
    uint32_t *code = gmem(4u), *errors = gmem(4u), hr;
    g_src = gstr(src);
    hr = ECALL(D3DCompile, g_src, (uint32_t)strlen(src), 0u, defines, include, gstr("main"), gstr(target), 0u, 0u, G(code), G(errors));
    if (hr != 0u) {
        printf("FAIL: D3DCompile(%s) %08x: %s\n", target, hr, *errors != 0u ? (char *)GP(blob_ptr(*errors)) : "");
        exit(1);
    }
    if (*errors != 0u) {
        RELEASE(*errors);
    }
    CHECK(in_guest(*code));
    return *code;
}

/* Reads a 4x4 RGBA8 texture back through a staging copy and Map, and compares the two halves. */
static void check_halves(uint32_t tex, uint32_t left, uint32_t right) {
    D3D11_TEXTURE2D_DESC *sd = gmem(sizeof *sd);
    uint32_t staging, *m = gmem(16u), x, y, objects, maps = live_maps();
    *sd = (D3D11_TEXTURE2D_DESC){4u, 4u, 1u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, {1u, 0u}, D3D11_USAGE_STAGING, 0u, D3D11_CPU_ACCESS_READ, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture2D, G(sd), 0u, G(g_out)));
    staging = *g_out;
    CALL(g_ctx, ID3D11DeviceContext, CopyResource, staging, tex);
    /* D3D11_MAPPED_SUBRESOURCE is 12 bytes for the guest: pData, RowPitch, DepthPitch. */
    m[3] = SENTINEL;
    objects = live_objects();
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, staging, 0u, D3D11_MAP_READ, 0u, G(m)));
    CHECK(m[3] == SENTINEL && in_guest(m[0]) && m[1] >= 16u && in_guest(m[0] + 3u * m[1] + 15u));
    CHECK(live_maps() == maps + 1u);
    for (y = 0u; y < 4u; ++y) {
        for (x = 0u; x < 4u; ++x) {
            uint32_t pixel = *(uint32_t *)GP(m[0] + y * m[1] + 4u * x), want = x < 2u ? left : right;
            if (pixel != want) {
                printf("FAIL: pixel (%u,%u) is %08x, expected %08x\n", x, y, pixel, want);
                exit(1);
            }
            ++g_checks;
        }
    }
    CALL(g_ctx, ID3D11DeviceContext, Unmap, staging, 0u);
    CHECK(live_maps() == maps && block_at(m[0]) != NULL && !block_at(m[0])->live); /* the shadow is freed */
    CHECK(RELEASE(staging) == 0u);
    CALL0(g_ctx, ID3D11DeviceContext, Flush);
    CHECK(live_objects() == objects - 1u);
}

/* RGBA bytes as the little-endian dword a guest reads. */
#define RGBA(r, g, b, a) ((uint32_t)(r) | (uint32_t)(g) << 8 | (uint32_t)(b) << 16 | (uint32_t)(a) << 24)

/* Parts of the context the triangle does not need. rt is a 4x4 render target, rtv its view. */
static void test_context(uint32_t rt, uint32_t rtv) {
    uint32_t *arr = gmem(32u), objects;
    /* Direct3D destroys what was released to 0 at the next Flush: count from a settled state. */
    CALL0(g_ctx, ID3D11DeviceContext, Flush);
    objects = live_objects();

    /* A count of "keep what is bound" means the array beside it is not read: here it is not even memory. */
    arr[0] = rtv;
    CALL(g_ctx, ID3D11DeviceContext, OMSetRenderTargetsAndUnorderedAccessViews, 1u, G(arr), 0u, 1u, D3D11_KEEP_UNORDERED_ACCESS_VIEWS, 0xdead0000u, 0u);
    CALL(g_ctx, ID3D11DeviceContext, OMSetRenderTargetsAndUnorderedAccessViews, D3D11_KEEP_RENDER_TARGETS_AND_DEPTH_STENCIL, 0xdead0000u, 0xdead0000u, 0u, 0u, 0u, 0u);
    no_stop();
    arr[0] = arr[1] = 0u;
    CALL(g_ctx, ID3D11DeviceContext, OMGetRenderTargetsAndUnorderedAccessViews, 1u, G(arr), 0u, 1u, 0u, 0u);
    CHECK(arr[0] == rtv && RELEASE(rtv) == 1u);

    /* State objects: descriptions pass through, the pipeline returns the guest objects it was given. */
    {
        D3D11_SAMPLER_DESC *sd = gmem(sizeof *sd), *sd2 = gmem(sizeof *sd2);
        D3D11_BLEND_DESC *bd = gmem(sizeof *bd), *bd2 = gmem(sizeof *bd2);
        D3D11_RASTERIZER_DESC *rd = gmem(sizeof *rd), *rd2 = gmem(sizeof *rd2);
        float *factor = gmem(16u), *factor2 = gmem(16u);
        uint32_t sampler, blend, raster, *mask = gmem(4u);
        *sd = (D3D11_SAMPLER_DESC){D3D11_FILTER_MIN_MAG_MIP_LINEAR, D3D11_TEXTURE_ADDRESS_CLAMP, D3D11_TEXTURE_ADDRESS_WRAP, D3D11_TEXTURE_ADDRESS_MIRROR, 0.5f, 1u, D3D11_COMPARISON_NEVER, {0.1f, 0.2f, 0.3f, 0.4f}, 0.0f, 8.0f};
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateSamplerState, G(sd), G(g_out)));
        sampler = *g_out;
        CALL(sampler, ID3D11SamplerState, GetDesc, G(sd2));
        {
            /* Direct3D may normalise fields the sampler does not use: the guest gets what the host says. */
            D3D11_SAMPLER_DESC h;
            ID3D11SamplerState_GetDesc((ID3D11SamplerState *)host_object(sampler), &h);
            CHECK(memcmp(sd2, &h, sizeof h) == 0);
        }
        CHECK(sd2->Filter == sd->Filter && sd2->AddressU == sd->AddressU && sd2->AddressV == sd->AddressV && sd2->AddressW == sd->AddressW);
        CHECK(sd2->MipLODBias == 0.5f && sd2->MinLOD == 0.0f && sd2->MaxLOD == 8.0f);
        arr[0] = arr[2] = sampler; /* slots 3 and 5; slot 4 empty */
        arr[1] = 0u;
        CALL(g_ctx, ID3D11DeviceContext, PSSetSamplers, 3u, 3u, G(arr));
        memset(arr, 0xff, 32u);
        CALL(g_ctx, ID3D11DeviceContext, PSGetSamplers, 2u, 5u, G(arr));
        CHECK(arr[0] == 0u && arr[1] == sampler && arr[2] == 0u && arr[3] == sampler && arr[4] == 0u && arr[5] == 0xffffffffu);
        CHECK(RELEASE(sampler) == 2u && RELEASE(sampler) == 1u);

        memset(bd, 0, sizeof *bd);
        bd->RenderTarget[0].BlendEnable = TRUE;
        bd->RenderTarget[0].SrcBlend = D3D11_BLEND_SRC_ALPHA;
        bd->RenderTarget[0].DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
        bd->RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
        bd->RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
        bd->RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
        bd->RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
        bd->RenderTarget[0].RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateBlendState, G(bd), G(g_out)));
        blend = *g_out;
        CALL(blend, ID3D11BlendState, GetDesc, G(bd2));
        CHECK(memcmp(&bd->RenderTarget[0], &bd2->RenderTarget[0], sizeof bd->RenderTarget[0]) == 0);
        factor[0] = 0.25f;
        factor[1] = 0.5f;
        factor[2] = 0.75f;
        factor[3] = 1.0f;
        CALL(g_ctx, ID3D11DeviceContext, OMSetBlendState, blend, G(factor), 0x0f0f0f0fu);
        CALL(g_ctx, ID3D11DeviceContext, OMGetBlendState, G(g_out), G(factor2), G(mask));
        CHECK(*g_out == blend && memcmp(factor, factor2, 16u) == 0 && *mask == 0x0f0f0f0fu && RELEASE(blend) == 1u);

        *rd = (D3D11_RASTERIZER_DESC){D3D11_FILL_SOLID, D3D11_CULL_NONE, TRUE, 3, 0.5f, 0.25f, TRUE, TRUE, FALSE, FALSE};
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateRasterizerState, G(rd), G(g_out)));
        raster = *g_out;
        CALL(raster, ID3D11RasterizerState, GetDesc, G(rd2));
        {
            D3D11_RASTERIZER_DESC h;
            ID3D11RasterizerState_GetDesc((ID3D11RasterizerState *)host_object(raster), &h);
            CHECK(memcmp(rd2, &h, sizeof h) == 0);
        }
        CHECK(rd2->FillMode == D3D11_FILL_SOLID && rd2->CullMode == D3D11_CULL_NONE && rd2->FrontCounterClockwise == TRUE);
        CHECK(rd2->DepthBias == 3 && rd2->DepthBiasClamp == 0.5f && rd2->SlopeScaledDepthBias == 0.25f && rd2->ScissorEnable == TRUE);
        CALL(g_ctx, ID3D11DeviceContext, RSSetState, raster);
        CALL(g_ctx, ID3D11DeviceContext, RSGetState, G(g_out));
        CHECK(*g_out == raster && RELEASE(raster) == 1u);
        CALL0(g_ctx, ID3D11DeviceContext, ClearState);
        CHECK(RELEASE(sampler) == 0u && RELEASE(blend) == 0u && RELEASE(raster) == 0u);
    }

    /* A query is passed where ID3D11Asynchronous is expected; its data is written to guest memory. */
    {
        D3D11_QUERY_DESC *qd = gmem(sizeof *qd), *qd2 = gmem(sizeof *qd2);
        uint32_t query, hr = 1u, tries, *done = gmem(8u);
        *qd = (D3D11_QUERY_DESC){D3D11_QUERY_EVENT, 0u};
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateQuery, G(qd), G(g_out)));
        query = *g_out;
        CALL(query, ID3D11Query, GetDesc, G(qd2));
        CHECK(qd2->Query == D3D11_QUERY_EVENT && CALL0(query, ID3D11Asynchronous, GetDataSize) == sizeof(BOOL));
        CALL(g_ctx, ID3D11DeviceContext, End, query);
        CALL0(g_ctx, ID3D11DeviceContext, Flush);
        done[1] = SENTINEL;
        for (tries = 0u; hr != 0u && tries < 5000u; ++tries) {
            hr = CALL(g_ctx, ID3D11DeviceContext, GetData, query, G(done), 4u, 0u);
            CHECK(hr == 0u || hr == 1u); /* S_OK, or S_FALSE while the event has not happened */
            if (hr != 0u) {
                Sleep(1);
            }
        }
        CHECK(hr == 0u && done[0] == 1u && done[1] == SENTINEL);
        CHECK(RELEASE(query) == 0u);
    }

    /* D3D11_SO_DECLARATION_ENTRY is 16 bytes for the guest, the semantic name a dword at offset 4.
     * A stream-output shader can be made from vertex shader bytecode. A name the shader does not
     * output is refused by the host, which shows the host reads the name the guest pointed at. */
    {
        uint32_t code = compile(VS_SRC, "vs_4_0", 0u, 0u), ptr = blob_ptr(code), size = CALL0(code, ID3D10Blob, GetBufferSize);
        uint32_t *so = gmem(16u), *stride = gmem(4u), gs;
        so[0] = 0u;                    /* Stream */
        so[1] = gstr("SV_Position");   /* SemanticName */
        so[2] = 0u;                    /* SemanticIndex */
        ((uint8_t *)so)[12] = 0u;      /* StartComponent */
        ((uint8_t *)so)[13] = 4u;      /* ComponentCount */
        ((uint8_t *)so)[14] = 0u;      /* OutputSlot */
        *stride = 16u;
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateGeometryShaderWithStreamOutput, ptr, size, G(so), 1u, G(stride), 1u, D3D11_SO_NO_RASTERIZED_STREAM, 0u, G(g_out)));
        gs = *g_out;
        CALL(g_ctx, ID3D11DeviceContext, GSSetShader, gs, 0u, 0u);
        CALL(g_ctx, ID3D11DeviceContext, GSGetShader, G(g_out), 0u, 0u);
        CHECK(*g_out == gs && RELEASE(gs) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, GSSetShader, 0u, 0u, 0u);
        CHECK(RELEASE(gs) == 0u);
        so[1] = gstr("NOT_AN_OUTPUT");
        CHECK(CALL(g_dev, ID3D11Device, CreateGeometryShaderWithStreamOutput, ptr, size, G(so), 1u, G(stride), 1u, D3D11_SO_NO_RASTERIZED_STREAM, 0u, G(g_out)) == (uint32_t)E_INVALIDARG);
        CHECK(*g_out == 0u && RELEASE(code) == 0u);
    }

    /* A deferred context records a clear into a command list; the immediate context plays it. */
    {
        uint32_t deferred, list;
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateDeferredContext, 0u, G(g_out)));
        deferred = *g_out;
        CHECK(deferred != g_ctx && CALL0(deferred, ID3D11DeviceContext, GetType) == D3D11_DEVICE_CONTEXT_DEFERRED);
        CALL(deferred, ID3D11DeviceContext, ClearRenderTargetView, rtv, gput((float[4]){0.0f, 1.0f, 0.0f, 1.0f}, 16u));
        CHECK_HR(CALL(deferred, ID3D11DeviceContext, FinishCommandList, 0u, G(g_out)));
        list = *g_out;
        CHECK(CALL0(list, ID3D11CommandList, GetContextFlags) == 0u);
        CALL(g_ctx, ID3D11DeviceContext, ClearRenderTargetView, rtv, gput((float[4]){0.0f, 0.0f, 1.0f, 1.0f}, 16u));
        check_halves(rt, RGBA(0, 0, 255, 255), RGBA(0, 0, 255, 255));
        CALL(g_ctx, ID3D11DeviceContext, ExecuteCommandList, list, 0u);
        check_halves(rt, RGBA(0, 255, 0, 255), RGBA(0, 255, 0, 255));
        CHECK(RELEASE(list) == 0u && RELEASE(deferred) == 0u);
    }

    /* An object another shim created on the host is given to the guest with d3d11_bridge_wrap. */
    {
        D3D11_TEXTURE2D_DESC desc = {8u, 2u, 1u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, {1u, 0u}, D3D11_USAGE_DEFAULT, D3D11_BIND_SHADER_RESOURCE, 0u, 0u};
        D3D11_TEXTURE2D_DESC *got = gmem(sizeof *got);
        ID3D11Texture2D *host = NULL;
        uint32_t guest;
        CHECK(SUCCEEDED(ID3D11Device_CreateTexture2D((ID3D11Device *)host_object(g_dev), &desc, NULL, &host)));
        guest = wrap(host, &IID_ID3D11Texture2D);
        CHECK(in_guest(guest) && host_object(guest) == (void *)host);
        CALL(guest, ID3D11Texture2D, GetDesc, G(got));
        CHECK(memcmp(got, &desc, sizeof desc) == 0 && RELEASE(guest) == 0u);
        CHECK(wrap(NULL, &IID_ID3D11Texture2D) == 0u);
    }
    CALL0(g_ctx, ID3D11DeviceContext, ClearState);
    CALL0(g_ctx, ID3D11DeviceContext, Flush);
    CHECK(live_objects() == objects);
    no_stop();
}

static void test_render(void) {
    static const float verts[3][7] = {
        {-1.0f, -1.0f, 0.5f, 1.0f, 0.8f, 0.0f, 1.0f},
        {-1.0f, 3.0f, 0.5f, 1.0f, 0.8f, 0.0f, 1.0f},
        {3.0f, -1.0f, 0.5f, 1.0f, 0.8f, 0.0f, 1.0f},
    };
    static const float tint[4] = {1.0f, 0.5f, 1.0f, 1.0f};
    static const float clear[4] = {0.2f, 0.4f, 0.6f, 1.0f};
    D3D11_TEXTURE2D_DESC *td = gmem(sizeof *td);
    D3D11_BUFFER_DESC *bd = gmem(sizeof *bd);
    D3D11_VIEWPORT *vp = gmem(sizeof *vp);
    uint32_t rt, rtv, vb, cb, tex, srv, vs_blob, ps_blob, vs, ps, layout, *init = gmem(12u), *elems = gmem(56u), *m = gmem(12u);
    uint32_t *arr = gmem(16u), *strides = gmem(4u), *offsets = gmem(4u), *defines = gmem(16u), *include_vtbl = gmem(8u), *n = gmem(4u);
    uint32_t objects;

    /* Render target and view. */
    *td = (D3D11_TEXTURE2D_DESC){4u, 4u, 1u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, {1u, 0u}, D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET, 0u, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture2D, G(td), 0u, G(g_out)));
    rt = *g_out;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateRenderTargetView, rt, 0u, G(g_out)));
    rtv = *g_out;
    {
        D3D11_TEXTURE2D_DESC *got = gmem(sizeof *got);
        D3D11_RENDER_TARGET_VIEW_DESC *vd = gmem(sizeof *vd);
        CALL(rt, ID3D11Texture2D, GetDesc, G(got));
        CHECK(memcmp(got, td, sizeof *td) == 0);
        CALL(rtv, ID3D11RenderTargetView, GetDesc, G(vd));
        CHECK(vd->Format == DXGI_FORMAT_R8G8B8A8_UNORM && vd->ViewDimension == D3D11_RTV_DIMENSION_TEXTURE2D);
        CALL(rt, ID3D11Resource, GetType, G(n));
        CHECK(*n == D3D11_RESOURCE_DIMENSION_TEXTURE2D);
        CALL(rtv, ID3D11View, GetResource, G(g_out)); /* returned as ID3D11Resource: the same guest object */
        CHECK(*g_out == rt);
        RELEASE(rt);
        CALL(rt, ID3D11DeviceChild, GetDevice, G(g_out));
        CHECK(*g_out == g_dev);
        RELEASE(g_dev);
    }

    /* Vertex buffer from D3D11_SUBRESOURCE_DATA: 12 bytes for the guest, pSysMem first. */
    *bd = (D3D11_BUFFER_DESC){sizeof verts, D3D11_USAGE_IMMUTABLE, D3D11_BIND_VERTEX_BUFFER, 0u, 0u, 0u};
    init[0] = gput(verts, sizeof verts);
    init[1] = init[2] = 0u;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateBuffer, G(bd), G(init), G(g_out)));
    vb = *g_out;

    /* Constant buffer written through Map: the guest writes a shadow the bridge copies to the host mapping. */
    *bd = (D3D11_BUFFER_DESC){sizeof tint, D3D11_USAGE_DYNAMIC, D3D11_BIND_CONSTANT_BUFFER, D3D11_CPU_ACCESS_WRITE, 0u, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateBuffer, G(bd), 0u, G(g_out)));
    cb = *g_out;
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, cb, 0u, D3D11_MAP_WRITE_DISCARD, 0u, G(m)));
    CHECK(in_guest(m[0]));
    memcpy(GP(m[0]), tint, sizeof tint);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, cb, 0u);

    /* 1x1 texture with initial data, and a view of it. */
    *td = (D3D11_TEXTURE2D_DESC){1u, 1u, 1u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, {1u, 0u}, D3D11_USAGE_IMMUTABLE, D3D11_BIND_SHADER_RESOURCE, 0u, 0u};
    init[0] = gput(&(uint32_t){RGBA(255, 128, 255, 255)}, 4u);
    init[1] = 4u;
    init[2] = 4u;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture2D, G(td), G(init), G(g_out)));
    tex = *g_out;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateShaderResourceView, tex, 0u, G(g_out)));
    srv = *g_out;

    /* Shaders: D3D_SHADER_MACRO is two 4-byte pointers for the guest, and the include handler is guest code. */
    defines[0] = gstr("BLUE");
    defines[1] = gstr("0.2");
    defines[2] = defines[3] = 0u;
    include_vtbl[0] = FN_INCLUDE_OPEN;
    include_vtbl[1] = FN_INCLUDE_CLOSE;
    g_include_obj = gput(&(uint32_t){G(include_vtbl)}, 4u);
    vs_blob = compile(VS_SRC, "vs_4_0", 0u, 0u);
    ps_blob = compile(PS_SRC, "ps_4_0", G(defines), g_include_obj);
    CHECK(g_opens == 1u && g_closes == 1u);
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateVertexShader, blob_ptr(vs_blob), CALL0(vs_blob, ID3D10Blob, GetBufferSize), 0u, G(g_out)));
    vs = *g_out;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreatePixelShader, blob_ptr(ps_blob), CALL0(ps_blob, ID3D10Blob, GetBufferSize), 0u, G(g_out)));
    ps = *g_out;

    /* D3D11_INPUT_ELEMENT_DESC is 28 bytes for the guest: seven dwords, the name pointer first. */
    elems[0] = gstr("POSITION");
    elems[1] = 0u;
    elems[2] = DXGI_FORMAT_R32G32B32_FLOAT;
    elems[3] = 0u;
    elems[4] = 0u;
    elems[5] = D3D11_INPUT_PER_VERTEX_DATA;
    elems[6] = 0u;
    elems[7] = gstr("COLOR");
    elems[8] = 0u;
    elems[9] = DXGI_FORMAT_R32G32B32A32_FLOAT;
    elems[10] = 0u;
    elems[11] = 12u;
    elems[12] = D3D11_INPUT_PER_VERTEX_DATA;
    elems[13] = 0u;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateInputLayout, G(elems), 2u, blob_ptr(vs_blob), CALL0(vs_blob, ID3D10Blob, GetBufferSize), G(g_out)));
    layout = *g_out;

    /* A blob is freed when its reference count reaches 0: object, guest object and the guest's copy of the buffer. */
    {
        uint32_t copy = blob_ptr(vs_blob);
        objects = live_objects();
        CHECK(CALL0(vs_blob, IUnknown, AddRef) == 2u && RELEASE(vs_blob) == 1u);
        CHECK(live_objects() == objects && block_at(vs_blob)->live && block_at(copy)->live);
        CHECK(RELEASE(vs_blob) == 0u);
        CHECK(live_objects() == objects - 1u && !block_at(vs_blob)->live && !block_at(copy)->live);
        CHECK(host_object(vs_blob) == NULL);
    }

    /* Clear, bind through arrays of 4-byte guest pointers, draw the left half. */
    CALL(g_ctx, ID3D11DeviceContext, ClearRenderTargetView, rtv, gput(clear, sizeof clear));
    arr[0] = rtv;
    CALL(g_ctx, ID3D11DeviceContext, OMSetRenderTargets, 1u, G(arr), 0u);
    *vp = (D3D11_VIEWPORT){0.0f, 0.0f, 2.0f, 4.0f, 0.0f, 1.0f};
    CALL(g_ctx, ID3D11DeviceContext, RSSetViewports, 1u, G(vp));
    CALL(g_ctx, ID3D11DeviceContext, IASetInputLayout, layout);
    CALL(g_ctx, ID3D11DeviceContext, IASetPrimitiveTopology, D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    arr[1] = vb;
    *strides = sizeof verts[0];
    *offsets = 0u;
    CALL(g_ctx, ID3D11DeviceContext, IASetVertexBuffers, 0u, 1u, G(&arr[1]), G(strides), G(offsets));
    arr[2] = cb;
    CALL(g_ctx, ID3D11DeviceContext, VSSetConstantBuffers, 0u, 1u, G(&arr[2]));
    arr[3] = srv;
    CALL(g_ctx, ID3D11DeviceContext, PSSetShaderResources, 0u, 1u, G(&arr[3]));
    CALL(g_ctx, ID3D11DeviceContext, VSSetShader, vs, 0u, 0u);
    CALL(g_ctx, ID3D11DeviceContext, PSSetShader, ps, 0u, 0u);
    CALL(g_ctx, ID3D11DeviceContext, Draw, 3u, 0u);
    no_stop();

    /* Left: vertex colour (1, .8, 0, 1) * tint (1, .5, 1, 1) * texel (1, 128/255, 1, 1) + bias (0, 0, .2, 0)
     * = (1, .2008, .2, 1) = bytes ff 33 33 ff. Right: the clear colour (.2, .4, .6, 1) = 33 66 99 ff. */
    check_halves(rt, RGBA(255, 51, 51, 255), RGBA(51, 102, 153, 255));

    /* What is bound comes back as the guest objects that were bound, with a reference each. */
    {
        uint32_t *back = gmem(8u * 4u), *st = gmem(4u), *of = gmem(4u), *topo = gmem(4u);
        back[1] = SENTINEL;
        CALL(g_ctx, ID3D11DeviceContext, OMGetRenderTargets, 1u, G(back), 0u);
        CHECK(back[0] == rtv && back[1] == SENTINEL && RELEASE(rtv) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, IAGetVertexBuffers, 0u, 1u, G(back), G(st), G(of));
        CHECK(back[0] == vb && *st == sizeof verts[0] && *of == 0u && RELEASE(vb) == 1u);
        memset(back, 0xff, 8u * 4u);
        CALL(g_ctx, ID3D11DeviceContext, VSGetConstantBuffers, 0u, 2u, G(back));
        CHECK(back[0] == cb && back[1] == 0u && back[2] == 0xffffffffu && RELEASE(cb) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, PSGetShaderResources, 0u, 1u, G(back));
        CHECK(back[0] == srv && RELEASE(srv) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, PSGetShader, G(back), 0u, 0u);
        CHECK(back[0] == ps && RELEASE(ps) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, IAGetInputLayout, G(back));
        CHECK(back[0] == layout && RELEASE(layout) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, IAGetPrimitiveTopology, G(topo));
        CHECK(*topo == D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        *n = 1u;
        CALL(g_ctx, ID3D11DeviceContext, RSGetViewports, G(n), G(back));
        CHECK(*n == 1u && memcmp(back, vp, sizeof *vp) == 0);
    }

    /* Direct3D keeps an object the pipeline or a view uses even at reference count 0, and hands it out
     * again. The guest object stays for exactly as long: here the render target, held by its view. */
    objects = live_objects();
    CHECK(RELEASE(rt) == 0u);
    CHECK(live_objects() == objects && block_at(rt)->live && host_object(rt) != NULL);
    CALL(rtv, ID3D11View, GetResource, G(g_out));
    CHECK(*g_out == rt);
    CHECK(CALL0(rt, IUnknown, AddRef) == 2u && RELEASE(rt) == 1u);

    /* ClearDepthStencilView takes a FLOAT by value: its bits arrive as a dword. */
    {
        D3D11_TEXTURE2D_DESC *dd = gmem(sizeof *dd);
        D3D11_DEPTH_STENCIL_DESC *sd = gmem(sizeof *sd);
        uint32_t depth, dsv, dss, dss2, *ref = gmem(4u);
        *dd = (D3D11_TEXTURE2D_DESC){4u, 4u, 1u, 1u, DXGI_FORMAT_D32_FLOAT, {1u, 0u}, D3D11_USAGE_DEFAULT, D3D11_BIND_DEPTH_STENCIL, 0u, 0u};
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture2D, G(dd), 0u, G(g_out)));
        depth = *g_out;
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateDepthStencilView, depth, 0u, G(g_out)));
        dsv = *g_out;
        /* Depth 0.25, test LESS: the triangle at z 0.5 fails everywhere, so a red clear survives. */
        CALL(g_ctx, ID3D11DeviceContext, ClearDepthStencilView, dsv, D3D11_CLEAR_DEPTH, fbits(0.25f), 0u);
        memset(sd, 0, sizeof *sd);
        sd->DepthEnable = TRUE;
        sd->DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
        sd->DepthFunc = D3D11_COMPARISON_LESS;
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateDepthStencilState, G(sd), G(g_out)));
        dss = *g_out;
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateDepthStencilState, G(sd), G(g_out)));
        dss2 = *g_out; /* Direct3D returns the same state object for the same description */
        CHECK(dss2 == dss && RELEASE(dss2) == 1u);
        CALL(g_ctx, ID3D11DeviceContext, OMSetDepthStencilState, dss, 7u);
        arr[0] = rtv;
        CALL(g_ctx, ID3D11DeviceContext, OMSetRenderTargets, 1u, G(arr), dsv);
        CALL(g_ctx, ID3D11DeviceContext, ClearRenderTargetView, rtv, gput((float[4]){1.0f, 0.0f, 0.0f, 1.0f}, 16u));
        CALL(g_ctx, ID3D11DeviceContext, Draw, 3u, 0u);
        check_halves(rt, RGBA(255, 0, 0, 255), RGBA(255, 0, 0, 255));
        /* Depth 0.75: the triangle passes. */
        CALL(g_ctx, ID3D11DeviceContext, ClearDepthStencilView, dsv, D3D11_CLEAR_DEPTH, fbits(0.75f), 0u);
        CALL(g_ctx, ID3D11DeviceContext, Draw, 3u, 0u);
        check_halves(rt, RGBA(255, 51, 51, 255), RGBA(255, 0, 0, 255));
        CALL(g_ctx, ID3D11DeviceContext, OMGetDepthStencilState, G(g_out), G(ref));
        CHECK(*g_out == dss && *ref == 7u && RELEASE(dss) == 1u);
        arr[1] = 0u;
        CALL(g_ctx, ID3D11DeviceContext, OMGetRenderTargets, 1u, G(arr), G(&arr[1]));
        CHECK(arr[0] == rtv && arr[1] == dsv);
        RELEASE(rtv);
        RELEASE(dsv);
        CALL0(g_ctx, ID3D11DeviceContext, ClearState);
        CHECK(RELEASE(dss) == 0u && RELEASE(dsv) == 0u && RELEASE(depth) == 0u);
    }

    test_context(rt, rtv);

    CHECK(RELEASE(rt) == 0u && RELEASE(rtv) == 0u);
    CHECK(RELEASE(vb) == 0u && RELEASE(cb) == 0u && RELEASE(srv) == 0u && RELEASE(tex) == 0u);
    CHECK(RELEASE(vs) == 0u && RELEASE(ps) == 0u && RELEASE(layout) == 0u && RELEASE(ps_blob) == 0u);
    no_stop();
}

/* ---- Map of the other resource kinds ------------------------------------------------------------ */

static void test_maps(void) {
    D3D11_BUFFER_DESC *bd = gmem(sizeof *bd);
    D3D11_TEXTURE1D_DESC *d1 = gmem(sizeof *d1);
    D3D11_TEXTURE2D_DESC *d2 = gmem(sizeof *d2);
    uint32_t dyn, staging, t1, t2, *m = gmem(12u), *init = gmem(24u), i;
    uint8_t pattern[100];
    for (i = 0u; i < sizeof pattern; ++i) {
        pattern[i] = (uint8_t)(i * 7u + 3u);
    }

    /* Buffer: write a dynamic buffer, copy it to a staging buffer, read that. */
    *bd = (D3D11_BUFFER_DESC){sizeof pattern, D3D11_USAGE_DYNAMIC, D3D11_BIND_VERTEX_BUFFER, D3D11_CPU_ACCESS_WRITE, 0u, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateBuffer, G(bd), 0u, G(g_out)));
    dyn = *g_out;
    *bd = (D3D11_BUFFER_DESC){sizeof pattern, D3D11_USAGE_STAGING, 0u, D3D11_CPU_ACCESS_READ, 0u, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateBuffer, G(bd), 0u, G(g_out)));
    staging = *g_out;
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, dyn, 0u, D3D11_MAP_WRITE_DISCARD, 0u, G(m)));
    memcpy(GP(m[0]), pattern, 60u);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, dyn, 0u);
    /* NO_OVERWRITE keeps what the buffer holds: the first 60 bytes must survive writing the rest. */
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, dyn, 0u, D3D11_MAP_WRITE_NO_OVERWRITE, 0u, G(m)));
    CHECK(memcmp(GP(m[0]), pattern, 60u) == 0);
    memcpy(GP(m[0] + 60u), pattern + 60, 40u);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, dyn, 0u);
    CALL(g_ctx, ID3D11DeviceContext, CopyResource, staging, dyn);
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, staging, 0u, D3D11_MAP_READ, 0u, G(m)));
    CHECK(memcmp(GP(m[0]), pattern, sizeof pattern) == 0);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, staging, 0u);
    /* UpdateSubresource reads guest memory directly; a box selects bytes 10..20 of the buffer. */
    {
        D3D11_BOX *box = gmem(sizeof *box);
        *bd = (D3D11_BUFFER_DESC){sizeof pattern, D3D11_USAGE_DEFAULT, D3D11_BIND_VERTEX_BUFFER, 0u, 0u, 0u};
        init[0] = gput(pattern, sizeof pattern);
        init[1] = init[2] = 0u;
        CHECK(RELEASE(dyn) == 0u);
        CHECK_HR(CALL(g_dev, ID3D11Device, CreateBuffer, G(bd), G(init), G(g_out)));
        dyn = *g_out;
        *box = (D3D11_BOX){10u, 0u, 0u, 20u, 1u, 1u};
        CALL(g_ctx, ID3D11DeviceContext, UpdateSubresource, dyn, 0u, G(box), gput("0123456789", 10u), 0u, 0u);
        CALL(g_ctx, ID3D11DeviceContext, CopyResource, staging, dyn);
        CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, staging, 0u, D3D11_MAP_READ, 0u, G(m)));
        CHECK(memcmp(GP(m[0]), pattern, 10u) == 0 && memcmp(GP(m[0] + 10u), "0123456789", 10u) == 0);
        CHECK(memcmp(GP(m[0] + 20u), pattern + 20, 80u) == 0);
        CALL(g_ctx, ID3D11DeviceContext, Unmap, staging, 0u);
    }
    CHECK(RELEASE(dyn) == 0u && RELEASE(staging) == 0u);

    /* Texture1D, read and written through one mapping. */
    *d1 = (D3D11_TEXTURE1D_DESC){5u, 1u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, D3D11_USAGE_STAGING, 0u, D3D11_CPU_ACCESS_READ | D3D11_CPU_ACCESS_WRITE, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture1D, G(d1), 0u, G(g_out)));
    t1 = *g_out;
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, t1, 0u, D3D11_MAP_READ_WRITE, 0u, G(m)));
    CHECK(m[1] >= 20u);
    memcpy(GP(m[0]), pattern, 20u);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, t1, 0u);
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, t1, 0u, D3D11_MAP_READ, 0u, G(m)));
    CHECK(memcmp(GP(m[0]), pattern, 20u) == 0);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, t1, 0u);
    CHECK(RELEASE(t1) == 0u);

    /* Texture2D with two mip levels: initial data is an array of two 12-byte entries; each level maps to its own rows. */
    *d2 = (D3D11_TEXTURE2D_DESC){2u, 2u, 2u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, {1u, 0u}, D3D11_USAGE_STAGING, 0u, D3D11_CPU_ACCESS_READ, 0u};
    init[0] = gput(pattern, 16u);
    init[1] = 8u;
    init[2] = 16u;
    init[3] = gput(pattern + 50, 4u);
    init[4] = 4u;
    init[5] = 4u;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture2D, G(d2), G(init), G(g_out)));
    t2 = *g_out;
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, t2, 0u, D3D11_MAP_READ, 0u, G(m)));
    CHECK(m[1] >= 8u && memcmp(GP(m[0]), pattern, 8u) == 0 && memcmp(GP(m[0] + m[1]), pattern + 8, 8u) == 0);
    CHECK(block_at(m[0])->size == 2u * m[1]);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, t2, 0u);
    CHECK_HR(CALL(g_ctx, ID3D11DeviceContext, Map, t2, 1u, D3D11_MAP_READ, 0u, G(m)));
    CHECK(memcmp(GP(m[0]), pattern + 50, 4u) == 0 && block_at(m[0])->size == m[1]);
    CALL(g_ctx, ID3D11DeviceContext, Unmap, t2, 1u);
    /* A failed Map leaves nothing behind: a staging texture cannot be mapped WRITE_DISCARD. */
    i = live_maps();
    CHECK(CALL(g_ctx, ID3D11DeviceContext, Map, t2, 0u, D3D11_MAP_WRITE_DISCARD, 0u, G(m)) == (uint32_t)E_INVALIDARG);
    CHECK(live_maps() == i);
    CHECK(RELEASE(t2) == 0u);
    no_stop();
}

/* ---- the other compiler entry points ------------------------------------------------------------ */

static void test_compiler(void) {
    uint32_t code = compile(VS_SRC, "vs_4_0", 0u, 0u), text, objects = live_objects();
    CHECK_HR(ECALL(D3DDisassemble, blob_ptr(code), CALL0(code, ID3D10Blob, GetBufferSize), 0u, 0u, G(g_out)));
    text = *g_out;
    CHECK(strstr(GP(blob_ptr(text)), "vs_4_0") != NULL && strstr(GP(blob_ptr(text)), "POSITION") != NULL);
    CHECK(RELEASE(text) == 0u);

    /* A compile error: no code, a message blob the guest can read. */
    {
        uint32_t *c = gmem(4u), *e = gmem(4u), bad = gstr("float4 main() : SV_Target { return nothing; }");
        *c = 0x12345678u;
        CHECK(ECALL(D3DCompile, bad, (uint32_t)strlen(GP(bad)), gstr("bad.hlsl"), 0u, 0u, gstr("main"), gstr("ps_4_0"), 0u, 0u, G(c), G(e)) == (uint32_t)E_FAIL);
        CHECK(*c == 0u && in_guest(*e) && strstr(GP(blob_ptr(*e)), "nothing") != NULL);
        CHECK(RELEASE(*e) == 0u);
    }

    /* An IID the host compiler does not know is the host's failure. */
    CHECK(ECALL(D3DReflect, blob_ptr(code), CALL0(code, ID3D10Blob, GetBufferSize), GI(IID_ID3D11Device), G(g_out)) != 0u && *g_out == 0u);
    CHECK(RELEASE(code) == 0u && live_objects() == objects - 1u);
    no_stop();
}

/* ---- D3DReflect, used the way the game uses it ---------------------------------------------------- */

static const char REFLECT_SRC[] =
    "cbuffer Scene : register(b1) { float4 tint; float4x4 world; };\n"
    "Texture2D albedo : register(t2);\n"
    "SamplerState smooth : register(s3);\n"
    "float4 main(float4 pos : SV_Position, float2 uv : TEXCOORD0) : SV_Target { return albedo.Sample(smooth, uv) * tint + world[0]; }\n";

/* What the guest read from one reflection. */
typedef struct reflected {
    uint32_t n_buffers, n_bindings;
    struct {
        char name[32];
        uint32_t type, variables, size, flags;
    } buffer[4];
    struct {
        char name[32];
        uint32_t type, bind_point, bind_count, flags, return_type, dimension, samples;
    } binding[8];
} reflected;

static uint32_t bridge_blocks(void) {
    uint32_t i, n = 0u;
    EnterCriticalSection(&g_lock);
    for (i = 0u; i < g_nblocks; ++i) {
        n += g_blocks[i].by_bridge && g_blocks[i].live;
    }
    LeaveCriticalSection(&g_lock);
    return n;
}

/* The game's two loops over a reflection (0x11474d52 and 0x1147576c in empire.retail.dll), with the stack
 * space the game gives each description and one guard dword behind it. Every answer is compared with what
 * the host object says when asked directly. Returns the first constant buffer. */
static uint32_t reflect_as_the_game(uint32_t refl, reflected *r) {
    ID3D11ShaderReflection *host = host_object(refl);
    uint32_t *bd = gmem(20u + 4u), *rd = gmem(32u + 4u), name_at[4] = {0u}, first = 0u, i, k;
    memset(r, 0, sizeof *r);
    CHECK(host != NULL);
    /* Constant buffers 0..12 through slot 4, until there is none or its slot 0 fails. */
    for (i = 0u; i < 13u; ++i) {
        D3D11_SHADER_BUFFER_DESC hd;
        ID3D11ShaderReflectionConstantBuffer *hcb = host->lpVtbl->GetConstantBufferByIndex(host, i);
        uint32_t cb = gcall("reflection slot 4", refl, 4u, (uint32_t[]){refl, i}, 2u);
        if (cb == 0u) {
            break;
        }
        CHECK(in_guest(cb) && host_object(cb) == (void *)hcb);
        CHECK(gcall("reflection slot 4", refl, 4u, (uint32_t[]){refl, i}, 2u) == cb); /* one buffer, one pointer */
        bd[5] = 0xfeedfaceu;
        if ((int32_t)gcall("constant buffer slot 0", cb, 0u, (uint32_t[]){cb, G(bd)}, 2u) < 0) {
            CHECK(FAILED(hcb->lpVtbl->GetDesc(hcb, &hd)));
            break;
        }
        CHECK(SUCCEEDED(hcb->lpVtbl->GetDesc(hcb, &hd)) && bd[5] == 0xfeedfaceu && in_guest(bd[0]));
        CHECK(strcmp(GP(bd[0]), hd.Name) == 0 && bd[1] == (uint32_t)hd.Type && bd[2] == hd.Variables && bd[3] == hd.Size && bd[4] == hd.uFlags);
        MUST(r->n_buffers < 4u && strlen(GP(bd[0])) < 32u);
        strcpy(r->buffer[r->n_buffers].name, GP(bd[0]));
        r->buffer[r->n_buffers].type = bd[1];
        r->buffer[r->n_buffers].variables = bd[2];
        r->buffer[r->n_buffers].size = bd[3];
        r->buffer[r->n_buffers].flags = bd[4];
        name_at[r->n_buffers++] = bd[0];
        first = first != 0u ? first : cb;
    }
    /* Resource bindings from 0 through slot 6, until it fails. */
    for (i = 0u;; ++i) {
        D3D11_SHADER_INPUT_BIND_DESC hd;
        const HRESULT hhr = host->lpVtbl->GetResourceBindingDesc(host, i, &hd);
        rd[8] = 0xfeedfaceu;
        if ((int32_t)gcall("reflection slot 6", refl, 6u, (uint32_t[]){refl, i, G(rd)}, 3u) < 0) {
            CHECK(FAILED(hhr));
            break;
        }
        CHECK(SUCCEEDED(hhr) && rd[8] == 0xfeedfaceu && in_guest(rd[0]) && strcmp(GP(rd[0]), hd.Name) == 0);
        CHECK(rd[1] == (uint32_t)hd.Type && rd[2] == hd.BindPoint && rd[3] == hd.BindCount && rd[4] == hd.uFlags);
        CHECK(rd[5] == (uint32_t)hd.ReturnType && rd[6] == (uint32_t)hd.Dimension && rd[7] == hd.NumSamples);
        MUST(r->n_bindings < 8u && strlen(GP(rd[0])) < 32u);
        strcpy(r->binding[r->n_bindings].name, GP(rd[0]));
        r->binding[r->n_bindings].type = rd[1];
        r->binding[r->n_bindings].bind_point = rd[2];
        r->binding[r->n_bindings].bind_count = rd[3];
        r->binding[r->n_bindings].flags = rd[4];
        r->binding[r->n_bindings].return_type = rd[5];
        r->binding[r->n_bindings].dimension = rd[6];
        r->binding[r->n_bindings].samples = rd[7];
        ++r->n_bindings;
        /* One text, one address: a constant buffer's name is the same string under both descriptions. */
        for (k = 0u; k < r->n_buffers; ++k) {
            CHECK(strcmp(GP(rd[0]), r->buffer[k].name) != 0 || rd[0] == name_at[k]);
        }
    }
    return first;
}

/* D3DCompiler_42.dll itself, where it is installed (the x64 one; this process cannot load the game's).
 * Its reflection of the same bytecode, read through slots 4, 0 and 6 as the game reads them, must say what
 * the guest was told: that makes d3dcompiler_47 behind those slots a faithful stand-in. It also shows the
 * structures D3DCompiler_42 fills are the SDK's: nothing is written past them. */
typedef void (*slot_fn)(void);
static void compare_with_42(const void *code, size_t size, const reflected *r) {
    HMODULE dll = LoadLibraryExA("D3DCompiler_42.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    HRESULT(WINAPI * reflect)(LPCVOID, SIZE_T, REFIID, void **);
    void *obj = NULL;
    slot_fn **o;
    uint32_t i, k, clean = 1u;
    if (dll == NULL) {
        printf("D3DCompiler_42.dll is not installed: its reflection was not compared\n");
        return;
    }
    reflect = (HRESULT(WINAPI *)(LPCVOID, SIZE_T, REFIID, void **))GetProcAddress(dll, "D3DReflect");
    CHECK(reflect != NULL && SUCCEEDED(reflect(code, size, &IID_Reflection42, &obj)) && obj != NULL);
    o = obj;
    for (i = 0u; i < 13u; ++i) {
        union {
            D3D11_SHADER_BUFFER_DESC d;
            unsigned char raw[64];
        } u;
        slot_fn **cb = ((void *(*)(void *, UINT))(*o)[4])(obj, i);
        memset(&u, 0xa5, sizeof u);
        if (cb == NULL || FAILED(((HRESULT(*)(void *, void *))(*cb)[0])(cb, &u))) {
            break;
        }
        CHECK(i < r->n_buffers && strcmp(u.d.Name, r->buffer[i].name) == 0 && (uint32_t)u.d.Type == r->buffer[i].type);
        CHECK(u.d.Variables == r->buffer[i].variables && u.d.Size == r->buffer[i].size && u.d.uFlags == r->buffer[i].flags);
        for (k = sizeof u.d; k < sizeof u.raw; ++k) {
            clean &= u.raw[k] == 0xa5;
        }
    }
    CHECK(i == r->n_buffers && clean);
    for (i = 0u;; ++i) {
        union {
            D3D11_SHADER_INPUT_BIND_DESC d;
            unsigned char raw[96];
        } u;
        memset(&u, 0xa5, sizeof u);
        if (FAILED(((HRESULT(*)(void *, UINT, void *))(*o)[6])(obj, i, &u))) {
            break;
        }
        CHECK(i < r->n_bindings && strcmp(u.d.Name, r->binding[i].name) == 0 && (uint32_t)u.d.Type == r->binding[i].type);
        CHECK(u.d.BindPoint == r->binding[i].bind_point && u.d.BindCount == r->binding[i].bind_count && u.d.uFlags == r->binding[i].flags);
        CHECK((uint32_t)u.d.ReturnType == r->binding[i].return_type && (uint32_t)u.d.Dimension == r->binding[i].dimension &&
              u.d.NumSamples == r->binding[i].samples);
        for (k = sizeof u.d; k < sizeof u.raw; ++k) {
            clean &= u.raw[k] == 0xa5;
        }
    }
    CHECK(i == r->n_bindings && clean);
    CHECK(((ULONG(*)(void *))(*o)[2])(obj) == 0u);
    FreeLibrary(dll);
    printf("D3DCompiler_42.dll gives the same %u constant buffers and %u bindings through slots 4, 0 and 6\n", r->n_buffers, r->n_bindings);
}

static void test_reflection(void) {
    uint32_t code = compile(REFLECT_SRC, "ps_4_0", 0u, 0u), size = CALL0(code, ID3D10Blob, GetBufferSize), objects = live_objects();
    uint32_t refl, cb, held, i, seen = 0u;
    reflected got, again;

    /* D3DReflect with the IID the game passes. */
    CHECK_HR(ECALL(D3DReflect, blob_ptr(code), size, GI(IID_Reflection42), G(g_out)));
    refl = *g_out;
    CHECK(in_guest(refl) && live_objects() == objects + 1u);
    CHECK_HR(CALL(refl, IUnknown, QueryInterface, GI(IID_Reflection42), G(g_out)));
    CHECK(*g_out == refl && RELEASE(refl) == 1u);

    cb = reflect_as_the_game(refl, &got);
    CHECK(got.n_buffers == 1u && strcmp(got.buffer[0].name, "Scene") == 0 && got.buffer[0].type == D3D_CT_CBUFFER);
    CHECK(got.buffer[0].variables == 2u && got.buffer[0].size == 80u);
    CHECK(got.n_bindings == 3u);
    for (i = 0u; i < got.n_bindings; ++i) {
        if (strcmp(got.binding[i].name, "Scene") == 0) {
            CHECK(got.binding[i].type == D3D_SIT_CBUFFER && got.binding[i].bind_point == 1u && got.binding[i].bind_count == 1u);
            seen |= 1u;
        } else if (strcmp(got.binding[i].name, "albedo") == 0) {
            CHECK(got.binding[i].type == D3D_SIT_TEXTURE && got.binding[i].bind_point == 2u && got.binding[i].bind_count == 1u);
            CHECK(got.binding[i].dimension == D3D_SRV_DIMENSION_TEXTURE2D && got.binding[i].return_type == D3D_RETURN_TYPE_FLOAT);
            seen |= 2u;
        } else if (strcmp(got.binding[i].name, "smooth") == 0) {
            CHECK(got.binding[i].type == D3D_SIT_SAMPLER && got.binding[i].bind_point == 3u && got.binding[i].bind_count == 1u);
            seen |= 4u;
        }
    }
    CHECK(seen == 7u && cb != 0u && live_objects() > objects + 1u); /* the constant buffers are objects of the bridge */
    no_stop();

    /* What the game does not call is not known, and stops the run. */
    gcall("reflection slot 3", refl, 3u, (uint32_t[]){refl}, 0u);
    expect_stop("slot 3");
    gcall("constant buffer slot 1", cb, 1u, (uint32_t[]){cb}, 0u);
    expect_stop("slot 1");

    /* Released: its constant buffers and its strings go with it. */
    CHECK(RELEASE(refl) == 0u && live_objects() == objects && host_object(cb) == NULL && host_object(refl) == NULL);
    held = bridge_blocks();
    CHECK_HR(ECALL(D3DReflect, blob_ptr(code), size, GI(IID_Reflection42), G(g_out)));
    refl = *g_out;
    reflect_as_the_game(refl, &again);
    CHECK(memcmp(&got, &again, sizeof got) == 0 && bridge_blocks() > held);
    CHECK(RELEASE(refl) == 0u && live_objects() == objects && bridge_blocks() == held);

    compare_with_42(GP(blob_ptr(code)), size, &got);
    CHECK(RELEASE(code) == 0u && live_objects() == objects - 1u);
    no_stop();
}

/* ---- swap chain --------------------------------------------------------------------------------- */

static void test_swapchain(void) {
    HWND window = CreateWindowExA(0, "STATIC", "d3d11 bridge test", WS_POPUP, 0, 0, 64, 64, NULL, NULL, NULL, NULL);
    uint32_t hwnd32 = (uint32_t)(uintptr_t)window, *sd = gmem(60u + 4u), *level = gmem(4u), *got = gmem(4u);
    uint32_t *pswap = gmem(4u), *pdev = gmem(4u), *pctx = gmem(4u), swap, dev, ctx, back, rtv, factory, swap2, objects = live_objects();
    D3D11_TEXTURE2D_DESC *td = gmem(sizeof *td);
    CHECK(window != NULL && (HWND)(intptr_t)(int32_t)hwnd32 == window);

    /* DXGI_SWAP_CHAIN_DESC for the guest: 60 bytes, the window handle a dword at offset 44. */
    sd[0] = 16u;                         /* BufferDesc.Width */
    sd[1] = 8u;                          /* BufferDesc.Height */
    sd[2] = 60u;                         /* BufferDesc.RefreshRate.Numerator */
    sd[3] = 1u;                          /* BufferDesc.RefreshRate.Denominator */
    sd[4] = DXGI_FORMAT_R8G8B8A8_UNORM;  /* BufferDesc.Format */
    sd[5] = 0u;                          /* BufferDesc.ScanlineOrdering */
    sd[6] = 0u;                          /* BufferDesc.Scaling */
    sd[7] = 1u;                          /* SampleDesc.Count */
    sd[8] = 0u;                          /* SampleDesc.Quality */
    sd[9] = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd[10] = 1u;                         /* BufferCount */
    sd[11] = hwnd32;                     /* OutputWindow */
    sd[12] = 1u;                         /* Windowed */
    sd[13] = DXGI_SWAP_EFFECT_DISCARD;
    sd[14] = 0u;                         /* Flags */
    *level = D3D_FEATURE_LEVEL_11_0;
    CHECK_HR(ECALL(D3D11CreateDeviceAndSwapChain, 0u, D3D_DRIVER_TYPE_WARP, 0u, 0u, G(level), 1u, D3D11_SDK_VERSION, G(sd), G(pswap), G(pdev), G(got), G(pctx)));
    swap = *pswap;
    dev = *pdev;
    ctx = *pctx;
    CHECK(in_guest(swap) && in_guest(dev) && in_guest(ctx) && dev != g_dev && *got == D3D_FEATURE_LEVEL_11_0);

    /* GetDesc writes the 60-byte layout back, with the same window. */
    {
        uint32_t *gd = gmem(60u + 4u);
        gd[15] = SENTINEL;
        CHECK_HR(CALL(swap, IDXGISwapChain, GetDesc, G(gd)));
        CHECK(gd[15] == SENTINEL && gd[0] == 16u && gd[1] == 8u && gd[4] == DXGI_FORMAT_R8G8B8A8_UNORM && gd[7] == 1u);
        CHECK(gd[10] == 1u && gd[11] == hwnd32 && gd[12] == 1u && gd[13] == DXGI_SWAP_EFFECT_DISCARD);
    }
    CHECK_HR(CALL(swap, IDXGIDeviceSubObject, GetDevice, GI(IID_ID3D11Device), G(g_out)));
    CHECK(*g_out == dev);
    RELEASE(dev);

    /* The back buffer by IID, as the game asks for it; draw to it and present. */
    CHECK_HR(CALL(swap, IDXGISwapChain, GetBuffer, 0u, GI(IID_ID3D11Texture2D), G(g_out)));
    back = *g_out;
    CALL(back, ID3D11Texture2D, GetDesc, G(td));
    CHECK(td->Width == 16u && td->Height == 8u && td->Format == DXGI_FORMAT_R8G8B8A8_UNORM);
    CHECK_HR(CALL(dev, ID3D11Device, CreateRenderTargetView, back, 0u, G(g_out)));
    rtv = *g_out;
    CALL(ctx, ID3D11DeviceContext, ClearRenderTargetView, rtv, gput((float[4]){0.0f, 1.0f, 0.0f, 1.0f}, 16u));
    CHECK((int32_t)CALL(swap, IDXGISwapChain, Present, 0u, 0u) >= 0);
    CHECK_HR(CALL(swap, IDXGISwapChain, GetLastPresentCount, G(got)));
    CHECK(*got >= 1u);

    /* ResizeBuffers needs every reference to the back buffer gone: the bridge holds none of its own. */
    CHECK(RELEASE(rtv) == 0u && RELEASE(back) == 0u);
    CALL0(ctx, ID3D11DeviceContext, ClearState);
    CALL0(ctx, ID3D11DeviceContext, Flush);
    CHECK_HR(CALL(swap, IDXGISwapChain, ResizeBuffers, 1u, 32u, 24u, DXGI_FORMAT_UNKNOWN, 0u));
    CHECK_HR(CALL(swap, IDXGISwapChain, GetBuffer, 0u, GI(IID_ID3D11Texture2D), G(g_out)));
    back = *g_out;
    CALL(back, ID3D11Texture2D, GetDesc, G(td));
    CHECK(td->Width == 32u && td->Height == 24u);
    CHECK(RELEASE(back) == 0u);

    /* The factory that owns the swap chain: window association, and a second swap chain made by method. */
    CHECK_HR(CALL(swap, IDXGIObject, GetParent, GI(IID_IDXGIFactory1), G(g_out)));
    factory = *g_out;
    CHECK_HR(CALL(factory, IDXGIFactory, MakeWindowAssociation, hwnd32, DXGI_MWA_NO_ALT_ENTER));
    *got = SENTINEL;
    CHECK_HR(CALL(factory, IDXGIFactory, GetWindowAssociation, G(got)));
    {
        /* Whatever DXGI answers, the guest gets the low 32 bits of it in one dword. */
        HWND host_answer = (HWND)(intptr_t)-1;
        CHECK(SUCCEEDED(IDXGIFactory_GetWindowAssociation((IDXGIFactory *)host_object(factory), &host_answer)));
        printf("window association: %08x (window %08x)\n", *got, hwnd32);
        CHECK(*got == (uint32_t)(uintptr_t)host_answer && (HWND)(intptr_t)(int32_t)*got == host_answer);
    }
    {
        HWND second = CreateWindowExA(0, "STATIC", "d3d11 bridge test 2", WS_POPUP, 0, 0, 64, 64, NULL, NULL, NULL, NULL);
        sd[11] = (uint32_t)(uintptr_t)second;
        sd[15] = SENTINEL;
        CHECK_HR(CALL(factory, IDXGIFactory, CreateSwapChain, dev, G(sd), G(g_out)));
        swap2 = *g_out;
        CHECK(swap2 != swap && sd[15] == SENTINEL);
        CHECK_HR(CALL(swap2, IDXGISwapChain, GetFullscreenState, G(got), G(g_out)));
        CHECK(*got == 0u && *g_out == 0u);
        CHECK(RELEASE(swap2) == 0u);
        DestroyWindow(second);
    }
    RELEASE(factory);
    CHECK(RELEASE(swap) == 0u);
    CALL0(ctx, ID3D11DeviceContext, ClearState);
    CALL0(ctx, ID3D11DeviceContext, Flush);
    RELEASE(ctx);
    CHECK(RELEASE(dev) == 0u);
    DestroyWindow(window);
    CHECK(live_objects() == objects);
    no_stop();
}

/* ---- several guest threads ---------------------------------------------------------------------- */

#define THREADS 4u
#define ROUNDS 150u
static uint32_t g_shared_state, g_first_vtbl[THREADS];
static HANDLE g_start;

/* Device methods are free-threaded in Direct3D 11. Each thread creates and releases its own buffers,
 * asks for a state every thread shares and for states that come and go. */
static DWORD WINAPI thread_main(void *param) {
    const uint32_t id = (uint32_t)(uintptr_t)param;
    D3D11_BUFFER_DESC *bd = gmem(sizeof *bd);
    D3D11_DEPTH_STENCIL_DESC *sd = gmem(sizeof *sd), *sd2 = gmem(sizeof *sd2);
    uint32_t *out = gmem(4u), *init = gmem(12u), *data = gmem(64u), i;
    *bd = (D3D11_BUFFER_DESC){64u, D3D11_USAGE_DEFAULT, D3D11_BIND_VERTEX_BUFFER, 0u, 0u, 0u};
    init[0] = G(data);
    /* No class linkage has been made yet, so its guest vtable does not exist: every thread needs it now. */
    WaitForSingleObject(g_start, INFINITE);
    MUST(CALL(g_dev, ID3D11Device, CreateClassLinkage, G(out)) == 0u);
    g_first_vtbl[id] = rd32(*out);
    MUST(RELEASE(*out) == 0u);
    for (i = 0u; i < ROUNDS; ++i) {
        uint32_t buffer, state;
        MUST(CALL(g_dev, ID3D11Device, CreateBuffer, G(bd), G(init), G(out)) == 0u);
        buffer = *out;
        MUST(in_guest(buffer));
        CALL(buffer, ID3D11DeviceChild, GetDevice, G(out));
        MUST(*out == g_dev);
        RELEASE(g_dev);
        MUST(RELEASE(buffer) == 0u);

        /* The state the main thread holds: one host object, so one guest object for every thread. */
        memset(sd, 0, sizeof *sd);
        sd->DepthEnable = TRUE;
        sd->DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
        sd->DepthFunc = D3D11_COMPARISON_GREATER;
        MUST(CALL(g_dev, ID3D11Device, CreateDepthStencilState, G(sd), G(out)) == 0u);
        MUST(*out == g_shared_state);
        MUST(RELEASE(g_shared_state) >= 1u);

        /* States no one holds for long: the threads race to create, share and release them. */
        sd->DepthFunc = (D3D11_COMPARISON_FUNC)(1u + (i + id) % 5u); /* NEVER .. NOT_EQUAL: not GREATER */
        MUST(CALL(g_dev, ID3D11Device, CreateDepthStencilState, G(sd), G(out)) == 0u);
        state = *out;
        CALL(state, ID3D11DepthStencilState, GetDesc, G(sd2));
        MUST(sd2->DepthFunc == sd->DepthFunc);
        RELEASE(state);
    }
    return i;
}

static void test_threads(void) {
    D3D11_DEPTH_STENCIL_DESC *sd = gmem(sizeof *sd);
    HANDLE threads[THREADS];
    uint32_t i, objects;
    CALL0(g_ctx, ID3D11DeviceContext, Flush);
    objects = live_objects();
    memset(sd, 0, sizeof *sd);
    sd->DepthEnable = TRUE;
    sd->DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ALL;
    sd->DepthFunc = D3D11_COMPARISON_GREATER;
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateDepthStencilState, G(sd), G(g_out)));
    g_shared_state = *g_out;
    g_start = CreateEventA(NULL, TRUE, FALSE, NULL);
    CHECK(g_start != NULL);
    for (i = 0u; i < THREADS; ++i) {
        threads[i] = CreateThread(NULL, 0, thread_main, (void *)(uintptr_t)i, 0, NULL);
        CHECK(threads[i] != NULL);
    }
    SetEvent(g_start);
    CHECK(WaitForMultipleObjects(THREADS, threads, TRUE, 120000) == WAIT_OBJECT_0);
    for (i = 0u; i < THREADS; ++i) {
        DWORD rounds = 0;
        CHECK(GetExitCodeThread(threads[i], &rounds) && rounds == ROUNDS);
        CHECK(g_first_vtbl[i] == g_first_vtbl[0]); /* one vtable, whichever thread built it */
        CloseHandle(threads[i]);
    }
    CloseHandle(g_start);
    CHECK(RELEASE(g_shared_state) == 0u);
    CALL0(g_ctx, ID3D11DeviceContext, Flush);
    CHECK(live_objects() == objects && live_maps() == 0u);
    no_stop();
}

/* ---- what must stop the run --------------------------------------------------------------------- */

static void test_stops(void) {
    D3D11_TEXTURE2D_DESC *td = gmem(sizeof *td);
    uint32_t tex, *junk = gmem(16u), objects;
    *td = (D3D11_TEXTURE2D_DESC){4u, 4u, 1u, 1u, DXGI_FORMAT_R8G8B8A8_UNORM, {1u, 0u}, D3D11_USAGE_DEFAULT, D3D11_BIND_RENDER_TARGET, 0u, 0u};
    CHECK_HR(CALL(g_dev, ID3D11Device, CreateTexture2D, G(td), 0u, G(g_out)));
    tex = *g_out;
    objects = live_objects();

    /* Guest memory that is not a bridged object. */
    CALL(g_ctx, ID3D11DeviceContext, ClearRenderTargetView, G(junk), G(junk));
    expect_stop("not a bridged Direct3D object");
    /* A bridged object of the wrong interface. */
    CALL(g_ctx, ID3D11DeviceContext, ClearRenderTargetView, tex, G(junk));
    expect_stop("ID3D11RenderTargetView is expected");
    /* An interface the host has and the bridge has not: named, and the reference is not leaked. */
    CHECK(CALL(tex, IUnknown, QueryInterface, GI(IID_IDXGISurface), G(g_out)) == (uint32_t)E_NOINTERFACE && *g_out == 0u);
    expect_stop("{cafcb56c-6ac3-4889-bf47-9e23bbd260ec}");
    CHECK(CALL0(tex, IUnknown, AddRef) == 2u && RELEASE(tex) == 1u);
    /* A guest IUnknown cannot be stored on a host object; clearing one is fine. */
    CALL(tex, ID3D11DeviceChild, SetPrivateDataInterface, GI(IID_IDXGISurface), G(junk));
    expect_stop("SetPrivateDataInterface");
    CHECK_HR(CALL(tex, ID3D11DeviceChild, SetPrivateDataInterface, GI(IID_IDXGISurface), 0u));
    /* Private data bytes round-trip. */
    {
        uint32_t *size = gmem(4u), *data = gmem(8u);
        CHECK_HR(CALL(tex, ID3D11DeviceChild, SetPrivateData, GI(IID_IDXGISurface), 5u, gstr("name")));
        *size = 8u;
        CHECK_HR(CALL(tex, ID3D11DeviceChild, GetPrivateData, GI(IID_IDXGISurface), G(size), G(data)));
        CHECK(*size == 5u && strcmp((char *)data, "name") == 0);
    }
    /* A FLOAT return value. */
    CALL(g_ctx, ID3D11DeviceContext, GetResourceMinLOD, tex);
    expect_stop("GetResourceMinLOD");
#ifndef TEST_LIVE
    /* An ID3DInclude without call_guest is refused before the compiler runs. */
    {
        d3d11_bridge_host_t host = {galloc, gfree, register_method, stop, NULL};
        bridge_init(&host);
        CHECK(ECALL(D3DCompile, gstr("x"), 1u, 0u, 0u, g_include_obj, gstr("main"), gstr("ps_4_0"), 0u, 0u, G(g_out), 0u) == (uint32_t)E_NOTIMPL);
        expect_stop("call_guest");
        host.call_guest = call_guest;
        bridge_init(&host);
    }
#endif
    CHECK(live_objects() == objects);
    CHECK(RELEASE(tex) == 0u);
}

/* ---- every reference released: nothing of the bridge's is left but the vtables ------------------- */

static void test_teardown(void) {
    uint32_t i, vtables = 0u;
    CALL0(g_ctx, ID3D11DeviceContext, ClearState);
    CALL0(g_ctx, ID3D11DeviceContext, Flush);
    RELEASE(g_ctx);
    CHECK(RELEASE(g_dev) == 0u);
    CHECK(live_objects() == 0u && live_maps() == 0u);
    CHECK(host_object(g_dev) == NULL && host_object(g_ctx) == NULL);
    for (i = 0u; i < g_nblocks; ++i) {
        const block *b = &g_blocks[i];
        if (b->by_bridge && b->live) {
            uint32_t k;
            for (k = 0u; k < g_nseen && g_seen_vtbl[k] != b->addr; ++k) {
            }
            if (k == g_nseen) {
                printf("FAIL: the bridge still holds %u bytes of guest memory at %08x\n", b->size, b->addr);
                exit(1);
            }
            ++vtables;
        }
    }
    CHECK(vtables == g_nseen);
    printf("%u guest vtables, %u methods registered (%u asked for again)\n", vtables, g_nthunks, g_asked_again);
    no_stop();
}

int main(void) {
    static const uintptr_t bases[] = {0x20000000u, 0x30000000u, 0x40000000u, 0x50000000u, 0x60000000u};
    void *mem = NULL;
    size_t i;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (i = 0u; mem == NULL && i < sizeof bases / sizeof bases[0]; ++i) {
        mem = VirtualAlloc((void *)bases[i], GUEST_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    CHECK(mem != NULL && (uintptr_t)mem + GUEST_SIZE <= 0x100000000ull);
    g_lo = g_top = (uint32_t)(uintptr_t)mem;
    g_hi = g_lo + GUEST_SIZE;
    InitializeCriticalSection(&g_lock);
#ifndef TEST_LIVE /* inside live_main.c the first call into the bridge initialises it */
    {
        d3d11_bridge_host_t host = {galloc, gfree, register_method, stop, call_guest};
        bridge_init(&host);
    }
#endif
    g_out = gmem(4u);
    test_dxgi();
    test_device();
    test_render();
    test_maps();
    test_compiler();
    test_reflection();
    test_swapchain();
    test_threads();
    test_stops();
    test_teardown();
#ifdef TEST_LIVE
    printf("d3d11 bridge, included as in live_main.c (%u shim rows): ", (unsigned)(sizeof g_shims / sizeof g_shims[0]));
#else
    printf("d3d11 bridge, linked: ");
#endif
    printf("%u checks passed over %u calls through guest vtables\n", g_checks, g_calls);
    return 0;
}
