/*
 * d3d11_bridge.h - Direct3D 11, DXGI and D3DCompiler for a 32-bit guest on a
 * 64-bit host.
 *
 * The guest is 32-bit code whose memory is identity-mapped in the low 4 GiB
 * of the host process: guest address A is host pointer (void *)(uintptr_t)A.
 * A host COM interface pointer is 8 bytes and its vtable holds 64-bit code,
 * so the guest cannot hold or call one. The bridge gives the guest an object
 * in guest memory instead (one dword, the address of a guest vtable) and
 * implements every vtable slot as a host function that converts the 32-bit
 * arguments, calls the real interface and converts the results back.
 *
 * The bridge uses nothing of the runner but the callbacks below.
 *
 * In live_main.c. live.exe is built from that one source, so the bridge is
 * included into it; d3d11_bridge.c then supplies the callbacks itself, from
 * the runner's galloc, gfree, stop, import_addr and guest_call:
 *
 *     #define D3D11_BRIDGE_LIVE
 *     #include "d3d11_bridge.c"         above g_shims
 *
 *     static const shim g_shims[] = {
 *         ...
 *         D3D11_BRIDGE_SHIMS            no comma after it
 *     };
 *
 * Nothing else changes, in live_main.c or in the build. Anywhere else, compile
 * d3d11_bridge.c as a source of its own and call d3d11_bridge_init.
 *
 * Calling convention. A bridge function receives the dwords the guest pushed,
 * a[0] first (for a method a[0] is the object), and returns the value for
 * EAX. The guest's functions are stdcall: the runner removes nargs dwords
 * after the call. A FLOAT argument arrives as its bit pattern.
 *
 * Object lifetime. A guest object stands for one host interface pointer, and
 * the same host pointer always gives the same guest object, so pointer
 * comparisons in the guest behave as they do natively. The bridge holds no
 * reference of its own: AddRef and Release go straight to the host object.
 * The guest object is freed when the host object is destroyed (the bridge is
 * told through a private-data interface the host object releases), or, for
 * the few objects without private data, when Release returns 0. Direct3D 11
 * keeps an object alive while the pipeline or a view uses it even at
 * reference count 0, and can hand it out again: the guest object stays valid
 * for exactly as long as the host pointer does.
 *
 * Threads. Every function here may be called from any guest thread, with or
 * without a lock of the runner's held. The callbacks are only called from
 * inside a bridge function the runner called, on that thread, never from a
 * thread Direct3D owns, and never while the bridge holds its own lock: they
 * may take any lock the runner has. No lock is held across call_guest either.
 *
 * Shader reflection. The game asks D3DReflect for D3DCompiler_42's
 * ID3D11ShaderReflection, which no SDK header describes any more. The object
 * the guest gets has the three methods the game calls on it (the constant
 * buffer at an index, that buffer's description, a resource binding's
 * description), answered by d3dcompiler_47; d3d11_bridge.c lists the call
 * sites they are taken from.
 *
 * Not bridged, and stopping the run when reached: the other slots of that
 * reflection interface, IDXGISurface, storing a guest IUnknown as private
 * data, software adapters, and ID3D11DeviceContext::GetResourceMinLOD.
 */
#ifndef ROME2_D3D11_BRIDGE_H
#define ROME2_D3D11_BRIDGE_H

#include <stdint.h>

/* The runner's CPU state of the calling guest thread. The bridge never looks inside: it hands the pointer
 * it was called with to call_guest. With this parameter a bridge function has the type of a live_main.c
 * shim. A caller without such a state passes NULL. */
struct lift_ctx;
typedef uint32_t (*d3d11_bridge_fn)(struct lift_ctx *c, const uint32_t *a);

typedef struct d3d11_bridge_host {
    /* Guest heap. galloc returns a guest address, 0 when memory is exhausted. */
    uint32_t (*galloc)(uint32_t size, int zero);
    void (*gfree)(uint32_t p);
    /* Makes fn callable by the guest as a stdcall function of nargs dwords and returns its guest address, 0
     * when it cannot. Called for each (interface that declares the method, vtable slot) when the interface is
     * first used; two threads doing that at once both call, and must be given the same address. */
    uint32_t (*register_method)(const char *iface_name, uint32_t method_idx, uint32_t nargs, d3d11_bridge_fn fn);
    /* Ends the run with a message: something the bridge cannot do faithfully. May return. */
    void (*stop)(const char *fmt, ...);
    /* Optional: calls the guest stdcall function at entry and returns its EAX. Only D3DCompile with an
     * ID3DInclude the guest implements needs it; without it that call stops the run. */
    uint32_t (*call_guest)(struct lift_ctx *c, uint32_t entry, uint32_t nargs, const uint32_t *args);
} d3d11_bridge_host_t;

/* Call once, before any other function. The struct is copied. Included into live_main.c the bridge calls
 * this itself, at the first call into it. */
void d3d11_bridge_init(const d3d11_bridge_host_t *host);

/* The entry points the guest imports or finds with GetProcAddress. */
typedef struct d3d11_bridge_export {
    const char *dll;  /* the DLL the 32-bit game names */
    const char *name;
    uint32_t nargs;
    d3d11_bridge_fn fn;
} d3d11_bridge_export_t;
extern const d3d11_bridge_export_t d3d11_bridge_exports[];
extern const uint32_t d3d11_bridge_export_count;

uint32_t d3d11_bridge_CreateDXGIFactory(struct lift_ctx *c, const uint32_t *a);
uint32_t d3d11_bridge_CreateDXGIFactory1(struct lift_ctx *c, const uint32_t *a);
uint32_t d3d11_bridge_D3D11CreateDevice(struct lift_ctx *c, const uint32_t *a);
uint32_t d3d11_bridge_D3D11CreateDeviceAndSwapChain(struct lift_ctx *c, const uint32_t *a);
uint32_t d3d11_bridge_D3DCompile(struct lift_ctx *c, const uint32_t *a);
uint32_t d3d11_bridge_D3DReflect(struct lift_ctx *c, const uint32_t *a);
uint32_t d3d11_bridge_D3DDisassemble(struct lift_ctx *c, const uint32_t *a);

/* For other shims that take or return Direct3D objects (D3DX11, for one).
 * host_object: the host interface pointer behind a guest object, NULL when guest is not one.
 * wrap: the guest object for a host interface pointer of the interface iid (a GUID); takes over one
 * reference, which becomes the guest's. 0 when the interface has no bridge or guest memory is exhausted. */
void *d3d11_bridge_host_object(uint32_t guest);
uint32_t d3d11_bridge_wrap(void *host_iface, const void *iid);

/* Number of guest objects alive, and of resources currently mapped. */
uint32_t d3d11_bridge_live_objects(void);
uint32_t d3d11_bridge_live_maps(void);

#endif /* ROME2_D3D11_BRIDGE_H */
