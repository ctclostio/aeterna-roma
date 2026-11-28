/*
 * shim_modules.h - the runner's shim modules, in one place.
 *
 * live.exe is built from live_main.c alone, and a shim for the 32-bit game is
 * a function of that file. A subsystem (Direct3D, and after it audio, input,
 * Steam, windowing) does not have to be written inside it: it can be a
 * module, a .c file that is included into the runner and tested without it.
 * live_main.c then has two lines for all modules together, and adding a
 * module changes this file only:
 *
 *     #include "shim_modules.h"        above g_shims, in place of the lines
 *                                      that include d3d11_bridge.c
 *     static const shim g_shims[] = {
 *         ...
 *         LIVE_SHIM_MODULE_ROWS        no comma after it; in place of
 *                                      D3D11_BRIDGE_SHIMS
 *     };
 *
 * What a module is (d3d11_bridge.c is the first; its section 7 is the part
 * that touches the runner):
 *
 *   - One .c file with one rows macro of shim initialisers, each
 *     {dll, name, nargs, fn, flags}: imports by the DLL the game names, COM
 *     slots as {"com", "<interface>#<slot>", ...}.
 *   - It uses the runner through a short list of names it states at the top
 *     (the bridge: stop, galloc, gfree, import_addr, guest_call,
 *     write_allowed), never the runner's other statics. The same list is what
 *     its test supplies.
 *   - It has a test of its own that includes it the way the runner does, with
 *     stand-ins for those names (test_d3d11_bridge.c, built with TEST_LIVE),
 *     so it is checked without the game and without the lifted functions.
 *   - It is tried in the real runner before it is merged:
 *     scripts/lift/live_private.py builds a live.exe from a copy of
 *     live_main.c with this checkout's modules beside it, and runs it next to
 *     the working build.
 *
 * A module's functions have the type of a shim, uint32_t f(lift_ctx *c,
 * const uint32_t *a): a[0] is the first dword the guest pushed, the result
 * goes to EAX, the runner removes nargs dwords.
 */
#ifndef ROME2_SHIM_MODULES_H
#define ROME2_SHIM_MODULES_H

/* Direct3D 11, DXGI, D3DCompiler and the game's four D3DX11 imports. */
#define D3D11_BRIDGE_LIVE
#include "d3d11_bridge.c"

#define LIVE_SHIM_MODULE_ROWS D3D11_BRIDGE_SHIMS

#endif /* ROME2_SHIM_MODULES_H */
