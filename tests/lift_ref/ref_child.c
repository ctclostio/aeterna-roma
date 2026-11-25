/*
 * ref_child.c - inert 32-bit process the reference debugger hijacks.
 *
 * ref_dbg.exe starts this image under a debugger, takes the initial thread at
 * the loader breakpoint (before this entry point is reached) and from then on
 * only runs guest code on it. The process never executes its own code again;
 * if it is ever started outside the debugger it exits at once.
 *
 * Linked without the CRT, at a fixed low base, with kernel32 as the only
 * import, so its address space stays clear of the guest image and arena.
 * See docs/lifted_tier.md.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

void __stdcall ref_child_entry(void) {
    ExitProcess(0u);
}
