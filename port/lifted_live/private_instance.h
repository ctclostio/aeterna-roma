/*
 * private_instance.h - force-included (/FI) into a copy of live_main.c by
 * scripts/lift/live_private.py; never part of the working build.
 *
 * The game allows one instance of itself: it creates a named mutex and leaves
 * when the name already exists. A development build run beside the working
 * one (a profile, a test of a shim module) must not be that second instance,
 * and must not keep the working build from starting either. Here every mutex
 * name the guest asks for gets this process's id in front, so two live.exe do
 * not see each other.
 */
#ifndef ROME2_PRIVATE_INSTANCE_H
#define ROME2_PRIVATE_INSTANCE_H

/* As live_main.c defines them before its own include of windows.h. */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#define CINTERFACE
#include <windows.h>

#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* "Global\name" stays in its namespace: the id goes after the last backslash. */
static HANDLE private_CreateMutexA(LPSECURITY_ATTRIBUTES sa, BOOL owner, LPCSTR name) {
    char own[MAX_PATH + 16];
    const char *leaf = name != NULL ? strrchr(name, '\\') : NULL;
    if (name == NULL) {
        return CreateMutexA(sa, owner, NULL);
    }
    leaf = leaf != NULL ? leaf + 1 : name;
    snprintf(own, sizeof own, "%.*s%lu-%s", (int)(leaf - name), name, GetCurrentProcessId(), leaf);
    return CreateMutexA(sa, owner, own);
}
static HANDLE private_CreateMutexW(LPSECURITY_ATTRIBUTES sa, BOOL owner, LPCWSTR name) {
    wchar_t own[MAX_PATH + 16];
    const wchar_t *leaf = name != NULL ? wcsrchr(name, L'\\') : NULL;
    if (name == NULL) {
        return CreateMutexW(sa, owner, NULL);
    }
    leaf = leaf != NULL ? leaf + 1 : name;
    _snwprintf(own, sizeof own / sizeof own[0], L"%.*s%lu-%s", (int)(leaf - name), name, GetCurrentProcessId(), leaf);
    own[sizeof own / sizeof own[0] - 1u] = L'\0';
    return CreateMutexW(sa, owner, own);
}
#define CreateMutexA private_CreateMutexA
#define CreateMutexW private_CreateMutexW

#endif /* ROME2_PRIVATE_INSTANCE_H */
