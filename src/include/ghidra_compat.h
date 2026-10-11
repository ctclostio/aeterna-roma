#pragma once
/* Ghidra decompiler type compatibility layer for x64 MSVC */
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  undefined1; typedef uint16_t undefined2;
typedef uint32_t undefined4; typedef uint64_t undefined8;
typedef uint8_t  byte;       typedef uint16_t ushort;
typedef uint32_t uint;       typedef uint8_t  ubyte;
typedef int      undefined4_signed_hack_dummy;
/* x87 extended precision (Ghidra float10); MSVC has no 80-bit long double */
typedef long double float10;

/* calling conventions collapse under MS x64 */
#define __thiscall
#define __stdcall
#define __cdecl
#define __fastcall

/* Ghidra casts through these freely */
typedef union {
  undefined1 u1; undefined2 u2; undefined4 u4; undefined8 u8;
  void *p; float f; double d;
} any_value;

/* additional Ghidra integer flavors */
typedef int64_t longlong;
typedef uint64_t ulonglong;
/* odd-size Ghidra ints */
typedef uint32_t undefined3;
typedef uint32_t undefined5;
typedef uint32_t undefined6;
typedef uint64_t undefined7;
