#pragma once
/* Ghidra decompiler type compatibility layer for x64 MSVC */
#include <stdint.h>
#include <stddef.h>

typedef uint8_t  undefined1; typedef uint16_t undefined2;
typedef uint32_t undefined4; typedef uint64_t undefined8;
typedef uint8_t  byte;       typedef uint16_t ushort;
typedef uint32_t uint;       typedef uint8_t  ubyte;
typedef int      undefined4_signed_hack_dummy;
/* Exact storage only: MSVC long double is not x87 extended precision.
 * Numeric operations need an explicit recovered conversion. */
typedef struct { uint8_t bytes[10]; } float10;

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
/* Exact guest storage extents, not native scalar arithmetic types. */
typedef struct { uint8_t bytes[3]; } undefined3;
typedef struct { uint8_t bytes[5]; } undefined5;
typedef struct { uint8_t bytes[6]; } undefined6;
typedef struct { uint8_t bytes[7]; } undefined7;
/* The historical syntax island uses MSVC's default C dialect. */
typedef char rome2_storage_u3_must_be_3[(sizeof(undefined3) == 3) ? 1 : -1];
typedef char rome2_storage_u5_must_be_5[(sizeof(undefined5) == 5) ? 1 : -1];
typedef char rome2_storage_u6_must_be_6[(sizeof(undefined6) == 6) ? 1 : -1];
typedef char rome2_storage_u7_must_be_7[(sizeof(undefined7) == 7) ? 1 : -1];
typedef char rome2_storage_f10_must_be_10[(sizeof(float10) == 10) ? 1 : -1];
