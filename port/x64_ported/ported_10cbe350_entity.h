#ifndef ROME2_PORTED_10CBE350_ENTITY_H
#define ROME2_PORTED_10CBE350_ENTITY_H

/*
 * ported_10cbe350_entity - Phase 4.2 reconstruction of the battle entity
 * dispatcher record constructor recovered from empire.retail.dll 0x10cbe350.
 *
 * Recovered shape
 * ---------------
 *   x86 entry : FUN_10cbe350 @ 0x10cbe350, body 0x10cbe350..0x10cbe54f (512 bytes)
 *   prototype : __thiscall, ECX = this, RET 0x4c  ->  19 stack words + ECX,
 *               returns EAX = this (MOV EAX,EDI at 0x10cbe545)
 *   callers   : 0x100e39c0 @ 0x100e42c1 (settlement battle benchmark harness)
 *               0x10745af0 @ 0x107464a9
 *               0x10ec7f40 @ 0x10ec8813
 *               0x11056e10 @ 0x1105721a
 *               0x11058850 @ 0x110589d5
 *               0x10f7a1a0 @ 0x10f7aa45
 *
 * Identity anchors
 * ----------------
 *   0x1174e298 "auto_generator_input"  - the name stored at this+0x010
 *   0x1174e08c "Climate Conditions"    - the nested record at this+0x070
 *   0x1173dad0 ""                      - the throwaway scratch string
 *   0x45000000 (2048.0f) written twice - the activation radius at +0x54/+0x58
 *   3 written at this+0x05c            - the default spawn point count
 *
 * Dispatch tables (installed twice, base first then derived):
 *   this+0x000 0x1174bbb0 -> 0x1174e12c
 *   this+0x004 0x1174bbd4 -> 0x1174e150
 *   this+0x008 0x1174bbfc -> 0x1174e178
 *
 * The Win64 ABI cannot reproduce nineteen independent stack words, so the
 * constructor takes a rome2_entity_ctor_args record.  Each member documents
 * the x86 stack index it replaces (arg N lives at E0+4+4*N).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ported_10145c70_unitcard.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_10CBE350_ENTITY_PC   UINT32_C(0x10cbe350)

/* Largest offset the constructor writes is this+0xe4. */
#define ROME2_ENTITY_RECORD_SIZE_X86    0xE8u
#define ROME2_ENTITY_RECORD_SIZE        0x120u

/*
 * Stride of one entry in the FUN_100f1700 string vector built at this+0x0bc.
 *
 * The retail image copies `count` 12-byte string records in a 12-byte-strided
 * loop (ADD ESI,0xc / ADD EBX,0xc at 0x10cbe4e0 and 0x10cbe4e3) and allocates
 * count*12 at 0x10cbe4a4.  On x64 each rome2_recovered_str is sixteen bytes, so
 * the host block is sized with sizeof(rome2_recovered_str); the loop still runs
 * exactly `count` times, which is what the comparison chain pins.
 */
#define ROME2_ENTITY_ITEM_STRIDE_X86     12u
#define ROME2_ENTITY_ITEM_STRIDE         16u
/* Admitted counts must also fit the original unsigned count * 12 request. */
#define ROME2_ENTITY_MAX_ITEM_COUNT      (UINT32_MAX / ROME2_ENTITY_ITEM_STRIDE_X86)

#define ROME2_ENTITY_NAME               "auto_generator_input"
#define ROME2_ENTITY_CLIMATE_NAME       "Climate Conditions"
#define ROME2_ENTITY_SCRATCH_NAME       ""

/* 0x1173dad0 is a NUL byte in the image, so the scratch string is empty. */
#define ROME2_ENTITY_SCRATCH_LENGTH     0

/* MOV dword [EDI+0x54],0x45000000 / [EDI+0x58],0x45000000 at 0x10cbe40f. */
#define ROME2_ENTITY_ACTIVATION_RADIUS  2048.0f

/* MOV dword [EDI+0x5c],3 at 0x10cbe422. */
#define ROME2_ENTITY_DEFAULT_POINT_COUNT UINT32_C(3)

/* Base dispatch triple installed before the derived triple overwrites it. */
#define ROME2_ENTITY_BASE_DISPATCH0     UINT32_C(0x1174bbb0)
#define ROME2_ENTITY_BASE_DISPATCH1     UINT32_C(0x1174bbd4)
#define ROME2_ENTITY_BASE_DISPATCH2     UINT32_C(0x1174bbfc)

/* Derived dispatch triple installed at 0x10cbe39a .. 0x10cbe3a7. */
#define ROME2_ENTITY_DISPATCH0          UINT32_C(0x1174e12c)
#define ROME2_ENTITY_DISPATCH1          UINT32_C(0x1174e150)
#define ROME2_ENTITY_DISPATCH2          UINT32_C(0x1174e178)
#define ROME2_ENTITY_DISPATCH3          UINT32_C(0)

/* Climate record dispatch triple (FUN_10cc1a10, entered at this+0x070). */
#define ROME2_CLIMATE_BASE_DISPATCH0    UINT32_C(0x1174bb50)
#define ROME2_CLIMATE_BASE_DISPATCH1    UINT32_C(0x1174bb74)
#define ROME2_CLIMATE_DISPATCH0         UINT32_C(0x1174dfec)
#define ROME2_CLIMATE_DISPATCH1         UINT32_C(0x1174e010)

#define ROME2_CLIMATE_RECORD_SIZE_X86   0x30u
#define ROME2_CLIMATE_RECORD_SIZE       0x40u
#define ROME2_ENTITY_DESCRIPTOR_SIZE_X86 12u
#define ROME2_ENTITY_DESCRIPTOR_SIZE     16u

/*
 * Two independent inputs: arg09 supplies the origin pair at 0x10cbe3b3;
 * arg10 supplies the vector descriptor at 0x10cbe453.  Only the descriptor's
 * +4 count and +8 item pointer are read (0x10cbe486 and 0x10cbe4c5).
 */
typedef struct rome2_entity_origin {
    uint32_t x;
    uint32_t y;
} rome2_entity_origin;

typedef struct rome2_entity_descriptor {
    uint32_t reserved_00;                    /* +0 not read             */
    uint32_t item_count;                     /* +4 -> this+0x0b4/0x0b8  */
    const rome2_recovered_str *items;        /* +8 -> this+0x0bc source  */
} rome2_entity_descriptor;

/* Nested "Climate Conditions" record constructed by FUN_10cc1a10. */
typedef struct rome2_climate_record {
    uint32_t dispatch0;             /* +0x00 base then derived vtable      */
    uint32_t dispatch1;             /* +0x04                               */
    uint32_t dispatch2;             /* +0x08 literal zero                  */
    rome2_recovered_str name;       /* +0x0c "Climate Conditions"          */
    rome2_recovered_str name_alt;   /* +0x18 assigned from the call chain  */
    uint32_t grid_a;                /* +0x24 arg02                         */
    uint32_t grid_b;                /* +0x28 arg03                         */
    uint32_t grid_c;                /* +0x2c arg04                         */
} rome2_climate_record;

/* Retail image size and measured host size of the descriptor. */
_Static_assert(sizeof(rome2_entity_descriptor)
                   == ROME2_ENTITY_DESCRIPTOR_SIZE,
    "entity descriptor must reproduce the measured x64 layout");
_Static_assert(offsetof(rome2_entity_descriptor, item_count) == 4,
    "descriptor item_count");
_Static_assert(offsetof(rome2_entity_descriptor, items) == 8,
    "descriptor items");
_Static_assert(sizeof(rome2_recovered_str) == ROME2_ENTITY_ITEM_STRIDE,
    "host item stride must match the widened string record");

_Static_assert(sizeof(rome2_climate_record) == ROME2_CLIMATE_RECORD_SIZE,
    "climate record must reproduce the measured x64 layout");
_Static_assert(offsetof(rome2_climate_record, dispatch2) == 8,
    "climate dispatch2");
_Static_assert(offsetof(rome2_climate_record, name) == 0x10, "climate name");
_Static_assert(offsetof(rome2_climate_record, name_alt) == 0x20,
    "climate name_alt");
_Static_assert(offsetof(rome2_climate_record, grid_a) == 0x30, "climate grid_a");
_Static_assert(offsetof(rome2_climate_record, grid_c) == 0x38, "climate grid_c");

/*
 * Host services.
 *
 *   alloc_items -> FUN_100fcc80(count * 12, heap 0) reached through the
 *                  trampoline at 0x10cbe4ab.  The retail branch at 0x10cbe49a
 *                  skips the call entirely when the count is zero.
 *   free_items  -> host companion for the vector allocation. This adapter
 *                  owns the vector only; all string data remains borrowed.
 * Both callbacks are required for a nonempty vector. Pass the same host to
 * construction and release; an allocation must provide count host records.
 */
typedef struct rome2_entity_host {
    void *(*alloc_items)(size_t bytes);
    void (*free_items)(void *items);
} rome2_entity_host;

/*
 * Recovered read-only .data anchors consumed by FUN_10cbe350.
 *
 *   DAT_11f958ec / DAT_11f958f0 : zero-initialised floats copied into
 *                                 this+0x03c and this+0x040
 *                                 (0x10cbe3ca MOVSS / 0x10cbe3e2 MOVSS)
 */
typedef struct rome2_entity_globals {
    float grid_extent_min;
    float grid_extent_max;
} rome2_entity_globals;

void rome2_entity_globals_from_image(rome2_entity_globals *globals);

/*
 * Borrowed projections of FUN_100f1800 and FUN_100f1700. Both set capacity to
 * length, matching FUN_100ef2c0, but retain the source bytes instead of making
 * the original owned copy. Empty inputs use the image sentinel identity.
 * Sources must remain valid for the lifetime of the resulting views, with
 * nonnegative lengths that fit int32_t and cover readable source bytes.
 */
void rome2_entity_str_assign_literal(rome2_recovered_str *dst, const char *src);
void rome2_entity_str_assign_view(rome2_recovered_str *dst,
                                  const rome2_recovered_str *src);

/*
 * The nineteen recovered stack words, in ABI order.  Stack word N lives at
 * E0+4+4*N, and the offset column below is what the raw listing computes after
 * subtracting the live `SUB ESP`/`PUSH` depth at the reading instruction.
 *
 *   word  offset  read at   recovered use
 *   arg00 E0+0x04 0x10cbe440  string source copied into this+0x0a0
 *   arg01 E0+0x08 0x10cbe44f  eight-byte copy into this+0x0ac / this+0x0b0
 *   arg02 E0+0x0c 0x10cbe3fb  climate->grid_a  (FUN_10cc1a10 dword chain)
 *   arg03 E0+0x10 0x10cbe3f4  climate->grid_b
 *   arg04 E0+0x14 0x10cbe3ec  climate->grid_c
 *   arg05 E0+0x18 0x10cbe3f0  dword copied into this+0x060
 *   arg06 E0+0x1c            by-value string length, released at 0x10cbe540
 *   arg07 E0+0x20            by-value string capacity
 *   arg08 E0+0x24            by-value string data
 *   arg09 E0+0x28 0x10cbe3b3  origin pair -> this+0x028/0x02c
 *   arg10 E0+0x2c 0x10cbe453  vector descriptor -> this+0x0b4/0x0b8/0x0bc
 *   arg11 E0+0x30 0x10cbe50f  string source -> this+0x0d0
 *   arg12 E0+0x34 0x10cbe3ff  low byte -> this+0x064
 *   arg13 E0+0x38 0x10cbe51e  low byte -> this+0x0dc
 *   arg14 E0+0x3c 0x10cbe409  dword -> this+0x06c
 *   arg15 E0+0x40 0x10cbe52c  dword -> this+0x0e0
 *   arg16 E0+0x44 0x10cbe536  low byte -> this+0x0e4
 *   arg17 E0+0x48 0x10cbe4f6  string source -> this+0x0c0
 *   arg18 E0+0x4c 0x10cbe505  low byte -> this+0x0cc
 *
 * The projection does not take ownership of or release arg06..arg08. Native
 * string allocation, the incoming by-value destructor, and callable vtables
 * remain outside this standalone test-only adapter.
 */
typedef struct rome2_entity_ctor_args {
    const rome2_recovered_str *arg00;
    const uint32_t *arg01;
    uint32_t arg02;
    uint32_t arg03;
    uint32_t arg04;
    uint32_t arg05;
    int32_t arg06;
    int32_t arg07;
    const char *arg08;
    const rome2_entity_origin *arg09;
    const rome2_entity_descriptor *arg10;
    const rome2_recovered_str *arg11;
    uint32_t arg12;
    uint32_t arg13;
    uint32_t arg14;
    uint32_t arg15;
    uint32_t arg16;
    const rome2_recovered_str *arg17;
    uint32_t arg18;
} rome2_entity_ctor_args;

/*
 * The reconstructed record.  Offsets come straight from the MOV [EDI+imm]
 * instructions of FUN_10cbe350; the `+0x..` marker on each line is the x86
 * image offset, the host offset is pinned by the layout contract below.
 */
typedef struct rome2_battle_entity {
    rome2_dispatch_triple dispatch;               /* +0x000                 */
    rome2_recovered_str    effect_name;           /* +0x010 "auto_generator_input" */
    rome2_recovered_str    category;              /* +0x01c                 */
    uint32_t               origin_x;              /* +0x028 arg09->x        */
    uint32_t               origin_y;              /* +0x02c arg09->y        */
    rome2_recovered_str    label;                 /* +0x030                 */
    float                  grid_extent_min;       /* +0x03c DAT_11f958ec    */
    float                  grid_extent_max;       /* +0x040 DAT_11f958f0    */
    rome2_recovered_str    descriptor_text;       /* +0x044                 */
    float                  activation_radius_min; /* +0x054 literal 2048.0f */
    float                  activation_radius_max; /* +0x058 literal 2048.0f */
    uint32_t               point_count;           /* +0x05c literal 3       */
    uint32_t               owner_id;              /* +0x060 arg05           */
    uint8_t                mode;                  /* +0x064 arg12 low byte  */
    uint8_t                pad_065[3];            /* +0x065..0x067 hole     */
    uint32_t               field_068;             /* +0x068 zeroed          */
    uint32_t               owner_ref;             /* +0x06c arg14           */
    rome2_climate_record   climate;               /* +0x070 .. +0x09f       */
    rome2_recovered_str    label_alt;             /* +0x0a0 from arg00      */
    uint32_t               tag_lo;                /* +0x0ac arg01[0]        */
    uint32_t               tag_hi;                /* +0x0b0 arg01[1]        */
    uint32_t               item_count;            /* +0x0b4 arg10->count    */
    uint32_t               item_alloc_count;      /* +0x0b8 arg10->count    */
    rome2_recovered_str   *items;                 /* +0x0bc heap block      */
    rome2_recovered_str    effect_kind;           /* +0x0c0 arg17           */
    uint8_t                flag_0cc;              /* +0x0cc arg18 low byte  */
    uint8_t                pad_0cd[3];            /* +0x0cd..0x0cf hole     */
    rome2_recovered_str    source_name;           /* +0x0d0 arg11           */
    uint8_t                flag_0dc;              /* +0x0dc arg13 low byte  */
    uint8_t                pad_0dd[3];            /* +0x0dd..0x0df hole     */
    uint32_t               field_0e0;             /* +0x0e0 arg15           */
    uint8_t                flag_0e4;              /* +0x0e4 arg16 low byte  */
    uint8_t                pad_0e5[3];            /* +0x0e5..0x0e7 hole     */
} rome2_battle_entity;

/*
 * Layout contract.
 *
 * The retail record is the 0xE8-byte x86 image. The host projection is 0x120
 * bytes and is not a memory overlay of that object. The offsets below pin
 * the host layout; the `+0x..` column in the
 * struct above is the address recovered from the retail MOV instructions.
 */
_Static_assert(sizeof(rome2_battle_entity) == ROME2_ENTITY_RECORD_SIZE,
    "entity record must reproduce the measured x64 layout");
_Static_assert(offsetof(rome2_battle_entity, dispatch) == 0x000, "dispatch");
_Static_assert(offsetof(rome2_battle_entity, effect_name) == 0x010,
    "effect_name");
_Static_assert(offsetof(rome2_battle_entity, category) == 0x020, "category");
_Static_assert(offsetof(rome2_battle_entity, origin_x) == 0x030, "origin_x");
_Static_assert(offsetof(rome2_battle_entity, origin_y) == 0x034, "origin_y");
_Static_assert(offsetof(rome2_battle_entity, label) == 0x038, "label");
_Static_assert(offsetof(rome2_battle_entity, grid_extent_min) == 0x048,
    "grid_extent_min");
_Static_assert(offsetof(rome2_battle_entity, grid_extent_max) == 0x04c,
    "grid_extent_max");
_Static_assert(offsetof(rome2_battle_entity, descriptor_text) == 0x050,
    "descriptor_text");
_Static_assert(offsetof(rome2_battle_entity, activation_radius_min) == 0x060,
    "activation_radius_min");
_Static_assert(offsetof(rome2_battle_entity, point_count) == 0x068,
    "point_count");
_Static_assert(offsetof(rome2_battle_entity, owner_id) == 0x06c, "owner_id");
_Static_assert(offsetof(rome2_battle_entity, mode) == 0x070, "mode");
_Static_assert(offsetof(rome2_battle_entity, field_068) == 0x074, "field_068");
_Static_assert(offsetof(rome2_battle_entity, owner_ref) == 0x078, "owner_ref");
_Static_assert(offsetof(rome2_battle_entity, climate) == 0x080, "climate");
_Static_assert(offsetof(rome2_battle_entity, label_alt) == 0x0c0, "label_alt");
_Static_assert(offsetof(rome2_battle_entity, tag_lo) == 0x0d0, "tag_lo");
_Static_assert(offsetof(rome2_battle_entity, tag_hi) == 0x0d4, "tag_hi");
_Static_assert(offsetof(rome2_battle_entity, item_count) == 0x0d8,
    "item_count");
_Static_assert(offsetof(rome2_battle_entity, item_alloc_count) == 0x0dc,
    "item_alloc_count");
_Static_assert(offsetof(rome2_battle_entity, items) == 0x0e0, "items");
_Static_assert(offsetof(rome2_battle_entity, effect_kind) == 0x0e8,
    "effect_kind");
_Static_assert(offsetof(rome2_battle_entity, flag_0cc) == 0x0f8, "flag_0cc");
_Static_assert(offsetof(rome2_battle_entity, source_name) == 0x100,
    "source_name");
_Static_assert(offsetof(rome2_battle_entity, flag_0dc) == 0x110, "flag_0dc");
_Static_assert(offsetof(rome2_battle_entity, field_0e0) == 0x114, "field_0e0");
_Static_assert(offsetof(rome2_battle_entity, flag_0e4) == 0x118, "flag_0e4");

/* Construct the nested "Climate Conditions" record (port of FUN_10cc1a10). */
void rome2_climate_record_ctor(
    rome2_climate_record *self,
    const rome2_recovered_str *name_alt,
    uint32_t grid_a,
    uint32_t grid_b,
    uint32_t grid_c);

/*
 * Bounded field projection of FUN_10cbe350. Returns self on success and NULL
 * on invalid input, unsupported count, missing host services or allocation
 * failure. Failures leave self unchanged. Null optional inputs project as
 * empty/zero; nonempty vectors require a valid count-element source span.
 * Construct into fresh or already released storage. String data is borrowed;
 * input records, output storage and the allocated vector must be disjoint.
 * Original write/effect order and untouched padding are not reproduced.
 */
rome2_battle_entity *rome2_battle_entity_ctor(
    rome2_battle_entity *self,
    const rome2_entity_ctor_args *args,
    const rome2_entity_globals *globals,
    const rome2_entity_host *host);

/* Release through the construction host. Missing free service preserves live
 * state and returns false. Successful repeated release is a no-op. */
bool rome2_battle_entity_release_items(
    rome2_battle_entity *self, const rome2_entity_host *host);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_10CBE350_ENTITY_H */
