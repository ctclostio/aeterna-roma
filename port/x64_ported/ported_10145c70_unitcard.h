#ifndef ROME2_PORTED_10145C70_UNITCARD_H
#define ROME2_PORTED_10145C70_UNITCARD_H

/*
 * ported_10145c70_unitcard - Phase 4.2 reconstruction of the battle unit card
 * descriptor constructor recovered from empire.retail.dll 0x10145c70.
 *
 * Recovered shape
 * ---------------
 *   x86 entry : FUN_10145c70 @ 0x10145c70, body 0x10145c70..0x10145faf (832 bytes)
 *   prototype : __thiscall, ECX = this, RET 0x44  ->  17 stack words + ECX
 *   callers   : 0x100e39c0 @ 0x100e4363 (settlement battle benchmark harness)
 *               0x10747450 @ 0x107479b8
 *               0x108cb2e0 @ 0x108cb572
 *               0x10ec7f40 @ 0x10ec8a06
 *               0x10f60ef0 @ 0x10f60f77
 *               0x1105ba50 @ 0x1105bbc5
 *
 * Every field offset below is read directly off the store instructions of the
 * function body (MOV [ESI+imm], ...) and is not inferred.  The 17 stack words
 * are addressed E0+4 .. E0+0x44 where E0 is the entry stack pointer; the
 * `arg00 .. arg16` names below preserve that index (arg N lives at E0+4+4*N).
 *
 * The x86 ABI passes seventeen independent words, several of which are read
 * only as a byte or only as a dword.  The Win64 ABI has no equivalent, so the
 * constructor takes a rome2_unit_card_args record; the index of every field is
 * documented in the table above it and repeated in the implementation.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "../recovered_types/tag_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ROME2_PORT_10145C70_UNITCARD_PC UINT32_C(0x10145c70)

/*
 * Recovered engine string descriptor (not a standard-library ABI claim).
 *
 * FUN_100f1850 writes {0, 0, 0x11af408e} and returns via a bare RET.
 * FUN_100f1c10 writes {0, 0, 0x11af4090} and returns via a bare RET.
 * FUN_100f1700 deep-copies length bytes through FUN_100ef2c0(data, data+len);
 * the resulting capacity equals length, rather than the source capacity.
 * FUN_100f1800 writes strlen(src) then calls FUN_100ef2c0(src, src+len).
 * FUN_100f1c80 reads data, rejects 0x11af408e and NULL, then frees data[-4].
 *
 * Both 0x11af408e and 0x11af4090 are zero-filled image sentinels, so the two
 * sentinels are distinguishable pointers even though both spell "".
 */
/*
 * Size of the string member as laid out by the retail x86 image.
 * On x64 the pointer field widens by four bytes, so the host view below is
 * sixteen bytes; the field ORDER and every non-pointer member are unchanged,
 * and each record offset below records both the recovered x86 offset and the
 * x64 offset it maps to.
 */
#define ROME2_UNITCARD_STR_SIZE_X86            12u
#define ROME2_UNITCARD_STR_SIZE                16u
#define ROME2_UNITCARD_EMPTY_SENTINEL_A        UINT32_C(0x11af408e)
#define ROME2_UNITCARD_EMPTY_SENTINEL_B        UINT32_C(0x11af4090)

/*
 * Retail image size of the record (last initialised byte is x86 +0x177) and the
 * measured host size after the pointer widening described at the struct.
 */
#define ROME2_UNITCARD_RECORD_SIZE_X86         0x178u
#define ROME2_UNITCARD_RECORD_SIZE             0x1C8u

/* Original requests and distinct native projection extents. */
#define ROME2_UNITCARD_TAG_GUEST_ALLOCATION_SIZE          0x10u
#define ROME2_UNITCARD_ATTACHMENT_GUEST_ALLOCATION_SIZE   0xE8u
#define ROME2_UNITCARD_TAG_BLOCK_SIZE          (sizeof(rome2_unit_card_tag))
#define ROME2_UNITCARD_ATTACHMENT_BLOCK_SIZE   0x120u

/* this+0x118 is written as the literal 1 at 0x10145e25. */
#define ROME2_UNITCARD_LIT_ENABLED             UINT32_C(1)

/* this+0x124 is written as the literal 0x14 at 0x10145e5a. */
#define ROME2_UNITCARD_LIT_SLOT_COUNT          UINT32_C(20)

/*
 * Unit classes 6 and 14 are the two immutable variants: the comparison chain
 * at 0x10145e64 (`CMP EDI,0x6` / `CMP EDI,0xe`) drives this+0x128.
 */
#define ROME2_UNITCARD_IMMUTABLE_CLASS_A       UINT32_C(6)
#define ROME2_UNITCARD_IMMUTABLE_CLASS_B       UINT32_C(14)

/* FUN_1024e480 is entered with ECX = this+0x13c; this+0x14c is written next. */
#define ROME2_UNITCARD_AUX_SUBOBJECT_OFFSET    0x13Cu
#define ROME2_UNITCARD_AUX_SUBOBJECT_SIZE      0x10u

/* Recovered string view (FUN_100f1700 / FUN_100f1800 / FUN_100f1850 layout).
 *
 * The retail member is the 12-byte triple {length, capacity, data} with a
 * 32-bit data pointer.  On x64 that pointer is eight bytes wide, so the host
 * view is 16 bytes with `data` naturally aligned at offset +8; the field order
 * is unchanged and no recovered semantic is lost. */
typedef struct rome2_recovered_str {
    int32_t length;
    int32_t capacity;
    const char *data;
} rome2_recovered_str;

/* MEASURE: recovered string view must stay 12 bytes wide */
_Static_assert(sizeof(rome2_recovered_str) == ROME2_UNITCARD_STR_SIZE,
    "recovered string view must stay 16 bytes wide on x64");
_Static_assert(offsetof(rome2_recovered_str, data) == 8,
    "recovered string data pointer must stay at +8");
_Static_assert(offsetof(rome2_recovered_str, capacity) == 4,
    "recovered string capacity must stay at +4");

/* Three guest vtable identities and the zero scalar at original +0x0c.
 * These four-byte cells are not callable native pointers. */
typedef struct rome2_dispatch_triple {
    uint32_t slot0;
    uint32_t slot1;
    uint32_t slot2;
    uint32_t slot3;
} rome2_dispatch_triple;

/*
 * Recovered read-only .data anchors consumed by the constructor.
 *
 *   DAT_11afbf14 / DAT_11afbf18 : two consecutive zero-initialised floats,
 *                                copied into this+0x94/0x98/0x9c/0xa0 as the
 *                                pairs (a,b) and (a,b) again (0x10145d57..0x10145d8f)
 *   DAT_11afbd20               : zero-initialised byte; OR-ed with arg14 into
 *                                this+0x11c (0x10145e34)
 *   DAT_11971460 / DAT_11971464 : 0xbf800000 == -1.0f, the "unbounded" sentinel
 *                                for the tactical grid extent at this+0x154/0x158
 */
typedef struct rome2_unit_card_globals {
    float colour_component_a;      /* DAT_11afbf14 */
    float colour_component_b;      /* DAT_11afbf18 */
    bool  global_retail_flag;      /* DAT_11afbd20 */
    float grid_extent_unset;       /* DAT_11971460 */
    float grid_extent_unset_hi;    /* DAT_11971464 */
} rome2_unit_card_globals;

struct rome2_battle_entity;

/*
 * Host services the constructor performs through engine calls that have no
 * standalone x86 counterpart in this reconstruction.
 *
 *   alloc_block  -> native projection allocation (24 / 288 bytes, not the
 *                   original 16 / 232-byte guest requests)
 *   init_tag     -> FUN_10132ce0 copy boundary: destination/source vectors,
 *                   &block->elements and &arg01->elements. Those are +8 in
 *                   native records, corresponding to original guest +4.
 *   init_attachment -> FUN_101350c0: allocated receiver AND arg00 source
 *   finish_setup -> FUN_101a97f0, entered with (this, 0) on both exits
 *
 * alloc_block returns storage suitably aligned for these native records.
 * Callbacks initialise the supplied native receivers and return normally.
 * A missing initializer suppresses its allocation. A NULL native arg01 means
 * an empty source (a checked host convenience). The caller owns both blocks
 * and any nested data its callbacks create; this legacy projection has no
 * general destroy API. owned_tag.h supplies a separate fully owned tag copy.
 * Other helper effects and complete constructor equivalence remain unproved.
 */
typedef struct rome2_unit_card_host {
    void *(*alloc_block)(size_t size);
    void (*init_tag)(rome2_unit_card_tag_vector *destination,
        const rome2_unit_card_tag_vector *source);
    void (*init_attachment)(struct rome2_battle_entity *receiver,
        const struct rome2_battle_entity *source);
    void (*finish_setup)(void *self);
} rome2_unit_card_host;

/*
 * The seventeen recovered stack words, in ABI order.
 *
 *   arg00  E0+0x04  pointer  ; entity copy source for FUN_101350c0; gates the
 *                              original 0xE8-byte attachment allocation.
 *   arg01  E0+0x08  pointer  ; tag source; guest source vector is arg01+4 at
 *                              0x10145f4e. Native: &arg01->elements.
 *   arg02  E0+0x0c  byte     ; -> this+0x024 (0x10145cac)
 *   arg03  E0+0x10  dword    ; -> this+0x00c (0x10145c8f)
 *   arg04  E0+0x14  byte     ; -> this+0x040 (0x10145cc3)
 *   arg05  E0+0x18  dword    ; -> this+0x054 (0x10145cdf)
 *   arg06  E0+0x1c  dword    ; -> FUN_1016db10 (0x10145ea3); never stored
 *   arg07  E0+0x20  dword    ; -> this+0x058 (0x10145ce6)
 *   arg08  E0+0x24  dword    ; -> this+0x074; also drives this+0x128 through
 *                              the class 6 / class 14 comparisons (0x10145e64)
 *   arg09  E0+0x28  float    ; -> this+0x078 via MOVSS (0x10145d20)
 *   arg10  E0+0x2c  dword    ; -> this+0x07c (0x10145d25)
 *   arg11  E0+0x30  dword    ; never read
 *   arg12  E0+0x34  byte     ; -> this+0x119 (0x10145e07)
 *   arg13  E0+0x38  byte     ; -> this+0x11a (0x10145e11)
 *   arg14  E0+0x3c  byte     ; -> this+0x11b (0x10145e1b)
 *   arg15  E0+0x40  byte     ; OR-ed with DAT_11afbd20 into this+0x11c
 *                              (0x10145dfe .. 0x10145e43)
 *   arg16  E0+0x44  byte     ; -> this+0x138 (0x10145e8f)
 */
typedef struct rome2_unit_card_args {
    const struct rome2_battle_entity *arg00;
    const rome2_unit_card_tag *arg01;
    uint8_t arg02;
    uint32_t arg03;
    uint8_t arg04;
    uint32_t arg05;
    uint32_t arg06;
    uint32_t arg07;
    uint32_t arg08;
    float arg09;
    uint32_t arg10;
    uint32_t arg11;
    uint8_t arg12;
    uint8_t arg13;
    uint8_t arg14;
    uint8_t arg15;
    uint8_t arg16;
} rome2_unit_card_args;

/*
 * The reconstructed record.  Field order and padding reproduce the recovered
 * offsets exactly; every hole that the constructor writes with a literal zero
 * is kept as an explicit member so the layout stays auditable.
 */
typedef struct rome2_unit_card {
    uint32_t          field_000;                 /* +0x000 zeroed          */
    uint32_t          field_004;                 /* +0x004 zeroed          */
    uint32_t          field_008;                 /* +0x008 zeroed          */
    uint32_t          owner;                     /* +0x00c arg03           */
    rome2_recovered_str str_010;                 /* +0x010 FUN_100f1850    */
    struct rome2_battle_entity *attachment;       /* +0x01c FUN_101350c0    */
    rome2_unit_card_tag *tag;                    /* +0x020 FUN_100d12b0    */
    uint8_t           selector;                  /* +0x024 arg02           */
    rome2_recovered_str str_028;                 /* +0x028 FUN_100f1850    */
    rome2_recovered_str str_034;                 /* +0x034 FUN_100f1850    */
    uint8_t           variant;                   /* +0x040 arg04           */
    rome2_recovered_str str_044;                 /* +0x044 FUN_100f1850    */
    uint16_t          pad_050;                   /* +0x050 word zeroed     */
    uint16_t          pad_052;                   /* +0x052 untouched hole  */
    uint32_t          priority;                  /* +0x054 arg05           */
    uint32_t          control_flags;             /* +0x058 arg07           */
    uint32_t          field_05c;                 /* +0x05c zeroed          */
    uint32_t          field_060;                 /* +0x060 zeroed          */
    uint32_t          field_064;                 /* +0x064 zeroed          */
    uint32_t          field_068;                 /* +0x068 zeroed          */
    uint32_t          field_06c;                 /* +0x06c zeroed          */
    uint32_t          field_070;                 /* +0x070 zeroed          */
    uint32_t          unit_class;                /* +0x074 arg08           */
    float             deployment;                /* +0x078 arg09 (MOVSS)   */
    uint32_t          strength;                  /* +0x07c arg10           */
    uint32_t          field_080;                 /* +0x080 zeroed          */
    uint8_t           field_084;                 /* +0x084 byte zeroed     */
    uint8_t           pad_085[3];                /* +0x085..0x087 hole     */
    uint32_t          field_088;                 /* +0x088 zeroed          */
    uint32_t          field_08c;                 /* +0x08c zeroed          */
    uint32_t          field_090;                 /* +0x090 zeroed          */
    float             colour_lo_x;               /* +0x094 DAT_11afbf14    */
    float             colour_lo_y;               /* +0x098 DAT_11afbf18    */
    float             colour_hi_x;               /* +0x09c DAT_11afbf14    */
    float             colour_hi_y;               /* +0x0a0 DAT_11afbf18    */
    rome2_recovered_str str_0a4;                 /* +0x0a4 FUN_100f1850    */
    rome2_recovered_str str_0b0;                 /* +0x0b0 FUN_100f1850    */
    rome2_recovered_str str_0bc;                 /* +0x0bc FUN_100f1850    */
    rome2_recovered_str str_0c8;                 /* +0x0c8 FUN_100f1850    */
    rome2_recovered_str str_0d4;                 /* +0x0d4 FUN_100f1850    */
    rome2_recovered_str str_0e0;                 /* +0x0e0 FUN_100f1850    */
    uint32_t          field_0ec;                 /* +0x0ec zeroed          */
    rome2_recovered_str str_0f0;                 /* +0x0f0 FUN_100f1850    */
    rome2_recovered_str str_0fc;                 /* +0x0fc FUN_100f1c10    */
    rome2_recovered_str str_108;                 /* +0x108 FUN_100f1850    */
    uint32_t          field_114;                 /* +0x114 zeroed          */
    uint8_t           enabled;                   /* +0x118 literal 1       */
    uint8_t           flag_119;                  /* +0x119 arg12           */
    uint8_t           flag_11a;                  /* +0x11a arg13           */
    uint8_t           flag_11b;                  /* +0x11b arg14           */
    uint8_t           flag_11c;                  /* +0x11c arg15|DAT_11afbd20 */
    uint8_t           flag_11d;                  /* +0x11d zeroed          */
    uint16_t          pad_11e;                   /* +0x11e..0x11f hole     */
    uint32_t          field_120;                 /* +0x120 zeroed          */
    uint32_t          slot_count;                /* +0x124 literal 0x14    */
    uint8_t           mutable_class;             /* +0x128 class 6/14 test */
    uint8_t           pad_129[3];                /* +0x129..0x12b hole     */
    rome2_recovered_str str_12c;                 /* +0x12c FUN_100f1850    */
    uint8_t           flag_138;                  /* +0x138 arg16           */
    uint8_t           pad_139;                   /* +0x139 word zeroed     */
    uint8_t           aux_subobject[ROME2_UNITCARD_AUX_SUBOBJECT_SIZE]; /* +0x13c */
    uint32_t          field_14c;                 /* +0x14c zeroed          */
    uint32_t          field_150;                 /* +0x150 zeroed          */
    float             grid_extent_min;           /* +0x154 DAT_11971460    */
    float             grid_extent_max;           /* +0x158 DAT_11971464    */
    uint32_t          field_15c;                 /* +0x15c zeroed          */
    uint32_t          field_160;                 /* +0x160 zeroed          */
    uint32_t          field_164;                 /* +0x164 zeroed          */
    uint32_t          field_168;                 /* +0x168 zeroed          */
    uint32_t          field_16c;                 /* +0x16c zeroed          */
    uint32_t          field_170;                 /* +0x170 zeroed          */
    uint8_t           field_174;                 /* +0x174 byte zeroed     */
    uint8_t           pad_175;                   /* +0x175 hole            */
    uint16_t          pad_176;                   /* +0x176 word zeroed     */
} rome2_unit_card;

/*
 * Layout contract.
 *
 * The retail record is the 0x178-byte x86 image.  Sixteen of its members hold
 * a 32-bit pointer that becomes eight bytes on x64, and the compiler inserts
 * eight more bytes of natural alignment, so the host record is 0x1C8 bytes.
 * The table below pins the host offsets; the `x86 +0x..` column in the struct
 * declaration above is the address recovered from the retail MOV instructions.
 * Every offset below therefore documents the widening, not a re-layout.
 */
_Static_assert(sizeof(rome2_unit_card) == ROME2_UNITCARD_RECORD_SIZE,
    "unit card record must reproduce the measured x64 layout");
_Static_assert(offsetof(rome2_unit_card, field_000) == 0x000, "field_000");
_Static_assert(offsetof(rome2_unit_card, owner) == 0x00c, "owner");
_Static_assert(offsetof(rome2_unit_card, str_010) == 0x010, "str_010");
_Static_assert(offsetof(rome2_unit_card, attachment) == 0x020, "attachment");
_Static_assert(offsetof(rome2_unit_card, tag) == 0x028, "tag");
_Static_assert(offsetof(rome2_unit_card, selector) == 0x030, "selector");
_Static_assert(offsetof(rome2_unit_card, str_028) == 0x038, "str_028");
_Static_assert(offsetof(rome2_unit_card, str_034) == 0x048, "str_034");
_Static_assert(offsetof(rome2_unit_card, variant) == 0x058, "variant");
_Static_assert(offsetof(rome2_unit_card, str_044) == 0x060, "str_044");
_Static_assert(offsetof(rome2_unit_card, pad_050) == 0x070, "pad_050");
_Static_assert(offsetof(rome2_unit_card, priority) == 0x074, "priority");
_Static_assert(offsetof(rome2_unit_card, control_flags) == 0x078,
    "control_flags");
_Static_assert(offsetof(rome2_unit_card, field_05c) == 0x07c, "field_05c");
_Static_assert(offsetof(rome2_unit_card, unit_class) == 0x094, "unit_class");
_Static_assert(offsetof(rome2_unit_card, deployment) == 0x098, "deployment");
_Static_assert(offsetof(rome2_unit_card, strength) == 0x09c, "strength");
_Static_assert(offsetof(rome2_unit_card, field_080) == 0x0a0, "field_080");
_Static_assert(offsetof(rome2_unit_card, colour_lo_x) == 0x0b4, "colour_lo_x");
_Static_assert(offsetof(rome2_unit_card, colour_hi_y) == 0x0c0, "colour_hi_y");
_Static_assert(offsetof(rome2_unit_card, str_0a4) == 0x0c8, "str_0a4");
_Static_assert(offsetof(rome2_unit_card, str_0e0) == 0x118, "str_0e0");
_Static_assert(offsetof(rome2_unit_card, field_0ec) == 0x128, "field_0ec");
_Static_assert(offsetof(rome2_unit_card, str_0f0) == 0x130, "str_0f0");
_Static_assert(offsetof(rome2_unit_card, str_0fc) == 0x140, "str_0fc");
_Static_assert(offsetof(rome2_unit_card, str_108) == 0x150, "str_108");
_Static_assert(offsetof(rome2_unit_card, field_114) == 0x160, "field_114");
_Static_assert(offsetof(rome2_unit_card, enabled) == 0x164, "enabled");
_Static_assert(offsetof(rome2_unit_card, flag_119) == 0x165, "flag_119");
_Static_assert(offsetof(rome2_unit_card, flag_11c) == 0x168, "flag_11c");
_Static_assert(offsetof(rome2_unit_card, field_120) == 0x16c, "field_120");
_Static_assert(offsetof(rome2_unit_card, slot_count) == 0x170, "slot_count");
_Static_assert(offsetof(rome2_unit_card, mutable_class) == 0x174,
    "mutable_class");
_Static_assert(offsetof(rome2_unit_card, str_12c) == 0x178, "str_12c");
_Static_assert(offsetof(rome2_unit_card, flag_138) == 0x188, "flag_138");
_Static_assert(offsetof(rome2_unit_card, aux_subobject) == 0x18a,
    "aux_subobject");
_Static_assert(offsetof(rome2_unit_card, field_14c) == 0x19c, "field_14c");
_Static_assert(offsetof(rome2_unit_card, grid_extent_min) == 0x1a4,
    "grid_extent_min");
_Static_assert(offsetof(rome2_unit_card, grid_extent_max) == 0x1a8,
    "grid_extent_max");
_Static_assert(offsetof(rome2_unit_card, pad_176) == 0x1c6, "pad_176");

/*
 * Vtable anchors recovered from .rdata; the tag block installed at this+0x020
 * receives PTR_FUN_1173fae4 as its first dword.
 */
#define ROME2_UNITCARD_TAG_VTABLE             ROME2_TAG_VTABLE_IDENTITY
#define ROME2_UNITCARD_TAG_VTABLE_FIRST_SLOT  UINT32_C(0x10cecea0)

/* Reset a recovered string view to the FUN_100f1850 / FUN_100f1c10 sentinels. */
void rome2_unit_card_str_reset(rome2_recovered_str *dst);
void rome2_unit_card_str_reset_alt(rome2_recovered_str *dst);

/* True when the record's unit class disables mutation (classes 6 and 14). */
bool rome2_unit_card_class_is_immutable(uint32_t unit_class);

/*
 * Bounded native projection of selected constructor fields. `args` and
 * `globals` are read-only; NULL globals select image defaults. Missing host
 * services suppress the affected allocation/call. No claim is made that this
 * reproduces FUN_1016db10, FUN_1016ee30, FUN_101a97f0, original write order or
 * general ownership behavior. Caller supplies writable native self storage.
 */
void rome2_unit_card_ctor(
    rome2_unit_card *self,
    const rome2_unit_card_args *args,
    const rome2_unit_card_globals *globals,
    const rome2_unit_card_host *host);

/* Recovered image defaults for the .data anchors. */
void rome2_unit_card_globals_from_image(rome2_unit_card_globals *globals);

#ifdef __cplusplus
}
#endif

#endif /* ROME2_PORTED_10145C70_UNITCARD_H */
