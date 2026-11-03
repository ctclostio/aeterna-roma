/*
 * ported_10145c70_unitcard.c - Phase 4.2 reconstruction of FUN_10145c70.
 *
 * Statement-for-statement translation of the recovered x86 body.  Each block
 * below is annotated with the address of the instruction range it reproduces;
 * the single exception is documented inline where the retail code performs an
 * undefined read that this port normalises.
 */

#include "ported_10145c70_unitcard.h"

#include <string.h>

void rome2_unit_card_str_reset(rome2_recovered_str *dst)
{
    if (dst == NULL) {
        return;
    }
    /* FUN_100f1850 @ 0x100f1850: three dword stores then a bare RET. */
    dst->length = 0;
    dst->capacity = 0;
    dst->data = (const char *)(uintptr_t)ROME2_UNITCARD_EMPTY_SENTINEL_A;
}

void rome2_unit_card_str_reset_alt(rome2_recovered_str *dst)
{
    if (dst == NULL) {
        return;
    }
    /* FUN_100f1c10 @ 0x100f1c10: same triple with the second image sentinel. */
    dst->length = 0;
    dst->capacity = 0;
    dst->data = (const char *)(uintptr_t)ROME2_UNITCARD_EMPTY_SENTINEL_B;
}

bool rome2_unit_card_class_is_immutable(uint32_t unit_class)
{
    /* CMP EDI,0x6 / CMP EDI,0xe at 0x10145e64 .. 0x10145e6c. */
    return unit_class == ROME2_UNITCARD_IMMUTABLE_CLASS_A
        || unit_class == ROME2_UNITCARD_IMMUTABLE_CLASS_B;
}

void rome2_unit_card_globals_from_image(rome2_unit_card_globals *globals)
{
    if (globals == NULL) {
        return;
    }
    /* Zero-initialised image bytes at 0x11afbf14 / 0x11afbf18 read as floats. */
    globals->colour_component_a = 0.0f;
    globals->colour_component_b = 0.0f;
    globals->global_retail_flag = false;
    /* 0xbf800000 at 0x11971460 and 0x11971464. */
    globals->grid_extent_unset = -1.0f;
    globals->grid_extent_unset_hi = -1.0f;
}

void rome2_unit_card_ctor(
    rome2_unit_card *self,
    const rome2_unit_card_args *args,
    const rome2_unit_card_globals *globals,
    const rome2_unit_card_host *host)
{
    static const rome2_unit_card_globals image_defaults = {
        0.0f, 0.0f, false, -1.0f, -1.0f
    };
    rome2_unit_card_tag *tag_block;
    void *attachment;

    if (self == NULL) {
        return;
    }
    if (args == NULL) {
        return;
    }
    if (globals == NULL) {
        globals = &image_defaults;
    }

    /* The constructor writes every byte it touches but not the two 4-byte
     * alignment holes at +0x52 and +0x85..+0x87, which the retail image also
     * leaves untouched.  Clearing first keeps the port deterministic without
     * inventing values for those holes. */
    memset(self, 0, sizeof(*self));

    /* 0x10145c7b .. 0x10145c8f: three dword zeroes, then arg03 into +0x0c. */
    self->field_000 = 0;
    self->field_004 = 0;
    self->field_008 = 0;
    self->owner = args->arg03;

    /* 0x10145c78 / 0x10145c92: FUN_100f1850 on this+0x010. */
    rome2_unit_card_str_reset(&self->str_010);

    /* 0x10145c9e .. 0x10145ca5: this+0x01c and this+0x020 start at zero; the
     * 0x020 slot is only replaced by the FUN_100d12b0 block further down. */
    self->attachment = NULL;
    self->tag = NULL;

    /* 0x10145cac: MOV byte [ESI+0x24],AL from stack word arg02. */
    self->selector = args->arg02;

    /* 0x10145caf, 0x10145cb7, 0x10145cc6: three more FUN_100f1850 resets. */
    rome2_unit_card_str_reset(&self->str_028);
    rome2_unit_card_str_reset(&self->str_034);
    rome2_unit_card_str_reset(&self->str_044);

    /* 0x10145cc3: MOV byte [ESI+0x40],AL from stack word arg04. */
    self->variant = args->arg04;

    /* 0x10145ced: MOV word [ESI+0x50],0. */
    self->pad_050 = 0;

    /* 0x10145cdf / 0x10145ce6: arg05 into +0x54, arg07 into +0x58. */
    self->priority = args->arg05;
    self->control_flags = args->arg07;

    /* 0x10145cf3 .. 0x10145d16: six consecutive dword zeroes, +0x5c..+0x70. */
    self->field_05c = 0;
    self->field_060 = 0;
    self->field_064 = 0;
    self->field_068 = 0;
    self->field_06c = 0;
    self->field_070 = 0;

    /* 0x10145d1d / 0x10145d25: arg08 into +0x74, arg10 into +0x7c. */
    self->unit_class = args->arg08;
    self->strength = args->arg10;

    /* 0x10145d20: MOVSS [ESI+0x78],XMM0 from stack word arg09. */
    self->deployment = args->arg09;

    /* 0x10145d28 .. 0x10145d4d: +0x80 dword, +0x84 byte, +0x88/0x8c/0x90. */
    self->field_080 = 0;
    self->field_084 = 0;
    self->field_088 = 0;
    self->field_08c = 0;
    self->field_090 = 0;

    /* 0x10145d57 .. 0x10145d8f: the DAT_11afbf14/18 pair is written twice,
     * once for the low corner and once for the high corner of the box. */
    self->colour_lo_x = globals->colour_component_a;
    self->colour_lo_y = globals->colour_component_b;
    self->colour_hi_x = globals->colour_component_a;
    self->colour_hi_y = globals->colour_component_b;

    /* 0x10145d97 .. 0x10145df9: eight string resets.  All but the one at
     * +0x0fc use FUN_100f1850; that one uses FUN_100f1c10 and therefore the
     * second image sentinel. */
    rome2_unit_card_str_reset(&self->str_0a4);
    rome2_unit_card_str_reset(&self->str_0b0);
    rome2_unit_card_str_reset(&self->str_0bc);
    rome2_unit_card_str_reset(&self->str_0c8);
    rome2_unit_card_str_reset(&self->str_0d4);
    rome2_unit_card_str_reset(&self->str_0e0);
    self->field_0ec = 0;
    rome2_unit_card_str_reset(&self->str_0f0);
    rome2_unit_card_str_reset_alt(&self->str_0fc);
    rome2_unit_card_str_reset(&self->str_108);

    /* 0x10145e1b / 0x10145e25: +0x114 zeroed, +0x118 literal 1. */
    self->field_114 = 0;
    self->enabled = (uint8_t)ROME2_UNITCARD_LIT_ENABLED;

    /* 0x10145e07 / 0x10145e11 / 0x10145e1b: three byte copies. */
    self->flag_119 = args->arg12;
    self->flag_11a = args->arg13;
    self->flag_11b = args->arg14;

    /* 0x10145dfe .. 0x10145e43: the OR of arg15 with the DAT_11afbd20 global
     * short-circuits into a 0/1 byte; both operands are truth-tested. */
    self->flag_11c = (uint8_t)(((args->arg15 != 0) || globals->global_retail_flag) ? 1 : 0);

    /* 0x10145e49 / 0x10145e50 / 0x10145e5a: +0x11d, +0x120, +0x124. */
    self->flag_11d = 0;
    self->field_120 = 0;
    self->slot_count = ROME2_UNITCARD_LIT_SLOT_COUNT;

    /* 0x10145e64 .. 0x10145e7a: classes 6 and 14 clear +0x128. */
    self->mutable_class = rome2_unit_card_class_is_immutable(args->arg08) ? 0u : 1u;

    /* 0x10145e80: FUN_100f1850 on this+0x12c. */
    rome2_unit_card_str_reset(&self->str_12c);

    /* 0x10145e8f / 0x10145e95: arg16 into +0x138, word zero at +0x139. */
    self->flag_138 = args->arg16;
    self->pad_139 = 0;

    /* 0x10145e9e: FUN_1024e480 is entered with ECX = this+0x13c.  The retail
     * routine initialises sixteen bytes that the caller never reads back in
     * this constructor, so the port only guarantees the zeroed region. */
    memset(self->aux_subobject, 0, sizeof(self->aux_subobject));

    /* 0x10145ea7 .. 0x10145f19: +0x14c and +0x150 zeroed, the DAT_11971460/64
     * pair lands in the tactical grid extent, then five dword zeroes. */
    self->field_14c = 0;
    self->field_150 = 0;
    self->grid_extent_min = globals->grid_extent_unset;
    self->grid_extent_max = globals->grid_extent_unset_hi;
    self->field_15c = 0;
    self->field_160 = 0;
    self->field_164 = 0;
    self->field_168 = 0;
    self->field_16c = 0;
    self->field_170 = 0;

    /* 0x10145f19 / 0x10145f20: byte zero at +0x174, word zero at +0x176. */
    self->field_174 = 0;
    self->pad_176 = 0;

    /* 0x10145ea3: FUN_1016db10 receives stack word arg06 with ECX = this.
     * 0x10145eb1 re-establishes ECX = this for the two calls that follow. */
    (void)args->arg06;

    /* 0x10145f3a .. 0x10145f64: 0x10-byte tag block.  The constructor stores
     * the block pointer at this+0x020 and, on the success branch only, writes
     * PTR_FUN_1173fae4 as the block's first dword after running FUN_10132ce0
     * on block+4 with arg01 as the source. */
    tag_block = NULL;
    if (host != NULL && host->alloc_block != NULL) {
        tag_block = (rome2_unit_card_tag *)host->alloc_block(
            ROME2_UNITCARD_TAG_BLOCK_SIZE);
    }
    if (tag_block != NULL) {
        if (host->init_tag != NULL) {
            host->init_tag(&tag_block->payload, args->arg01);
        } else {
            tag_block->payload = NULL;
        }
        tag_block->vtable = ROME2_UNITCARD_TAG_VTABLE;
    }
    self->tag = tag_block;

    /* 0x10145f67 .. 0x10145f8c: the 0xE8-byte attachment is only allocated
     * when arg00 is non-zero; a failed allocation stores NULL and still runs
     * FUN_101a97f0.  The early return at 0x10145f98 is the success path. */
    attachment = NULL;
    if (args->arg00 != NULL && host != NULL && host->alloc_block != NULL) {
        attachment = host->alloc_block(ROME2_UNITCARD_ATTACHMENT_BLOCK_SIZE);
    }
    if (attachment != NULL && host->init_attachment != NULL) {
        self->attachment = host->init_attachment(args->arg00);
    } else {
        self->attachment = NULL;
    }

    /* 0x10145f8f / 0x10145fa4: FUN_101a97f0(this, 0) closes both exits. */
    if (host != NULL && host->finish_setup != NULL) {
        host->finish_setup(self);
    }
}