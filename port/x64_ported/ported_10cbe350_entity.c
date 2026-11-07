/*
 * Bounded host record projection of FUN_10cbe350 and FUN_10cc1a10.
 * Original instruction addresses identify scalar sources, not native calls.
 * String bytes are borrowed; only the widened item vector is host-owned.
 */
#include "ported_10cbe350_entity.h"
#include "../recovered_types/image_defaults.h"

#include <string.h>

void rome2_entity_globals_from_image(rome2_entity_globals *globals)
{
    const rome2_initial_global_snapshot initial = rome2_recovered_image_defaults();
    if (globals != NULL) {
        /* Initial image values, not observations of live engine globals. */
        globals->grid_extent_min = initial.entity_grid_min;
        globals->grid_extent_max = initial.entity_grid_max;
    }
}

void rome2_entity_str_assign_literal(rome2_recovered_str *dst, const char *src)
{
    if (dst == NULL) {
        return;
    }
    if (src == NULL || src[0] == '\0') {
        rome2_unit_card_str_reset(dst);
        return;
    }
    /* Valid literals fit the original signed length field. */
    dst->length = (int32_t)strlen(src);
    dst->capacity = dst->length;
    dst->data = src;
}

void rome2_entity_str_assign_view(rome2_recovered_str *dst,
    const rome2_recovered_str *src)
{
    if (dst == NULL) {
        return;
    }
    if (src == NULL || src->length == 0) {
        rome2_unit_card_str_reset(dst);
        return;
    }
    /* FUN_100f1700 -> FUN_100ef2c0 sets capacity to length. The adapter
     * borrows data instead of performing that helper's allocation/copy. */
    dst->length = src->length;
    dst->capacity = src->length;
    dst->data = src->data;
}

void rome2_climate_record_ctor(rome2_climate_record *self,
    const rome2_recovered_str *name_alt,
    uint32_t grid_a, uint32_t grid_b, uint32_t grid_c)
{
    if (self == NULL) {
        return;
    }
    /* Final derived identities at 0x10cc1a52/5c; +8 remains zero. */
    self->dispatch0 = ROME2_CLIMATE_DISPATCH0;
    self->dispatch1 = ROME2_CLIMATE_DISPATCH1;
    self->dispatch2 = 0;
    rome2_entity_str_assign_literal(&self->name, ROME2_ENTITY_CLIMATE_NAME);
    rome2_entity_str_assign_view(&self->name_alt, name_alt);
    /* 0x10cc1a70/77/7e: three dwords after the by-value string argument. */
    self->grid_a = grid_a;
    self->grid_b = grid_b;
    self->grid_c = grid_c;
}

rome2_battle_entity *rome2_battle_entity_ctor(rome2_battle_entity *self,
    const rome2_entity_ctor_args *args,
    const rome2_entity_globals *globals,
    const rome2_entity_host *host)
{
    static const rome2_entity_globals image_defaults = { 0.0f, 0.0f };
    rome2_battle_entity result;
    rome2_recovered_str scratch;
    rome2_recovered_str *items = NULL;
    uint32_t count;
    uint32_t i;

    if (self == NULL || args == NULL) {
        return NULL;
    }
    /* 0x10cbe453 selects arg10 independently of arg09's origin pair.
     * Exclude negative and x86 multiplication-overflow counts before effects.
     * The retail CMOVS allocation clamp does not bound its later copy loop. */
    count = args->arg10 != NULL ? args->arg10->item_count : 0u;
    if (count > ROME2_ENTITY_MAX_ITEM_COUNT) {
        return NULL;
    }
    if (count != 0u) {
        if (args->arg10->items == NULL || host == NULL
            || host->alloc_items == NULL || host->free_items == NULL) {
            return NULL;
        }
        items = host->alloc_items((size_t)count * sizeof(*items));
        if (items == NULL) {
            return NULL;
        }
        /* Original stride: 12. Widened host stride: sizeof(*items). */
        for (i = 0; i < count; ++i) {
            rome2_entity_str_assign_view(&items[i], &args->arg10->items[i]);
        }
    }
    if (globals == NULL) {
        globals = &image_defaults;
    }
    /* Build selected fields privately; host padding is outside the contract.
     * Original prefix-commit ordering is not reproduced. Publish on success. */
    memset(&result, 0, sizeof(result));
    result.dispatch.slot0 = ROME2_ENTITY_DISPATCH0;
    result.dispatch.slot1 = ROME2_ENTITY_DISPATCH1;
    result.dispatch.slot2 = ROME2_ENTITY_DISPATCH2;
    rome2_entity_str_assign_literal(&result.effect_name, ROME2_ENTITY_NAME);
    rome2_unit_card_str_reset(&result.category);
    if (args->arg09 != NULL) {
        result.origin_x = args->arg09->x;
        result.origin_y = args->arg09->y;
    }
    rome2_unit_card_str_reset(&result.label);
    result.grid_extent_min = globals->grid_extent_min;
    result.grid_extent_max = globals->grid_extent_max;
    rome2_unit_card_str_reset(&result.descriptor_text);
    result.activation_radius_min = ROME2_ENTITY_ACTIVATION_RADIUS;
    result.activation_radius_max = ROME2_ENTITY_ACTIVATION_RADIUS;
    result.point_count = ROME2_ENTITY_DEFAULT_POINT_COUNT;
    result.owner_id = args->arg05;
    result.mode = (uint8_t)args->arg12;             /* 0x10cbe3ff/406 */
    result.owner_ref = args->arg14;                /* 0x10cbe409/430 */
    /* The scratch string is explicitly constructed at 0x10cbe433, then
     * passed by value to the RET 0x18 climate constructor at 0x10cbe43b. */
    rome2_entity_str_assign_literal(&scratch, ROME2_ENTITY_SCRATCH_NAME);
    rome2_climate_record_ctor(&result.climate, &scratch,
        args->arg02, args->arg03, args->arg04);
    rome2_entity_str_assign_view(&result.label_alt, args->arg00);
    if (args->arg01 != NULL) {
        result.tag_lo = args->arg01[0];
        result.tag_hi = args->arg01[1];
    }
    result.item_count = count;
    result.item_capacity = count;
    result.items = items;
    rome2_entity_str_assign_view(&result.effect_kind, args->arg17);
    result.flag_0cc = (uint8_t)args->arg18;         /* 0x10cbe505/513 */
    rome2_entity_str_assign_view(&result.source_name, args->arg11);
    result.flag_0dc = (uint8_t)args->arg13;         /* 0x10cbe51e/526 */
    result.field_0e0 = args->arg15;                /* 0x10cbe52c/530 */
    result.flag_0e4 = (uint8_t)args->arg16;         /* 0x10cbe536/53a */
    /* No ownership transfer of the incoming arg06..arg08 string. */
    *self = result;
    return self;
}

bool rome2_battle_entity_release_items(rome2_battle_entity *self,
    const rome2_entity_host *host)
{
    if (self == NULL) {
        return false;
    }
    if (self->items != NULL) {
        if (host == NULL || host->free_items == NULL) {
            return false;
        }
        host->free_items(self->items);
    }
    self->items = NULL;
    self->item_count = 0;
    self->item_capacity = 0;
    return true;
}
