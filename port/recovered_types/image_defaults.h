#ifndef ROME2_RECOVERED_IMAGE_DEFAULTS_H
#define ROME2_RECOVERED_IMAGE_DEFAULTS_H

#include "guest32_layouts.h"

/* Typed initial-image values authenticated by contracts.json. This snapshot
 * precedes original initializers and is NOT a live process-global binding.
 * Original sentinel and observer addresses remain data/code identities.
 */
typedef struct rome2_initial_global_snapshot {
    uint8_t narrow_terminator;                   /* 11af4088 */
    uint8_t narrow_empty_unit;                   /* 11af408e */
    uint16_t wide_empty_unit;                    /* 11af4090 */
    rome2_code_address32 allocation_observer;    /* 119f3eb0 */
    float unit_colour_a, unit_colour_b;          /* 11afbf14/18 */
    uint8_t unit_retail_flag;                    /* 11afbd20 */
    float unit_grid_min, unit_grid_max;          /* 11971460/64 */
    float entity_grid_min, entity_grid_max;      /* 11f958ec/f0 */
} rome2_initial_global_snapshot;

static inline rome2_initial_global_snapshot rome2_recovered_image_defaults(void)
{
    rome2_initial_global_snapshot values = {
        0, 0, 0, 0, 0.0f, 0.0f, 0, -1.0f, -1.0f, 0.0f, 0.0f
    };
    return values;
}

#endif
