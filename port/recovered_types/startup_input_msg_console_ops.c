#include "startup_input_msg_console_ops.h"

#include <stdio.h>
#include <string.h>

static uint32_t rb_parent(const rome2_startup_rb_tree *tree, uint32_t idx) {
    return (idx <= ROME2_STARTUP_MAX_RB_NODES) ? tree->nodes[idx].parent_idx : 0u;
}

static uint32_t rb_left(const rome2_startup_rb_tree *tree, uint32_t idx) {
    return (idx <= ROME2_STARTUP_MAX_RB_NODES) ? tree->nodes[idx].left_idx : 0u;
}

static uint32_t rb_right(const rome2_startup_rb_tree *tree, uint32_t idx) {
    return (idx <= ROME2_STARTUP_MAX_RB_NODES) ? tree->nodes[idx].right_idx : 0u;
}

static uint8_t rb_is_nil(const rome2_startup_rb_tree *tree, uint32_t idx) {
    return (idx == 0u || idx > ROME2_STARTUP_MAX_RB_NODES) ? 1u : tree->nodes[idx].guest.is_nil_29;
}

static uint8_t rb_color(const rome2_startup_rb_tree *tree, uint32_t idx) {
    return (idx == 0u || idx > ROME2_STARTUP_MAX_RB_NODES) ? 1u : tree->nodes[idx].guest.color_28;
}

static void rb_set_color(rome2_startup_rb_tree *tree, uint32_t idx, uint8_t color) {
    if (idx > 0u && idx <= ROME2_STARTUP_MAX_RB_NODES) {
        tree->nodes[idx].guest.color_28 = color;
    }
}

static void rb_set_parent(rome2_startup_rb_tree *tree, uint32_t idx, uint32_t p) {
    if (idx > 0u && idx <= ROME2_STARTUP_MAX_RB_NODES) {
        tree->nodes[idx].parent_idx = p;
    }
}

static void rb_replace_child(rome2_startup_rb_tree *tree, uint32_t parent, uint32_t old_ch, uint32_t new_ch) {
    if (parent == 0u) {
        tree->root_idx = new_ch;
        tree->nodes[0].parent_idx = new_ch;
    } else if (parent <= ROME2_STARTUP_MAX_RB_NODES) {
        if (tree->nodes[parent].left_idx == old_ch) {
            tree->nodes[parent].left_idx = new_ch;
        } else {
            tree->nodes[parent].right_idx = new_ch;
        }
    }
}

static void record_console_freed_va(rome2_startup_console_registry_env *env, uint32_t va) {
    if (env && va != 0u) {
        if (env->freed_count < 16u) {
            env->freed_vas[env->freed_count] = va;
        }
        env->freed_count += 1u;
    }
}

static void init_warscape_console_slot(
    rome2_startup_console_registry_env *env,
    rome2_startup_warscape_console_group *group,
    size_t idx,
    uint32_t va,
    const char *name,
    uint32_t vtable_va,
    uint32_t tag) {
    if (!group || idx >= 8u) {
        return;
    }
    rome2_startup_console_node_init_100f0fd0(&group->slots[idx], name);
    group->slots[idx].layout.vtable_00 = vtable_va;
    group->slots[idx].layout.tag_or_slot_3c = tag;
    group->slots[idx].node_va = va;
    group->slot_vas[idx] = va;
    if (idx >= 1u && env) {
        group->slots[idx].registered = 1u;
        if (env->registered_count < 8u) {
            env->registered_node_vas[env->registered_count] = va;
        }
        env->registered_count += 1u;
    }
}

static uint32_t dinput_poll_single(
    uint32_t poll_hr,
    uint32_t reacquire_hr,
    uint32_t retry_hr,
    uint32_t *acquire_calls,
    uint32_t *unacquire_calls) {
    if (poll_hr == 0u) {
        return 0u;
    }
    if (poll_hr != ROME2_STARTUP_DIERR_INPUTLOST && poll_hr != ROME2_STARTUP_DIERR_NOTACQUIRED) {
        return poll_hr;
    }
    *acquire_calls += 1u;
    if (reacquire_hr != 0u) {
        return reacquire_hr;
    }
    if (retry_hr == 0u) {
        return 0u;
    }
    *unacquire_calls += 1u;
    return retry_hr;
}

static void init_wfstream_internal_ptrs(rome2_startup_wfstream_filebuf_state *fb) {
    fb->dirty_36 = 0u;
    fb->slot_08 = 0u;
    fb->ptr_0c = 0x04u;
    fb->ptr_10 = 0x08u;
    fb->ptr_1c = 0x14u;
    fb->ptr_20 = 0x18u;
    fb->ptr_2c = 0x24u;
    fb->ptr_30 = 0x28u;
}

/* `0x112bff20` */
uint8_t rome2_startup_get_vfs_flag_112bff20(uint8_t global_12031ae5) {
    return global_12031ae5;
}

/* `0x112ac3f0` */
void rome2_startup_sub_u64_112ac3f0(uint64_t *out, const uint64_t *lhs, const uint64_t *rhs) {
    if (out && lhs && rhs) {
        *out = *lhs - *rhs;
    }
}

/* `0x11683d60` */
double rome2_startup_crt_ultod3_11683d60(uint32_t lo_ecx, uint32_t hi_edx) {
    static const double k_adj[2] = { 0.0, 4294967296.0 };
    double lo = (double)(int32_t)lo_ecx + k_adj[lo_ecx >> 31];
    if (hi_edx == 0u) {
        return lo;
    }
    {
        double hi = ((double)(int32_t)hi_edx + k_adj[hi_edx >> 31]) * k_adj[1];
        return lo + hi;
    }
}

/* `0x112e2c20` */
uint32_t rome2_startup_u64_us_to_ms_112e2c20(uint64_t us) {
    return (uint32_t)(us / 1000ULL);
}

/* `0x112e2b00` */
float rome2_startup_u64_us_to_seconds_112e2b00(uint64_t us) {
    uint64_t ms64 = us / 1000ULL;
    double ms_f64 = rome2_startup_crt_ultod3_11683d60(
        (uint32_t)(ms64 & 0xFFFFFFFFu),
        (uint32_t)(ms64 >> 32));
    return (float)ms_f64 * 0.001f;
}

/* `0x10101980` */
rome2_startup_power_info *rome2_startup_query_power_info_10101980(
    rome2_startup_power_info *out,
    const rome2_startup_sys_power_status12_32 *os_status) {
    if (!out || !os_status) {
        return out;
    }
    out->battery_state = -1;
    out->is_charging = 0u;
    if (os_status->ac_line_status_00 == 0u) {
        out->ac_status = 1;
    } else {
        out->ac_status = (os_status->ac_line_status_00 != 0xFFu) ? 0 : -1;
    }
    if (os_status->battery_flag_01 == 0u) {
        out->battery_state = 1;
        out->battery_life_time_sec = os_status->battery_life_time_04;
        return out;
    }
    if ((os_status->battery_flag_01 & 1u) != 0u) {
        out->battery_state = 0;
    }
    if ((os_status->battery_flag_01 & 2u) != 0u) {
        out->battery_state = 1;
    }
    if ((os_status->battery_flag_01 & 4u) != 0u) {
        out->battery_state = 2;
    }
    if ((os_status->battery_flag_01 & 8u) != 0u) {
        out->is_charging = 1u;
    }
    out->battery_life_time_sec = os_status->battery_life_time_04;
    if ((int8_t)os_status->battery_flag_01 < 0) {
        out->battery_state = 3;
    }
    return out;
}

/* `0x101061b0` */
uint32_t rome2_startup_pump_messages_101061b0(rome2_startup_msg_pump_env *env) {
    uint32_t last_msg = 0u;
    if (!env) {
        return 0u;
    }
    while (env->cursor < env->count && env->cursor < ROME2_STARTUP_MAX_MSG_QUEUE) {
        last_msg = env->queue[env->cursor].message;
        env->cursor += 1u;
        env->translated_count += 1u;
        env->dispatched_count += 1u;
        if (last_msg == ROME2_STARTUP_MSG_WM_QUIT) {
            return 1u;
        }
        if (last_msg == ROME2_STARTUP_MSG_WM_SYSCHAR) {
            break;
        }
        last_msg = 0u;
    }
    return last_msg & 0xFFFFFF00u;
}

/* `0x1010eda0` */
uint8_t rome2_startup_poll_dinput_1010eda0(rome2_startup_dinput_env *env) {
    uint32_t k_hr = 0u;
    uint32_t m_hr = 0u;
    if (!env || env->has_keyboard == 0u) {
        return 0u;
    }
    memset(&env->pub_mouse, 0, sizeof(env->pub_mouse));
    memcpy(env->prev_keys, env->curr_keys, sizeof(env->prev_keys));

    k_hr = dinput_poll_single(
        env->kbd_poll_hr, env->kbd_reacquire_hr, env->kbd_retry_hr,
        &env->kbd_acquire_calls, &env->kbd_unacquire_calls);
    if (k_hr != 0u) {
        return 0u;
    }
    memcpy(env->curr_keys, env->next_keys, sizeof(env->curr_keys));

    memset(&env->scratch_mouse, 0, sizeof(env->scratch_mouse));
    if (env->has_mouse == 0u) {
        return 0u;
    }
    m_hr = dinput_poll_single(
        env->mouse_poll_hr, env->mouse_reacquire_hr, env->mouse_retry_hr,
        &env->mouse_acquire_calls, &env->mouse_unacquire_calls);
    if (m_hr != 0u) {
        return 0u;
    }

    env->scratch_mouse = env->next_mouse;
    env->pub_mouse.dx_f32_00 = (float)env->scratch_mouse.lX_00;
    env->pub_mouse.neg_dy_f32_04 = -(float)env->scratch_mouse.lY_04;
    env->pub_mouse.neg_dz_f32_08 = -(float)env->scratch_mouse.lZ_08;
    env->pub_mouse.btn0_0c = (uint8_t)(env->scratch_mouse.rgb_buttons_0c[0] >> 7);
    env->pub_mouse.btn2_0d = (uint8_t)(env->scratch_mouse.rgb_buttons_0c[2] >> 7);
    env->pub_mouse.btn1_0e = (uint8_t)(env->scratch_mouse.rgb_buttons_0c[1] >> 7);
    return 1u;
}

/* `0x100eabf0` */
uint32_t rome2_startup_dir_rb_max_100eabf0(const rome2_startup_rb_tree *tree, uint32_t idx) {
    uint32_t steps = 0u;
    if (!tree || idx == 0u || idx > ROME2_STARTUP_MAX_RB_NODES) {
        return idx;
    }
    while (rb_is_nil(tree, rb_right(tree, idx)) == 0u && steps <= ROME2_STARTUP_MAX_RB_NODES) {
        idx = rb_right(tree, idx);
        steps += 1u;
    }
    return idx;
}

/* `0x100eac10` */
uint32_t rome2_startup_dir_rb_min_100eac10(const rome2_startup_rb_tree *tree, uint32_t idx) {
    uint32_t steps = 0u;
    if (!tree || idx == 0u || idx > ROME2_STARTUP_MAX_RB_NODES) {
        return idx;
    }
    while (rb_is_nil(tree, rb_left(tree, idx)) == 0u && steps <= ROME2_STARTUP_MAX_RB_NODES) {
        idx = rb_left(tree, idx);
        steps += 1u;
    }
    return idx;
}

/* `0x100eaba0` */
void rome2_startup_dir_rb_lrotate_100eaba0(rome2_startup_rb_tree *tree, uint32_t idx) {
    uint32_t pivot = 0u;
    uint32_t p_left = 0u;
    uint32_t parent = 0u;
    if (!tree || idx == 0u || idx > ROME2_STARTUP_MAX_RB_NODES) {
        return;
    }
    pivot = tree->nodes[idx].right_idx;
    if (pivot == 0u || pivot > ROME2_STARTUP_MAX_RB_NODES) {
        return;
    }
    p_left = tree->nodes[pivot].left_idx;
    tree->nodes[idx].right_idx = p_left;
    if (rb_is_nil(tree, p_left) == 0u && p_left <= ROME2_STARTUP_MAX_RB_NODES) {
        tree->nodes[p_left].parent_idx = idx;
    }
    parent = tree->nodes[idx].parent_idx;
    tree->nodes[pivot].parent_idx = parent;
    rb_replace_child(tree, parent, idx, pivot);
    tree->nodes[pivot].left_idx = idx;
    tree->nodes[idx].parent_idx = pivot;
}

/* `0x100ec560` */
void rome2_startup_dir_rb_rrotate_100ec560(rome2_startup_rb_tree *tree, uint32_t idx) {
    uint32_t pivot = 0u;
    uint32_t p_right = 0u;
    uint32_t parent = 0u;
    if (!tree || idx == 0u || idx > ROME2_STARTUP_MAX_RB_NODES) {
        return;
    }
    pivot = tree->nodes[idx].left_idx;
    if (pivot == 0u || pivot > ROME2_STARTUP_MAX_RB_NODES) {
        return;
    }
    p_right = tree->nodes[pivot].right_idx;
    tree->nodes[idx].left_idx = p_right;
    if (rb_is_nil(tree, p_right) == 0u && p_right <= ROME2_STARTUP_MAX_RB_NODES) {
        tree->nodes[p_right].parent_idx = idx;
    }
    parent = tree->nodes[idx].parent_idx;
    tree->nodes[pivot].parent_idx = parent;
    rb_replace_child(tree, parent, idx, pivot);
    tree->nodes[pivot].right_idx = idx;
    tree->nodes[idx].parent_idx = pivot;
}

/* `0x100e0ff0` */
void rome2_startup_dir_rb_iter_next_100e0ff0(const rome2_startup_rb_tree *tree, uint32_t *idx_inout) {
    uint32_t node = 0u;
    uint32_t p = 0u;
    uint32_t steps = 0u;
    if (!tree || !idx_inout) {
        return;
    }
    node = *idx_inout;
    if (rb_is_nil(tree, node) != 0u) {
        return;
    }
    if (rb_is_nil(tree, rb_right(tree, node)) == 0u) {
        *idx_inout = rome2_startup_dir_rb_min_100eac10(tree, rb_right(tree, node));
        return;
    }
    p = rb_parent(tree, node);
    while (rb_is_nil(tree, p) == 0u && node == rb_right(tree, p) && steps <= ROME2_STARTUP_MAX_RB_NODES) {
        node = p;
        p = rb_parent(tree, node);
        steps += 1u;
    }
    *idx_inout = p;
}

/* `0x100e7920` */
void rome2_startup_dir_rb_erase_subtree_100e7920(rome2_startup_rb_tree *tree, uint32_t root_idx) {
    uint32_t stack[ROME2_STARTUP_MAX_RB_NODES + 1u];
    uint32_t top = 0u;
    if (!tree || rb_is_nil(tree, root_idx) != 0u) {
        return;
    }
    stack[top++] = root_idx;
    while (top > 0u) {
        uint32_t cur = stack[--top];
        while (rb_is_nil(tree, cur) == 0u && cur <= ROME2_STARTUP_MAX_RB_NODES) {
            uint32_t r = tree->nodes[cur].right_idx;
            uint32_t l = tree->nodes[cur].left_idx;
            if (rb_is_nil(tree, r) == 0u && top <= ROME2_STARTUP_MAX_RB_NODES) {
                stack[top++] = r;
            }
            memset(&tree->nodes[cur], 0, sizeof(tree->nodes[cur]));
            tree->nodes[cur].guest.is_nil_29 = 1u;
            tree->nodes[cur].guest.color_28 = 1u;
            if (tree->count > 0u) {
                tree->count -= 1u;
            }
            cur = l;
        }
    }
}

/* `0x100e7960` */
uint32_t rome2_startup_dir_rb_erase_100e7960(rome2_startup_rb_tree *tree, uint32_t where_idx) {
    uint32_t next_idx = where_idx;
    uint32_t fix_node = 0u;
    uint32_t fix_parent = 0u;
    uint32_t splice = where_idx;
    uint8_t erased_color = 1u;
    uint32_t steps = 0u;

    if (!tree || where_idx == 0u || where_idx > ROME2_STARTUP_MAX_RB_NODES || rb_is_nil(tree, where_idx) != 0u) {
        return 0u;
    }

    rome2_startup_dir_rb_iter_next_100e0ff0(tree, &next_idx);
    if (rb_is_nil(tree, rb_left(tree, where_idx)) != 0u) {
        fix_node = rb_right(tree, where_idx);
    } else if (rb_is_nil(tree, rb_right(tree, where_idx)) != 0u) {
        fix_node = rb_left(tree, where_idx);
    } else {
        splice = next_idx;
        fix_node = rb_right(tree, splice);
    }

    if (splice == where_idx) {
        fix_parent = rb_parent(tree, where_idx);
        if (rb_is_nil(tree, fix_node) == 0u) {
            rb_set_parent(tree, fix_node, fix_parent);
        }
        rb_replace_child(tree, fix_parent, where_idx, fix_node);
        if (tree->leftmost_idx == where_idx) {
            tree->leftmost_idx = rb_is_nil(tree, fix_node) != 0u
                                     ? fix_parent
                                     : rome2_startup_dir_rb_min_100eac10(tree, fix_node);
        }
        if (tree->rightmost_idx == where_idx) {
            tree->rightmost_idx = rb_is_nil(tree, fix_node) != 0u
                                      ? fix_parent
                                      : rome2_startup_dir_rb_max_100eabf0(tree, fix_node);
        }
        erased_color = rb_color(tree, where_idx);
    } else {
        uint8_t orig_color = rb_color(tree, where_idx);
        rb_set_parent(tree, rb_left(tree, where_idx), splice);
        tree->nodes[splice].left_idx = rb_left(tree, where_idx);
        if (splice == rb_right(tree, where_idx)) {
            fix_parent = splice;
        } else {
            fix_parent = rb_parent(tree, splice);
            if (rb_is_nil(tree, fix_node) == 0u) {
                rb_set_parent(tree, fix_node, fix_parent);
            }
            if (fix_parent <= ROME2_STARTUP_MAX_RB_NODES) {
                tree->nodes[fix_parent].left_idx = fix_node;
            }
            tree->nodes[splice].right_idx = rb_right(tree, where_idx);
            rb_set_parent(tree, rb_right(tree, where_idx), splice);
        }
        rb_replace_child(tree, rb_parent(tree, where_idx), where_idx, splice);
        rb_set_parent(tree, splice, rb_parent(tree, where_idx));
        erased_color = rb_color(tree, splice);
        rb_set_color(tree, splice, orig_color);
    }

    if (erased_color == 1u) {
        while (fix_node != tree->root_idx && rb_color(tree, fix_node) == 1u && steps <= ROME2_STARTUP_MAX_RB_NODES) {
            steps += 1u;
            if (fix_node == rb_left(tree, fix_parent)) {
                uint32_t sib = rb_right(tree, fix_parent);
                if (rb_color(tree, sib) == 0u) {
                    rb_set_color(tree, sib, 1u);
                    rb_set_color(tree, fix_parent, 0u);
                    rome2_startup_dir_rb_lrotate_100eaba0(tree, fix_parent);
                    sib = rb_right(tree, fix_parent);
                }
                if (rb_is_nil(tree, sib) != 0u) {
                    break;
                }
                if (rb_color(tree, rb_left(tree, sib)) == 1u && rb_color(tree, rb_right(tree, sib)) == 1u) {
                    rb_set_color(tree, sib, 0u);
                    fix_node = fix_parent;
                    fix_parent = rb_parent(tree, fix_node);
                } else {
                    if (rb_color(tree, rb_right(tree, sib)) == 1u) {
                        rb_set_color(tree, rb_left(tree, sib), 1u);
                        rb_set_color(tree, sib, 0u);
                        rome2_startup_dir_rb_rrotate_100ec560(tree, sib);
                        sib = rb_right(tree, fix_parent);
                    }
                    rb_set_color(tree, sib, rb_color(tree, fix_parent));
                    rb_set_color(tree, fix_parent, 1u);
                    rb_set_color(tree, rb_right(tree, sib), 1u);
                    rome2_startup_dir_rb_lrotate_100eaba0(tree, fix_parent);
                    break;
                }
            } else {
                uint32_t sib = rb_left(tree, fix_parent);
                if (rb_color(tree, sib) == 0u) {
                    rb_set_color(tree, sib, 1u);
                    rb_set_color(tree, fix_parent, 0u);
                    rome2_startup_dir_rb_rrotate_100ec560(tree, fix_parent);
                    sib = rb_left(tree, fix_parent);
                }
                if (rb_is_nil(tree, sib) != 0u) {
                    break;
                }
                if (rb_color(tree, rb_right(tree, sib)) == 1u && rb_color(tree, rb_left(tree, sib)) == 1u) {
                    rb_set_color(tree, sib, 0u);
                    fix_node = fix_parent;
                    fix_parent = rb_parent(tree, fix_node);
                } else {
                    if (rb_color(tree, rb_left(tree, sib)) == 1u) {
                        rb_set_color(tree, rb_right(tree, sib), 1u);
                        rb_set_color(tree, sib, 0u);
                        rome2_startup_dir_rb_lrotate_100eaba0(tree, sib);
                        sib = rb_left(tree, fix_parent);
                    }
                    rb_set_color(tree, sib, rb_color(tree, fix_parent));
                    rb_set_color(tree, fix_parent, 1u);
                    rb_set_color(tree, rb_left(tree, sib), 1u);
                    rome2_startup_dir_rb_rrotate_100ec560(tree, fix_parent);
                    break;
                }
            }
        }
        rb_set_color(tree, fix_node, 1u);
    }

    memset(&tree->nodes[where_idx], 0, sizeof(tree->nodes[where_idx]));
    tree->nodes[where_idx].guest.is_nil_29 = 1u;
    tree->nodes[where_idx].guest.color_28 = 1u;
    if (tree->count > 0u) {
        tree->count -= 1u;
    }
    return next_idx;
}

/* `0x100f2d60` */
rome2_vfs_reg_status rome2_startup_concat_cstr_and_str_100f2d60(
    const char *prefix,
    const char *suffix,
    char *out_buf,
    size_t out_cap,
    size_t *out_len) {
    size_t plen = 0u;
    size_t slen = 0u;
    if (!prefix || !suffix || !out_buf || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    plen = strlen(prefix);
    slen = strlen(suffix);
    if (plen + slen + 1u > out_cap) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    memcpy(out_buf, prefix, plen);
    memcpy(out_buf + plen, suffix, slen);
    out_buf[plen + slen] = '\0';
    if (out_len) {
        *out_len = plen + slen;
    }
    return ROME2_VFS_REG_OK;
}

/* `0x100f7260` */
int32_t rome2_startup_utf16_slice_compare_range_100f7260(
    const rome2_startup_utf16_cslice *lhs,
    uint32_t offset,
    uint32_t count,
    const rome2_startup_utf16_cslice *rhs) {
    uint32_t avail = 0u;
    uint32_t rlen = 0u;
    uint32_t cmp_len = 0u;
    uint32_t i = 0u;

    if (!lhs || !rhs) {
        return 0;
    }
    avail = (offset < lhs->len) ? (lhs->len - offset) : 0u;
    if (count < avail) {
        avail = count;
    }
    rlen = rhs->len;
    cmp_len = (avail < rlen) ? avail : rlen;
    for (i = 0u; i < cmp_len; ++i) {
        uint16_t a = lhs->buf ? lhs->buf[offset + i] : 0u;
        uint16_t b = rhs->buf ? rhs->buf[i] : 0u;
        if (a != b) {
            return (int32_t)a - (int32_t)b;
        }
    }
    if (avail < rlen) {
        return -1;
    }
    if (avail > rlen) {
        return 1;
    }
    return 0;
}

/* `0x10114380` */
int32_t rome2_startup_utf16_slice_rfind_char_10114380(
    const rome2_startup_utf16_cslice *slice,
    uint16_t ch,
    uint32_t max_pos) {
    uint32_t lim = 0u;
    uint32_t i = 0u;
    if (!slice || !slice->buf || slice->len == 0u || max_pos == 0u) {
        return -1;
    }
    lim = (slice->len < max_pos) ? slice->len : max_pos;
    for (i = lim; i > 0u; --i) {
        if (slice->buf[i - 1u] == ch) {
            return (int32_t)(i - 1u);
        }
    }
    return -1;
}

/* `0x100f5f20` */
uint8_t rome2_startup_format_utf16_str_spec_100f5f20(
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len,
    uint16_t spec_ch,
    const uint16_t *arg_u16,
    char *err_diag_ascii,
    size_t err_cap) {
    size_t cur = 0u;
    size_t slen = 0u;
    if (!out_u16 || out_cap == 0u || !out_len) {
        return 0u;
    }
    if (spec_ch != (uint16_t)'C' && spec_ch != (uint16_t)'S' && spec_ch != (uint16_t)'s') {
        if (err_diag_ascii && err_cap > 0u) {
            (void)snprintf(
                err_diag_ascii, err_cap,
                "Unexpected format %%%c used with type const UniChar16*",
                (int)(spec_ch & 0xFFu));
        }
        return 0u;
    }
    cur = *out_len;
    if (arg_u16) {
        while (arg_u16[slen] != 0u && cur + slen + 1u < out_cap) {
            out_u16[cur + slen] = arg_u16[slen];
            slen += 1u;
        }
    }
    cur += slen;
    if (cur < out_cap) {
        out_u16[cur] = 0u;
    }
    *out_len = cur;
    return 1u;
}

/* `0x1011fb70` */
uint8_t rome2_startup_format_next_utf16_spec_1011fb70(
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len,
    const uint16_t *fmt_u16,
    size_t *fmt_pos_inout,
    const uint16_t *arg_u16,
    char *err_diag_ascii,
    size_t err_cap) {
    size_t pos = 0u;
    if (!out_u16 || out_cap == 0u || !out_len || !fmt_u16 || !fmt_pos_inout) {
        return 0u;
    }
    pos = *fmt_pos_inout;
    while (fmt_u16[pos] != 0u) {
        if (fmt_u16[pos] == (uint16_t)'%') {
            pos += 1u;
            if (fmt_u16[pos] == (uint16_t)'l') {
                pos += 1u;
            }
            if (fmt_u16[pos] == 0u) {
                return 0u;
            }
            {
                uint16_t spec = fmt_u16[pos];
                uint8_t ok = rome2_startup_format_utf16_str_spec_100f5f20(
                    out_u16, out_cap, out_len, spec, arg_u16, err_diag_ascii, err_cap);
                pos += 1u;
                *fmt_pos_inout = pos;
                return ok;
            }
        }
        if (*out_len + 1u < out_cap) {
            out_u16[*out_len] = fmt_u16[pos];
            *out_len += 1u;
            out_u16[*out_len] = 0u;
        }
        pos += 1u;
    }
    *fmt_pos_inout = pos;
    return 0u;
}

/* `0x10121350` */
rome2_vfs_reg_status rome2_startup_build_user_subpath_10121350(
    rome2_startup_path_env *path_env,
    uint32_t category_idx,
    const uint16_t *rel_name_u16,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len) {
    const uint16_t *cached_base = NULL;
    const char *col0 = NULL;
    uint16_t col0_u16[64];
    size_t col0_len = 0u;
    size_t rel_len = 0u;
    rome2_startup_utf16_cslice rel_slice;
    rome2_startup_utf16_cslice col0_slice;
    uint8_t append_col0 = 1u;

    if (!path_env || !rel_name_u16 || !out_u16 || out_cap == 0u) {
        return ROME2_VFS_REG_BAD_ARGUMENT;
    }
    cached_base = rome2_startup_get_cached_user_folder_path_10120d90(path_env, category_idx);
    if (!cached_base) {
        return ROME2_VFS_REG_RANGE_ERROR;
    }
    col0 = rome2_startup_get_user_folder_col0_prefix_10122e40(category_idx);
    if (!col0) {
        col0 = "";
    }
    while (col0[col0_len] != '\0' && col0_len < 63u) {
        col0_u16[col0_len] = (uint8_t)col0[col0_len];
        col0_len += 1u;
    }
    col0_u16[col0_len] = 0u;

    while (rel_name_u16[rel_len] != 0u && rel_len < ROME2_STARTUP_MAX_PATH_U16) {
        rel_len += 1u;
    }
    rel_slice.len = (uint32_t)rel_len;
    rel_slice.cap = (uint32_t)rel_len;
    rel_slice.buf = rel_name_u16;
    col0_slice.len = (uint32_t)col0_len;
    col0_slice.cap = (uint32_t)col0_len;
    col0_slice.buf = col0_u16;

    if (rel_len >= col0_len &&
        rome2_startup_utf16_slice_compare_range_100f7260(
            &rel_slice, (uint32_t)(rel_len - col0_len), UINT32_MAX, &col0_slice) == 0) {
        append_col0 = 0u;
    }

    out_u16[0] = 0u;
    if (out_len) {
        *out_len = 0u;
    }
    if (append_col0 == 0u) {
        return rome2_startup_utf16_concat_100e1050(cached_base, rel_name_u16, out_u16, out_cap, out_len);
    }
    {
        static const uint16_t k_fmt3[7] = { '%', 's', '%', 's', '%', 's', 0 };
        size_t pos = 0u;
        size_t written = 0u;
        char diag[80];
        if (rome2_startup_format_next_utf16_spec_1011fb70(
                out_u16, out_cap, &written, k_fmt3, &pos, cached_base, diag, sizeof(diag)) == 0u ||
            rome2_startup_format_next_utf16_spec_1011fb70(
                out_u16, out_cap, &written, k_fmt3, &pos, rel_name_u16, diag, sizeof(diag)) == 0u ||
            rome2_startup_format_next_utf16_spec_1011fb70(
                out_u16, out_cap, &written, k_fmt3, &pos, col0_u16, diag, sizeof(diag)) == 0u) {
            return ROME2_VFS_REG_RANGE_ERROR;
        }
        if (out_len) {
            *out_len = written;
        }
        return ROME2_VFS_REG_OK;
    }
}

/* `0x100ddfc0` */
rome2_vfs_reg_status rome2_startup_format_user_appdata_rel_100ddfc0(
    rome2_startup_path_env *path_env,
    uint16_t *out_u16,
    size_t out_cap,
    size_t *out_len) {
    static const uint16_t k_user[5] = { 'u', 's', 'e', 'r', 0 };
    return rome2_startup_build_user_subpath_10121350(
        path_env, 8u, k_user, out_u16, out_cap, out_len);
}

/* `0x11349100` */
void rome2_startup_wfstream_filebuf_init_open_11349100(
    rome2_startup_wfstream_filebuf_state *fb,
    rome2_startup_crt_stream_model *file_stream,
    int32_t open_mode,
    uint32_t global_locale_120351cc) {
    if (!fb) {
        return;
    }
    init_wfstream_internal_ptrs(fb);
    fb->is_wide_mode_3c = (open_mode == 1) ? 1u : 0u;
    fb->file_40 = file_stream;
    fb->locale_38 = global_locale_120351cc;
}

/* `0x11347290` */
rome2_startup_wfstream_filebuf_state *rome2_startup_wfstream_filebuf_close_11347290(
    rome2_startup_wfstream_filebuf_state *fb,
    rome2_startup_crt_stdio_env *crt_env,
    uint32_t global_locale_120351cc) {
    rome2_startup_wfstream_filebuf_state *ret = NULL;
    if (!fb) {
        return NULL;
    }
    if (fb->file_40 != NULL) {
        if (rome2_startup_crt_fclose_1168ed98(crt_env, fb->file_40) == 0) {
            ret = fb;
        }
    }
    init_wfstream_internal_ptrs(fb);
    fb->is_wide_mode_3c = 0u;
    fb->file_40 = NULL;
    fb->locale_38 = global_locale_120351cc;
    return ret;
}

/* `0x100d1e30` */
void rome2_startup_ptr_vec12_init_100d1e30(rome2_startup_ptr_vec12 *vec) {
    if (!vec) {
        return;
    }
    vec->cap = 0u;
    vec->count = 0u;
    vec->backing_va = 0u;
}

/* `0x100d32b0` */
void rome2_startup_ptr_vec12_destroy_100d32b0(rome2_startup_ptr_vec12 *vec) {
    uint32_t i = 0u;
    if (!vec) {
        return;
    }
    for (i = 0u; i < vec->count && i < 8u; ++i) {
        if (vec->element_vas[i] != 0u) {
            if (vec->destroyed_count < 8u) {
                vec->destroyed_element_vas[vec->destroyed_count] = vec->element_vas[i];
            }
            vec->destroyed_count += 1u;
            vec->element_vas[i] = 0u;
        }
    }
    if (vec->backing_va != 0u) {
        vec->backing_freed = 1u;
        vec->backing_va = 0u;
    }
}

/* `0x100d3690` */
void rome2_startup_warscape_console_group_destroy_100d3690(
    rome2_startup_warscape_console_group *group) {
    size_t i = 0u;
    if (!group) {
        return;
    }
    for (i = 1u; i < 8u; ++i) {
        if (group->slot_vas[i] != 0u) {
            if (group->destroyed_count < 8u) {
                group->destroyed_slot_vas[group->destroyed_count] = group->slot_vas[i];
            }
            group->destroyed_count += 1u;
            group->slot_vas[i] = 0u;
        }
    }
}

/* `0x100f0fd0` */
void rome2_startup_console_node_init_100f0fd0(
    rome2_startup_console_cmd_entry *node,
    const char *name) {
    size_t nlen = 0u;
    if (!node) {
        return;
    }
    memset(&node->layout, 0, sizeof(node->layout));
    node->layout.vtable_00 = ROME2_STARTUP_VTABLE_CONSOLE_BASE;
    nlen = name ? strlen(name) : 0u;
    if (nlen >= sizeof(node->name)) {
        nlen = sizeof(node->name) - 1u;
    }
    node->layout.name_08.length = (uint32_t)nlen;
    if (nlen > 0u && name) {
        memcpy(node->name, name, nlen);
    }
    node->name[nlen] = '\0';
    node->layout.desc_14.length = 9u;
    memcpy(node->desc, "<Unknown>", 10u);
    node->layout.index_34 = -1;
    node->layout.flag_38 = 0u;
}

/* `0x100fc8f0` */
void rome2_startup_init_global_console_registry_100fc8f0(
    rome2_startup_console_registry_env *env,
    uint32_t cfg_word_04,
    uint32_t cfg_word_08) {
    if (!env) {
        return;
    }
    rome2_startup_console_node_init_100f0fd0(&env->registry_base_node, "");
    env->registry_raw_va = 0x60001000u;
    env->global_registry_va = 0x60001004u;
    env->registry_vtable_00 = ROME2_STARTUP_VTABLE_CONSOLE_REG;
    env->registry_base_node.layout.vtable_00 = ROME2_STARTUP_VTABLE_CONSOLE_REG;
    env->registry_observer_vtable_3c = ROME2_STARTUP_VTABLE_OBSERVER_NODE;
    env->cfg_field_04 = cfg_word_04;
    env->cfg_field_08 = cfg_word_08;
}

/* `0x100fd130` */
void rome2_startup_destroy_global_console_registry_100fd130(
    rome2_startup_console_registry_env *env) {
    if (!env || env->global_registry_va == 0u) {
        return;
    }
    record_console_freed_va(env, env->registry_raw_va);
    env->registry_raw_va = 0u;
    env->global_registry_va = 0u;
}

/* `0x100d2860` */
void rome2_startup_warscape_console_group_init_100d2860(
    rome2_startup_console_registry_env *env,
    rome2_startup_warscape_console_group *group) {
    static const char *const k_cvar_names[5] = {
        "Warscape/Debug Line Renderer",
        "Warscape/Shadows",
        "Warscape/WireFrame",
        "Warscape/MipLevel",
        "Warscape/TexelDensity",
    };
    size_t i = 0u;
    if (!group) {
        return;
    }
    memset(group, 0, sizeof(*group));
    if (!env || env->global_registry_va == 0u) {
        return;
    }
    init_warscape_console_slot(
        env, group, 0u, 0x60002000u, "Warscape/Show profiler",
        ROME2_STARTUP_VTABLE_WARSCAPE_CVAR, env->crash_singleton_va + 1u);
    init_warscape_console_slot(
        env, group, 1u, 0x60002040u, "Warscape/Reload FX",
        ROME2_STARTUP_VTABLE_WARSCAPE_RELOAD, 1u);
    init_warscape_console_slot(
        env, group, 2u, 0x60002080u, "Warscape/Reload Textures",
        ROME2_STARTUP_VTABLE_WARSCAPE_RELOAD, 2u);
    for (i = 0u; i < 5u; ++i) {
        init_warscape_console_slot(
            env, group, 3u + i, 0x600020c0u + (uint32_t)(i * 0x40u),
            k_cvar_names[i], ROME2_STARTUP_VTABLE_WARSCAPE_CVAR, env->crash_iface_slots[i]);
    }
}

/* `0x100e8660` */
uint8_t rome2_startup_handler_warscape_console_init_100e8660(
    rome2_startup_console_registry_env *env,
    uint32_t ctx_va,
    uint32_t empire_app_va,
    rome2_startup_warscape_console_group *group_storage,
    rome2_startup_ptr_vec12 *vec_storage) {
    (void)ctx_va;
    if (!env) {
        return 0u;
    }
    env->handler_vtable_00 = ROME2_STARTUP_VTABLE_CONSOLE_HANDLER;
    rome2_startup_init_global_console_registry_100fc8f0(env, empire_app_va + 0x80cu, 0x1000u);
    env->flag_100d6560 = 0u;
    env->group_04 = group_storage;
    if (group_storage) {
        env->group_04_va = 0x60003000u;
        rome2_startup_warscape_console_group_init_100d2860(env, group_storage);
    } else {
        env->group_04_va = 0u;
    }
    env->vec_08 = vec_storage;
    if (vec_storage) {
        env->vec_08_va = 0x60004000u;
        rome2_startup_ptr_vec12_init_100d1e30(vec_storage);
    } else {
        env->vec_08_va = 0u;
    }
    return 1u;
}

/* `0x100e12e0` */
uint32_t rome2_startup_handler_warscape_console_dtor_100e12e0(
    rome2_startup_console_registry_env *env,
    uint8_t flags) {
    if (!env) {
        return 0u;
    }
    env->handler_vtable_00 = ROME2_STARTUP_VTABLE_CONSOLE_HANDLER;
    if (env->vec_08 != NULL && env->vec_08_va != 0u) {
        rome2_startup_ptr_vec12_destroy_100d32b0(env->vec_08);
        record_console_freed_va(env, env->vec_08_va);
        env->vec_08_va = 0u;
        env->vec_08 = NULL;
    }
    if (env->group_04 != NULL && env->group_04_va != 0u) {
        rome2_startup_warscape_console_group_destroy_100d3690(env->group_04);
        record_console_freed_va(env, env->group_04_va);
        env->group_04_va = 0u;
        env->group_04 = NULL;
    }
    rome2_startup_destroy_global_console_registry_100fd130(env);
    env->handler_vtable_00 = ROME2_STARTUP_VTABLE_BASE_ADAPTER;
    if ((flags & 1u) != 0u) {
        record_console_freed_va(env, env->handler_va);
    }
    return env->handler_va;
}
