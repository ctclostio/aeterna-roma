#include "ported_100edd70_policy.h"

/*
 * Pinned literal from VA 0x1173f894, raw file offset 0x173e294, 44 bytes /
 * 22 UTF-16LE code units including its NUL terminator:
 *   "-no_exception_handler"
 * Expressed as explicit numeric units; no wchar_t dependency.
 */
static const uint16_t rome2_no_exception_handler_literal[22] = {
    UINT16_C(0x002d), /* U+002D '-'    */
    UINT16_C(0x006e), /* U+006E 'n'    */
    UINT16_C(0x006f), /* U+006F 'o'    */
    UINT16_C(0x005f), /* U+005F '_'    */
    UINT16_C(0x0065), /* U+0065 'e'    */
    UINT16_C(0x0078), /* U+0078 'x'    */
    UINT16_C(0x0063), /* U+0063 'c'    */
    UINT16_C(0x0065), /* U+0065 'e'    */
    UINT16_C(0x0070), /* U+0070 'p'    */
    UINT16_C(0x0074), /* U+0074 't'    */
    UINT16_C(0x0069), /* U+0069 'i'    */
    UINT16_C(0x006f), /* U+006F 'o'    */
    UINT16_C(0x006e), /* U+006E 'n'    */
    UINT16_C(0x005f), /* U+005F '_'    */
    UINT16_C(0x0068), /* U+0068 'h'    */
    UINT16_C(0x0061), /* U+0061 'a'    */
    UINT16_C(0x006e), /* U+006E 'n'    */
    UINT16_C(0x0064), /* U+0064 'd'    */
    UINT16_C(0x006c), /* U+006C 'l'    */
    UINT16_C(0x0065), /* U+0065 'e'    */
    UINT16_C(0x0072), /* U+0072 'r'    */
    UINT16_C(0x0000)  /* U+0000 NUL    */
};

rome2_guest_status rome2_port_100edd70_select_invalid_parameter_policy(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 command_line,
    rome2_invalid_parameter_policy *policy_out)
{
    rome2_guest_addr32 cursor;
    rome2_guest_status status;
    uint16_t unit;
    size_t index;

    if (policy_out == NULL) {
        return ROME2_GUEST_BAD_ARGUMENT;
    }

    cursor = command_line;
    for (index = 0; index < 22; ++index) {
        status = rome2_guest_read_u16_le(view, cursor, &unit);
        if (status != ROME2_GUEST_OK) {
            return status;
        }
        if (unit != rome2_no_exception_handler_literal[index]) {
            /* First mismatch decides immediately; the unread suffix,
             * even if it lies outside the view, no longer matters. */
            *policy_out = ROME2_INVALID_PARAMETER_INSTALL_HANDLER;
            return ROME2_GUEST_OK;
        }
        if (index != 21) {
            status = rome2_guest_add_checked(cursor, UINT32_C(2), &cursor);
            if (status != ROME2_GUEST_OK) {
                return status;
            }
        }
    }

    *policy_out = ROME2_INVALID_PARAMETER_SKIP_HANDLER;
    return ROME2_GUEST_OK;
}

