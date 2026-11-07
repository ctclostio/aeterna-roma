#include "fauna_config.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>

static bool wide_equal(const rome2_host_string16 *s, const char *ascii, bool fold)
{
    size_t i;
    const size_t length = strlen(ascii);
    if ((size_t)s->length_units != length) { return false; }
    for (i = 0; i < length; ++i) {
        uint16_t c = s->data[i];
        if (fold && c >= 'A' && c <= 'Z') { c = (uint16_t)(c + ('a' - 'A')); }
        if (c != (unsigned char)ascii[i]) { return false; }
    }
    return true;
}

static const rome2_xml_node *first_named(const rome2_xml_node *parent, const char *name)
{
    const rome2_xml_node *n;
    for (n = parent->first_child; n != NULL; n = n->next_sibling) {
        if (wide_equal(&n->name, name, false)) { return n; }
    }
    return NULL;
}

static uint32_t unsigned_scalar(const rome2_xml_node *n)
{
    uint32_t value = 0;
    int32_t i;
    if (n == NULL) { return 0; }
    for (i = 0; i < n->text.length_units; ++i) {
        const uint16_t c = n->text.data[i];
        if (c < '0' || c > '9') { return 0; }
        value = value * UINT32_C(10) + (uint32_t)(c - '0');
    }
    return value;
}

static bool digit(uint16_t c) { return c >= '0' && c <= '9'; }
static bool classic_space(uint16_t c)
{
    return c == ' ' || (c >= '\t' && c <= '\r');
}

/* 11347ed0 retains 36 significant mantissa digits and eight non-leading
 * exponent digits; discarded integer digits/leading fractional zeros become
 * a separate power-of-ten adjustment. 11347490 scans that bounded token and
 * rounds its scaling steps to binary32. This is intentionally not strtof of
 * the complete, unnormalized source. Input units are bounded by the DOM. */
static float probability(const rome2_xml_node *n, _locale_t locale)
{
    char token[60];
    size_t at = 0, p = 0, significant = 0, exponent_digits = 0;
    int32_t adjustment = 0;
    bool any = false, integer = false, exponent_zero = false, exponent_any = false;
    float value = 0.0f;
    float small_step;
    const uint32_t small_step_bits = UINT32_C(0x33d6bf97);
    const uint16_t *s;
    if (n == NULL) { return 0.0f; }
    s = n->text.data;
    while (classic_space(s[p])) { ++p; }
    if (s[p] == '+' || s[p] == '-') { token[at++] = (char)s[p++]; }
    while (digit(s[p])) {
        if (significant < 36u) {
            if (s[p] != '0' || significant != 0) { token[at++] = (char)s[p]; ++significant; }
        } else { ++adjustment; }
        ++p; any = true; integer = true;
    }
    if (integer && significant == 0) { token[at++] = '0'; }
    if (s[p] == '.') { token[at++] = '.'; ++p; }
    if (significant == 0) {
        while (s[p] == '0') { --adjustment; ++p; any = true; }
        if (adjustment < 0) { token[at++] = '0'; ++adjustment; }
    }
    while (digit(s[p])) {
        if (significant < 36u) { token[at++] = (char)s[p]; ++significant; }
        ++p; any = true;
    }
    if (any && (s[p] == 'e' || s[p] == 'E')) {
        token[at++] = 'e'; ++p;
        if (s[p] == '+' || s[p] == '-') { token[at++] = (char)s[p++]; }
        while (s[p] == '0') { ++p; exponent_zero = true; }
        if (exponent_zero) { token[at++] = '0'; exponent_any = true; }
        while (digit(s[p])) {
            if (exponent_digits < 8u) { token[at++] = (char)s[p]; ++exponent_digits; }
            ++p; exponent_any = true;
        }
        if (!exponent_any) { any = false; }
    }
    if (!any) { return 0.0f; }
    token[at] = '\0';
    if (_sscanf_s_l(token, "%f", locale, &value) != 1) { return 0.0f; }
    memcpy(&small_step, &small_step_bits, sizeof small_step);
    while (adjustment >= 8) {
        value *= 10.0f; value *= 10000000.0f; adjustment -= 8;
    }
    while (adjustment > 0) { value *= 10.0f; --adjustment; }
    while (adjustment <= -8) {
        value *= 0.1f; value *= small_step; adjustment += 8;
    }
    while (adjustment < 0) { value *= 0.1f; ++adjustment; }
    return value;
}

typedef struct named_mask { const char *name; uint32_t bit; } named_mask;

static uint32_t conditions(const rome2_xml_node *parent, const char *key,
    const named_mask *values, size_t count, uint32_t any_mask)
{
    const rome2_xml_node *n;
    uint32_t mask = 0;
    size_t i;
    if (parent == NULL) { return 0; }
    for (n = parent->first_child; n != NULL; n = n->next_sibling) {
        if (!wide_equal(&n->name, key, false)) { continue; }
        if (any_mask != 0 && wide_equal(&n->text, "any", true)) { mask = any_mask; continue; }
        for (i = 0; i < count; ++i) {
            if (wide_equal(&n->text, values[i].name, true)) { mask |= values[i].bit; break; }
        }
    }
    return mask;
}

static size_t encoded_size(const rome2_host_string16 *s)
{
    int32_t i;
    size_t bytes = 0;
    for (i = 0; i < s->length_units && s->data[i] != 0; ++i) {
        bytes += s->data[i] < 0x80 ? 1u : (s->data[i] < 0x800 ? 2u : 3u);
    }
    return bytes;
}

static void encode_lower(char *out, const rome2_host_string16 *s)
{
    int32_t i;
    size_t p = 0;
    for (i = 0; i < s->length_units && s->data[i] != 0; ++i) {
        uint16_t c = s->data[i];
        if (c < 0x80) {
            if (c >= 'A' && c <= 'Z') { c = (uint16_t)(c + ('a' - 'A')); }
            out[p++] = (char)c;
        } else if (c < 0x800) {
            out[p++] = (char)(0xc0u | (c >> 6));
            out[p++] = (char)(0x80u | (c & 0x3fu));
        } else {
            out[p++] = (char)(0xe0u | (c >> 12));
            out[p++] = (char)(0x80u | ((c >> 6) & 0x3fu));
            out[p++] = (char)(0x80u | (c & 0x3fu));
        }
    }
    out[p] = '\0';
}

static rome2_fauna_config_status append_record(rome2_owned_fauna_vector *out,
    const rome2_xml_node *node, const rome2_owned_string_allocator *a, _locale_t locale)
{
    static const char *const animals[] = {"deer", "wolf", "lion", "elephant", "camel", "boar",
        "horse", "milan", "turtle_dove", "crow", "vulture", "ibis", "peasant", "whale", "seagull"};
    static const named_mask tiles[] = {{"inland", 1}, {"open_sea", 2}, {"coastal", 4}};
    static const named_mask seasons[] = {{"spring", 1}, {"summer", 2}, {"autumn", 4}, {"winter", 8}};
    static const named_mask times[] = {{"day", 1}, {"night", 2}};
    static const named_mask precip[] = {{"dry", 1}, {"rain", 2}, {"snow", 4}, {"fog", 8}};
    rome2_fauna_record record = {0};
    const rome2_xml_node *spawn = first_named(node, "spawn_conditions"), *n;
    size_t i, bytes = 0, count = 0, raw_bytes = 0;
    void *raw = NULL;
    rome2_host_string8 *strings = NULL;
    char *data;
    rome2_fauna_status status;
    for (i = 0; i < sizeof animals / sizeof animals[0]; ++i) {
        if (wide_equal(&node->name, animals[i], true)) { record.values.animal_type = (uint32_t)i; break; }
    }
    record.values.min_entities = unsigned_scalar(first_named(node, "min_entities"));
    record.values.max_entities = unsigned_scalar(first_named(node, "max_entities"));
    record.values.spawn_probability = probability(first_named(node, "spawn_probability"), locale);
    record.values.tile_mask = conditions(spawn, "tile", tiles, 3, 0);
    record.values.season_mask = conditions(spawn, "season", seasons, 4, 15);
    record.values.time_of_day_mask = conditions(spawn, "time_of_day", times, 2, 3);
    record.values.precipitation_mask = conditions(spawn, "precipitation", precip, 4, 15);
    if (spawn != NULL) {
        for (n = spawn->first_child; n != NULL; n = n->next_sibling) {
            if (wide_equal(&n->name, "climate", false)) { ++count; bytes += encoded_size(&n->text) + 1u; }
        }
    }
    if (count > ROME2_FAUNA_MAX_STRINGS || bytes > INT32_MAX) { return ROME2_FAUNA_CONFIG_LIMIT_EXCEEDED; }
    if (count != 0) {
        raw_bytes = count * sizeof *strings + bytes + 7u;
        raw = a->allocate(a->context, raw_bytes, 0);
        if (raw == NULL) { return ROME2_FAUNA_CONFIG_ALLOCATION_FAILED; }
        strings = (rome2_host_string8 *)(void *)((unsigned char *)raw + ((8u - (uintptr_t)raw % 8u) % 8u));
        data = (char *)(void *)(strings + count);
        i = 0;
        for (n = spawn->first_child; n != NULL; n = n->next_sibling) {
            if (wide_equal(&n->name, "climate", false)) {
                const size_t length = encoded_size(&n->text);
                strings[i].length = (int32_t)length; strings[i].capacity = (int32_t)length;
                strings[i].data = data;
                encode_lower(data, &n->text); data += length + 1u; ++i;
            }
        }
    }
    record.strings.count = (uint32_t)count; record.strings.capacity = (uint32_t)count;
    record.strings.items = strings;
    status = rome2_owned_fauna_vector_push(out, &record);
    if (raw != NULL) { a->release(a->context, raw, raw_bytes, 0); }
    if (status == ROME2_FAUNA_OK) { return ROME2_FAUNA_CONFIG_OK; }
    return status == ROME2_FAUNA_ALLOCATION_FAILED ? ROME2_FAUNA_CONFIG_ALLOCATION_FAILED :
        ROME2_FAUNA_CONFIG_INTERNAL_ERROR;
}

static rome2_fauna_config_status decode_children(rome2_owned_fauna_vector **out,
    const rome2_xml_node *parent, const rome2_owned_string_allocator *a)
{
    rome2_owned_fauna_vector *result = NULL;
    const rome2_xml_node *node;
    rome2_fauna_config_status status = ROME2_FAUNA_CONFIG_OK;
    rome2_fauna_status fauna;
    _locale_t locale = _create_locale(LC_ALL, "C");
    if (locale == NULL) { return ROME2_FAUNA_CONFIG_SYSTEM_ERROR; }
    fauna = rome2_owned_fauna_vector_create(&result, a);
    if (fauna != ROME2_FAUNA_OK) { status = ROME2_FAUNA_CONFIG_ALLOCATION_FAILED; goto cleanup; }
    for (node = parent->first_child; node != NULL; node = node->next_sibling) {
        status = append_record(result, node, a, locale);
        if (status != ROME2_FAUNA_CONFIG_OK) { goto cleanup; }
    }
cleanup:
    _free_locale(locale);
    if (status == ROME2_FAUNA_CONFIG_OK) { *out = result; }
    else if (result != NULL) { (void)rome2_owned_fauna_vector_destroy(&result); }
    return status;
}

rome2_fauna_config_status rome2_fauna_config_decode_node(
    rome2_owned_fauna_vector **out, const rome2_xml_document *document,
    const rome2_xml_node *parent, const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator a;
    if (out == NULL || *out != NULL || !rome2_xml_document_contains_node(document, parent)) {
        return ROME2_FAUNA_CONFIG_BAD_ARGUMENT;
    }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_FAUNA_CONFIG_INVALID_ALLOCATOR;
    }
    a = *allocator;
    return decode_children(out, parent, &a);
}

rome2_fauna_config_status rome2_fauna_config_decode(rome2_owned_fauna_vector **out,
    const unsigned char *bytes, size_t size, const rome2_owned_string_allocator *allocator,
    rome2_xml_status *xml_error)
{
    rome2_owned_string_allocator a;
    rome2_xml_document *doc = NULL;
    rome2_owned_fauna_vector *result = NULL;
    const rome2_xml_node *root;
    rome2_xml_status xml;
    rome2_fauna_config_status status;
    if (xml_error != NULL) { *xml_error = ROME2_XML_OK; }
    if (out == NULL || *out != NULL || (size != 0 && bytes == NULL)) { return ROME2_FAUNA_CONFIG_BAD_ARGUMENT; }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) {
        return ROME2_FAUNA_CONFIG_INVALID_ALLOCATOR;
    }
    a = *allocator;
    xml = rome2_xml_document_parse(&doc, bytes, size, &a);
    if (xml_error != NULL) { *xml_error = xml; }
    if (xml != ROME2_XML_OK) {
        return xml == ROME2_XML_ALLOCATION_FAILED ? ROME2_FAUNA_CONFIG_ALLOCATION_FAILED :
            ROME2_FAUNA_CONFIG_XML_ERROR;
    }
    root = rome2_xml_document_root(doc);
    status = root != NULL && wide_equal(&root->name, "fauna_config", false) ?
        decode_children(&result, root, &a) : ROME2_FAUNA_CONFIG_ROOT_NOT_FOUND;
    if (rome2_xml_document_destroy(&doc) != ROME2_XML_OK) { status = ROME2_FAUNA_CONFIG_INTERNAL_ERROR; }
    if (status == ROME2_FAUNA_CONFIG_OK) { *out = result; }
    else if (result != NULL) { (void)rome2_owned_fauna_vector_destroy(&result); }
    return status;
}
