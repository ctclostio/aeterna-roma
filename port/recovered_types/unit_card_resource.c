#include "unit_card_resource.h"

static void diagnostic_init(rome2_card_resource_diagnostic *d)
{
    d->pack = ROME2_PACK_OK; d->config = ROME2_FAUNA_CONFIG_OK;
    d->xml = ROME2_XML_OK; d->card = ROME2_UNIT_CARD_OK;
    d->selected_archive = SIZE_MAX;
}

static bool valid_inputs(const uint16_t *const *paths, size_t count,
    const rome2_owned_string_allocator *a)
{
    size_t i;
    if (a == NULL || a->allocate == NULL || a->release == NULL || (count != 0 && paths == NULL)) {
        return false;
    }
    for (i = 0; i < count; ++i) { if (paths[i] == NULL || paths[i][0] == 0) { return false; } }
    return true;
}

static rome2_card_resource_status load_config(rome2_owned_fauna_vector **out,
    const uint16_t *const *paths, size_t count, const rome2_owned_string_allocator *a,
    rome2_card_resource_diagnostic *d)
{
    rome2_pack_blob *blob = NULL;
    const rome2_pack_blob_view *view;
    size_t i;
    d->pack = ROME2_PACK_NOT_FOUND;
    for (i = 0; i < count; ++i) {
        d->pack = rome2_pack_read_file(&blob, paths[i], "Script/fauna_config.xml",
            16u * 1024u * 1024u, a);
        if (d->pack == ROME2_PACK_NOT_FOUND) { continue; }
        if (d->pack != ROME2_PACK_OK) { return ROME2_CARD_RESOURCE_PACK_ERROR; }
        d->selected_archive = i;
        break;
    }
    if (blob == NULL) { return ROME2_CARD_RESOURCE_PACK_ERROR; }
    view = rome2_pack_blob_get(blob);
    if (view == NULL) {
        d->pack = ROME2_PACK_CORRUPT;
        (void)rome2_pack_blob_destroy(&blob);
        return ROME2_CARD_RESOURCE_PACK_ERROR;
    }
    d->config = rome2_fauna_config_decode(out, view->data, view->size, a, &d->xml);
    (void)rome2_pack_blob_destroy(&blob);
    return d->config == ROME2_FAUNA_CONFIG_OK ? ROME2_CARD_RESOURCE_OK : ROME2_CARD_RESOURCE_CONFIG_ERROR;
}

static rome2_card_resource_status apply_setup(rome2_owned_unit_card *card,
    const rome2_owned_fauna_vector *config, rome2_card_resource_diagnostic *d)
{
    const rome2_fauna_vector_view *view = rome2_owned_fauna_vector_get(config);
    if (view == NULL) { d->config = ROME2_FAUNA_CONFIG_INTERNAL_ERROR; return ROME2_CARD_RESOURCE_CONFIG_ERROR; }
    /* Setup has already cleared. An empty decoded node needs no replacement
     * handle/backing allocation and retains the original backing identity. */
    if (view->count == 0) { return ROME2_CARD_RESOURCE_OK; }
    d->card = rome2_owned_unit_card_replace_config(card, view);
    return d->card == ROME2_UNIT_CARD_OK ? ROME2_CARD_RESOURCE_OK : ROME2_CARD_RESOURCE_CARD_ERROR;
}

rome2_card_resource_status rome2_owned_unit_card_create_from_packs(
    rome2_owned_unit_card **out, const rome2_unit_card_args *args,
    const rome2_unit_card_globals *globals, const uint16_t *const *archive_paths,
    size_t archive_count, const rome2_owned_string_allocator *allocator,
    rome2_card_resource_diagnostic *diagnostic)
{
    rome2_card_resource_diagnostic local;
    rome2_owned_string_allocator a;
    rome2_owned_fauna_vector *config = NULL;
    rome2_owned_unit_card *result = NULL;
    rome2_card_resource_status status;
    diagnostic_init(&local);
    if (out == NULL || *out != NULL || args == NULL || !valid_inputs(archive_paths, archive_count, allocator)) {
        status = ROME2_CARD_RESOURCE_BAD_ARGUMENT; goto done;
    }
    a = *allocator;
    status = load_config(&config, archive_paths, archive_count, &a, &local);
    if (status != ROME2_CARD_RESOURCE_OK) { goto done; }
    local.card = rome2_owned_unit_card_create_from_config(&result, args, globals,
        rome2_owned_fauna_vector_get(config), &a);
    status = local.card == ROME2_UNIT_CARD_OK ? ROME2_CARD_RESOURCE_OK : ROME2_CARD_RESOURCE_CARD_ERROR;
    (void)rome2_owned_fauna_vector_destroy(&config);
    if (status == ROME2_CARD_RESOURCE_OK) { *out = result; }
done:
    if (diagnostic != NULL) { *diagnostic = local; }
    return status;
}

rome2_card_resource_status rome2_owned_unit_card_reload_from_packs(
    rome2_owned_unit_card *card, const uint16_t *const *archive_paths,
    size_t archive_count, const rome2_owned_string_allocator *allocator,
    rome2_card_resource_diagnostic *diagnostic)
{
    rome2_card_resource_diagnostic local;
    rome2_owned_string_allocator a;
    rome2_owned_fauna_vector *config = NULL;
    rome2_card_resource_status status;
    diagnostic_init(&local);
    if (rome2_owned_unit_card_get(card) == NULL || !valid_inputs(archive_paths, archive_count, allocator)) {
        status = ROME2_CARD_RESOURCE_BAD_ARGUMENT; goto done;
    }
    a = *allocator;
    status = load_config(&config, archive_paths, archive_count, &a, &local);
    if (status != ROME2_CARD_RESOURCE_OK) { goto done; }
    local.card = rome2_owned_unit_card_replace_config(card, rome2_owned_fauna_vector_get(config));
    status = local.card == ROME2_UNIT_CARD_OK ? ROME2_CARD_RESOURCE_OK : ROME2_CARD_RESOURCE_CARD_ERROR;
    (void)rome2_owned_fauna_vector_destroy(&config);
done:
    if (diagnostic != NULL) { *diagnostic = local; }
    return status;
}

rome2_card_resource_status rome2_owned_unit_card_setup_from_packs(
    rome2_owned_unit_card *card, const uint16_t *const *archive_paths,
    size_t archive_count, const rome2_owned_string_allocator *allocator,
    rome2_card_resource_diagnostic *diagnostic)
{
    rome2_card_resource_diagnostic local;
    rome2_owned_string_allocator a;
    rome2_owned_fauna_vector *config = NULL;
    rome2_card_resource_status status;
    diagnostic_init(&local);
    if (rome2_owned_unit_card_get(card) == NULL || !valid_inputs(archive_paths, archive_count, allocator)) {
        status = ROME2_CARD_RESOURCE_BAD_ARGUMENT; goto done;
    }
    /* Capture before clear can invoke release/observer callbacks. */
    a = *allocator;
    local.card = rome2_owned_unit_card_clear_fauna(card);
    if (local.card != ROME2_UNIT_CARD_OK) {
        status = ROME2_CARD_RESOURCE_CARD_ERROR; goto done;
    }
    status = load_config(&config, archive_paths, archive_count, &a, &local);
    if (status == ROME2_CARD_RESOURCE_OK) { status = apply_setup(card, config, &local); }
    (void)rome2_owned_fauna_vector_destroy(&config);
done:
    if (diagnostic != NULL) { *diagnostic = local; }
    return status;
}

rome2_card_resource_status rome2_owned_unit_card_setup_from_xml_node(
    rome2_owned_unit_card *card, const rome2_xml_document *document,
    const rome2_xml_node *parent, const rome2_owned_string_allocator *allocator,
    rome2_card_resource_diagnostic *diagnostic)
{
    rome2_card_resource_diagnostic local;
    rome2_owned_string_allocator a;
    rome2_owned_fauna_vector *config = NULL;
    rome2_card_resource_status status;
    diagnostic_init(&local);
    if (rome2_owned_unit_card_get(card) == NULL || !valid_inputs(NULL, 0, allocator) ||
        !rome2_xml_document_contains_node(document, parent)) {
        status = ROME2_CARD_RESOURCE_BAD_ARGUMENT; goto done;
    }
    a = *allocator;
    local.card = rome2_owned_unit_card_clear_fauna(card);
    if (local.card != ROME2_UNIT_CARD_OK) { status = ROME2_CARD_RESOURCE_CARD_ERROR; goto done; }
    local.config = rome2_fauna_config_decode_node(&config, document, parent, &a);
    status = local.config == ROME2_FAUNA_CONFIG_OK ? apply_setup(card, config, &local) : ROME2_CARD_RESOURCE_CONFIG_ERROR;
    (void)rome2_owned_fauna_vector_destroy(&config);
done:
    if (diagnostic != NULL) { *diagnostic = local; }
    return status;
}
