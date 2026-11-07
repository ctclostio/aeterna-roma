#define COBJMACROS
#include "native_xml.h"
#include <windows.h>
#include <objidl.h>
#include <shlwapi.h>
#include <xmllite.h>
#include <string.h>

#define XML_LIVE UINT32_C(0x584d4c44)
#define XML_MAX_BYTES (16u * 1024u * 1024u)
#define XML_MAX_DEPTH 128u
#define XML_MAX_NODES 1000000u

typedef struct xml_owned_node {
    rome2_xml_node view;
    struct xml_owned_node *next_owned, *last_child;
    void *raw;
    rome2_host_string16 name, text;
    rome2_owned_string_owner name_owner, text_owner;
} xml_owned_node;

struct rome2_xml_document {
    uint32_t state, node_count;
    const rome2_xml_document *self;
    void *raw;
    rome2_owned_string_allocator allocator;
    xml_owned_node *nodes, *root;
};

static void *align8(void *raw)
{
    return (unsigned char *)raw + (8u - (uintptr_t)raw % 8u) % 8u;
}

static bool live(const rome2_xml_document *h)
{
    return h != NULL && h->state == XML_LIVE && h->self == h && h->raw != NULL &&
        align8(h->raw) == h && h->allocator.allocate != NULL && h->allocator.release != NULL;
}

static rome2_xml_status string_status(rome2_owned_string_status s)
{
    if (s == ROME2_OWNED_STRING_OK) { return ROME2_XML_OK; }
    return s == ROME2_OWNED_STRING_ALLOCATION_FAILED ? ROME2_XML_ALLOCATION_FAILED : ROME2_XML_SYSTEM_ERROR;
}

static rome2_xml_status read_status(HRESULT hr)
{
    if (hr == E_OUTOFMEMORY) { return ROME2_XML_ALLOCATION_FAILED; }
    if (hr == (HRESULT)WC_E_DTDPROHIBITED) { return ROME2_XML_UNSUPPORTED; }
    if (hr == (HRESULT)SC_E_MAXELEMENTDEPTH) { return ROME2_XML_LIMIT_EXCEEDED; }
    return ROME2_XML_MALFORMED;
}

static rome2_xml_status discard(rome2_xml_document *h)
{
    const rome2_owned_string_allocator a = h->allocator;
    void *handle_raw = h->raw;
    xml_owned_node *n = h->nodes;
    rome2_xml_status status = ROME2_XML_OK;
    h->state = 0; h->nodes = NULL; h->root = NULL;
    while (n != NULL) {
        xml_owned_node *next = n->next_owned;
        void *raw = n->raw;
        if (rome2_owned_string16_destroy(&n->name, &n->name_owner) != ROME2_OWNED_STRING_OK) {
            status = ROME2_XML_SYSTEM_ERROR;
        }
        if (rome2_owned_string16_destroy(&n->text, &n->text_owner) != ROME2_OWNED_STRING_OK) {
            status = ROME2_XML_SYSTEM_ERROR;
        }
        a.release(a.context, raw, sizeof *n + 7u, 0);
        n = next;
    }
    a.release(a.context, handle_raw, sizeof *h + 7u, 0);
    return status;
}

/* Check both elements and attributes. Namespace declarations are deliberately
 * outside this frontend's admitted domain, even xmlns="". */
static rome2_xml_status no_namespace(IXmlReader *reader)
{
    LPCWSTR value = NULL;
    UINT length = 0;
    HRESULT hr = IXmlReader_GetPrefix(reader, &value, &length);
    if (FAILED(hr)) { return read_status(hr); }
    if (length != 0) { return ROME2_XML_UNSUPPORTED; }
    hr = IXmlReader_GetNamespaceUri(reader, &value, &length);
    if (FAILED(hr)) { return read_status(hr); }
    return length == 0 ? ROME2_XML_OK : ROME2_XML_UNSUPPORTED;
}

static rome2_xml_status check_attributes(IXmlReader *reader)
{
    HRESULT hr = IXmlReader_MoveToFirstAttribute(reader);
    while (hr == S_OK) {
        const rome2_xml_status s = no_namespace(reader);
        if (s != ROME2_XML_OK) { return s; }
        hr = IXmlReader_MoveToNextAttribute(reader);
    }
    if (FAILED(hr)) { return read_status(hr); }
    hr = IXmlReader_MoveToElement(reader);
    return FAILED(hr) ? read_status(hr) : ROME2_XML_OK;
}

static rome2_xml_status make_node(rome2_xml_document *h, IXmlReader *reader,
    xml_owned_node *parent, xml_owned_node **out)
{
    xml_owned_node *n;
    LPCWSTR name = NULL;
    UINT length = 0;
    void *raw;
    rome2_xml_status s;
    rome2_string16_view source;
    const rome2_string16_view empty = {NULL, 0};
    HRESULT hr = IXmlReader_GetLocalName(reader, &name, &length);
    if (FAILED(hr)) { return read_status(hr); }
    if (length == 0 || length > INT32_MAX) { return ROME2_XML_MALFORMED; }
    if (h->node_count == XML_MAX_NODES) { return ROME2_XML_LIMIT_EXCEEDED; }
    raw = h->allocator.allocate(h->allocator.context, sizeof *n + 7u, 0);
    if (raw == NULL) { return ROME2_XML_ALLOCATION_FAILED; }
    n = align8(raw); memset(n, 0, sizeof *n); n->raw = raw;
    n->next_owned = h->nodes; h->nodes = n; ++h->node_count;
    source.data = (const uint16_t *)name; source.length_units = length;
    s = string_status(rome2_owned_string16_copy(&n->name, &n->name_owner, source, &h->allocator));
    if (s != ROME2_XML_OK) { return s; }
    s = string_status(rome2_owned_string16_copy(&n->text, &n->text_owner, empty, &h->allocator));
    if (s != ROME2_XML_OK) { return s; }
    n->view.name = n->name; n->view.text = n->text;
    if (parent == NULL) { h->root = n; }
    else {
        if (parent->last_child == NULL) { parent->view.first_child = &n->view; }
        else { parent->last_child->view.next_sibling = &n->view; }
        parent->last_child = n; ++parent->view.child_count;
    }
    *out = n;
    return ROME2_XML_OK;
}

static rome2_xml_status append_text(rome2_xml_document *h, xml_owned_node *n, IXmlReader *reader)
{
    LPCWSTR value = NULL;
    UINT length = 0;
    rome2_host_string16 fresh = {0};
    rome2_owned_string_owner owner = ROME2_OWNED_STRING_OWNER_INIT;
    rome2_string16_view source;
    uint16_t *combined;
    void *raw = NULL;
    size_t bytes = 0;
    rome2_xml_status status;
    HRESULT hr = IXmlReader_GetValue(reader, &value, &length);
    if (FAILED(hr)) { return read_status(hr); }
    if (length == 0) { return ROME2_XML_OK; }
    if (length > INT32_MAX || (uint32_t)n->text.length_units > (uint32_t)INT32_MAX - length) {
        return ROME2_XML_LIMIT_EXCEEDED;
    }
    source.data = (const uint16_t *)value;
    source.length_units = n->text.length_units + (ptrdiff_t)length;
    if (n->text.length_units != 0) {
        bytes = (size_t)source.length_units * sizeof *combined + 1u;
        raw = h->allocator.allocate(h->allocator.context, bytes, 0);
        if (raw == NULL) { return ROME2_XML_ALLOCATION_FAILED; }
        combined = (uint16_t *)(void *)((unsigned char *)raw + (uintptr_t)raw % 2u);
        memcpy(combined, n->text.data, (size_t)n->text.length_units * sizeof *combined);
        memcpy(combined + n->text.length_units, value, (size_t)length * sizeof *combined);
        source.data = combined;
    }
    status = string_status(rome2_owned_string16_copy(&fresh, &owner, source, &h->allocator));
    if (raw != NULL) { h->allocator.release(h->allocator.context, raw, bytes, 0); }
    if (status != ROME2_XML_OK) { return status; }
    status = string_status(rome2_owned_string16_destroy(&n->text, &n->text_owner));
    if (status == ROME2_XML_OK) {
        status = string_status(rome2_owned_string16_move(&n->text, &n->text_owner, &fresh, &owner));
    }
    (void)rome2_owned_string16_destroy(&fresh, &owner);
    if (status == ROME2_XML_OK) { n->view.text = n->text; }
    return status;
}

static rome2_xml_status read_tree(rome2_xml_document *h, IXmlReader *reader)
{
    xml_owned_node *stack[XML_MAX_DEPTH] = {0};
    UINT open = 0;
    XmlNodeType type;
    HRESULT hr;
    while ((hr = IXmlReader_Read(reader, &type)) == S_OK) {
        rome2_xml_status s;
        UINT depth = 0;
        if (type == XmlNodeType_Element) {
            BOOL empty;
            xml_owned_node *n = NULL;
            hr = IXmlReader_GetDepth(reader, &depth);
            if (FAILED(hr)) { return read_status(hr); }
            if (depth >= XML_MAX_DEPTH) { return ROME2_XML_LIMIT_EXCEEDED; }
            if (depth != open || (depth == 0 && h->root != NULL)) { return ROME2_XML_MALFORMED; }
            empty = IXmlReader_IsEmptyElement(reader);
            s = no_namespace(reader);
            if (s != ROME2_XML_OK) { return s; }
            s = check_attributes(reader);
            if (s != ROME2_XML_OK) { return s; }
            s = make_node(h, reader, open == 0 ? NULL : stack[open - 1u], &n);
            if (s != ROME2_XML_OK) { return s; }
            if (!empty) { stack[open++] = n; }
        } else if (type == XmlNodeType_EndElement) {
            hr = IXmlReader_GetDepth(reader, &depth);
            if (FAILED(hr)) { return read_status(hr); }
            /* XmlLite reports end-element depth after its open element. */
            if (open == 0 || depth != open) { return ROME2_XML_MALFORMED; }
            stack[--open] = NULL;
        } else if (type == XmlNodeType_Text || type == XmlNodeType_CDATA || type == XmlNodeType_Whitespace) {
            if (open != 0) {
                s = append_text(h, stack[open - 1u], reader);
                if (s != ROME2_XML_OK) { return s; }
            }
        } else if (type == XmlNodeType_DocumentType) { return ROME2_XML_UNSUPPORTED; }
    }
    if (hr != S_FALSE) { return read_status(hr); }
    return open == 0 && h->root != NULL && IXmlReader_IsEOF(reader) ? ROME2_XML_OK : ROME2_XML_MALFORMED;
}

rome2_xml_status rome2_xml_document_parse(rome2_xml_document **out,
    const unsigned char *bytes, size_t size, const rome2_owned_string_allocator *allocator)
{
    rome2_owned_string_allocator a;
    rome2_xml_document *h;
    void *raw;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    HRESULT hr;
    rome2_xml_status status;
    if (out == NULL || *out != NULL || (size != 0 && bytes == NULL)) { return ROME2_XML_BAD_ARGUMENT; }
    if (allocator == NULL || allocator->allocate == NULL || allocator->release == NULL) { return ROME2_XML_INVALID_ALLOCATOR; }
    if (size > XML_MAX_BYTES) { return ROME2_XML_LIMIT_EXCEEDED; }
    if (size == 0) { return ROME2_XML_MALFORMED; }
    a = *allocator;
    raw = a.allocate(a.context, sizeof *h + 7u, 0);
    if (raw == NULL) { return ROME2_XML_ALLOCATION_FAILED; }
    h = align8(raw); memset(h, 0, sizeof *h); h->raw = raw; h->self = h; h->allocator = a;
    stream = SHCreateMemStream(bytes, (UINT)size);
    if (stream == NULL) { status = ROME2_XML_ALLOCATION_FAILED; goto cleanup; }
    hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL);
    if (FAILED(hr)) { status = hr == E_OUTOFMEMORY ? ROME2_XML_ALLOCATION_FAILED : ROME2_XML_SYSTEM_ERROR; goto cleanup; }
    hr = IXmlReader_SetProperty(reader, XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit);
    if (SUCCEEDED(hr)) { hr = IXmlReader_SetProperty(reader, XmlReaderProperty_XmlResolver, 0); }
    if (SUCCEEDED(hr)) { hr = IXmlReader_SetProperty(reader, XmlReaderProperty_MaxElementDepth, XML_MAX_DEPTH); }
    if (FAILED(hr)) { status = ROME2_XML_SYSTEM_ERROR; goto cleanup; }
    hr = IXmlReader_SetInput(reader, (IUnknown *)stream);
    if (FAILED(hr)) { status = read_status(hr); goto cleanup; }
    status = read_tree(h, reader);
cleanup:
    if (reader != NULL) { IXmlReader_Release(reader); }
    if (stream != NULL) { IStream_Release(stream); }
    if (status == ROME2_XML_OK) { h->state = XML_LIVE; *out = h; }
    else if (discard(h) != ROME2_XML_OK) { status = ROME2_XML_SYSTEM_ERROR; }
    return status;
}

const rome2_xml_node *rome2_xml_document_root(const rome2_xml_document *document)
{
    return live(document) && document->root != NULL ? &document->root->view : NULL;
}

rome2_xml_status rome2_xml_document_destroy(rome2_xml_document **document)
{
    rome2_xml_document *h;
    if (document == NULL) { return ROME2_XML_BAD_ARGUMENT; }
    h = *document;
    if (h == NULL) { return ROME2_XML_OK; }
    if (!live(h)) { return ROME2_XML_BAD_ARGUMENT; }
    *document = NULL;
    return discard(h);
}
