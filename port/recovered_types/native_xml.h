#ifndef ROME2_RECOVERED_NATIVE_XML_H
#define ROME2_RECOVERED_NATIVE_XML_H

#include "owned_string.h"

/* Native XML tree produced by the Windows XmlLite frontend. This is a host
 * adapter, not an original game XML object layout. Child/sibling order is
 * document order, names are case-sensitive, text is direct element character
 * content (not descendant text), with no application trimming/case folding.
 * All strings are owned UTF-16, terminated and immutable until destruction.
 * Comments, PI and declarations are ignored. DTDs and namespaces are outside
 * the admitted configuration domain. Attributes are ignored. */
typedef struct rome2_xml_node {
    rome2_host_string16 name;
    rome2_host_string16 text;
    const struct rome2_xml_node *first_child;
    const struct rome2_xml_node *next_sibling;
    uint32_t child_count;
} rome2_xml_node;
typedef struct rome2_xml_document rome2_xml_document;
typedef enum rome2_xml_status {
    ROME2_XML_OK = 0,
    ROME2_XML_BAD_ARGUMENT,
    ROME2_XML_INVALID_ALLOCATOR,
    ROME2_XML_MALFORMED,
    ROME2_XML_UNSUPPORTED,
    ROME2_XML_LIMIT_EXCEEDED,
    ROME2_XML_ALLOCATION_FAILED,
    ROME2_XML_SYSTEM_ERROR
} rome2_xml_status;

/* Byte input is bounded and borrowed only during this call. UTF-8 and UTF-16
 * XML are accepted according to XmlLite's encoding detection. Requires a NULL
 * output handle; every failure preserves it and releases all partial state.
 * Host bounds: input <= 16 MiB, element depth <= 128, <= 1000000 nodes.
 * Captured class-zero allocator and arbitrary raw alignment follow
 * owned_string.h. XmlLite/stream COM allocations use the Windows runtime;
 * all COM references must be released, and no COM initialization is required
 * from the caller. No external resource resolver. No callback reentry; access
 * requires caller synchronization. Destruction invalidates all cached views. */
rome2_xml_status rome2_xml_document_parse(rome2_xml_document **out,
    const unsigned char *bytes, size_t size,
    const rome2_owned_string_allocator *allocator);
const rome2_xml_node *rome2_xml_document_root(const rome2_xml_document *document);
/* Identity membership in this live document. The candidate is not dereferenced
 * unless it is one of the document's owned nodes; NULL/foreign nodes fail.
 * The document and its immutable views must remain alive for a consuming call. */
bool rome2_xml_document_contains_node(const rome2_xml_document *document,
    const rome2_xml_node *node);
rome2_xml_status rome2_xml_document_destroy(rome2_xml_document **document);

#endif
