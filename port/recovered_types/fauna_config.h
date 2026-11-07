#ifndef ROME2_RECOVERED_FAUNA_CONFIG_H
#define ROME2_RECOVERED_FAUNA_CONFIG_H

#include "native_xml.h"
#include "owned_fauna.h"

typedef enum rome2_fauna_config_status {
    ROME2_FAUNA_CONFIG_OK = 0,
    ROME2_FAUNA_CONFIG_BAD_ARGUMENT,
    ROME2_FAUNA_CONFIG_INVALID_ALLOCATOR,
    ROME2_FAUNA_CONFIG_XML_ERROR,
    ROME2_FAUNA_CONFIG_ROOT_NOT_FOUND,
    ROME2_FAUNA_CONFIG_LIMIT_EXCEEDED,
    ROME2_FAUNA_CONFIG_ALLOCATION_FAILED,
    ROME2_FAUNA_CONFIG_SYSTEM_ERROR,
    ROME2_FAUNA_CONFIG_INTERNAL_ERROR
} rome2_fauna_config_status;

/* Decode the case-sensitive fauna_config document root and each direct child
 * in document order. Implements the recovered 10141630 record meaning and
 * 1015e280 append order. Unknown animal names default to deer(0); lookup keys
 * are case-sensitive, but names and values use ASCII lowercase. Repeated
 * climate/condition tags are all used; scalar keys use the first occurrence.
 * Climate conversion reproduces 10103d10's independent UTF-16-unit encoding
 * (including six bytes for a surrogate pair), then 10102bc0 ASCII folding.
 * Integer scalars require digits only, wrap modulo2^32, and fall back to zero
 * for any non-digit. Probability uses the recovered decimal token normalizer,
 * a private C-locale CRT conversion and explicit binary32 scaling; process
 * locale is unchanged. Full historic CRT/locale/FP-environment equivalence is
 * not asserted. XmlLite's accepted XML domain is described in native_xml.h.
 *
 * out must point to NULL. Source is borrowed for this call; successful output
 * owns every record and climate string. Every failure preserves *out and
 * releases the partial DOM, scratch buffers and records. Optional xml_error
 * is set to the frontend status. Missing expected root is explicit failure,
 * not a fabricated empty configuration. Captured allocator and callback rules
 * follow owned_string.h. Windows XML/CRT runtime allocations are separate from
 * the caller's allocation policy and are released during the call. */
rome2_fauna_config_status rome2_fauna_config_decode(
    rome2_owned_fauna_vector **out, const unsigned char *bytes, size_t size,
    const rome2_owned_string_allocator *allocator, rome2_xml_status *xml_error);

#endif
