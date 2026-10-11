#ifndef ROME2_PORTED_100E8240_FASTPATH_H
#define ROME2_PORTED_100E8240_FASTPATH_H

#include "guest32.h"

/*
 * Identity of the original crash-record global 0x119f3a38.  The admitted
 * fast path only returns this identity; it never reads or writes the record.
 */
#define ROME2_PORT_100E8240_CRASH_RECORD UINT32_C(0x119f3a38)

/*
 * Port only the no-crash fast path of original 0x100e8240
 * ([0x100e8240, 0x100e8268)).  The original reads the TLS slot index from the
 * zero-initialized global 0x12125644.  FS:[0x2c] supplies the thread's
 * ThreadLocalStoragePointer (the TLS-vector base), and the original reads the
 * TLS data pointer from that vector.  It then reads the signed TLS value at
 * TLS data + 4 and the signed global threshold from the zero-initialized
 * 0x119f3ab0.  The pinned branch bytes
 * are `cmp eax, [ecx+4]; jg +9`: the comparison computes threshold minus the
 * TLS value, so the crash-handler window 0x100e8268-0x100e8376 is taken when
 * the signed threshold is strictly greater than the signed TLS value
 * (equivalently tls value < threshold), and the original otherwise falls
 * through and returns the crash-record identity 0x119f3a38 without any
 * write.  The canonical decompilation renders the same branch as
 * `tls value < threshold`, which the pinned bytes confirm.
 *
 * The borrowed read-only guest32 view must contain, pairwise disjoint and
 * non-null: the TLS index cell, the TLS-vector slot cell
 * (guest_tls_vector + 4 * index), the TLS value cell (tls data + 4), and the
 * threshold cell.  guest_tls_vector is the injected result of FS:[0x2c], not
 * a TEB address.  A TLS index above 0x3fffffff, a TLS-vector/TLS-data address
 * that overflows 32 bits, a null TLS-vector/TLS-data address, or an out-of-view
 * cell rejects the call as a fail-closed modeling precondition.  A signed TLS
 * value below the threshold rejects the call because that condition enters
 * the excluded crash-handler initialization and crash-file window.  Every
 * failure preserves the view, all guest bytes, and guest_record_out
 * byte-for-byte.  The excluded half-open window is
 * [0x100e8268, 0x100e8376).
 */
rome2_guest_status rome2_port_100e8240_crash_record_fastpath(
    const rome2_guest_read_view *view,
    rome2_guest_addr32 guest_tls_vector,
    rome2_guest_addr32 guest_tls_index_cell,
    rome2_guest_addr32 guest_threshold_cell,
    rome2_guest_addr32 *guest_record_out);

#endif
