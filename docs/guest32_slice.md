# Guest32 read-only runtime slice

The first executable port-layer behavior keeps x86 addresses as explicit
four-byte values while running on an x64 host. It does not admit a canonical
translation unit to the DLL or execute any recovered initializer.

## Scope and evidence

`rome2_guest32_runtime` implements a borrowed read-only view of one contiguous
guest-address interval, unaligned little-endian address-cell reads, and checked
guest-address addition. Guest addresses are structures containing exactly one
`uint32_t`; the API never returns a native pointer.

The behavioral slice covers two original functions:

- `0x100e81a0` returns its x86 `this` address plus four.
- `0x1093c450` loads the four-byte address at its x86 `this` and tail-forwards
  to `0x100e81a0`.

The original PE establishes the thunk as `mov ecx,[ecx]` followed by a jump to
`0x100e81a0`. The port returns the corresponding guest address, not a host
`char *`. Invalid null or overflowing inputs fail closed instead of reproducing
x86 wraparound; this is an explicit safety policy for malformed guest state.

## Boundary

The runtime has no global arena, allocation, host-to-guest cast, writable view,
function-pointer dispatch, DLL export, startup hook, or initializer. It is a
separate static library used only by its CTest executable in this milestone.
The x64 bootstrap DLL, its inert `DllMain` and `entry_point`, and its sparse
export table remain unchanged.

The two legacy names at export ordinals 243 and 266 alias target `0x100e81a0`,
but remain unresolved. Their x86 C++ pointer-return ABI is not silently replaced
by this internal guest-address API.

The view interval is half-open. An end exactly at `2^32` is valid; a larger
extent is rejected. Address cells may be unaligned but must fit completely in
the view. A zero value loaded from a valid cell is representable, while trying
to dereference or add to a null address is rejected. Outputs are unchanged on
failure.

## Build and verification

Run the normal hardened bootstrap build:

```powershell
cmd /d /c scripts\build_x64_bootstrap.bat
```

The evidence gate can also be run independently:

```powershell
python -B scripts\test_guest32_provenance.py
```

CMake builds `rome2_guest32_runtime` as C17 with the repository's x64 hardened
warning policy and runs `rome2_guest32_tests` through CTest. The tests cover
unaligned and boundary reads, malformed view extents, null/error precedence,
unchanged failure outputs, checked addition, and the composed original-function
behavior. A prerequisite CTest independently pins the original PE instruction
bytes, canonical-source hashes, and the two unresolved export aliases before
the runtime test is admitted.

The existing export-contract, compile-island, and startup-audit checks remain
separate provenance gates. Passing this slice does not classify any initializer
or compile-island translation unit as runtime-safe.
