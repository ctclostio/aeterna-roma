# Static return-domain evidence for `0x100ec5c0`

Status: authenticated evidence only. The original body is not executed or
ported.

The exact 1,199-byte body at VA `0x100ec5c0`, raw offset `0x000eb9c0`, has
SHA-256
`bf1adcefe07251e80f2711a590dcc479071d845c00535ec57d5b0f7385e25e5e`.
Raw control flow establishes two ordinary return forms:

- five conditions converge on `0x100ec68d`, whose 16-byte epilogue loads
  literal `2` into EAX and returns;
- `0x100eca35-0x100eca4e` calls `0x112bff20`, converts AL to a Boolean mask,
  applies `and eax,2`, and returns, yielding exactly 0 or 2.

The exceptional branch at `0x100eca4f-0x100eca6e` has SHA-256
`0756cbe584a461d314d996199fe3c7dbb1635088e18718aaf4cd6ce6f60d544a`.
It ends in opcode `CC` (`INT3`) after calling `0x100edcd0`. It contains neither
`call eax` nor a return instruction. The decompiler's synthetic
`swi(3)`/indirect-return presentation is therefore not an executable return
domain and must not be ported as one.

Consequently, every ordinary return is in `{0,2}`; the debug path traps rather
than returning. This statement does not guarantee termination because the body
also contains a loop and extensive platform/global/virtual-call behavior.

The parent window at `0x100ed4c1-0x100ed4d3`, raw offset `0x000ec8c1`, has
SHA-256
`cbec5f0803aee5e4667fae58f23b30896440fae3bfbf06ad4fa97b359032c7bd`.
It calls `0x100ec5c0`, exits through cleanup for result 2, loops for every result
other than 1, and enters a restart/handler-list path for result 1. Because the
authenticated child has no ordinary result-1 return, that parent path cannot
be attributed to the child's normal domain.

The next implementation boundary is not the whole function. It is either a
pure fail-closed result guard around a future platform adapter or another leaf
behind one of the function's platform/virtual seams. No current code may
synthesize result 1, suppress `INT3`, or map the trap branch to 0 or 2.
