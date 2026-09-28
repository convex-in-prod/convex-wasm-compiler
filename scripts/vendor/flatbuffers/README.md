FlatBuffers C++ headers from the upstream `v25.2.10` release:
https://github.com/google/flatbuffers/releases/tag/v25.2.10

The source archive SHA-256 is
`b9c2df49707c57a48fc0923d52b8c73beb72d675f9d44b2211e4569be40a7421`.
This directory contains the four headers needed by `flexbuffers.h` and its
`LICENSE`. One trailing space was removed from `stl_emulation.h` for repository
whitespace checks.
The native capability runtime uses `flatbuffers/flexbuffers.h` to read packed
documents returned by the host.
