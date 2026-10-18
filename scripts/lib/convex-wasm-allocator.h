#ifndef CONVEX_WASM_ALLOCATOR_H
#define CONVEX_WASM_ALLOCATOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum { CONVEX_WASM_FREE_PAYLOAD_CAPACITY = 128 };

struct ConvexWasmFreePayloadRange {
  size_t start;
  size_t end;
};

struct ConvexWasmFreePayload {
  size_t count;
  size_t visited;
  struct ConvexWasmFreePayloadRange ranges[CONVEX_WASM_FREE_PAYLOAD_CAPACITY];
};

// Enumerate whole pages inside currently free allocator payload. The caller
// owns exclusive guest access and keeps allocation and collection quiescent
// until discard finishes. Output storage must be a live, non-aliased allocation.
// A zero result means enumeration completed; one means a bounded partial result.
// A partial result grants authority only for returned ranges, not the rest of
// the allocator. No allocation, host callback or whole-heap walk occurs here.
unsigned convex_wasm_allocator_free_payload(
    struct ConvexWasmFreePayload *output,
    size_t page_size,
    size_t visit_limit);

#ifdef __cplusplus
}
#endif
#endif
