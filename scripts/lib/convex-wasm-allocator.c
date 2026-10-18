/* Resolve only through the pinned SDK include path, not a sibling source file. */
#include <dlmalloc.c>
#include "convex-wasm-allocator.h"

/* This optional export is for a quiescent, single-threaded guest. The caller
 * supplies live scratch storage and must not resume allocation or collection
 * between enumeration and discard. Exporting addresses alone does not pin them.
 * A partial result remains useful; it never establishes that no other free
 * storage exists. No allocation, host callback or heap-wide walk occurs here. */
_Static_assert(!USE_LOCKS, "free payload export requires a quiescent allocator");

static void append_free_payload(
    mchunkptr chunk, size_t size, size_t page_size,
    struct ConvexWasmFreePayload *output) {
  const size_t address = (size_t)chunk;
  /* Keep free-list links, tree metadata, neighboring boundary tags and footer
   * space resident. The host must not infer these margins from allocator offsets. */
  const size_t prefix = 2 * sizeof(struct malloc_tree_chunk);
  const size_t suffix = FOUR_SIZE_T_SIZES;
  const size_t mask = page_size - 1;
  if (size < prefix + suffix + page_size)
    return;
  if (is_inuse(chunk) || size != chunksize(chunk) || address > MAX_SIZE_T - size)
    __builtin_trap();
  size_t start = (address + prefix + mask) & ~mask;
  size_t end = (address + size - suffix) & ~mask;
  if (start < end) {
    output->ranges[output->count].start = start;
    output->ranges[output->count].end = end;
    ++output->count;
  }
}

/* Returns zero for complete enumeration, one for a bounded partial result. */
__attribute__((visibility("default")))
unsigned convex_wasm_allocator_free_payload(
    struct ConvexWasmFreePayload *output, size_t page_size, size_t visit_limit) {
  if (!output || page_size < 4096 ||
      (page_size & (page_size - 1)) || page_size > 65536 ||
      !visit_limit || visit_limit > 4096)
    __builtin_trap();
  output->count = 0;
  output->visited = 0;
  if (!is_initialized(gm))
    return 0;

  if (gm->top) {
    ++output->visited;
    append_free_payload(gm->top, gm->topsize, page_size, output);
  }
  if (output->count == CONVEX_WASM_FREE_PAYLOAD_CAPACITY || output->visited == visit_limit)
    return 1;
  if (gm->dvsize) {
    ++output->visited;
    append_free_payload(gm->dv, gm->dvsize, page_size, output);
  }
  if (output->count == CONVEX_WASM_FREE_PAYLOAD_CAPACITY || output->visited == visit_limit)
    return 1;

  /* Small bins cannot contain a complete host page. Start at the bin containing
   * the minimum useful size; higher bins hold only larger sizes. Tree depth is
   * bounded by the size bits, independently of the number of allocated chunks. */
  bindex_t first;
  const size_t minimum = page_size + 2 * sizeof(struct malloc_tree_chunk) +
      FOUR_SIZE_T_SIZES;
  compute_tree_index(minimum, first);
  for (bindex_t index = NTREEBINS; index-- > first;) {
    if (!treemap_is_marked(gm, index))
      continue;
    tchunkptr pending[SIZE_T_BITSIZE];
    size_t depth = 0;
    pending[depth++] = *treebin_at(gm, index);
    while (depth) {
      tchunkptr node = pending[--depth];
      if (!node || node->index != index)
        __builtin_trap();
      for (unsigned child = 0; child != 2; ++child) {
        if (node->child[child]) {
          if (depth == SIZE_T_BITSIZE)
            __builtin_trap();
          pending[depth++] = node->child[child];
        }
      }
      tchunkptr sibling = node;
      do {
        ++output->visited;
        append_free_payload((mchunkptr)sibling, chunksize(sibling), page_size, output);
        if (output->count == CONVEX_WASM_FREE_PAYLOAD_CAPACITY || output->visited == visit_limit)
          return 1;
        sibling = sibling->fd;
        if (!sibling)
          __builtin_trap();
      } while (sibling != node);
    }
  }
  return 0;
}
