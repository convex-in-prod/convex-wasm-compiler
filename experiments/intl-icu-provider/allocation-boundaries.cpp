#include "cmemory.h"
#include "unicode/uclean.h"
#include <cstdlib>
#include <limits>

namespace {
bool failAllocation = false;
bool failReallocation = false;
size_t allocationCalls = 0;
size_t freeCalls = 0;
void *U_CALLCONV allocate(const void *, size_t size) {
  ++allocationCalls;
  return failAllocation ? nullptr : std::malloc(size);
}
void *U_CALLCONV reallocate(const void *, void *pointer, size_t size) {
  return failReallocation ? nullptr : std::realloc(pointer, size);
}
void U_CALLCONV release(const void *, void *pointer) {
  ++freeCalls;
  std::free(pointer);
}
}

extern "C" int intl_allocation_boundary_run(int mode) {
  UErrorCode status = U_ZERO_ERROR;
  u_setMemoryFunctions(nullptr, allocate, reallocate, release, &status);
  if (U_FAILURE(status)) return 1;
  switch (mode) {
    case 0: {
      void *zero = uprv_malloc(0);
      if (!zero || allocationCalls) return 2;
      uprv_free(zero);
      if (freeCalls) return 3;
      void *memory = uprv_realloc(zero, 8);
      if (!memory || allocationCalls != 1) return 4;
      void *resized = uprv_realloc(memory, 0);
      if (!resized || freeCalls != 1) return 5;
      uprv_free(resized);
      return freeCalls == 1 ? 0 : 6;
    }
    case 1:
      failAllocation = true;
      uprv_malloc(8);
      return 7;
    case 2: {
      void *memory = uprv_malloc(8);
      failReallocation = true;
      uprv_realloc(memory, 16);
      return 8;
    }
    case 3:
      // This would wrap exactly to zero without the overflow check.
      uprv_calloc(2, std::numeric_limits<size_t>::max() / 2 + 1);
      return 9;
    default:
      return 10;
  }
}
