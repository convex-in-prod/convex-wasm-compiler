#include "hermes/VM/static_h.h"
#include "hermes/hermes.h"
#include "jsi/instrumentation.h"
#include <cstdio>
#include <exception>
#include <chrono>
#include <cmath>
#ifdef INTL_PROBE_STANDALONE
#include <cstddef>
#include <cstdlib>
#include <limits>
#include <malloc.h>
#include <unicode/uclean.h>

namespace {
// This harness is single-threaded. Count ICU's requested payload separately
// from malloc's rounded chunks, which can vary for the same live allocation set.
struct alignas(std::max_align_t) IcuAllocation {
  size_t bytes;
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  IcuAllocation *previous, *next;
  size_t faultIndex, attempt;
#endif
};
size_t icuRequestedBytes = 0;
size_t icuAllocationCount = 0;
bool icuTrackingInitialized = false;
#ifdef INTL_PROBE_ALLOCATION_FAILURES
IcuAllocation *icuLiveAllocations = nullptr;
size_t icuAllocationAttempts = 0;
size_t icuFailAtAllocation = 0;
bool icuFaultInjected = false;
int selectedAllocationCase = -1;
int selectedAllocationIndex = 0;

bool failIcuAllocation() {
  ++icuAllocationAttempts;
  if (icuFailAtAllocation && icuAllocationAttempts == icuFailAtAllocation) {
    icuFaultInjected = true;
    std::fprintf(stderr, "{\"icuAllocationFailure\":true,\"allocationIndex\":%zu}\n", icuAllocationAttempts);
    return true;
  }
  return false;
}
#endif

void *U_CALLCONV trackIcuAllocate(const void *, size_t bytes) {
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  if (failIcuAllocation()) return nullptr;
#endif
  if (bytes > std::numeric_limits<size_t>::max() - sizeof(IcuAllocation)) return nullptr;
  auto *allocation = static_cast<IcuAllocation *>(std::malloc(sizeof(IcuAllocation) + bytes));
  if (!allocation) return nullptr;
  allocation->bytes = bytes;
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  allocation->previous = nullptr;
  allocation->next = icuLiveAllocations;
  if (icuLiveAllocations) icuLiveAllocations->previous = allocation;
  icuLiveAllocations = allocation;
  allocation->faultIndex = icuFailAtAllocation;
  allocation->attempt = icuAllocationAttempts;
#endif
  icuRequestedBytes += bytes;
  ++icuAllocationCount;
  return allocation + 1;
}

void U_CALLCONV trackIcuFree(const void *, void *memory) {
  if (!memory) return;
  auto *allocation = static_cast<IcuAllocation *>(memory) - 1;
  if (!icuAllocationCount || allocation->bytes > icuRequestedBytes) std::abort();
  icuRequestedBytes -= allocation->bytes;
  --icuAllocationCount;
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  if (allocation->previous) allocation->previous->next = allocation->next;
  else icuLiveAllocations = allocation->next;
  if (allocation->next) allocation->next->previous = allocation->previous;
#endif
  std::free(allocation);
}

void *U_CALLCONV trackIcuReallocate(const void *context, void *memory, size_t bytes) {
  if (!memory) return trackIcuAllocate(context, bytes);
  if (!bytes) { trackIcuFree(context, memory); return nullptr; }
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  if (failIcuAllocation()) return nullptr;
#endif
  if (bytes > std::numeric_limits<size_t>::max() - sizeof(IcuAllocation)) return nullptr;
  auto *previous = static_cast<IcuAllocation *>(memory) - 1;
  const size_t oldBytes = previous->bytes;
  auto *allocation = static_cast<IcuAllocation *>(std::realloc(previous, sizeof(IcuAllocation) + bytes));
  // A failed realloc retains both the previous allocation and its accounting.
  if (!allocation) return nullptr;
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  if (allocation->previous) allocation->previous->next = allocation;
  else icuLiveAllocations = allocation;
  if (allocation->next) allocation->next->previous = allocation;
#endif
  if (!icuAllocationCount || oldBytes > icuRequestedBytes) std::abort();
  allocation->bytes = bytes;
  icuRequestedBytes = icuRequestedBytes - oldBytes + bytes;
  return allocation + 1;
}
} // namespace
#endif
#include <unicode/ucal.h>
#include <unicode/uloc.h>
#include <unicode/ulocdata.h>
#include <unicode/uversion.h>
extern "C" SHUnit *sh_export_intl_probe(void);
#ifdef INTL_PROBE_STANDALONE
extern "C" int intl_probe_run() {
#else
int main() {
#endif
  const auto start = std::chrono::steady_clock::now();
#ifdef INTL_PROBE_STANDALONE
  if (!icuTrackingInitialized) {
    UErrorCode status = U_ZERO_ERROR;
    u_setMemoryFunctions(nullptr, trackIcuAllocate, trackIcuReallocate, trackIcuFree, &status);
    if (U_FAILURE(status)) {
      std::fprintf(stderr, "ICU allocation tracking initialization failed\n");
      return 1;
    }
    icuTrackingInitialized = true;
  }
#endif
  // The standalone harness fixes defaults explicitly; production must provide
  // the same contract without consulting host process locale or timezone state.
  UErrorCode defaultsError = U_ZERO_ERROR;
  uloc_setDefault("en_US", &defaultsError);
  ucal_setDefaultTimeZone(u"UTC", &defaultsError);
  if (U_FAILURE(defaultsError)) {
    std::fprintf(stderr, "ICU probe default configuration failed\n");
    return 1;
  }
  auto runtime = facebook::hermes::makeHermesRuntime(
      hermes::vm::RuntimeConfig::Builder().withIntl(true).build());
  const auto initialized = std::chrono::steady_clock::now();
  auto &js = *runtime;
  using namespace facebook::jsi;
  js.global().setProperty(js, "gc", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "gc"), 0,
      [](Runtime &rt, const Value &, const Value *, size_t) {
        rt.instrumentation().collectGarbage("Intl binding coercion probe");
        return Value::undefined();
      }));
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  js.global().setProperty(js, "icuAllocationSelection", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "icuAllocationSelection"), 0,
      [](Runtime &rt, const Value &, const Value *, size_t) {
        if (selectedAllocationCase < 0) return Value::undefined();
        Object result(rt);
        result.setProperty(rt, "caseIndex", selectedAllocationCase);
        result.setProperty(rt, "allocationIndex", selectedAllocationIndex);
        return Value(rt, result);
      }));
  js.global().setProperty(js, "icuAllocationFault", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "icuAllocationFault"), 1,
      [](Runtime &rt, const Value &, const Value *args, size_t count) {
        if (count != 1 || !args[0].isNumber() || !std::isfinite(args[0].getNumber()) || args[0].getNumber() < 0 ||
            args[0].getNumber() > 1000000 || args[0].getNumber() != static_cast<size_t>(args[0].getNumber()))
          throw JSError(rt, "Invalid ICU allocation fault index");
        Object result(rt);
        result.setProperty(rt, "attempts", static_cast<double>(icuAllocationAttempts));
        result.setProperty(rt, "injected", icuFaultInjected);
        icuAllocationAttempts = 0;
        icuFaultInjected = false;
        icuFailAtAllocation = static_cast<size_t>(args[0].getNumber());
        return Value(rt, result);
      }));
  js.global().setProperty(js, "icuAllocationCase", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "icuAllocationCase"), 2,
      [](Runtime &rt, const Value &, const Value *args, size_t count) {
        if (count != 2 || !args[0].isString() || !args[1].isNumber())
          throw JSError(rt, "Invalid ICU allocation case");
        const auto id = args[0].getString(rt).utf8(rt);
        std::fprintf(stderr, "{\"allocationCase\":\"%s\",\"allocationIndex\":%.0f}\n", id.c_str(), args[1].getNumber());
        return Value::undefined();
      }));
#endif
  js.global().setProperty(js, "print", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "print"), 1,
      [](Runtime &rt, const Value &, const Value *args, size_t count) {
        if (count != 1 || !args[0].isString())
          throw JSError(rt, "Probe output must be a string");
        const auto value = args[0].getString(rt).utf8(rt);
        if (std::fwrite(value.data(), 1, value.size(), stdout) != value.size() ||
            std::fputc('\n', stdout) == EOF || std::fflush(stdout) == EOF)
          throw JSError(rt, "Probe output failed");
        return Value::undefined();
      }));
  try {
    const auto evaluationStart = std::chrono::steady_clock::now();
    runtime->evaluateSHUnit(sh_export_intl_probe);
    const auto evaluated = std::chrono::steady_clock::now();
    js.instrumentation().collectGarbage("Intl portability probe");
    const auto collected = std::chrono::steady_clock::now();
    UVersionInfo version, cldr;
    UErrorCode error = U_ZERO_ERROR;
    u_getVersion(version);
    ulocdata_getCLDRVersion(cldr, &error);
    const char *tz = ucal_getTZDataVersion(&error);
    if (U_FAILURE(error) || !tz) throw JSError(js, "ICU version lookup failed");
    std::fprintf(stderr,
        "{\"icu\":\"%u.%u.%u.%u\",\"cldr\":\"%u.%u.%u.%u\","
        "\"tz\":\"%s\",\"runtimeInitMs\":%.3f,\"evaluationMs\":%.3f,\"finalGcMs\":%.3f}\n",
        version[0], version[1], version[2], version[3],
        cldr[0], cldr[1], cldr[2], cldr[3], tz,
        std::chrono::duration<double, std::milli>(initialized - start).count(),
        std::chrono::duration<double, std::milli>(evaluated - evaluationStart).count(),
        std::chrono::duration<double, std::milli>(collected - evaluated).count());
  } catch (const std::exception &error) {
#ifdef INTL_PROBE_ALLOCATION_FAILURES
    icuFailAtAllocation = 0;
#endif
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
  }
  return 0;
}

#ifdef INTL_PROBE_STANDALONE
namespace {
int cleanupTrackedIcu() {
  // All formatters and runtimes have been destroyed. ICU cleanup distinguishes
  // its retained process caches from allocations that outlive their owners.
  u_cleanup();
  icuTrackingInitialized = false;
  std::fprintf(stderr,
      "{\"lifecycleCleanup\":true,\"icuRequestedBytes\":%zu,\"icuAllocationCount\":%zu}\n",
      icuRequestedBytes, icuAllocationCount);
#ifdef INTL_PROBE_ALLOCATION_FAILURES
  for (const auto *allocation = icuLiveAllocations; allocation; allocation = allocation->next)
    std::fprintf(stderr, "{\"icuLeakBytes\":%zu,\"createdDuringFault\":%zu,\"allocationAttempt\":%zu}\n",
        allocation->bytes, allocation->faultIndex, allocation->attempt);
#endif
  if (icuRequestedBytes || icuAllocationCount) return 1;
  return 0;
}
} // namespace

extern "C" int intl_probe_lifecycle_run() {
  // Keep the same Wasm memory and ICU caches, but destroy the entire Hermes
  // runtime between iterations. Fresh Wasm instances would conceal retention.
  for (int cycle = 0; cycle < 16; ++cycle) {
    const int status = intl_probe_run();
    if (status != 0) return status;
    const auto allocation = mallinfo();
    std::fprintf(stderr,
        "{\"lifecycleCycle\":%d,\"nativeAllocatedBytes\":%zu,"
        "\"icuRequestedBytes\":%zu,\"icuAllocationCount\":%zu}\n",
        cycle, allocation.uordblks, icuRequestedBytes, icuAllocationCount);
  }
  return cleanupTrackedIcu();
}
#endif

#ifdef INTL_PROBE_ALLOCATION_FAILURES
extern "C" void intl_probe_allocation_failure_configure(int caseIndex, int allocationIndex) {
  if (caseIndex < 0 || allocationIndex < 0 || allocationIndex > 1000000) std::abort();
  selectedAllocationCase = caseIndex;
  selectedAllocationIndex = allocationIndex;
}

extern "C" int intl_probe_allocation_failures_run() {
  const int status = intl_probe_run();
  icuFailAtAllocation = 0;
  const int cleanup = cleanupTrackedIcu();
  return status ? status : cleanup;
}
#endif
