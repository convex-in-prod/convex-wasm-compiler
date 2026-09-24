#include "convex_wasm_opaque_abi_v3.h"
#include "hermes/VM/static_h.h"
#include "jsi/jsi.h"

#include <cstdint>
#include <limits>
#include <memory>

extern "C" SHUnit *CONVEX_WASM_EXPORTED_UNIT(void);
#if defined(CONVEX_WASM_BRIDGE_EXPORTED_UNIT) && \
    defined(CONVEX_WASM_FORMATTER_EXPORTED_UNIT) && \
    defined(CONVEX_WASM_APPLICATION_EXPORTED_UNIT)
extern "C" SHUnit *CONVEX_WASM_BRIDGE_EXPORTED_UNIT(void);
extern "C" SHUnit *CONVEX_WASM_FORMATTER_EXPORTED_UNIT(void);
extern "C" SHUnit *CONVEX_WASM_APPLICATION_EXPORTED_UNIT(void);
#endif

namespace {

using facebook::jsi::Function;
using facebook::jsi::Runtime;

SHRuntime *runtime = nullptr;

SHRuntime *initialize_runtime() {
  char program[] = "convex-wasm-generated-fixture";
  char init_heap[] = "--gc-init-heap=4MiB";
  char max_heap[] = "--gc-max-heap=32MiB";
  char alloc_young[] = "--gc-alloc-young=true";
  char revert_young[] = "--gc-revert-to-yg-at-tti=false";
  char register_stack[] = "--max-register-stack=16384";
  char *argv[] = {
      program,
      init_heap,
      max_heap,
      alloc_young,
      revert_young,
      register_stack,
  };
  return _sh_init(6, argv);
}

void destroy_runtime() {
  if (runtime != nullptr) {
    _sh_done(runtime);
    runtime = nullptr;
  }
}

struct InvocationResult {
  int status;
  bool retire_runtime;
};

InvocationResult error_exit(Runtime &js, std::shared_ptr<Function> &cleanup,
                            bool &guest_cleanup_attempted,
                            bool &host_cancel_attempted, int status) {
  if (!guest_cleanup_attempted && cleanup != nullptr) {
    guest_cleanup_attempted = true;
    try {
      (void)cleanup->call(js);
    } catch (...) {
      // The outer invocation boundary retires the runtime when guest cleanup fails.
    }
  }
  cleanup.reset();
  if (!host_cancel_attempted) {
    host_cancel_attempted = true;
    (void)convex_async_operation_cancel_all();
  }
  return {status, true};
}

InvocationResult run_initialized_runtime() {
  auto &js = *reinterpret_cast<facebook::jsi::Runtime *>(
      _sh_get_hermes_runtime(runtime));
  std::shared_ptr<Function> cleanup;
  bool guest_cleanup_attempted = false;
  bool host_cancel_attempted = false;

  try {
    auto global = js.global();
    if (!global.hasProperty(js, "__convexWasmInvocationDone")) {
      return error_exit(js, cleanup, guest_cleanup_attempted,
                        host_cancel_attempted, 5);
    }

    auto done = global.getPropertyAsFunction(js, "__convexWasmInvocationDone");
    cleanup = std::make_shared<Function>(
        global.getPropertyAsFunction(js, "__convexWasmInvocationCleanup"));
    auto settle = global.getPropertyAsFunction(js, "__convexWasmSettle");
    auto status = global.getPropertyAsFunction(js, "__convexWasmInvocationStatus");

    if (!js.drainMicrotasks()) {
      return error_exit(js, cleanup, guest_cleanup_attempted,
                        host_cancel_attempted, 2);
    }
    while (!done.call(js).getBool()) {
      const auto settle_operation = [&](int32_t operation_handle) {
        const int32_t completion_status =
            convex_async_operation_completion_status(operation_handle);
        const int64_t payload_handle =
            convex_async_operation_completion_take(operation_handle);
        settle.call(js,
                    static_cast<double>(operation_handle),
                    static_cast<double>(completion_status),
                    static_cast<double>(payload_handle));
      };
      const int32_t operation_handle = convex_async_operation_wait_any();
      if (operation_handle <= 0) {
        return error_exit(js, cleanup, guest_cleanup_attempted,
                          host_cancel_attempted, 3);
      }
      settle_operation(operation_handle);
      // Polling only consumes already-ready completions from this host batch.
      while (true) {
        const int32_t ready_operation_handle =
            convex_async_operation_poll_ready();
        if (ready_operation_handle == 0) {
          break;
        }
        if (ready_operation_handle < 0) {
          return error_exit(js, cleanup, guest_cleanup_attempted,
                            host_cancel_attempted, 3);
        }
        settle_operation(ready_operation_handle);
      }
      if (!js.drainMicrotasks()) {
        return error_exit(js, cleanup, guest_cleanup_attempted,
                          host_cancel_attempted, 2);
      }
    }
    guest_cleanup_attempted = true;
    const double guest_abandoned_value = cleanup->call(js).getNumber();
    cleanup.reset();
    if (guest_abandoned_value < 0 ||
        guest_abandoned_value > std::numeric_limits<int32_t>::max()) {
      return error_exit(js, cleanup, guest_cleanup_attempted,
                        host_cancel_attempted, 6);
    }
    const auto guest_abandoned = static_cast<int32_t>(guest_abandoned_value);
    if (static_cast<double>(guest_abandoned) != guest_abandoned_value) {
      return error_exit(js, cleanup, guest_cleanup_attempted,
                        host_cancel_attempted, 6);
    }
    host_cancel_attempted = true;
    const int32_t host_abandoned = convex_async_operation_cancel_all();
    if (host_abandoned != guest_abandoned) {
      return error_exit(js, cleanup, guest_cleanup_attempted,
                        host_cancel_attempted, 6);
    }
    return {static_cast<int>(status.call(js).getNumber()), false};
  } catch (const facebook::jsi::JSError &) {
    return error_exit(js, cleanup, guest_cleanup_attempted,
                      host_cancel_attempted, 4);
  } catch (...) {
    return error_exit(js, cleanup, guest_cleanup_attempted,
                      host_cancel_attempted, 5);
  }
}

}  // namespace

extern "C" int convex_wasm_udf_run(void) {
  if (runtime == nullptr) {
    runtime = initialize_runtime();
  }
#if defined(CONVEX_WASM_BRIDGE_EXPORTED_UNIT) && \
    defined(CONVEX_WASM_FORMATTER_EXPORTED_UNIT) && \
    defined(CONVEX_WASM_APPLICATION_EXPORTED_UNIT)
  const bool initialized = _sh_initialize_units(
      runtime, 3, CONVEX_WASM_BRIDGE_EXPORTED_UNIT,
      CONVEX_WASM_FORMATTER_EXPORTED_UNIT,
      CONVEX_WASM_APPLICATION_EXPORTED_UNIT);
#else
  const bool initialized =
      _sh_initialize_units(runtime, 1, CONVEX_WASM_EXPORTED_UNIT);
#endif
  if (!initialized) {
    destroy_runtime();
    return 1;
  }

  const InvocationResult result = run_initialized_runtime();
  if (result.retire_runtime) {
    destroy_runtime();
  }
  return result.status;
}

extern "C" void convex_wasm_udf_destroy_runtime(void) {
  destroy_runtime();
}
