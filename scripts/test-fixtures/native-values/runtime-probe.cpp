#include "../../lib/convex-wasm-native-capability-runtime-main.cpp"

#include "jsi/instrumentation.h"

#include <stdexcept>

extern "C" SHUnit *sh_export_native_runtime_probe(void);
extern "C" double convex_invocation_unix_timestamp_ms(void) { return 1; }
extern "C" long long convex_capability_current(void) {
  throw std::runtime_error("Runtime probe unexpectedly requested a capability");
}
extern "C" double convex_math_random(long long) {
  throw std::runtime_error("Runtime probe unexpectedly requested randomness");
}

extern "C" int convex_wasm_native_runtime_probe_run(void) try {
  for (int lifecycle = 0; lifecycle < 3; ++lifecycle) {
    std::unique_ptr<SHRuntime, decltype(&_sh_done)> hermes(initialize_runtime(), &_sh_done);
    if (!hermes) throw std::runtime_error("Native probe runtime initialization failed");
    auto &js = *reinterpret_cast<Runtime *>(_sh_get_hermes_runtime(hermes.get()));
    install_intrinsic_snapshot_factory(js);
    if (!_sh_initialize_units(hermes.get(), 1, sh_export_native_runtime_probe)) {
      throw std::runtime_error("Native probe unit initialization failed");
    }
    // The compiled closure retains formatters and the actual native descriptor
    // snapshots across collection. Release local JSI roots before runtime teardown.
    auto probe = js.global().getPropertyAsFunction(js, "__convexNativeRuntimeProbe");
    for (int invocation = 0; invocation < 3; ++invocation) {
      js.instrumentation().collectGarbage("native runtime probe");
      const auto result = probe.call(js).getString(js).utf8(js);
      std::printf("CONVEX_NATIVE_RUNTIME_PROBE:%s\n", result.c_str());
    }
  }
  return 0;
} catch (const std::exception &error) {
  std::fprintf(stderr, "Native runtime probe failed: %s\n", error.what());
  return 1;
}
