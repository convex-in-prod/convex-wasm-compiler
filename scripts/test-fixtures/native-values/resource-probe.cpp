#include "../../lib/convex-wasm-native-capability-runtime-main.cpp"

#include <cstdlib>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" double convex_invocation_unix_timestamp_ms(void) { return 1; }
extern "C" long long convex_capability_current(void) {
  throw std::runtime_error("Resource probe unexpectedly requested a capability");
}
extern "C" double convex_math_random(long long) {
  throw std::runtime_error("Resource probe unexpectedly requested randomness");
}

namespace {
enum class Allocation { Malloc, Realloc, CppContainers };
constexpr size_t blockBytes = 1024 * 1024;

int run(Allocation allocation, size_t blocks) {
  std::unique_ptr<SHRuntime, decltype(&_sh_done)> hermes(initialize_runtime(), &_sh_done);
  if (!hermes) throw std::runtime_error("Resource probe runtime initialization failed");
  auto &js = *reinterpret_cast<Runtime *>(_sh_get_hermes_runtime(hermes.get()));
  {
    auto intl = js.global().getPropertyAsObject(js, "Intl");
    auto number = intl.getPropertyAsFunction(js, "NumberFormat").callAsConstructor(js, "en-US").getObject(js);
    auto date = intl.getPropertyAsFunction(js, "DateTimeFormat").callAsConstructor(js, "en-US").getObject(js);
    auto collator = intl.getPropertyAsFunction(js, "Collator").callAsConstructor(js, "en-US").getObject(js);
    if (number.getPropertyAsFunction(js, "format").call(js, 1234.5).getString(js).utf8(js) != "1,234.5" ||
        date.getPropertyAsFunction(js, "format").call(js, 0).getString(js).utf8(js) != "1/1/1970" ||
        collator.getPropertyAsFunction(js, "compare").call(js, "alpha", "beta").getNumber() >= 0) {
      throw std::runtime_error("Resource probe native Intl baseline differs");
    }
  }
  std::puts("NATIVE_INTL_READY");
  if (std::fflush(stdout) != 0) throw std::runtime_error("Resource probe output failed");

  // These allocations use libc/libc++, outside the ICU allocation counter and
  // Hermes GC statistics. Keep them live so the host must charge linear growth.
  std::vector<void *> buffers;
  std::vector<std::string> strings;
  void *resized = nullptr;
  for (size_t index = 0; index < blocks; ++index) {
    if (allocation == Allocation::CppContainers) {
      strings.emplace_back(blockBytes, 'x');
      volatile char *bytes = strings.back().data();
      bytes[0] = 'a';
    } else {
      const size_t size = allocation == Allocation::Malloc ? blockBytes : (index + 1) * blockBytes;
      void *buffer = allocation == Allocation::Malloc ? std::malloc(size) : std::realloc(resized, size);
      if (!buffer) throw std::runtime_error("Resource probe allocator returned null");
      volatile unsigned char *bytes = static_cast<unsigned char *>(buffer);
      bytes[0] = 1;
      bytes[size - 1] = 2;
      if (allocation == Allocation::Malloc) buffers.push_back(buffer);
      else resized = buffer;
    }
  }
  for (void *buffer : buffers) std::free(buffer);
  std::free(resized);
  std::puts("NATIVE_ALLOCATIONS_COMPLETE");
  if (std::fflush(stdout) != 0) throw std::runtime_error("Resource probe output failed");
  return 0;
}
} // namespace

extern "C" int convex_wasm_resource_probe_control(void) { return run(Allocation::CppContainers, 2); }
extern "C" int convex_wasm_resource_probe_malloc(void) { return run(Allocation::Malloc, 256); }
extern "C" int convex_wasm_resource_probe_realloc(void) { return run(Allocation::Realloc, 256); }
extern "C" int convex_wasm_resource_probe_cpp(void) { return run(Allocation::CppContainers, 256); }
