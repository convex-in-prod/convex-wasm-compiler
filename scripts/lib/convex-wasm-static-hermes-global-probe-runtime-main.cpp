#include "hermes/VM/static_h.h"
#include "jsi/jsi.h"

#include <cstdio>
#include <string>

extern "C" SHUnit *CONVEX_WASM_GLOBAL_PROBE_EXPORTED_UNIT(void);

namespace {

SHRuntime *initialize_runtime() {
  char program[] = "convex-wasm-static-hermes-global-probe";
  char init_heap[] = "--gc-init-heap=4MiB";
  char max_heap[] = "--gc-max-heap=64MiB";
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

const char *value_type(
    facebook::jsi::Runtime &js,
    const facebook::jsi::Value &value) {
  if (value.isUndefined()) return "undefined";
  if (value.isNull()) return "object";
  if (value.isBool()) return "boolean";
  if (value.isNumber()) return "number";
  if (value.isString()) return "string";
  if (value.isSymbol()) return "symbol";
  if (value.isObject()) {
    return value.getObject(js).isFunction(js) ? "function" : "object";
  }
  return "unclassified";
}

facebook::jsi::Object snapshot(facebook::jsi::Runtime &js) {
  auto global = js.global();
  auto object = global.getPropertyAsObject(js, "Object");
  auto get_names = object.getPropertyAsFunction(js, "getOwnPropertyNames");
  auto get_descriptor =
      object.getPropertyAsFunction(js, "getOwnPropertyDescriptor");
  auto names = get_names.call(js, global).getObject(js).getArray(js);
  facebook::jsi::Array keys(js, names.size(js));
  facebook::jsi::Object value_types(js);
  for (size_t index = 0; index < names.size(js); ++index) {
    auto name = names.getValueAtIndex(js, index).getString(js);
    const std::string utf8 = name.utf8(js);
    keys.setValueAtIndex(js, index, name);
    auto descriptor =
        get_descriptor.call(js, global, name).getObject(js);
    const auto value = descriptor.getProperty(js, "value");
    value_types.setProperty(js, utf8.c_str(), value_type(js, value));
  }
  facebook::jsi::Object result(js);
  result.setProperty(js, "keys", keys);
  result.setProperty(js, "valueTypes", value_types);
  return result;
}

std::string stringify(
    facebook::jsi::Runtime &js,
    const facebook::jsi::Object &value) {
  auto json = js.global().getPropertyAsObject(js, "JSON");
  auto stringify = json.getPropertyAsFunction(js, "stringify");
  return stringify.call(js, value).getString(js).utf8(js);
}

}  // namespace

extern "C" int convex_wasm_static_hermes_global_probe_run(void) {
  SHRuntime *runtime = initialize_runtime();
  if (runtime == nullptr) return 1;
  auto &js = *reinterpret_cast<facebook::jsi::Runtime *>(
      _sh_get_hermes_runtime(runtime));
  try {
    auto raw = snapshot(js);
    if (!_sh_initialize_units(
            runtime, 1, CONVEX_WASM_GLOBAL_PROBE_EXPORTED_UNIT)) {
      _sh_done(runtime);
      return 2;
    }
    auto effective_first = snapshot(js);
    auto effective_second = snapshot(js);
    facebook::jsi::Object report(js);
    report.setProperty(js, "effectiveFirst", effective_first);
    report.setProperty(js, "effectiveSecond", effective_second);
    report.setProperty(js, "raw", raw);
    const std::string output = stringify(js, report);
    std::fwrite(output.data(), 1, output.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
  } catch (const facebook::jsi::JSError &error) {
    std::fprintf(stderr, "Static Hermes global probe JSI error: %.2048s\n", error.getMessage().c_str());
    _sh_done(runtime);
    return 3;
  } catch (...) {
    std::fputs("Static Hermes global probe failed\n", stderr);
    _sh_done(runtime);
    return 4;
  }
  _sh_done(runtime);
  return 0;
}
