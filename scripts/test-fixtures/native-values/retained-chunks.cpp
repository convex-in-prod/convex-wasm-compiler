#include "../../lib/convex-wasm-native-capability-runtime-main.cpp"

#include "jsi/instrumentation.h"

#include <iostream>
#include <stdexcept>

extern "C" double convex_invocation_unix_timestamp_ms(void) { return 1; }
extern "C" long long convex_capability_current(void) { return 0; }

extern "C" SHUnit *sh_export_test_valid_chunk(void);
extern "C" SHUnit *sh_export_test_failed_chunk(void);
extern "C" int32_t convex_wasm_application_chunk_slot_count(void) { return 2; }
extern "C" void convex_wasm_clear_selected_entry(void) {}
extern "C" int32_t convex_wasm_application_chunk_dependency_by_specifier(
    int32_t, const char *specifier) {
  if (std::strcmp(specifier, "valid") == 0 ||
      std::strcmp(specifier, "./__convex_wasm_import_initialization_00000000.js") == 0) return 0;
  if (std::strcmp(specifier, "failed") == 0 ||
      std::strcmp(specifier, "./__convex_wasm_import_initialization_00000001.js") == 0) return 1;
  return -1;
}
extern "C" SHUnitCreator convex_wasm_application_factory_by_unit_slot(
    int32_t slot) {
  if (slot == 0) return sh_export_test_valid_chunk;
  if (slot == 1) return sh_export_test_failed_chunk;
  return nullptr;
}

int main() {
  auto require = [](bool condition) {
    if (!condition) throw std::runtime_error("Retained chunk contract failed");
  };
  runtime = initialize_runtime();
  require(runtime != nullptr);
  {
    auto &js = *reinterpret_cast<Runtime *>(_sh_get_hermes_runtime(runtime));
    auto noop = Function::createFromHostFunction(
        js, PropNameID::forAscii(js, "validate"), 0,
        [](Runtime &, const Value &, const Value *, size_t) { return Value(true); });
    guest_bridge = std::make_unique<GuestBridge>();
    application_global_facade = std::make_unique<Value>(Object(js));
    application_initializer_reporter = std::make_shared<Function>(std::move(noop));
    intrinsic_descriptor_state_validator = application_initializer_reporter;
    guest_initialization_error_constructors =
        capture_guest_initialization_error_constructors(js);
    bridge_unit_initialization_count = formatter_unit_initialization_count = 1;
    declared_application_entry_count = 1;
    declared_application_unit_count = 3;
    application_export_slots.resize(declared_application_entry_count);
    pending_application_exports.resize(declared_application_entry_count);

    unsigned inspected_initializations = 0;
    js.global().setProperty(js, "inspectChunkInitialization",
        Function::createFromHostFunction(
            js, PropNameID::forAscii(js, "inspectChunkInitialization"), 0,
            [&](Runtime &js, const Value &, const Value *, size_t) {
              // A callback inside module evaluation must not reuse the earlier
              // valid table while a namespace is only partially initialized.
              require(!retained_runtime_state_is_valid());
              js.instrumentation().collectGarbage("chunk initialization");
              require(!retained_runtime_state_is_valid());
              ++inspected_initializations;
              return Value::undefined();
            }));

    require(retained_runtime_state_is_valid());
    require(retained_runtime_state_is_valid());
    {
      auto first = initialize_official_chunk_unit(js, 0);
      require(inspected_initializations == 1);
      require(first.isObject() && retained_runtime_state_is_valid());
      js.instrumentation().collectGarbage("retained namespace");
      auto again = initialize_official_chunk_unit(js, 0);
      require(Value::strictEquals(js, first, again));
      require(inspected_initializations == 1 && retained_runtime_state_is_valid());

      // These checks remain live even after the chunk table itself was validated.
      application_export_slots[0].unit_initialization_count = 1;
      require(!retained_runtime_state_is_valid());
      application_export_slots[0].unit_initialization_count = 0;
      pending_application_exports[0] = std::make_unique<Value>(js, first);
      require(!retained_runtime_state_is_valid());
      pending_application_exports[0].reset();
      ++declared_application_unit_count;
      require(!retained_runtime_state_is_valid());
      --declared_application_unit_count;
      require(retained_runtime_state_is_valid());

      unsigned assigned = 0;
      Array bindings(js, 2);
      for (size_t index = 0; index < 2; ++index) {
        Array pair(js, 2);
        pair.setValueAtIndex(js, 0, String::createFromAscii(js, index == 0 ? "failed" : "valid"));
        pair.setValueAtIndex(js, 1, Function::createFromHostFunction(
            js, PropNameID::forAscii(js, "assign"), 1,
            [&, index](Runtime &js, const Value &, const Value *values, size_t count) {
              require(index == 1 && count == 1 && Value::strictEquals(js, values[0], first));
              ++assigned;
              return Value::undefined();
            }));
        bindings.setValueAtIndex(js, index, std::move(pair));
      }
      expose_official_chunk_unit_bindings(js, 0);
      bool failed = false;
      try {
        js.global().getPropertyAsFunction(js, "__convexWasmOfficialChunkRequire").call(
            js, String::createFromAscii(js, "./__convex_wasm_initialize_imports.js"), bindings);
      } catch (const JSError &) {
        failed = true;
      }
      require(failed && assigned == 1 && inspected_initializations == 2);
      // Guest code may catch a deferred initialization error. The runtime must
      // still reject retention instead of accepting an old validation result.
      require(!retained_runtime_state_is_valid());
      require(!retained_runtime_state_is_valid());
    }
  }
  // Release local roots before destroying the underlying Hermes runtime.
  reset_runtime_state();
  require(retained_runtime_state_is_empty());
  std::cout << "retained chunk validation passed\n";
}
