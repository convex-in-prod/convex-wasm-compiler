#include "../../lib/convex-wasm-native-capability-runtime-main.cpp"

#include "jsi/instrumentation.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

int main(int argc, char **argv) {
  if (argc != 2) throw std::runtime_error("Hardening source path is required");
  auto hermes = facebook::hermes::makeHermesRuntime();
  auto &js = *hermes;
  auto evaluate = [&](const std::string &source) {
    return js.evaluateJavaScript(
        std::make_shared<facebook::jsi::StringBuffer>(source), "native-values");
  };
  auto require = [](bool condition) {
    if (!condition) throw std::runtime_error("Native value contract failed");
  };
  auto array_buffer = js.global().getPropertyAsFunction(js, "ArrayBuffer");
  const Value pending = Value::undefined();
  flexbuffers::Builder packed;
  packed.Map([&] {
    packed.String("__proto__", "own data");
    packed.Int("count", INT64_C(9007199254740993));
    packed.String("name", "document");
    packed.Vector("values", [&] {
      packed.Double(3.5);
      packed.Bool(true);
    });
  });
  packed.Finish();
  std::vector<uint8_t> frame{'C', 'V', 'A', '1', 10};
  const uint32_t length = packed.GetBuffer().size();
  for (size_t i = 0; i < 4; ++i) frame.push_back(length >> (8 * i));
  frame.insert(frame.end(), packed.GetBuffer().begin(), packed.GetBuffer().end());
  for (int i = 0; i < 2; ++i) {
    auto document = ValueAbiReader(js, frame.data(), frame.size(), pending, array_buffer).decode();
    js.global().setProperty(js, "document", document);
    require(evaluate(
        "Object.getPrototypeOf(document) === Object.prototype && "
        "document.__proto__ === 'own data' && document.count === 9007199254740993n && "
        "document.name === 'document' && document.values.length === 2 && "
        "document.values[0] === 3.5 && document.values[1] === true").getBool());
    evaluate("document.name = 'changed'; document.values.push('local')");
    js.instrumentation().collectGarbage("materialization");
  }
  frame.pop_back();
  bool rejected = false;
  try {
    ValueAbiReader(js, frame.data(), frame.size(), pending, array_buffer).decode();
  } catch (const JSError &) {
    rejected = true;
  }
  require(rejected);

  install_intrinsic_snapshot_factory(js);
  std::ifstream input(argv[1]);
  if (!input) throw std::runtime_error("Hardening source is unavailable");
  const std::string hardening{std::istreambuf_iterator<char>(input), {}};
  evaluate(hardening);
  require(!js.global().hasProperty(js, "__convexWasmCaptureIntrinsicState"));
  auto validator = js.global().getPropertyAsFunction(js, kIntrinsicDescriptorStateValidatorBinding);
  require(validator.call(js).getBool());
  require(evaluate(
      "Date.now() === 1 && new Date().getTime() === 1 && "
      "typeof Date() === 'string' && Date.prototype.constructor === Date").getBool());
  evaluate("globalThis.savedDateToString = Date.prototype.toString; "
           "Date.prototype.toString = function() { return 'changed'; }");
  require(!validator.call(js).getBool());
  evaluate("Date.prototype.toString = savedDateToString; delete globalThis.savedDateToString");
  require(validator.call(js).getBool());
  evaluate("globalThis.newApplicationBinding = 1");
  require(validator.call(js).getBool());
  evaluate("Object.prototype.toString = function() { return 'changed'; }");
  require(!validator.call(js).getBool());
  std::cout << "native values and intrinsic validation passed\n";
}
