#include "../../lib/convex-wasm-native-capability-runtime-main.cpp"

#include "jsi/instrumentation.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

int main(int argc, char **argv) {
  if (argc != 4) throw std::runtime_error("Hardening and SDK source paths are required");
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

  auto record = Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "record"), 3,
      [](Runtime &js, const Value &, const Value *args, size_t count) -> Value {
        if (count < 2 || count > 3) throw JSError(js, "Invalid record arity");
        const Value missing = Value::undefined();
        return QueryAbiWriter(js).record(args[0], args[1], count == 3 ? args[2] : missing);
      });
  js.global().setProperty(js, "record", std::move(record));
  evaluate(R"JS(
    function makeQuery(native, sourceKind) {
      const captured = new ArrayBuffer(5);
      new Uint8Array(captured).set([67, 86, 65, 49, 0]);
      const literal = native ? record(1, captured) : {$literal: captured};
      const field = native ? record(2, "field") : {$field: "field"};
      const equal = native ? record(3, field, literal) : {$eq: [field, literal]};
      const predicate = native ? record(16, [equal, equal]) : {$and: [equal, equal]};
      let source;
      if (sourceKind === 1) source = {type: "FullTableScan", tableName: "documents", order: "desc"};
      else if (sourceKind === 2) source = {type: "IndexRange", indexName: "documents.by_field", order: null,
        range: native ? [record(21, "field", captured), record(25, "other", undefined)] :
          [{type: "Eq", fieldPath: "field", value: captured}, {type: "Lte", fieldPath: "other", value: undefined}]};
      else source = {type: "Search", indexName: "documents.search", filters: native ?
        [record(26, "text", "word"), record(27, "field", captured)] :
        [{type: "Search", fieldPath: "text", value: "word"}, {type: "Eq", fieldPath: "field", value: captured}]};
      return {source, operators: native ? [record(28, predicate), record(29, 3)] :
        [{filter: predicate}, {limit: 3}]};
    }
  )JS");
  for (const char *terminal : {"collect", "first", "unique", "stream", "paginate"}) {
    for (int source = 1; source <= 3; ++source) {
      auto legacy = evaluate("makeQuery(false, " + std::to_string(source) + ")");
      auto compact = evaluate("makeQuery(true, " + std::to_string(source) + ")");
      auto pagination = evaluate("({cursor: null, endCursor: 'end', maximumBytesRead: 1000, maximumRowsRead: null, pageSize: 3})");
      const Value kind(String::createFromAscii(js, terminal));
      auto expected = QueryAbiWriter(js).encode(legacy, kind, pagination);
      js.instrumentation().collectGarbage("query records");
      require(QueryAbiWriter(js).encode(compact, kind, pagination) == expected);
    }
  }
  require(evaluate(R"JS(
    (() => {
      let expression = record(2, "field");
      for (let i = 1; i < 64; ++i) expression = record(15, expression);
      try { record(15, expression); return false; }
      catch (error) { return /invalid/.test(error.message); }
    })()
  )JS").getBool());

  std::ifstream sdk_input(argv[2]);
  if (!sdk_input) throw std::runtime_error("SDK source is unavailable");
  evaluate(std::string{std::istreambuf_iterator<char>(sdk_input), {}});
  for (int source = 1; source <= 3; ++source) {
    auto legacy = evaluate("captureSdkQuery(false, " + std::to_string(source) + ")").asObject(js);
    auto compact = evaluate("captureSdkQuery(true, " + std::to_string(source) + ")").asObject(js);
    if (std::string(argv[3]) == "require-records")
      require(compact.getProperty(js, "records").getNumber() >= 8);
    auto kind = Value(String::createFromAscii(js, "collect"));
    auto expected = QueryAbiWriter(js).encode(legacy.getProperty(js, "query"), kind, Value::null());
    js.instrumentation().collectGarbage("SDK query records");
    require(QueryAbiWriter(js).encode(compact.getProperty(js, "query"), kind, Value::null()) == expected);
  }
  evaluate("delete globalThis.Convex; delete globalThis.captureSdkQuery");

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
