#include "../../lib/convex-wasm-native-capability-runtime-main.cpp"

#include "jsi/instrumentation.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace {
long long clock_capability = 0;
double clock_timestamp_ms = 0;
size_t clock_reads = 0;
}
extern "C" long long convex_capability_current(void) { return clock_capability; }
extern "C" double convex_invocation_unix_timestamp_ms(void) {
  ++clock_reads;
  return clock_timestamp_ms;
}

int main(int argc, char **argv) {
  if (argc != 4) throw std::runtime_error("Hardening and SDK source paths are required");
  std::unique_ptr<SHRuntime, decltype(&_sh_done)> hermes(initialize_runtime(), &_sh_done);
  if (!hermes) throw std::runtime_error("Native adapter initialization failed");
  auto &js = *reinterpret_cast<Runtime *>(_sh_get_hermes_runtime(hermes.get()));
  SHHeapStatistics heap_before{};
  _sh_get_heap_statistics(hermes.get(), &heap_before);
  auto evaluate = [&](const std::string &source) {
    return js.evaluateJavaScript(
        std::make_shared<facebook::jsi::StringBuffer>(source), "native-values");
  };
  auto require = [](bool condition) {
    if (!condition) throw std::runtime_error("Native value contract failed");
  };
  require(evaluate(
      "Object.getOwnPropertyNames(new Promise(function() {})).length === 0 && "
      "!('createNativePromiseCore' in HermesInternal) && "
      "typeof HermesInternal.drainJobs === 'undefined'").getBool());
  // Exercise the linked provider data, not only the presence of Intl globals.
  require(evaluate(
      "new Intl.NumberFormat('de-DE').format(1234.5) === '1.234,5' && "
      "new Intl.DateTimeFormat('en-GB', {timeZone: 'UTC', year: 'numeric', "
      "month: '2-digit', day: '2-digit'}).format(0) === '01/01/1970' && "
      "new Intl.Collator('en', {sensitivity: 'base'}).compare('caf\\u00e9', 'cafe') === 0"
      ).getBool());
  evaluate("globalThis.clockFormatter = new Intl.DateTimeFormat('en-GB', "
           "{timeZone: 'UTC', year: 'numeric', month: '2-digit', day: '2-digit'}); "
           "globalThis.clockFormat = clockFormatter.format;");
  for (const bool active : {false, true, false}) {
    clock_capability = active ? 1 : 0;
    clock_timestamp_ms = 86400000;
    const auto reads_before = clock_reads;
    require(evaluate(
        "clockFormat(0) === '01/01/1970' && "
        "clockFormatter.formatToParts(0).map(p => p.value).join('') === '01/01/1970' && "
        "new Date(0).getTime() === 0").getBool());
    require(clock_reads == reads_before);
    for (const auto *source : {
             "Date.now()", "Date()", "new Date()", "clockFormat()",
             "clockFormat(undefined)", "clockFormatter.formatToParts()",
             "clockFormatter.formatToParts(undefined)"}) {
      bool rejected = false;
      try {
        evaluate(source);
      } catch (const JSError &) {
        rejected = true;
      }
      require(rejected != active);
    }
    if (active) {
      require(evaluate(
          "Date.now() === 86400000 && new Date().getTime() === 86400000 && "
          "clockFormat() === '02/01/1970' && "
          "clockFormatter.formatToParts().map(p => p.value).join('') === '02/01/1970'"
          ).getBool());
    } else {
      require(clock_reads == reads_before);
    }
  }
  evaluate("delete globalThis.clockFormatter; delete globalThis.clockFormat;");
  auto array_buffer = js.global().getPropertyAsFunction(js, "ArrayBuffer");
  const QueryAbiProperties query_properties(js);
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
  SHHeapStatistics heap_after{};
  _sh_get_heap_statistics(hermes.get(), &heap_after);
  require(heap_after.collections > heap_before.collections);
  require(heap_after.allocated_bytes > heap_before.allocated_bytes);
  require(heap_after.gc_wall_nanos >= heap_before.gc_wall_nanos);
  require(heap_after.gc_cpu_nanos >= heap_before.gc_cpu_nanos);
  // Cross the inline-key capacity and recurse while the parent views are live.
  flexbuffers::Builder wide;
  wide.Map([&] {
    for (unsigned i = 0; i < 40; ++i) {
      const std::string key = "field" + std::to_string(100 + i);
      wide.Map(key.c_str(), [&] { wide.Double("value", i); });
    }
  });
  wide.Finish();
  std::vector<uint8_t> wide_frame{'C', 'V', 'A', '1', 10};
  for (size_t i = 0; i < 4; ++i) {
    wide_frame.push_back(wide.GetBuffer().size() >> (8 * i));
  }
  wide_frame.insert(wide_frame.end(), wide.GetBuffer().begin(), wide.GetBuffer().end());
  for (int i = 0; i < 2; ++i) {
    auto document = ValueAbiReader(js, wide_frame.data(), wide_frame.size(), pending, array_buffer).decode();
    js.global().setProperty(js, "wideDocument", document);
    require(evaluate(
        "Object.keys(wideDocument).length === 40 && "
        "Object.keys(wideDocument).every((key, i) => wideDocument[key].value === i)").getBool());
    evaluate("wideDocument.field100.value = -1; delete wideDocument.field139");
    js.instrumentation().collectGarbage("wide materialization");
  }
  const ValueAbiIntrinsics wide_intrinsics{
      js.global().getPropertyAsObject(js, "Object").getPropertyAsObject(js, "prototype")};
  const auto wide_input = evaluate(R"JS(
    (() => {
      const value = {};
      for (let i = 0; i < 40; ++i) value[`field${100 + i}`] = {value: i};
      return value;
    })()
  )JS");
  const auto wide_encoded =
      ValueAbiWriter(js, pending, wide_intrinsics, ValueAbiMode::Value).encode(wide_input);
  const auto wide_round_trip =
      ValueAbiReader(js, wide_encoded.data(), wide_encoded.size(), pending, array_buffer).decode();
  js.global().setProperty(js, "wideRoundTrip", wide_round_trip);
  require(evaluate(
      "Object.keys(wideRoundTrip).length === 40 && "
      "wideRoundTrip.field100.value === 0 && wideRoundTrip.field139.value === 39")
              .getBool());
  js.instrumentation().collectGarbage("wide encode fallback");
  // Each packed document has its own bytes; reuse must validate equal keys,
  // preserve independent values, and work for the ordinary CVA1 layout too.
  for (const bool use_packed : {true, false}) {
    std::vector<uint8_t> collection{'C', 'V', 'A', '1', 11, 8, 0, 0, 0};
    for (unsigned i = 0; i < 8; ++i) {
      if (use_packed) {
        collection.insert(collection.end(), frame.begin() + 4, frame.end());
      } else {
        collection.insert(collection.end(), {8, 1, 0, 0, 0, 4, 0, 0, 0});
        collection.insert(collection.end(), {'n', 'a', 'm', 'e', 5, 8, 0, 0, 0});
        collection.insert(collection.end(), {'d', 'o', 'c', 'u', 'm', 'e', 'n', 't'});
      }
    }
    const auto before = js.instrumentation().getHeapInfo(false).at("hermes_objectLayoutHintHits");
    auto decoded = ValueAbiReader(js, collection.data(), collection.size(), pending, array_buffer).decode();
    const auto after = js.instrumentation().getHeapInfo(false).at("hermes_objectLayoutHintHits");
    require(after - before == 7);
    js.global().setProperty(js, "collection", decoded);
    require(evaluate(
        "collection.length === 8 && collection.every(x => x.name === 'document') && "
        "collection.every((x, i) => collection.indexOf(x) === i)").getBool());
    evaluate("collection[0].name = 'changed'; delete collection[0].count");
    require(evaluate("collection.slice(1).every(x => x.name === 'document')").getBool());
    js.instrumentation().collectGarbage("hinted document collection");
  }
  // FlexBuffers structural verification does not establish our sorted-key
  // contract. Reject duplicates and descending keys before layout lookup.
  for (const char replacement : {'a', 'z'}) {
    flexbuffers::Builder invalid;
    invalid.Map([&] { invalid.Double("a", 1); invalid.Double("b", 2); });
    invalid.Finish();
    std::vector<uint8_t> invalid_frame{'C', 'V', 'A', '1', 10};
    for (size_t i = 0; i < 4; ++i) {
      invalid_frame.push_back(invalid.GetBuffer().size() >> (8 * i));
    }
    invalid_frame.insert(invalid_frame.end(), invalid.GetBuffer().begin(), invalid.GetBuffer().end());
    const auto keys = flexbuffers::GetRoot(invalid_frame.data() + 9, invalid_frame.size() - 9).AsMap().Keys();
    const char *key = keys[replacement == 'a' ? 1 : 0].AsKey();
    invalid_frame[reinterpret_cast<const uint8_t *>(key) - invalid_frame.data()] = replacement;
    bool rejected_keys = false;
    try {
      ValueAbiReader(js, invalid_frame.data(), invalid_frame.size(), pending, array_buffer).decode();
    } catch (const JSError &) {
      rejected_keys = true;
    }
    require(rejected_keys);
  }
  // The reader borrows C-string key views only after structural verification.
  // Keep these buffers exact-sized: trailing storage must not supply a missing
  // terminator or hide a key/value count mismatch.
  {
    const std::vector<uint8_t> valid{'a', 0, 1, 3, 1, 1, 1, 1, 4, 2, 36, 1};
    require(flexbuffers::VerifyBuffer(valid.data(), valid.size()));
    auto unterminated_key = valid;
    unterminated_key[1] = 'b';
    auto wrong_count = valid;
    wrong_count[2] = 0;
    flexbuffers::Builder strings;
    strings.Map([&] {
      strings.String("", "");
      strings.String("embedded", std::string("a\0b", 3));
      strings.Vector("shared", [&] {
        for (unsigned i = 0; i < 3; ++i)
          strings.Map([&] { strings.Int("key", i); });
      });
      strings.String("text", "value");
    });
    strings.Finish();
    auto wrong_terminator = strings.GetBuffer();
    const auto text = flexbuffers::GetRoot(wrong_terminator.data(), wrong_terminator.size())
                          .AsMap()["text"].AsString();
    wrong_terminator[reinterpret_cast<const uint8_t *>(text.c_str()) -
                     wrong_terminator.data() + text.size()] = 'x';
    for (const auto &invalid : {unterminated_key, wrong_count, wrong_terminator}) {
      require(!flexbuffers::VerifyBuffer(invalid.data(), invalid.size()));
      std::vector<uint8_t> invalid_frame{'C', 'V', 'A', '1', 10};
      for (size_t i = 0; i < 4; ++i)
        invalid_frame.push_back(invalid.size() >> (8 * i));
      invalid_frame.insert(invalid_frame.end(), invalid.begin(), invalid.end());
      bool rejected = false;
      try {
        ValueAbiReader(js, invalid_frame.data(), invalid_frame.size(), pending, array_buffer).decode();
      } catch (const JSError &) {
        rejected = true;
      }
      require(rejected);
    }
    std::vector<uint8_t> string_frame{'C', 'V', 'A', '1', 10};
    for (size_t i = 0; i < 4; ++i)
      string_frame.push_back(strings.GetBuffer().size() >> (8 * i));
    string_frame.insert(string_frame.end(), strings.GetBuffer().begin(), strings.GetBuffer().end());
    js.global().setProperty(js, "packedStrings",
        ValueAbiReader(js, string_frame.data(), string_frame.size(), pending, array_buffer).decode());
    require(evaluate(
        "packedStrings[''] === '' && packedStrings.embedded === 'a\\0b' && "
        "packedStrings.text === 'value' && packedStrings.shared.length === 3 && "
        "packedStrings.shared.every((x, i) => x.key === BigInt(i))").getBool());
  }
  // Match the host's page envelope: a document collection inside an object,
  // followed by cursor fields that must survive the reader's indexing pass.
  for (uint32_t count : {0u, 2u}) {
    std::vector<uint8_t> page{'C', 'V', 'A', '1', 8, 5, 0, 0, 0};
    auto append_slice = [&](std::string_view text) {
      for (size_t i = 0; i < 4; ++i) page.push_back(text.size() >> (8 * i));
      page.insert(page.end(), text.begin(), text.end());
    };
    append_slice("continueCursor");
    page.push_back(5);
    append_slice("next");
    append_slice("isDone");
    page.push_back(count == 0 ? 2 : 1);
    append_slice("page");
    page.push_back(11);
    for (size_t i = 0; i < 4; ++i) page.push_back(count >> (8 * i));
    const size_t first_entry = page.size();
    if (count != 0) {
      page.insert(page.end(), frame.begin() + 4, frame.end());
      // Collections may mix packed documents and ordinary object values.
      page.insert(page.end(), {8, 1, 0, 0, 0});
      append_slice("name");
      page.push_back(5);
      append_slice("pending");
    }
    append_slice("pageStatus");
    page.push_back(0);
    append_slice("splitCursor");
    page.push_back(5);
    append_slice("split");
    for (int i = 0; i < 2; ++i) {
      auto result = ValueAbiReader(js, page.data(), page.size(), pending, array_buffer).decode();
      js.global().setProperty(js, "pageResult", result);
      require(evaluate(
          "pageResult.continueCursor === 'next' && "
          "pageResult.pageStatus === null && pageResult.splitCursor === 'split' && "
          "(pageResult.isDone ? pageResult.page.length === 0 : "
          "pageResult.page.length === 2 && "
          "pageResult.page[0].count === 9007199254740993n && "
          "pageResult.page[0].__proto__ === 'own data' && "
          "pageResult.page[1].name === 'pending')").getBool());
      evaluate("pageResult.page.push('local')");
      js.instrumentation().collectGarbage("page materialization");
    }
    if (count != 0) {
      page[first_entry] = 0;
      bool rejected_entry = false;
      try {
        ValueAbiReader(js, page.data(), page.size(), pending, array_buffer).decode();
      } catch (const JSError &) {
        rejected_entry = true;
      }
      require(rejected_entry);
    }
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
      [&query_properties](Runtime &js, const Value &, const Value *args, size_t count) -> Value {
        if (count < 2 || count > 3) throw JSError(js, "Invalid record arity");
        const Value missing = Value::undefined();
        return QueryAbiWriter(js, query_properties).record(args[0], args[1], count == 3 ? args[2] : missing);
      });
  js.global().setProperty(js, "record", std::move(record));
  const ValueAbiIntrinsics query_intrinsics{
      js.global().getPropertyAsObject(js, "Object").getPropertyAsObject(js, "prototype")};
  const auto scalar_values = evaluate("[1, 0x0102030405060708n, 'x'.repeat(258)]");
  std::vector<uint8_t> scalar_bytes{
      'C', 'V', 'A', '1', 7, 3, 0, 0, 0,
      3, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f,
      4, 8, 7, 6, 5, 4, 3, 2, 1,
      5, 2, 1, 0, 0};
  scalar_bytes.insert(scalar_bytes.end(), 258, 'x');
  require(ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
              .encode(scalar_values) == scalar_bytes);
  for (const size_t tail_bytes : {size_t{1}, size_t{9}}) {
    for (const size_t overflow : {size_t{0}, size_t{1}}) {
      // The array header and byte-buffer header use fourteen bytes. Exercise
      // both a final tag byte and a final fixed-width number at the frame limit.
      const size_t payload_size =
          kValueAbiMaximumFrameBytes - 14 - tail_bytes + overflow;
      auto payload = array_buffer.callAsConstructor(js, static_cast<double>(payload_size));
      Array values(js, 2);
      values.setValueAtIndex(js, 0, payload);
      values.setValueAtIndex(js, 1, tail_bytes == 1 ? Value(true) : Value(1));
      bool rejected_size = false;
      try {
        auto encoded = ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
                           .encode(Value(std::move(values)));
        require(overflow == 0 && encoded.size() == kValueAbiMaximumFrameBytes);
      } catch (const JSError &error) {
        require(error.getMessage() == "Typed value frame exceeds the byte limit");
        rejected_size = true;
      }
      require(rejected_size == (overflow != 0));
    }
    js.instrumentation().collectGarbage("value frame limit");
  }
  auto value_record = Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "valueRecord"), 3,
      [&](Runtime &js, const Value &, const Value *args, size_t count) -> Value {
        if (count != 3) throw JSError(js, "Invalid value record arity");
        return QueryAbiWriter(js, query_properties).record_value(args[0], args[1], args[2], pending,
                                               query_intrinsics);
      });
  js.global().setProperty(js, "valueRecord", std::move(value_record));
  for (const char *source : {"undefined", "null", "true", "false", "0", "-0",
                            "Infinity", "NaN", "-9223372036854775808n",
                            "9223372036854775807n", "'text 😀'", "[1, 'a']",
                            "({nested: [1]})", "new ArrayBuffer(3)"}) {
    auto input = evaluate(source);
    Value captured = Value::undefined();
    if (!input.isUndefined()) {
      auto bytes = ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value).encode(input);
      auto buffer = array_buffer.callAsConstructor(js, static_cast<double>(bytes.size()))
                        .asObject(js).getArrayBuffer(js);
      std::memcpy(buffer.data(js), bytes.data(), bytes.size());
      captured = Value(std::move(buffer));
    }
    const Value field(String::createFromAscii(js, "field"));
    for (const int code : {1, 21, 22, 23, 24, 25, 27}) {
      const Value kind(code);
      auto old = code == 1 ? QueryAbiWriter(js, query_properties).record(kind, captured, pending)
                           : QueryAbiWriter(js, query_properties).record(kind, field, captured);
      auto combined = QueryAbiWriter(js, query_properties).record_value(kind, field, input, pending,
                                                       query_intrinsics);
      js.instrumentation().collectGarbage("combined query records");
      const auto expected = old.asObject(js).getNativeState<QueryAbiRecord>(js);
      const auto actual = combined.asObject(js).getNativeState<QueryAbiRecord>(js);
      require(expected->bytes == actual->bytes && expected->kind == actual->kind &&
              expected->expression_nodes == actual->expression_nodes &&
              expected->expression_depth == actual->expression_depth);
    }
  }
  evaluate("globalThis.cyclicValue = {}; cyclicValue.self = cyclicValue");
  bool rejected_cycle = false;
  try {
    ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
        .encode(evaluate("cyclicValue"));
  } catch (const JSError &error) {
    require(error.getMessage() == "Cyclic objects are not Convex values");
    rejected_cycle = true;
  }
  require(rejected_cycle);
  const auto reentrant_input = evaluate("({values: [1, 2]})");
  const auto reentrant_bytes =
      ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
          .encode(reentrant_input);
  size_t encoding_collections = 0;
  auto encoding_gc = Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "collectDuringEncoding"), 0,
      [&](Runtime &js, const Value &, const Value *, size_t) -> Value {
        js.instrumentation().collectGarbage("encoding ancestor lifetime");
        ++encoding_collections;
        require(ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
                    .encode(reentrant_input) == reentrant_bytes);
        return Value::undefined();
      });
  js.global().setProperty(js, "collectDuringEncoding", std::move(encoding_gc));
  const auto shared_input = evaluate(R"JS(
    (() => {
      const child = {get value() { collectDuringEncoding(); return 7; }};
      return [child, child, {get child() { collectDuringEncoding(); return child; }}];
    })()
  )JS");
  require(ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
              .encode(shared_input) ==
          ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
              .encode(evaluate("[{value: 7}, {value: 7}, {child: {value: 7}}]")));
  require(encoding_collections == 4);
  rejected_cycle = false;
  try {
    ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
        .encode(evaluate(R"JS(
          (() => {
            const root = [];
            root.push({get back() { collectDuringEncoding(); return root; }});
            return root;
          })()
        )JS"));
  } catch (const JSError &error) {
    require(error.getMessage() == "Cyclic objects are not Convex values");
    rejected_cycle = true;
  }
  require(rejected_cycle && encoding_collections == 5);
  for (const size_t overflow : {size_t{0}, size_t{1}}) {
    Value nested(1);
    for (size_t depth = 0; depth < kValueAbiMaximumNesting + overflow; ++depth) {
      Array parent(js, 1);
      parent.setValueAtIndex(js, 0, nested);
      nested = Value(std::move(parent));
    }
    bool rejected_nesting = false;
    try {
      ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value).encode(nested);
    } catch (const JSError &error) {
      require(error.getMessage() == "Typed value nesting exceeds the limit");
      rejected_nesting = true;
    }
    require(rejected_nesting == (overflow != 0));
  }
  for (const int field_count : {16, 17, 40}) {
    js.global().setProperty(js, "encodingFieldCount", field_count);
    const auto sorted_input = evaluate(R"JS(
      (() => {
        globalThis.encodingReads = [];
        const record = {};
        function addField(index) {
          Object.defineProperty(record, `field${100 + index}`, {
            enumerable: true,
            get() {
              encodingReads.push(`root${index}`);
              return {
                text: `value${index}`,
                get number() {
                  encodingReads.push(`child${index}`);
                  collectDuringEncoding();
                  return index;
                }
              };
            }
          });
        }
        for (let i = encodingFieldCount - 1; i >= 0; --i) addField(i);
        return record;
      })()
    )JS");
    const auto expected_input = evaluate(R"JS(
      (() => {
        const record = {};
        for (let i = 0; i < encodingFieldCount; ++i) {
          record[`field${100 + i}`] = {text: `value${i}`, number: i};
        }
        return record;
      })()
    )JS");
    const auto sorted_bytes =
        ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
            .encode(sorted_input);
    if (sorted_bytes !=
        ValueAbiWriter(js, pending, query_intrinsics, ValueAbiMode::Value)
            .encode(expected_input)) {
      throw std::runtime_error("Sorted snapshot encoding changed values");
    }
    if (!evaluate(R"JS(
      (() => {
        const expected = [];
        for (let i = encodingFieldCount - 1; i >= 0; --i) expected.push(`root${i}`);
        for (let i = 0; i < encodingFieldCount; ++i) expected.push(`child${i}`);
        return encodingReads.join('|') === expected.join('|');
      })()
    )JS").getBool()) {
      throw std::runtime_error("Sorted snapshot encoding changed getter order");
    }
  }
  auto snapshot = evaluate("globalThis.queryInput = {nested: [1]}; valueRecord(21, 'field', queryInput)");
  const auto snapshot_bytes = snapshot.asObject(js).getNativeState<QueryAbiRecord>(js)->bytes;
  evaluate("queryInput.nested.push(9); delete queryInput.nested");
  js.instrumentation().collectGarbage("query snapshot mutation");
  require(snapshot.asObject(js).getNativeState<QueryAbiRecord>(js)->bytes == snapshot_bytes);
  require(evaluate(R"JS(
    (() => {
      let getterCalled = false;
      const invalid = {get value() { getterCalled = true; throw new Error("snapshot getter failed"); }};
      let error;
      try { valueRecord(21, 42, invalid); } catch (e) { error = e; }
      if (!error || !getterCalled || error.message !== "snapshot getter failed") return false;
      for (const kind of [0, 2, 26, 28, 1.5, NaN, Infinity]) {
        try { valueRecord(kind, 'field', null); return false; }
        catch (e) { if (!/invalid/.test(e.message)) throw e; }
      }
      try { valueRecord(21, 'field', 9223372036854775808n); return false; }
      catch (e) { if (!/signed 64-bit/.test(e.message)) throw e; }
      return true;
    })()
  )JS").getBool());
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
      auto expected = QueryAbiWriter(js, query_properties).encode(legacy, kind, pagination);
      js.instrumentation().collectGarbage("query records");
      require(QueryAbiWriter(js, query_properties).encode(compact, kind, pagination) == expected);
    }
  }
  auto observed_query = evaluate(R"JS(
    globalThis.queryReads = [];
    globalThis.querySource = {type: 'FullTableScan', order: 'desc', tableName: 'documents'};
    globalThis.queryOperator = {limit: 9007199254740991};
    new Proxy({source: new Proxy(querySource, {
      get(target, key) { queryReads.push('source:' + key); return target[key]; }
    }), operators: [queryOperator]}, {
      get(target, key) { queryReads.push('query:' + key); return target[key]; }
    })
  )JS");
  // An unrelated native state must retain the ordinary query-object path.
  js.global().getPropertyAsObject(js, "queryOperator")
      .setNativeState(js, std::make_shared<facebook::jsi::NativeState>());
  const Value collect(String::createFromAscii(js, "collect"));
  std::vector<uint8_t> query_bytes{
      'C', 'Q', 'R', '1', 1, 1, 2, 9, 0, 0, 0,
      'd', 'o', 'c', 'u', 'm', 'e', 'n', 't', 's',
      1, 0, 0, 0, 2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0};
  for (int iteration = 0; iteration < 2; ++iteration) {
    evaluate("queryReads.length = 0");
    js.instrumentation().collectGarbage("query property identifiers");
    require(QueryAbiWriter(js, query_properties).encode(
                observed_query, collect, Value::null()) == query_bytes);
    require(evaluate(
        "queryReads.join('|') === "
        "'query:source|source:type|source:order|source:tableName|query:operators'")
                .getBool());
    evaluate("querySource.tableName = 'documents2'");
    if (iteration == 0) {
      query_bytes[7] = 10;
      query_bytes.insert(query_bytes.begin() + 20, '2');
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
    auto expected = QueryAbiWriter(js, query_properties).encode(legacy.getProperty(js, "query"), kind, Value::null());
    js.instrumentation().collectGarbage("SDK query records");
    require(QueryAbiWriter(js, query_properties).encode(compact.getProperty(js, "query"), kind, Value::null()) == expected);
    if (std::string(argv[3]) == "require-records") {
      auto combined = evaluate("captureSdkQuery(true, " + std::to_string(source) + ", true)").asObject(js);
      js.instrumentation().collectGarbage("combined SDK query records");
      require(combined.getProperty(js, "records").getNumber() >= 8);
      require(QueryAbiWriter(js, query_properties).encode(combined.getProperty(js, "query"), kind, Value::null()) == expected);
    }
  }
  evaluate("delete globalThis.Convex; delete globalThis.captureSdkQuery");

  install_intrinsic_snapshot_factory(js);
  std::ifstream input(argv[1]);
  if (!input) throw std::runtime_error("Hardening source is unavailable");
  const std::string hardening{std::istreambuf_iterator<char>(input), {}};
  evaluate(hardening);
  auto settlement = evaluate(R"JS(
    (function () {
      var state = { value: 0 };
      var resolve;
      var promise = new Promise(function (r) { resolve = r; });
      promise.then(function (value) { state.value = value; });
      Object.freeze(promise);
      resolve(42);
      return state;
    })()
  )JS").asObject(js);
  js.drainMicrotasks();
  require(settlement.getProperty(js, "value").getNumber() == 42);
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
