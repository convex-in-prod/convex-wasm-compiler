#include "convex-wasm-native-url.h"
#include "ada.h"
#include "hermes/hermes.h"
#include "jsi/instrumentation.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <source_location>
#include <stdexcept>

using namespace facebook::jsi;

int main(int argc, char **argv) {
  if (argc != 4) throw std::runtime_error("Support, corpus and fixture paths are required");
  auto runtime = facebook::hermes::makeHermesRuntime(
      hermes::vm::RuntimeConfig::Builder().withES6BlockScoping(true).build());
  auto &js = *runtime;
  auto evaluate = [&](const std::string &source, const std::string &name = "native-url") {
    return js.evaluateJavaScript(std::make_shared<StringBuffer>(source), name);
  };
  auto require = [](bool value, std::source_location location = std::source_location::current()) {
    if (!value) throw std::runtime_error("Native URL contract failed at line " + std::to_string(location.line()));
  };
  convex_wasm::installNativeUrl(js);
  auto operations = js.global().getPropertyAsObject(js, "__convexWasmNativeUrl");
  auto parse = operations.getPropertyAsFunction(js, "parse");
  auto get = operations.getPropertyAsFunction(js, "get");
  auto set = operations.getPropertyAsFunction(js, "set");
  bool rejected = false;
  try {
    get.call(js, Object(js), 0);
  } catch (const JSError &) { rejected = true; }
  require(rejected);
  js.global().setProperty(js, "collectForUrlTest", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "collectForUrlTest"), 0,
      [](Runtime &js, const Value &, const Value *, size_t) {
        js.instrumentation().collectGarbage("URL coercion");
        return Value::undefined();
      }));
  evaluate(R"JS(
    globalThis.__convexWasmApplicationInstallRuntimeSupport = function(support) {
      globalThis.URL = support.URL;
      globalThis.URLSearchParams = support.URLSearchParams;
      if (typeof URL.canParse !== 'function' || typeof URL.parse !== 'function') {
        throw new Error('Missing URL statics: ' + Object.getOwnPropertyNames(URL).join(','));
      }
      for (const ctor of [URL, URLSearchParams]) {
        for (const obj of [ctor, ctor.prototype]) {
          for (const key of Reflect.ownKeys(obj)) {
            const d = Object.getOwnPropertyDescriptor(obj, key);
            for (const f of [d.value, d.get, d.set]) {
              if (typeof f === 'function') Object.freeze(f);
            }
          }
          Object.freeze(obj);
        }
      }
      delete globalThis.__convexWasmApplicationInstallRuntimeSupport;
    };
  )JS");
  for (int i = 1; i < argc; ++i) {
    std::ifstream stream(argv[i]);
    if (!stream) throw std::runtime_error("Native URL fixture input is missing");
    evaluate(std::string(std::istreambuf_iterator<char>(stream), {}), argv[i]);
  }
  require(!js.global().hasProperty(js, "__convexWasmNativeUrl"));

  js.instrumentation().collectGarbage("URL memory baseline");
  const auto before = js.instrumentation().getHeapInfo(false).at("hermes_externalBytes");
  {
    const std::string input = "https://example.test/" + std::string(100000, 'x');
    auto handle = parse.call(js, String::createFromUtf8(js, input), Value::undefined());
    auto reference = ada::parse<ada::url_aggregator>(input);
    require(reference.has_value());
    js.instrumentation().collectGarbage("URL initial capacity");
    const auto initial = js.instrumentation().getHeapInfo(false).at("hermes_externalBytes") - before;
    require(initial >= static_cast<int64_t>(reference->retained_bytes()));
    const auto stateOverhead = initial - reference->retained_bytes();
    set.call(js, handle, 8, String::createFromAscii(js, "/short"));
    reference->set_pathname("/short");
    js.instrumentation().collectGarbage("URL retained capacity after shortening");
    const auto shortened = js.instrumentation().getHeapInfo(false).at("hermes_externalBytes") - before;
    require(shortened == static_cast<int64_t>(reference->retained_bytes() + stateOverhead));
    const std::string grownPath = "/" + std::string(250000, 'y');
    set.call(js, handle, 8, String::createFromUtf8(js, grownPath));
    reference->set_pathname(grownPath);
    js.instrumentation().collectGarbage("URL grown capacity");
    const auto grown = js.instrumentation().getHeapInfo(false).at("hermes_externalBytes") - before;
    require(grown == static_cast<int64_t>(reference->retained_bytes() + stateOverhead));
    require(grown > initial);
    set.call(js, handle, 0, String::createFromAscii(js, "https://example.test/tiny"));
    reference->set_href("https://example.test/tiny");
    js.instrumentation().collectGarbage("URL replaced capacity");
    const auto replaced = js.instrumentation().getHeapInfo(false).at("hermes_externalBytes") - before;
    require(replaced == static_cast<int64_t>(reference->retained_bytes() + stateOverhead));
    // Ada's href setter copies into its old buffer; shortening must keep that
    // capacity charged until the URL itself is collected.
    require(replaced == grown);
    js.instrumentation().collectGarbage("URL rooted native handle");
    require(get.call(js, handle, 0).getString(js).utf8(js) == "https://example.test/tiny");
  }
  js.instrumentation().collectGarbage("URL native state release");
  require(js.instrumentation().getHeapInfo(false).at("hermes_externalBytes") == before);
  std::cout << "native URL wrappers, corpus and retained memory passed\n";
}
