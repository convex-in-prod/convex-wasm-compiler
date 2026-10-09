#include "convex-wasm-native-url.h"
#include "ada.h"

#include <memory>
#include <string>
#include <utility>

namespace convex_wasm {
namespace {
using namespace facebook::jsi;

constexpr const char *kBinding = "__convexWasmNativeUrl";

struct NativeUrl final : NativeState {
  explicit NativeUrl(ada::url_aggregator parsed) : url(std::move(parsed)) {}
  ada::url_aggregator url;

  size_t retainedBytes() const {
    return sizeof(NativeUrl) - sizeof(url) + url.retained_bytes();
  }
};

std::shared_ptr<NativeUrl> requireUrl(Runtime &js, const Object &object) {
  if (!object.hasNativeState(js)) {
    throw JSError(js, "Native URL handle has no state");
  }
  auto state = std::dynamic_pointer_cast<NativeUrl>(object.getNativeState(js));
  if (!state) throw JSError(js, "Native URL handle has the wrong state type");
  return state;
}

// Field numbers are private to the native-url-impl support module.
unsigned requireField(Runtime &js, const Value &value) {
  if (!value.isNumber()) throw JSError(js, "Native URL field must be a number");
  const double field = value.getNumber();
  if (!(field >= 0 && field <= 10) || field != static_cast<unsigned>(field)) {
    throw JSError(js, "Native URL field is invalid");
  }
  return static_cast<unsigned>(field);
}
} // namespace

void installNativeUrl(Runtime &js) {
  auto global = js.global();
  if (global.hasProperty(js, kBinding)) {
    throw JSError(js, "Native URL bootstrap already exists");
  }
  Object operations(js);
  operations.setProperty(js, "parse", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "parseURL"), 2,
      [](Runtime &js, const Value &, const Value *args, size_t count) -> Value {
        if (count != 2 || !args[0].isString() ||
            !(args[1].isString() || args[1].isUndefined())) {
          throw JSError(js, "Native URL parse arguments are invalid");
        }
        const auto input = args[0].getString(js).utf8(js);
        ada::result<ada::url_aggregator> parsed;
        if (args[1].isString()) {
          const auto baseInput = args[1].getString(js).utf8(js);
          auto base = ada::parse<ada::url_aggregator>(baseInput);
          if (!base) return Value::null();
          parsed = ada::parse<ada::url_aggregator>(input, &*base);
        } else {
          parsed = ada::parse<ada::url_aggregator>(input);
        }
        if (!parsed) return Value::null();
        auto state = std::make_shared<NativeUrl>(std::move(*parsed));
        Object handle(js);
        handle.setNativeState(js, state);
        handle.setExternalMemoryPressure(js, state->retainedBytes());
        return handle;
      }));
  operations.setProperty(js, "get", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "getURL"), 2,
      [](Runtime &js, const Value &, const Value *args, size_t count) -> Value {
        if (count != 2 || !args[0].isObject()) {
          throw JSError(js, "Native URL get arguments are invalid");
        }
        const auto state = requireUrl(js, args[0].getObject(js));
        const auto &url = state->url;
        std::string_view value;
        switch (requireField(js, args[1])) {
          case 0: value = url.get_href(); break;
          case 1: return String::createFromUtf8(js, url.get_origin());
          case 2: value = url.get_protocol(); break;
          case 3: value = url.get_username(); break;
          case 4: value = url.get_password(); break;
          case 5: value = url.get_host(); break;
          case 6: value = url.get_hostname(); break;
          case 7: value = url.get_port(); break;
          case 8: value = url.get_pathname(); break;
          case 9: value = url.get_search(); break;
          case 10: value = url.get_hash(); break;
        }
        return String::createFromUtf8(
            js, reinterpret_cast<const uint8_t *>(value.data()), value.size());
      }));
  operations.setProperty(js, "set", Function::createFromHostFunction(
      js, PropNameID::forAscii(js, "setURL"), 3,
      [](Runtime &js, const Value &, const Value *args, size_t count) -> Value {
        if (count != 3 || !args[0].isObject() || !args[2].isString()) {
          throw JSError(js, "Native URL set arguments are invalid");
        }
        auto object = args[0].getObject(js);
        auto state = requireUrl(js, object);
        const auto input = args[2].getString(js).utf8(js);
        auto &url = state->url;
        bool accepted;
        switch (requireField(js, args[1])) {
          case 0: accepted = url.set_href(input); break;
          case 1: throw JSError(js, "Native URL origin cannot be assigned");
          case 2: accepted = url.set_protocol(input); break;
          case 3: accepted = url.set_username(input); break;
          case 4: accepted = url.set_password(input); break;
          case 5: accepted = url.set_host(input); break;
          case 6: accepted = url.set_hostname(input); break;
          case 7: accepted = url.set_port(input); break;
          case 8: accepted = url.set_pathname(input); break;
          case 9: url.set_search(input); accepted = true; break;
          case 10: url.set_hash(input); accepted = true; break;
          default: throw JSError(js, "Native URL field is invalid");
        }
        // Setters may retain a larger capacity even when the resulting URL is
        // short. Charge the actual buffer after both accepted and ignored sets.
        object.setExternalMemoryPressure(js, state->retainedBytes());
        return Value(accepted);
      }));
  auto objectConstructor = global.getPropertyAsObject(js, "Object");
  auto freeze = objectConstructor.getPropertyAsFunction(js, "freeze");
  for (const char *name : {"parse", "get", "set"}) {
    freeze.call(js, operations.getProperty(js, name));
  }
  freeze.call(js, operations);
  Object descriptor(js);
  descriptor.setProperty(js, "value", operations);
  descriptor.setProperty(js, "configurable", true);
  descriptor.setProperty(js, "writable", false);
  descriptor.setProperty(js, "enumerable", false);
  objectConstructor.getPropertyAsFunction(js, "defineProperty")
      .call(js, global, String::createFromAscii(js, kBinding), descriptor);
}
} // namespace convex_wasm
