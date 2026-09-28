#include "convex_wasm_opaque_abi_v3.h"
#include "hermes/hermes.h"
#include "hermes/VM/static_h.h"
#include "jsi/jsi.h"
#if defined(__EMSCRIPTEN__)
// Packed values are verified and dispatched by type. Avoid FlexBuffers' unused
// string-to-number fallback, which pulls a non-PIC locale singleton into the base module.
#define FLATBUFFERS_LOCALE_INDEPENDENT 0
#endif
#include "flatbuffers/flexbuffers.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

extern "C" SHUnit *CONVEX_WASM_BRIDGE_EXPORTED_UNIT(void);
extern "C" SHUnit *CONVEX_WASM_FORMATTER_EXPORTED_UNIT(void);
extern "C" int32_t convex_wasm_application_entry_count(void);
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
extern "C" int32_t convex_wasm_application_unit_count(void);
extern "C" int32_t convex_wasm_application_chunk_slot_count(void);
extern "C" int32_t
convex_wasm_application_entry_publication_unit_slot_by_handoff_slot(
    int32_t entry_slot);
extern "C" SHUnitCreator
convex_wasm_application_factory_by_unit_slot(int32_t unit_slot);
extern "C" int32_t convex_wasm_application_chunk_dependency_by_specifier(
    int32_t unit_slot,
    const char *specifier);
extern "C" int32_t
convex_wasm_application_entry_chunk_slot_by_handoff_slot(
    int32_t entry_slot);
#elif defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
extern "C" int32_t convex_wasm_application_unit_count(void);
extern "C" SHUnitCreator
convex_wasm_application_factory_by_unit_slot(int32_t unit_slot);
#else
extern "C" SHUnitCreator
convex_wasm_application_factory_by_slot(int32_t entry_slot);
#endif
extern "C" int32_t
convex_wasm_application_invocation_abi_by_slot(int32_t entry_slot);
extern "C" const char *convex_wasm_selected_handler_export_name(void);
extern "C" int32_t convex_wasm_selected_handler_udf_kind(void);
extern "C" int32_t convex_wasm_selected_invocation_abi(void);
extern "C" int32_t convex_wasm_selected_entry_slot(void);
extern "C" void convex_wasm_clear_selected_entry(void);

namespace {

using facebook::jsi::Array;
using facebook::jsi::BigInt;
using facebook::jsi::Function;
using facebook::jsi::JSError;
using facebook::jsi::Object;
using facebook::jsi::PropNameID;
using facebook::jsi::Runtime;
using facebook::jsi::String;
using facebook::jsi::Value;

struct GuestBridge {
  std::shared_ptr<Function> create_context;
  std::shared_ptr<Function> read_request;
  std::shared_ptr<Function> invoke;
  std::shared_ptr<Function> done;
  std::shared_ptr<Function> cleanup;
  std::shared_ptr<Function> settle;
  std::shared_ptr<Function> status;
  std::shared_ptr<Function> activate_sdk;
  std::shared_ptr<Function> invoke_registered_wrapper;
  std::shared_ptr<Function> read_tagged_request;
  std::shared_ptr<Function> start_typed_get;
  std::shared_ptr<Function> start_typed_string;
  std::shared_ptr<Function> start_typed_write;
  std::shared_ptr<Function> start_typed_run_udf;
  std::shared_ptr<Function> start_typed_schedule;
  std::shared_ptr<Function> start_typed_query;
};

struct GuestInitializationErrorConstructors {
  std::shared_ptr<Function> error;
  std::shared_ptr<Function> type_error;
  std::shared_ptr<Function> range_error;
  std::shared_ptr<Function> reference_error;
  std::shared_ptr<Function> syntax_error;
  std::shared_ptr<Function> eval_error;
  std::shared_ptr<Function> uri_error;
};

struct CompileProfileOutputSlot {
  bool closed = false;
  std::unique_ptr<Value> output;
};

struct ApplicationExportSlot {
  std::unique_ptr<Value> exports;
  uint32_t unit_initialization_count = 0;
};

#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
enum class ChunkApplicationUnitState : uint8_t {
  Uninitialized,
  Initializing,
  Initialized,
};

struct ChunkApplicationUnitSlot {
  std::unique_ptr<Value> namespace_value;
  ChunkApplicationUnitState state = ChunkApplicationUnitState::Uninitialized;
  bool published = false;
};
#endif

SHRuntime *runtime = nullptr;
std::unique_ptr<GuestBridge> guest_bridge;
std::unique_ptr<CompileProfileOutputSlot> compile_profile_output_slot;
std::shared_ptr<Function> bridge_bootstrap;
std::shared_ptr<Function> intrinsic_descriptor_state_validator;
std::unique_ptr<Value> application_global_facade;
std::shared_ptr<Function> application_initializer_reporter;
std::shared_ptr<GuestInitializationErrorConstructors>
    guest_initialization_error_constructors;
uint64_t guest_initialization_report_count = 0;
uint32_t bridge_unit_initialization_count = 0;
uint32_t formatter_unit_initialization_count = 0;
int32_t declared_application_entry_count = 0;
int32_t declared_application_unit_count = 0;

#if defined(CONVEX_WASM_FORMATTER_PARTIAL_INITIALIZATION_FIXTURE)
bool fixture_formatter_initialization_failure_armed = false;
uint64_t fixture_initialization_trace_value = 0;

constexpr uint8_t kFixtureBridgeInitialized = 1;
constexpr uint8_t kFixtureFormatterInitialized = 2;
constexpr uint8_t kFixtureApplicationAInitialized = 3;
constexpr uint8_t kFixtureApplicationBInitialized = 4;
constexpr uint8_t kFixtureFormatterInitializationFailed = 5;

void record_fixture_initialization_event(uint8_t event) {
  fixture_initialization_trace_value =
      (fixture_initialization_trace_value << 8) | event;
}
#endif

constexpr int32_t kMaxApplicationEntrySlots = 8;
std::array<ApplicationExportSlot, kMaxApplicationEntrySlots>
    application_export_slots;

#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
constexpr int32_t kMaxApplicationUnitSlots = 1024;
std::array<ChunkApplicationUnitSlot, kMaxApplicationUnitSlots>
    chunk_application_unit_slots;
std::array<std::unique_ptr<Value>, kMaxApplicationEntrySlots>
    pending_application_exports;
bool official_chunk_initialization_dirty = false;
#endif

constexpr int32_t kSelectedUdfKindQuery = 1;
constexpr int32_t kSelectedUdfKindMutation = 2;
constexpr int32_t kSelectedInvocationAbiLegacyHandler = 1;
constexpr int32_t kSelectedInvocationAbiOfficialWrapper = 2;
constexpr const char *kApplicationGlobalFacadeBinding =
    "__convexWasmApplicationGlobalThis";
constexpr const char *kApplicationProfilePublisherBinding =
    "__convexWasmApplicationPublishCompileProfile";
constexpr const char *kApplicationInitializerReporterBinding =
    "__convexWasmApplicationReportThrown";
constexpr const char *kCapabilityBootstrapBinding =
    "__convexWasmCapabilityBootstrap";
constexpr const char *kRuntimeSupportInstallerBinding =
    "__convexWasmApplicationInstallRuntimeSupport";
constexpr const char *kIntrinsicDescriptorStateValidatorBinding =
    "__convexWasmValidateIntrinsicDescriptorState";
constexpr const char *kCommitTsPlaceholderExportName =
    "__convexWasmSdkCommitTsPlaceholder";
constexpr size_t kGuestInitializationDiagnosticMaximumBytes = 640;
constexpr size_t kValueAbiMaximumFrameBytes = 16 * 1024 * 1024;
constexpr size_t kValueAbiMaximumNesting = 64;
constexpr uint32_t kValueAbiMaximumArrayLength = 8192;
constexpr uint32_t kValueAbiMaximumObjectFields = 1024;
#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)
constexpr size_t kGuestInitializationExceptionMessageMaximumBytes = 512;
constexpr size_t kGuestInitializationExceptionMessageMaximumCodeUnits = 128;
#endif
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
constexpr const char *kOfficialChunkBeginBinding =
    "__convexWasmOfficialChunkBegin";
constexpr const char *kOfficialChunkPublishBinding =
    "__convexWasmOfficialChunkPublish";
constexpr const char *kOfficialChunkPublishEntryBinding =
    "__convexWasmOfficialChunkPublishEntry";
constexpr const char *kOfficialChunkReadNamespaceBinding =
    "__convexWasmOfficialChunkReadNamespace";
constexpr const char *kOfficialChunkReportThrownBinding =
    "__convexWasmOfficialChunkReportThrown";
constexpr const char *kOfficialChunkRequireBinding =
    "__convexWasmOfficialChunkRequire";
#endif

enum class JSErrorPhase : int32_t {
  ReserveCompileProfileOutput = 40,
  InitializeBridgeUnit = 41,
  RetainBridgeBootstrap = 42,
  OpenCompileProfileOutput = 43,
  ExposeApplicationBindings = 44,
  InitializeApplicationUnit = 45,
  CloseCompileProfileOutput = 46,
  ClearApplicationBindings = 47,
  InstallGuestBridge = 48,
  ReadCapabilityIdentity = 49,
  CreateInvocationContext = 50,
  ReadInvocationRequest = 51,
  SelectHandler = 52,
  InvokeHandler = 53,
  DrainInitialMicrotasks = 54,
  ReadInvocationDone = 55,
  SettleOperation = 56,
  DrainOperationMicrotasks = 57,
  CleanupInvocation = 58,
  ValidateCleanupResult = 59,
  ReadInvocationStatus = 60,
  ValidateRuntimeSupportInstaller = 61,
  InitializeFormatterUnit = 62,
  VerifyRuntimeSupportInstallation = 63,
  ActivateSdkFacade = 64,
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
  InitializeOfficialChunkUnit = 65,
  InitializeOfficialEntryPublicationUnit = 66,
#endif
  ValidateIntrinsicDescriptorState = 67,
  ValidatePreparationAuthority = 68,
  ValidatePreparationQuiescence = 69,
};

const char *handler_udf_kind(int32_t udf_kind) {
  switch (udf_kind) {
    case kSelectedUdfKindQuery:
      return "query";
    case kSelectedUdfKindMutation:
      return "mutation";
    default:
      return nullptr;
  }
}

bool valid_invocation_abi(int32_t invocation_abi) {
  return invocation_abi == kSelectedInvocationAbiLegacyHandler ||
         invocation_abi == kSelectedInvocationAbiOfficialWrapper;
}

struct SelectedEntryLease {
  ~SelectedEntryLease() { convex_wasm_clear_selected_entry(); }
};

struct InvocationFailure {
  int32_t status;
};

struct ValueAbiPayloadLease {
  int64_t handle;
  ~ValueAbiPayloadLease() { convex_guest_value_payload_release(handle); }
};

struct ValueAbiEncodeError {
  const char *message;
};

struct ValueAbiIntrinsics {
  Object object_prototype;
};

enum class ValueAbiMode { Value, Patch, Committed };

template <typename Append>
void append_hermes_utf8(Runtime &js, const String &input, Append append) {
  char16_t high_surrogate = 0;
  auto codepoint = [&](uint32_t value) {
    uint8_t encoded[4];
    size_t count;
    if (value <= 0x7f) {
      encoded[0] = static_cast<uint8_t>(value);
      count = 1;
    } else if (value <= 0x7ff) {
      encoded[0] = static_cast<uint8_t>(0xc0 | (value >> 6));
      encoded[1] = static_cast<uint8_t>(0x80 | (value & 0x3f));
      count = 2;
    } else if (value <= 0xffff) {
      encoded[0] = static_cast<uint8_t>(0xe0 | (value >> 12));
      encoded[1] = static_cast<uint8_t>(0x80 | ((value >> 6) & 0x3f));
      encoded[2] = static_cast<uint8_t>(0x80 | (value & 0x3f));
      count = 3;
    } else {
      encoded[0] = static_cast<uint8_t>(0xf0 | (value >> 18));
      encoded[1] = static_cast<uint8_t>(0x80 | ((value >> 12) & 0x3f));
      encoded[2] = static_cast<uint8_t>(0x80 | ((value >> 6) & 0x3f));
      encoded[3] = static_cast<uint8_t>(0x80 | (value & 0x3f));
      count = 4;
    }
    append(encoded, count);
  };
  auto write = [&](bool ascii, const void *data, size_t count) {
    if (ascii) {
      if (high_surrogate != 0) {
        throw ValueAbiEncodeError{"Typed value string has an unpaired surrogate"};
      }
      append(static_cast<const uint8_t *>(data), count);
      return;
    }
    const auto *units = static_cast<const char16_t *>(data);
    for (size_t index = 0; index < count; ++index) {
      const uint16_t unit = units[index];
      if (high_surrogate != 0) {
        if (unit < 0xdc00 || unit > 0xdfff) {
          throw ValueAbiEncodeError{"Typed value string has an unpaired surrogate"};
        }
        codepoint(0x10000 + ((high_surrogate - 0xd800) << 10) +
                  (unit - 0xdc00));
        high_surrogate = 0;
      } else if (unit >= 0xd800 && unit <= 0xdbff) {
        high_surrogate = unit;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        throw ValueAbiEncodeError{"Typed value string has an unpaired surrogate"};
      } else {
        codepoint(unit);
      }
    }
  };
  input.getStringData(js, write);
  if (high_surrogate != 0) {
    throw ValueAbiEncodeError{"Typed value string has an unpaired surrogate"};
  }
}

class ValueAbiWriter {
 public:
  ValueAbiWriter(Runtime &js,
                 const Value &commit_ts_placeholder,
                 const ValueAbiIntrinsics &intrinsics,
                 ValueAbiMode mode)
      : js_(js),
        commit_ts_placeholder_(commit_ts_placeholder),
        intrinsics_(intrinsics),
        mode_(mode) {}

  std::vector<uint8_t> encode(const Value &input) {
    static constexpr uint8_t magic[] = {'C', 'V', 'A', '1'};
    try {
      append(magic, sizeof(magic));
      value(input, 0);
      return std::move(bytes_);
    } catch (const ValueAbiEncodeError &error) {
      throw JSError(js_, error.message);
    }
  }

 private:
  void append(const uint8_t *source, size_t length) {
    if (length > kValueAbiMaximumFrameBytes - bytes_.size()) {
      throw ValueAbiEncodeError{"Typed value frame exceeds the byte limit"};
    }
    if (length != 0) bytes_.insert(bytes_.end(), source, source + length);
  }

  void byte(uint8_t value) { append(&value, 1); }

  void u32(size_t value) {
    if (value > std::numeric_limits<uint32_t>::max()) {
      throw ValueAbiEncodeError{"Typed value length exceeds the byte limit"};
    }
    for (size_t shift = 0; shift < 32; shift += 8) {
      byte(static_cast<uint8_t>(value >> shift));
    }
  }

  void u64(uint64_t value) {
    for (size_t shift = 0; shift < 64; shift += 8) {
      byte(static_cast<uint8_t>(value >> shift));
    }
  }

  void patch_u32(size_t offset, size_t value) {
    if (value > std::numeric_limits<uint32_t>::max()) {
      throw ValueAbiEncodeError{"Typed value length exceeds the byte limit"};
    }
    for (size_t index = 0; index < 4; ++index) {
      bytes_[offset + index] = static_cast<uint8_t>(value >> (index * 8));
    }
  }

  void string(const String &input) {
    const size_t length_offset = bytes_.size();
    u32(0);
    const size_t start = bytes_.size();
    // The callback reads Hermes string storage without creating a JS string
    // property lookup or a second encoded copy.
    append_hermes_utf8(js_, input, [&](const uint8_t *data, size_t count) {
      append(data, count);
    });
    patch_u32(length_offset, bytes_.size() - start);
  }

  void field_name(const std::u16string &name) {
    if (name.size() > 1024 || (!name.empty() && name[0] == '$')) {
      throw ValueAbiEncodeError{"Typed value object field name is invalid"};
    }
    for (char16_t unit : name) {
      if (unit < 0x20 || unit > 0x7e) {
        throw ValueAbiEncodeError{"Typed value object field name is invalid"};
      }
    }
    u32(name.size());
    for (char16_t unit : name) byte(static_cast<uint8_t>(unit));
  }

  void value(const Value &input, size_t nesting) {
    if (input.isObject() &&
        Value::strictEquals(js_, input, commit_ts_placeholder_)) {
      if (mode_ == ValueAbiMode::Committed) {
        throw ValueAbiEncodeError{"Pending commit timestamp is not allowed in scheduled arguments"};
      }
      byte(9);
      return;
    }
    if (input.isNull()) {
      byte(0);
    } else if (input.isBool()) {
      byte(input.getBool() ? 2 : 1);
    } else if (input.isNumber()) {
      byte(3);
      uint64_t bits;
      const double number = input.getNumber();
      std::memcpy(&bits, &number, sizeof(bits));
      u64(bits);
    } else if (input.isBigInt()) {
      const auto integer = input.asBigInt(js_);
      if (!integer.isInt64(js_)) {
        throw ValueAbiEncodeError{"Typed value integer exceeds signed 64-bit range"};
      }
      byte(4);
      u64(static_cast<uint64_t>(integer.getInt64(js_)));
    } else if (input.isString()) {
      byte(5);
      string(input.asString(js_));
    } else if (input.isObject()) {
      const auto object = input.asObject(js_);
      if (object.isArrayBuffer(js_)) {
        const auto buffer = object.getArrayBuffer(js_);
        byte(6);
        u32(buffer.size(js_));
        append(buffer.data(js_), buffer.size(js_));
        return;
      }
      for (const auto &ancestor : ancestors_) {
        if (Value::strictEquals(js_, ancestor, input)) {
          throw ValueAbiEncodeError{"Cyclic objects are not Convex values"};
        }
      }
      if (nesting >= kValueAbiMaximumNesting) {
        throw ValueAbiEncodeError{"Typed value nesting exceeds the limit"};
      }
      ancestors_.emplace_back(js_, input);
      if (object.isArray(js_)) {
        const auto array = object.asArray(js_);
        const size_t count = array.size(js_);
        if (count > kValueAbiMaximumArrayLength) {
          throw ValueAbiEncodeError{"Typed value array length exceeds the limit"};
        }
        byte(7);
        u32(count);
        for (size_t index = 0; index < count; ++index) {
          const auto key = std::to_string(index);
          if (!object.hasProperty(js_, key.c_str())) {
            // The SDK's array map leaves a hole, which its JSON transport turns into null.
            byte(0);
            continue;
          }
          value(array.getValueAtIndex(js_, index), nesting + 1);
        }
      } else {
        if (object.isFunction(js_)) {
          throw ValueAbiEncodeError{"Functions are not Convex values"};
        }
        const auto prototype = js_.getPrototypeOf(object);
        if (!prototype.isNull() &&
            (!prototype.isObject() ||
             !Object::strictEquals(js_, prototype.asObject(js_),
                                   intrinsics_.object_prototype))) {
          throw ValueAbiEncodeError{"Only plain objects are Convex values"};
        }
        // Snapshot values before sorting keys so getters observe property order.
        auto own_entries = static_cast<facebook::hermes::HermesRuntime &>(js_)
                               .getOwnEnumerableEntries(object);
        struct Entry {
          std::u16string units;
          Value value;
        };
        std::vector<Entry> entries;
        entries.reserve(own_entries.size());
        for (auto &entry : own_entries) {
          entries.push_back(Entry{entry.first.utf16(js_), std::move(entry.second)});
        }
        std::sort(entries.begin(), entries.end(), [](const Entry &left, const Entry &right) {
          return left.units < right.units;
        });
        byte(8);
        const size_t count_offset = bytes_.size();
        u32(0);
        size_t count = 0;
        for (const auto &entry : entries) {
          if (entry.value.isUndefined() &&
              !(mode_ == ValueAbiMode::Patch && nesting == 0)) {
            continue;
          }
          if (count >= kValueAbiMaximumObjectFields) {
            throw ValueAbiEncodeError{"Typed value object length exceeds the limit"};
          }
          field_name(entry.units);
          if (entry.value.isUndefined()) {
            byte(12);
          } else {
            value(entry.value, nesting + 1);
          }
          ++count;
        }
        patch_u32(count_offset, count);
      }
      ancestors_.pop_back();
    } else {
      throw ValueAbiEncodeError{"Unsupported Convex value"};
    }
  }

  Runtime &js_;
  const Value &commit_ts_placeholder_;
  const ValueAbiIntrinsics &intrinsics_;
  ValueAbiMode mode_;
  std::vector<uint8_t> bytes_;
  std::vector<Value> ancestors_;
};

class QueryAbiWriter {
 public:
  explicit QueryAbiWriter(Runtime &js) : js_(js) {}

  std::vector<uint8_t> encode(const Value &query_input,
                              const Value &terminal_input,
                              const Value &pagination_input) {
    try {
      const Object query = object(query_input);
      const Value source_value = query.getProperty(js_, "source");
      const Object source = object(source_value);
      const Value source_type = source.getProperty(js_, "type");
      const std::string terminal_name = string_value(terminal_input);
      const std::string source_name = string_value(source_type);
      append(reinterpret_cast<const uint8_t *>("CQR1"), 4);
      if (terminal_name == "collect") byte(1);
      else if (terminal_name == "first") byte(2);
      else if (terminal_name == "unique") byte(3);
      else if (terminal_name == "stream") byte(4);
      else if (terminal_name == "paginate") byte(5);
      else invalid();
      if (source_name == "FullTableScan") byte(1);
      else if (source_name == "IndexRange") byte(2);
      else if (source_name == "Search") byte(3);
      else invalid();
      const Value order = source_name == "Search"
                              ? Value::null()
                              : source.getProperty(js_, "order");
      if (order.isNull()) byte(0);
      else if (string_value(order) == "asc") byte(1);
      else if (string_value(order) == "desc") byte(2);
      else invalid();
      if (source_name == "FullTableScan") {
        string(source.getProperty(js_, "tableName"));
      } else {
        const std::string index_name = string_value(source.getProperty(js_, "indexName"));
        const size_t separator = index_name.find('.');
        if (separator == 0 || separator == std::string::npos ||
            separator + 1 == index_name.size() ||
            index_name.find('.', separator + 1) != std::string::npos) invalid();
        string_bytes(index_name.substr(0, separator));
        string_bytes(index_name.substr(separator + 1));
      }
      if (source_name == "IndexRange") {
        const Array constraints = array(source.getProperty(js_, "range"));
        const size_t count = constraints.size(js_);
        if (count > 256) invalid();
        u32(count);
        for (size_t i = 0; i < count; ++i) {
          const Object constraint = object(constraints.getValueAtIndex(js_, i));
          const std::string kind = string_value(constraint.getProperty(js_, "type"));
          if (kind == "Eq") byte(1);
          else if (kind == "Gt") byte(2);
          else if (kind == "Gte") byte(3);
          else if (kind == "Lt") byte(4);
          else if (kind == "Lte") byte(5);
          else invalid();
          string(constraint.getProperty(js_, "fieldPath"));
          optional_value(constraint.getProperty(js_, "value"));
        }
      } else if (source_name == "Search") {
        const Array filters = array(source.getProperty(js_, "filters"));
        const size_t count = filters.size(js_);
        if (count == 0 || count > 256) invalid();
        u32(count);
        for (size_t i = 0; i < count; ++i) {
          const Object filter = object(filters.getValueAtIndex(js_, i));
          const std::string kind = string_value(filter.getProperty(js_, "type"));
          if (i == 0 && kind == "Search") byte(1);
          else if (i > 0 && kind == "Eq") byte(2);
          else invalid();
          string(filter.getProperty(js_, "fieldPath"));
          if (i == 0) string(filter.getProperty(js_, "value"));
          else optional_value(filter.getProperty(js_, "value"));
        }
      }
      const Array operators = array(query.getProperty(js_, "operators"));
      const size_t count = operators.size(js_);
      if (count > 256) invalid();
      u32(count);
      for (size_t i = 0; i < count; ++i) {
        const Object operator_object = object(operators.getValueAtIndex(js_, i));
        const Array keys = operator_object.getPropertyNames(js_);
        if (keys.size(js_) != 1) invalid();
        const std::string kind = string_value(keys.getValueAtIndex(js_, 0));
        if (kind == "filter") {
          byte(1);
          expression(operator_object.getProperty(js_, "filter"), 0);
        } else if (kind == "limit") {
          byte(2);
          integer(operator_object.getProperty(js_, "limit"));
        } else {
          invalid();
        }
      }
      if (terminal_name == "paginate") {
        const Object pagination = object(pagination_input);
        optional_string(pagination.getProperty(js_, "cursor"));
        optional_string(pagination.getProperty(js_, "endCursor"));
        optional_integer(pagination.getProperty(js_, "maximumBytesRead"));
        optional_integer(pagination.getProperty(js_, "maximumRowsRead"));
        integer(pagination.getProperty(js_, "pageSize"));
      }
      return std::move(bytes_);
    } catch (const ValueAbiEncodeError &error) {
      throw JSError(js_, error.message);
    }
  }

 private:
  [[noreturn]] void invalid() const {
    throw ValueAbiEncodeError{"Typed query request is invalid"};
  }

  Object object(const Value &value) const {
    if (!value.isObject() || value.asObject(js_).isArray(js_)) invalid();
    return value.asObject(js_);
  }

  Array array(const Value &value) const {
    if (!value.isObject() || !value.asObject(js_).isArray(js_)) invalid();
    return value.asObject(js_).asArray(js_);
  }

  std::string string_value(const Value &value) const {
    if (!value.isString()) invalid();
    return value.asString(js_).utf8(js_);
  }

  void append(const uint8_t *data, size_t length) {
    if (length > kValueAbiMaximumFrameBytes - bytes_.size()) {
      throw ValueAbiEncodeError{"Typed query request exceeds the byte limit"};
    }
    if (length != 0) bytes_.insert(bytes_.end(), data, data + length);
  }

  void byte(uint8_t value) { append(&value, 1); }

  void u32(size_t value) {
    if (value > std::numeric_limits<uint32_t>::max()) invalid();
    for (size_t shift = 0; shift < 32; shift += 8) byte(value >> shift);
  }

  void u64(uint64_t value) {
    for (size_t shift = 0; shift < 64; shift += 8) byte(value >> shift);
  }

  void string_bytes(const std::string &value) {
    u32(value.size());
    append(reinterpret_cast<const uint8_t *>(value.data()), value.size());
  }

  void string(const Value &value) {
    if (!value.isString()) invalid();
    const size_t length_offset = bytes_.size();
    u32(0);
    const size_t start = bytes_.size();
    append_hermes_utf8(js_, value.asString(js_), [&](const uint8_t *data, size_t count) {
      append(data, count);
    });
    const size_t length = bytes_.size() - start;
    if (length > std::numeric_limits<uint32_t>::max()) invalid();
    for (size_t index = 0; index < 4; ++index) {
      bytes_[length_offset + index] = static_cast<uint8_t>(length >> (index * 8));
    }
  }

  void optional_string(const Value &value) {
    if (value.isNull()) byte(0);
    else { byte(1); string(value); }
  }

  void integer(const Value &value) {
    if (!value.isNumber()) invalid();
    const double number = value.getNumber();
    if (!std::isfinite(number) || number < 0.0 ||
        number > 9007199254740991.0 || std::floor(number) != number) invalid();
    u64(static_cast<uint64_t>(number));
  }

  void optional_integer(const Value &value) {
    if (value.isNull()) byte(0);
    else { byte(1); integer(value); }
  }

  void optional_value(const Value &value) {
    if (value.isUndefined()) {
      byte(0);
      return;
    }
    if (!value.isObject() || !value.asObject(js_).isArrayBuffer(js_)) invalid();
    const auto buffer = value.asObject(js_).getArrayBuffer(js_);
    const size_t length = buffer.size(js_);
    byte(1);
    u32(length);
    append(buffer.data(js_), length);
  }

  void expression(const Value &value, size_t depth) {
    if (depth >= 64 || ++expression_nodes_ > 4096) invalid();
    const Object node = object(value);
    const Array keys = node.getPropertyNames(js_);
    if (keys.size(js_) != 1) invalid();
    const std::string kind = string_value(keys.getValueAtIndex(js_, 0));
    const Value operand = node.getProperty(js_, kind.c_str());
    if (kind == "$literal") { byte(1); optional_value(operand); }
    else if (kind == "$field") { byte(2); string(operand); }
    else {
      uint8_t tag;
      if (kind == "$eq") tag = 3;
      else if (kind == "$neq") tag = 4;
      else if (kind == "$lt") tag = 5;
      else if (kind == "$lte") tag = 6;
      else if (kind == "$gt") tag = 7;
      else if (kind == "$gte") tag = 8;
      else if (kind == "$add") tag = 9;
      else if (kind == "$sub") tag = 10;
      else if (kind == "$mul") tag = 11;
      else if (kind == "$div") tag = 12;
      else if (kind == "$mod") tag = 13;
      else if (kind == "$neg") tag = 14;
      else if (kind == "$not") tag = 15;
      else if (kind == "$and") tag = 16;
      else if (kind == "$or") tag = 17;
      else invalid();
      byte(tag);
      if (tag <= 13) {
        const Array operands = array(operand);
        if (operands.size(js_) != 2) invalid();
        expression(operands.getValueAtIndex(js_, 0), depth + 1);
        expression(operands.getValueAtIndex(js_, 1), depth + 1);
      } else if (tag <= 15) {
        expression(operand, depth + 1);
      } else {
        const Array operands = array(operand);
        const size_t count = operands.size(js_);
        if (count > 256) invalid();
        u32(count);
        for (size_t index = 0; index < count; ++index) {
          expression(operands.getValueAtIndex(js_, index), depth + 1);
        }
      }
    }
  }

  Runtime &js_;
  std::vector<uint8_t> bytes_;
  size_t expression_nodes_ = 0;
};

class ValueAbiReader {
 public:
  ValueAbiReader(Runtime &js,
                 const uint8_t *bytes,
                 size_t length,
                 const Value &commit_ts_placeholder,
                 const Function &array_buffer_constructor,
                 const Function &define_property)
      : js_(js),
        cursor_(bytes),
        end_(bytes + length),
        commit_ts_placeholder_(commit_ts_placeholder),
        array_buffer_constructor_(array_buffer_constructor),
        define_property_(define_property) {}

  Value decode() {
    static constexpr uint8_t magic[] = {'C', 'V', 'A', '1'};
    const uint8_t *header = take(sizeof(magic));
    if (std::memcmp(header, magic, sizeof(magic)) != 0) {
      throw JSError(js_, "Typed value frame has an invalid header");
    }
    Value result = value(0);
    if (cursor_ != end_) {
      throw JSError(js_, "Typed value frame has trailing bytes");
    }
    return result;
  }

 private:
  const uint8_t *take(size_t length) {
    if (length > static_cast<size_t>(end_ - cursor_)) {
      throw JSError(js_, "Typed value frame is truncated");
    }
    const uint8_t *result = cursor_;
    cursor_ += length;
    return result;
  }

  uint8_t byte() { return *take(1); }

  uint32_t u32() {
    const uint8_t *bytes = take(4);
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
  }

  uint64_t u64() {
    const uint8_t *bytes = take(8);
    uint64_t result = 0;
    for (size_t index = 0; index < 8; ++index) {
      result |= static_cast<uint64_t>(bytes[index]) << (index * 8);
    }
    return result;
  }

  std::pair<const uint8_t *, size_t> slice() {
    const size_t length = u32();
    return {take(length), length};
  }

  void define_field(Object &object,
                    const char *bytes,
                    size_t length,
                    Value field) {
    auto key = String::createFromUtf8(js_,
                                      reinterpret_cast<const uint8_t *>(bytes),
                                      length);
    if (length == sizeof("__proto__") - 1 &&
        std::memcmp(bytes, "__proto__", length) == 0) {
      // Assignment invokes the inherited setter instead of defining an own
      // field. Convex permits this field name.
      Object descriptor(js_);
      descriptor.setProperty(js_, "configurable", true);
      descriptor.setProperty(js_, "enumerable", true);
      descriptor.setProperty(js_, "writable", true);
      descriptor.setProperty(js_, "value", std::move(field));
      define_property_.call(js_, object, key, descriptor);
    } else {
      object.setProperty(js_, key, std::move(field));
    }
  }

  Value packed(flexbuffers::Reference reference, size_t nesting) {
    if (reference.IsNull()) return Value::null();
    if (reference.IsBool()) return Value(reference.AsBool());
    if (reference.IsInt()) {
      return Value(BigInt::fromInt64(js_, reference.AsInt64()));
    }
    if (reference.IsFloat()) return Value(reference.AsDouble());
    if (reference.IsString()) {
      const auto string = reference.AsString();
      return Value(String::createFromUtf8(
          js_, reinterpret_cast<const uint8_t *>(string.c_str()),
          string.length()));
    }
    if (reference.GetType() == flexbuffers::FBT_BLOB) {
      const auto blob = reference.AsBlob();
      auto buffer = array_buffer_constructor_
                        .callAsConstructor(js_, static_cast<double>(blob.size()))
                        .asObject(js_)
                        .getArrayBuffer(js_);
      if (buffer.size(js_) != blob.size()) {
        throw JSError(js_, "Packed value byte buffer has an invalid size");
      }
      if (blob.size() != 0) {
        std::memcpy(buffer.data(js_), blob.data(), blob.size());
      }
      return Value(std::move(buffer));
    }
    if (nesting >= kValueAbiMaximumNesting) {
      throw JSError(js_, "Packed value nesting exceeds the limit");
    }
    if (reference.IsMap()) {
      const auto map = reference.AsMap();
      if (map.size() > kValueAbiMaximumObjectFields) {
        throw JSError(js_, "Packed value object length is invalid");
      }
      const auto keys = map.Keys();
      const auto values = map.Values();
      Object result(js_);
      const char *previous_key = nullptr;
      for (size_t index = 0; index < map.size(); ++index) {
        const char *key = keys[index].AsKey();
        if (previous_key != nullptr && std::strcmp(previous_key, key) >= 0) {
          throw JSError(js_, "Packed document object keys are invalid");
        }
        define_field(result, key, std::strlen(key),
                     packed(values[index], nesting + 1));
        previous_key = key;
      }
      return Value(std::move(result));
    }
    if (reference.IsAnyVector()) {
      const size_t count = reference.IsUntypedVector()
                               ? reference.AsVector().size()
                               : reference.IsTypedVector()
                                     ? reference.AsTypedVector().size()
                                     : reference.AsFixedTypedVector().size();
      if (count > kValueAbiMaximumArrayLength) {
        throw JSError(js_, "Packed value array length is invalid");
      }
      Array result(js_, count);
      for (size_t index = 0; index < count; ++index) {
        const auto element = reference.IsUntypedVector()
                                 ? reference.AsVector()[index]
                                 : reference.IsTypedVector()
                                       ? reference.AsTypedVector()[index]
                                       : reference.AsFixedTypedVector()[index];
        result.setValueAtIndex(js_, index, packed(element, nesting + 1));
      }
      return Value(std::move(result));
    }
    throw JSError(js_, "Packed document contains an unsupported value type");
  }

  Value value(size_t nesting) {
    switch (byte()) {
      case 0:
        return Value::null();
      case 1:
        return Value(false);
      case 2:
        return Value(true);
      case 3: {
        const uint64_t bits = u64();
        double number;
        std::memcpy(&number, &bits, sizeof(number));
        return Value(number);
      }
      case 4: {
        const uint64_t bits = u64();
        int64_t integer;
        std::memcpy(&integer, &bits, sizeof(integer));
        return Value(BigInt::fromInt64(js_, integer));
      }
      case 5: {
        const auto [bytes, length] = slice();
        return Value(String::createFromUtf8(js_, bytes, length));
      }
      case 6: {
        const auto [bytes, length] = slice();
        auto buffer = array_buffer_constructor_
                          .callAsConstructor(js_, static_cast<double>(length))
                          .asObject(js_)
                          .getArrayBuffer(js_);
        if (buffer.size(js_) != length) {
          throw JSError(js_, "Typed value byte buffer has an invalid size");
        }
        if (length != 0) {
          std::memcpy(buffer.data(js_), bytes, length);
        }
        return Value(std::move(buffer));
      }
      case 7: {
        if (nesting >= kValueAbiMaximumNesting) {
          throw JSError(js_, "Typed value nesting exceeds the limit");
        }
        const uint32_t count = u32();
        if (count > kValueAbiMaximumArrayLength ||
            count > static_cast<size_t>(end_ - cursor_)) {
          throw JSError(js_, "Typed value array length is invalid");
        }
        Array result(js_, count);
        for (uint32_t index = 0; index < count; ++index) {
          result.setValueAtIndex(js_, index, value(nesting + 1));
        }
        return Value(std::move(result));
      }
      case 8: {
        if (nesting >= kValueAbiMaximumNesting) {
          throw JSError(js_, "Typed value nesting exceeds the limit");
        }
        const uint32_t count = u32();
        if (count > kValueAbiMaximumObjectFields ||
            count > static_cast<size_t>(end_ - cursor_) / 5) {
          throw JSError(js_, "Typed value object length is invalid");
        }
        Object result(js_);
        for (uint32_t index = 0; index < count; ++index) {
          const auto [bytes, length] = slice();
          Value field = value(nesting + 1);
          define_field(result, reinterpret_cast<const char *>(bytes), length,
                       std::move(field));
        }
        return Value(std::move(result));
      }
      case 9:
        if (commit_ts_placeholder_.isUndefined()) {
          throw JSError(js_, "Pending value is not allowed in this invocation");
        }
        return Value(js_, commit_ts_placeholder_);
      case 10: {
        const auto [bytes, length] = slice();
        if (!flexbuffers::VerifyBuffer(bytes, length)) {
          throw JSError(js_, "Packed document is invalid");
        }
        const auto root = flexbuffers::GetRoot(bytes, length);
        if (!root.IsMap()) {
          throw JSError(js_, "Packed document root is not an object");
        }
        return packed(root, nesting);
      }
      case 11: {
        const uint32_t count = u32();
        if (count > kValueAbiMaximumArrayLength ||
            count > static_cast<size_t>(end_ - cursor_)) {
          throw JSError(js_, "Document collection length is invalid");
        }
        Array result(js_, count);
        for (uint32_t index = 0; index < count; ++index) {
          if (cursor_ == end_ || (*cursor_ != 8 && *cursor_ != 10)) {
            throw JSError(js_, "Document collection entry is invalid");
          }
          result.setValueAtIndex(js_, index, value(0));
        }
        return Value(std::move(result));
      }
      default:
        throw JSError(js_, "Typed value frame contains an unsupported tag");
    }
  }

  Runtime &js_;
  const uint8_t *cursor_;
  const uint8_t *end_;
  const Value &commit_ts_placeholder_;
  const Function &array_buffer_constructor_;
  const Function &define_property_;
};

Value take_typed_host_value(Runtime &js,
                            int64_t consuming_value_handle,
                            const Value &commit_ts_placeholder,
                            const Function &array_buffer_constructor,
                            const Function &define_property) {
  const int64_t payload_handle =
      convex_guest_value_encode_binary(consuming_value_handle);
  if (payload_handle <= 0) {
    throw JSError(js, "Typed host value encode failed");
  }
  std::vector<uint8_t> bytes;
  {
    ValueAbiPayloadLease payload{payload_handle};
    const int32_t length = convex_guest_value_payload_len(payload_handle);
    if (length < 5 || static_cast<size_t>(length) > kValueAbiMaximumFrameBytes) {
      throw JSError(js, "Typed host value length is invalid");
    }
    bytes.resize(static_cast<size_t>(length));
    if (convex_guest_value_payload_copy(
            payload_handle,
            reinterpret_cast<char *>(bytes.data()),
            length) != length) {
      throw JSError(js, "Typed host value copy failed");
    }
  }
  return ValueAbiReader(js,
                        bytes.data(),
                        bytes.size(),
                        commit_ts_placeholder,
                        array_buffer_constructor,
                        define_property)
      .decode();
}

SHRuntime *initialize_runtime() {
  char program[] = "convex-wasm-native-capability";
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

std::shared_ptr<Function> guest_function(Runtime &js, const Value &value) {
  return std::make_shared<Function>(value.asObject(js).asFunction(js));
}

void publish_compile_profile_output(Runtime &js,
                                    const Value *arguments,
                                    size_t count) {
#if defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
  if (count == 2) {
    if (compile_profile_output_slot == nullptr ||
        compile_profile_output_slot->closed || !arguments[0].isNumber()) {
      throw JSError(js, "Compile-profile scalar output slot is closed");
    }
    const double slot_number = arguments[0].getNumber();
    if (slot_number < 0 || slot_number >= declared_application_entry_count) {
      throw JSError(js, "Compile-profile scalar output slot is invalid");
    }
    const auto entry_slot = static_cast<int32_t>(slot_number);
    if (static_cast<double>(entry_slot) != slot_number ||
        application_export_slots[entry_slot].exports != nullptr ||
        !arguments[1].isObject()) {
      throw JSError(js, "Compile-profile scalar output assignment is invalid");
    }
    application_export_slots[entry_slot].exports =
        std::make_unique<Value>(js, arguments[1]);
    return;
  }
#endif
  if (count != 1) {
    throw JSError(js, "Compile-profile output assignment is invalid");
  }
  if (compile_profile_output_slot == nullptr ||
      compile_profile_output_slot->closed) {
    throw JSError(js, "Compile-profile output slot is closed");
  }
  if (compile_profile_output_slot->output != nullptr) {
    throw JSError(js, "Compile-profile output was already published");
  }
  // A split application publishes once after its synchronous initializer has
  // constructed the complete export table.
  compile_profile_output_slot->output =
      std::make_unique<Value>(js, arguments[0]);
}

void reserve_compile_profile_output(Runtime &js) {
  if (compile_profile_output_slot != nullptr) {
    throw JSError(js, "Compile-profile output slot was already reserved");
  }
  compile_profile_output_slot = std::make_unique<CompileProfileOutputSlot>();
  auto setter = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "setCompileProfileOutput"),
      1,
      [](Runtime &js,
         const Value &,
         const Value *arguments,
         size_t count) -> Value {
        publish_compile_profile_output(js, arguments, count);
        return Value::undefined();
      });
  Object descriptor(js);
  descriptor.setProperty(js, "configurable", false);
  descriptor.setProperty(js, "enumerable", false);
  descriptor.setProperty(js, "set", std::move(setter));
  auto global = js.global();
  global.getPropertyAsObject(js, "Object")
      .getPropertyAsFunction(js, "defineProperty")
      .call(js, global, "__convexWasmCompileProfile", descriptor);
}

void open_compile_profile_output(Runtime &js) {
  if (compile_profile_output_slot == nullptr) {
    throw JSError(js, "Compile-profile output slot was not reserved");
  }
  if (!compile_profile_output_slot->closed) {
    if (compile_profile_output_slot->output != nullptr) {
      throw JSError(js,
                    "Compile-profile output was populated before application "
                    "initialization");
    }
    return;
  }
  compile_profile_output_slot->closed = false;
  compile_profile_output_slot->output.reset();
}

void close_compile_profile_output(Runtime &js, int32_t entry_slot) {
  if (compile_profile_output_slot == nullptr ||
      compile_profile_output_slot->closed) {
    throw JSError(js, "Compile-profile output slot is not open");
  }
  compile_profile_output_slot->closed = true;
  if (compile_profile_output_slot->output == nullptr ||
      !compile_profile_output_slot->output->isObject()) {
    throw JSError(js, "Compile-profile output is invalid");
  }
  auto &application_slot = application_export_slots[entry_slot];
  if (application_slot.exports != nullptr) {
    throw JSError(js, "Compile-profile exports were already retained");
  }
  application_slot.exports = std::move(compile_profile_output_slot->output);
}

#if defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
void close_multi_entry_compile_profile_outputs(Runtime &js) {
  if (compile_profile_output_slot == nullptr ||
      compile_profile_output_slot->closed ||
      compile_profile_output_slot->output != nullptr) {
    throw JSError(js, "Multi-entry compile-profile output slot is invalid");
  }
  compile_profile_output_slot->closed = true;
  for (int32_t entry_slot = 0;
       entry_slot < declared_application_entry_count; ++entry_slot) {
    auto &application_slot = application_export_slots[entry_slot];
    if (application_slot.exports == nullptr ||
        !application_slot.exports->isObject() ||
        application_slot.unit_initialization_count != 0) {
      throw JSError(js, "Multi-entry compile-profile output is incomplete");
    }
    application_slot.unit_initialization_count = 1;
  }
}
#endif

Object selected_application_exports(Runtime &js, int32_t entry_slot) {
  auto &application_slot = application_export_slots[entry_slot];
  if (application_slot.exports == nullptr ||
      !application_slot.exports->isObject()) {
    throw JSError(js, "Compile-profile handler selection is invalid");
  }
  return application_slot.exports->asObject(js);
}

Function selected_application_export(Runtime &js,
                                     int32_t entry_slot,
                                     const char *export_name) {
  return selected_application_exports(js, entry_slot)
      .getPropertyAsFunction(js, export_name);
}

Value selected_commit_ts_placeholder(Runtime &js, int32_t entry_slot) {
  auto placeholder = selected_application_exports(js, entry_slot)
                         .getProperty(js, kCommitTsPlaceholderExportName);
  if (!placeholder.isObject()) {
    throw JSError(
        js,
        "Compile-profile SDK commit timestamp placeholder is invalid");
  }
  return placeholder;
}

void remove_hidden_global(Runtime &js, const char *name) {
  auto global = js.global();
  auto reflect = global.getPropertyAsObject(js, "Reflect");
  auto removed = reflect.getPropertyAsFunction(js, "deleteProperty")
                     .call(js, global, String::createFromAscii(js, name));
  if (!removed.isBool() || !removed.getBool()) {
    throw JSError(js, "Temporary application binding could not be removed");
  }
}

void define_hidden_global(Runtime &js, const char *name, const Value &value) {
  Object descriptor(js);
  descriptor.setProperty(js, "configurable", true);
  descriptor.setProperty(js, "enumerable", false);
  descriptor.setProperty(js, "value", Value(js, value));
  descriptor.setProperty(js, "writable", false);
  auto global = js.global();
  global.getPropertyAsObject(js, "Object")
      .getPropertyAsFunction(js, "defineProperty")
      .call(js, global, name, descriptor);
}

enum class GuestInitializationErrorClass : uint8_t {
  NonError,
  Error,
  TypeError,
  RangeError,
  ReferenceError,
  SyntaxError,
  EvalError,
  URIError,
};

const char *guest_initialization_error_class_name(
    GuestInitializationErrorClass error_class) {
  switch (error_class) {
    case GuestInitializationErrorClass::NonError:
      return "non-error";
    case GuestInitializationErrorClass::Error:
      return "error";
    case GuestInitializationErrorClass::TypeError:
      return "type-error";
    case GuestInitializationErrorClass::RangeError:
      return "range-error";
    case GuestInitializationErrorClass::ReferenceError:
      return "reference-error";
    case GuestInitializationErrorClass::SyntaxError:
      return "syntax-error";
    case GuestInitializationErrorClass::EvalError:
      return "eval-error";
    case GuestInitializationErrorClass::URIError:
      return "uri-error";
  }
  return nullptr;
}

GuestInitializationErrorClass guest_initialization_error_class(
    Runtime &js,
    const Value &value,
    const GuestInitializationErrorConstructors &constructors) {
  if (!value.isObject()) {
    return GuestInitializationErrorClass::NonError;
  }
  const auto object = value.asObject(js);
  if (object.instanceOf(js, *constructors.type_error)) {
    return GuestInitializationErrorClass::TypeError;
  }
  if (object.instanceOf(js, *constructors.range_error)) {
    return GuestInitializationErrorClass::RangeError;
  }
  if (object.instanceOf(js, *constructors.reference_error)) {
    return GuestInitializationErrorClass::ReferenceError;
  }
  if (object.instanceOf(js, *constructors.syntax_error)) {
    return GuestInitializationErrorClass::SyntaxError;
  }
  if (object.instanceOf(js, *constructors.eval_error)) {
    return GuestInitializationErrorClass::EvalError;
  }
  if (object.instanceOf(js, *constructors.uri_error)) {
    return GuestInitializationErrorClass::URIError;
  }
  if (object.instanceOf(js, *constructors.error)) {
    return GuestInitializationErrorClass::Error;
  }
  return GuestInitializationErrorClass::NonError;
}

#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)
bool write_guest_initialization_failure_message_with_exception(
    Runtime &js,
    int32_t unit_slot,
    const char *error_class_name,
    const Value &error,
    std::array<char, kGuestInitializationDiagnosticMaximumBytes> &message) {
  try {
    if (!error.isObject()) {
      return false;
    }
    const auto exception_message_value =
        error.asObject(js).getProperty(js, "message");
    if (!exception_message_value.isString()) {
      return false;
    }
    const auto exception_message_string = exception_message_value.getString(js);
    if (exception_message_string.length(js) >
        kGuestInitializationExceptionMessageMaximumCodeUnits) {
      return false;
    }
    const std::string exception_message = exception_message_string.utf8(js);
    std::array<char, kGuestInitializationExceptionMessageMaximumBytes + 1>
        escaped_exception_message{};
    size_t escaped_length = 0;
    for (const unsigned char exception_byte : exception_message) {
      const bool literal = exception_byte >= 0x20 && exception_byte <= 0x7e &&
          exception_byte != '"' && exception_byte != '\\';
      const size_t encoded_length = literal ? 1 : 4;
      if (escaped_length + encoded_length >
          kGuestInitializationExceptionMessageMaximumBytes) {
        break;
      }
      if (literal) {
        escaped_exception_message[escaped_length] =
            static_cast<char>(exception_byte);
      } else {
        constexpr char kHexDigits[] = "0123456789ABCDEF";
        escaped_exception_message[escaped_length] = '\\';
        escaped_exception_message[escaped_length + 1] = 'x';
        escaped_exception_message[escaped_length + 2] =
            kHexDigits[exception_byte >> 4];
        escaped_exception_message[escaped_length + 3] =
            kHexDigits[exception_byte & 0x0f];
      }
      escaped_length += encoded_length;
    }
    const int message_length = std::snprintf(
        message.data(),
        message.size(),
        "Guest initialization failed: unit_slot=%d error_class=%s "
        "exception_message=\"%s\"",
        unit_slot,
        error_class_name,
        escaped_exception_message.data());
    return message_length >= 0 &&
        static_cast<size_t>(message_length) < message.size();
  } catch (const JSError &) {
    // Reading an application-controlled accessor must not replace the original
    // initialization failure with a diagnostic failure.
    return false;
  }
}
#endif

void report_guest_initialization_failure_classified(
    Runtime &js,
    int32_t unit_slot,
    GuestInitializationErrorClass error_class
#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)
    ,
    const Value &error
#endif
    ) {
  if (application_initializer_reporter == nullptr || unit_slot < 0 ||
      unit_slot >= declared_application_unit_count) {
    throw JSError(js, "Guest initialization diagnostic unit slot is invalid");
  }
  const char *error_class_name =
      guest_initialization_error_class_name(error_class);
  if (error_class_name == nullptr) {
    throw JSError(js, "Guest initialization diagnostic error class is invalid");
  }
  std::array<char, kGuestInitializationDiagnosticMaximumBytes> message{};
#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)
  if (write_guest_initialization_failure_message_with_exception(
          js, unit_slot, error_class_name, error, message)) {
    application_initializer_reporter->call(
        js, String::createFromAscii(js, message.data()));
    return;
  }
#endif
  const int message_length = std::snprintf(
      message.data(),
      message.size(),
      "Guest initialization failed: unit_slot=%d error_class=%s",
      unit_slot,
      error_class_name);
  if (message_length < 0 ||
      static_cast<size_t>(message_length) >= message.size()) {
    throw JSError(js, "Guest initialization diagnostic is invalid");
  }
  application_initializer_reporter->call(
      js, String::createFromAscii(js, message.data()));
}

std::shared_ptr<GuestInitializationErrorConstructors>
capture_guest_initialization_error_constructors(Runtime &js) {
  auto constructors = std::make_shared<GuestInitializationErrorConstructors>();
  auto global = js.global();
  constructors->error = guest_function(js, global.getProperty(js, "Error"));
  constructors->type_error =
      guest_function(js, global.getProperty(js, "TypeError"));
  constructors->range_error =
      guest_function(js, global.getProperty(js, "RangeError"));
  constructors->reference_error =
      guest_function(js, global.getProperty(js, "ReferenceError"));
  constructors->syntax_error =
      guest_function(js, global.getProperty(js, "SyntaxError"));
  constructors->eval_error =
      guest_function(js, global.getProperty(js, "EvalError"));
  constructors->uri_error =
      guest_function(js, global.getProperty(js, "URIError"));
  return constructors;
}

Function guest_initialization_reporter(Runtime &js, int32_t unit_slot) {
  if (unit_slot < 0 || unit_slot >= declared_application_unit_count ||
      guest_initialization_error_constructors == nullptr) {
    throw JSError(js, "Guest initialization reporter unit slot is invalid");
  }
  const auto constructors = guest_initialization_error_constructors;
  return Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "reportGuestInitializationFailure"),
      1,
      [unit_slot, constructors](Runtime &js,
                                const Value &,
                                const Value *arguments,
                                size_t count) -> Value {
        if (count != 1) {
          throw JSError(js, "Guest initialization reporter input is invalid");
        }
        const auto error_class = guest_initialization_error_class(
            js, arguments[0], *constructors);
#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)
        report_guest_initialization_failure_classified(
            js, unit_slot, error_class, arguments[0]);
#else
        report_guest_initialization_failure_classified(
            js, unit_slot, error_class);
#endif
        guest_initialization_report_count += 1;
        return Value::undefined();
      });
}

void evaluate_application_initializer(Runtime &js,
                                      SHUnitCreator factory,
                                      int32_t unit_slot) {
  const uint64_t reports_before = guest_initialization_report_count;
  try {
    _sh_get_hermes_runtime(runtime)->evaluateSHUnit(factory);
  } catch (const JSError &error) {
    if (guest_initialization_report_count == reports_before) {
      const auto error_class = guest_initialization_error_class(
          js, error.value(), *guest_initialization_error_constructors);
      // A raw unit failure did not enter its JavaScript wrapper. Production
      // reporting remains limited to authenticated slot and error-class data;
      // the explicit local diagnostic build may add its bounded message.
#if defined(CONVEX_WASM_LOCAL_TEST_GUEST_INITIALIZATION_DIAGNOSTICS)
      report_guest_initialization_failure_classified(
          js, unit_slot, error_class, error.value());
#else
      report_guest_initialization_failure_classified(js, unit_slot, error_class);
#endif
    }
    throw;
  }
}

int64_t exact_positive_handle(Runtime &js, const Value &value);
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
int32_t exact_i32(Runtime &js, const Value &value, const char *description);
Value initialize_official_chunk_unit(Runtime &js, int32_t unit_slot);
void clear_official_chunk_initialization_bindings(Runtime &js);
void validate_intrinsic_descriptor_state(Runtime &js);

bool valid_official_chunk_namespace(const Value &value) {
  return value.isObject();
}

void expose_official_chunk_unit_bindings(Runtime &js, int32_t unit_slot) {
  if (application_global_facade == nullptr) {
    throw JSError(js, "Official chunk application facade is unavailable");
  }
  auto require_namespace = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "requireOfficialChunkNamespace"),
      1,
      [unit_slot](Runtime &js,
                  const Value &,
                  const Value *arguments,
                  size_t count) -> Value {
        try {
          if (count != 1 || !arguments[0].isString()) {
            throw JSError(js, "Official chunk require specifier is invalid");
          }
          const std::string specifier = arguments[0].getString(js).utf8(js);
          const int32_t dependency_slot =
              convex_wasm_application_chunk_dependency_by_specifier(
                  unit_slot, specifier.c_str());
          if (dependency_slot < 0 ||
              dependency_slot >= convex_wasm_application_chunk_slot_count()) {
            throw JSError(
                js, "Official chunk requested an undeclared dependency");
          }
          return initialize_official_chunk_unit(js, dependency_slot);
        } catch (...) {
          official_chunk_initialization_dirty = true;
          throw;
        }
      });
  auto begin_namespace = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "beginOfficialChunkNamespace"),
      1,
      [unit_slot](Runtime &js,
                  const Value &,
                  const Value *arguments,
                  size_t count) -> Value {
        try {
          auto &unit = chunk_application_unit_slots[unit_slot];
          if (count != 1 ||
              unit.state != ChunkApplicationUnitState::Initializing ||
              unit.published || !valid_official_chunk_namespace(arguments[0])) {
            throw JSError(
                js, "Official chunk registered invalid CommonJS exports");
          }
          unit.namespace_value = std::make_unique<Value>(js, arguments[0]);
          return Value::undefined();
        } catch (...) {
          official_chunk_initialization_dirty = true;
          throw;
        }
      });
  auto publish_namespace = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "publishOfficialChunkNamespace"),
      1,
      [unit_slot](Runtime &js,
                  const Value &,
                  const Value *arguments,
                  size_t count) -> Value {
        try {
          auto &unit = chunk_application_unit_slots[unit_slot];
          if (count != 1 ||
              unit.state != ChunkApplicationUnitState::Initializing ||
              unit.published || unit.namespace_value == nullptr ||
              !valid_official_chunk_namespace(arguments[0]) ||
              !Value::strictEquals(js, *unit.namespace_value, arguments[0])) {
            throw JSError(js, "Official chunk published an invalid namespace");
          }
          unit.published = true;
          return Value::undefined();
        } catch (...) {
          official_chunk_initialization_dirty = true;
          throw;
        }
      });
  auto reporter = guest_initialization_reporter(js, unit_slot);
  define_hidden_global(
      js,
      kApplicationGlobalFacadeBinding,
      Value(js, *application_global_facade));
  define_hidden_global(
      js, kOfficialChunkRequireBinding, Value(js, require_namespace));
  define_hidden_global(
      js, kOfficialChunkBeginBinding, Value(js, begin_namespace));
  define_hidden_global(
      js, kOfficialChunkPublishBinding, Value(js, publish_namespace));
  define_hidden_global(
      js,
      kOfficialChunkReportThrownBinding,
      Value(js, reporter));
}

Value initialize_official_chunk_unit(Runtime &js, int32_t unit_slot) {
  if (unit_slot < 0 ||
      unit_slot >= convex_wasm_application_chunk_slot_count()) {
    official_chunk_initialization_dirty = true;
    throw JSError(js, "Official chunk unit slot is invalid");
  }
  auto &slot = chunk_application_unit_slots[unit_slot];
  if (slot.state == ChunkApplicationUnitState::Initialized) {
    if (!slot.published || slot.namespace_value == nullptr) {
      official_chunk_initialization_dirty = true;
      throw JSError(js, "Initialized official chunk namespace is invalid");
    }
    return Value(js, *slot.namespace_value);
  }
  if (slot.state == ChunkApplicationUnitState::Initializing) {
    // CommonJS cycles observe the namespace registered before transformed
    // module evaluation. Later module.exports replacement does not rewrite a
    // reference already returned to a dependency.
    if (slot.namespace_value == nullptr) {
      official_chunk_initialization_dirty = true;
      throw JSError(
          js, "Official chunk cycle preceded CommonJS namespace registration");
    }
    return Value(js, *slot.namespace_value);
  }
  if (slot.state != ChunkApplicationUnitState::Uninitialized) {
    official_chunk_initialization_dirty = true;
    throw JSError(js, "Official chunk unit state is invalid");
  }
  const SHUnitCreator factory =
      convex_wasm_application_factory_by_unit_slot(unit_slot);
  if (factory == nullptr) {
    official_chunk_initialization_dirty = true;
    throw JSError(js, "Official chunk unit factory is unavailable");
  }
  try {
    slot.state = ChunkApplicationUnitState::Initializing;
    expose_official_chunk_unit_bindings(js, unit_slot);
    evaluate_application_initializer(js, factory, unit_slot);
    if (!slot.published || slot.namespace_value == nullptr) {
      throw JSError(js, "Official chunk unit did not publish its namespace");
    }
    slot.state = ChunkApplicationUnitState::Initialized;
    // The wrapper captures these host callbacks as IIFE parameters. Clearing the
    // global properties before returning lets a nested or deferred literal
    // require expose its own authenticated unit bindings without retaining them.
    clear_official_chunk_initialization_bindings(js);
    validate_intrinsic_descriptor_state(js);
    return Value(js, *slot.namespace_value);
  } catch (...) {
    // A deferred literal import can catch this error in guest code. Mark the
    // retained Store unusable and remove loader authority before guest control
    // resumes; the outer invocation retires the Store before it returns.
    official_chunk_initialization_dirty = true;
    clear_official_chunk_initialization_bindings(js);
    throw;
  }
}

void expose_official_entry_publication_bindings(Runtime &js,
                                                int32_t entry_slot,
                                                int32_t unit_slot,
                                                int32_t chunk_slot) {
  auto read_namespace = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "readOfficialChunkNamespace"),
      1,
      [chunk_slot](Runtime &js,
                   const Value &,
                   const Value *arguments,
                   size_t count) -> Value {
        try {
          if (count != 1) {
            throw JSError(js, "Official entry namespace slot is invalid");
          }
          const int32_t requested_chunk_slot = exact_i32(
              js, arguments[0], "Official entry namespace slot is invalid");
          if (requested_chunk_slot != chunk_slot) {
            throw JSError(js, "Official entry namespace slot is invalid");
          }
          auto &unit = chunk_application_unit_slots[chunk_slot];
          if (unit.state != ChunkApplicationUnitState::Initialized ||
              !unit.published || unit.namespace_value == nullptr) {
            throw JSError(js, "Official entry namespace is unavailable");
          }
          return Value(js, *unit.namespace_value);
        } catch (...) {
          official_chunk_initialization_dirty = true;
          throw;
        }
      });
  auto publish_entry = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "publishOfficialEntryNamespace"),
      2,
      [entry_slot, chunk_slot](Runtime &js,
                               const Value &,
                               const Value *arguments,
                               size_t count) -> Value {
        try {
          if (count != 2) {
            throw JSError(js, "Official entry publication is invalid");
          }
          const int32_t handoff_slot = exact_i32(
              js, arguments[0], "Official entry handoff slot is invalid");
          if (handoff_slot != entry_slot ||
              pending_application_exports[entry_slot] != nullptr) {
            throw JSError(js, "Official entry handoff slot is invalid");
          }
          const auto &unit = chunk_application_unit_slots[chunk_slot];
          if (unit.state != ChunkApplicationUnitState::Initialized ||
              unit.namespace_value == nullptr || !arguments[1].isObject() ||
              !Value::strictEquals(js, *unit.namespace_value, arguments[1])) {
            throw JSError(
                js, "Official entry publication namespace is invalid");
          }
          // Publication stays provisional until the complete finalizer returns
          // successfully. A failure cannot leave any selectable entry behind.
          pending_application_exports[entry_slot] =
              std::make_unique<Value>(js, arguments[1]);
          return Value::undefined();
        } catch (...) {
          official_chunk_initialization_dirty = true;
          throw;
        }
      });
  auto reporter = guest_initialization_reporter(js, unit_slot);
  define_hidden_global(
      js, kOfficialChunkReadNamespaceBinding, Value(js, read_namespace));
  define_hidden_global(
      js, kOfficialChunkPublishEntryBinding, Value(js, publish_entry));
  define_hidden_global(
      js,
      kOfficialChunkReportThrownBinding,
      Value(js, reporter));
}

void clear_official_chunk_initialization_bindings(Runtime &js) {
  for (const char *binding : {
           kOfficialChunkBeginBinding,
           kOfficialChunkPublishBinding,
           kOfficialChunkPublishEntryBinding,
           kOfficialChunkReadNamespaceBinding,
           kOfficialChunkReportThrownBinding,
           kOfficialChunkRequireBinding,
       }) {
    if (js.global().hasProperty(js, binding)) {
      remove_hidden_global(js, binding);
    }
  }
  if (js.global().hasProperty(js, kApplicationGlobalFacadeBinding)) {
    remove_hidden_global(js, kApplicationGlobalFacadeBinding);
  }
}

void validate_official_chunk_application_topology(Runtime &js) {
  const int32_t chunk_slot_count =
      convex_wasm_application_chunk_slot_count();
  if (declared_application_unit_count < 2 ||
      declared_application_unit_count > kMaxApplicationUnitSlots ||
      chunk_slot_count <= 0 ||
      chunk_slot_count + declared_application_entry_count !=
          declared_application_unit_count) {
    throw JSError(js, "Official chunk application topology is invalid");
  }
  std::array<bool, kMaxApplicationUnitSlots> publication_slots{};
  for (int32_t entry_slot = 0;
       entry_slot < declared_application_entry_count; ++entry_slot) {
    const int32_t entry_chunk_slot =
        convex_wasm_application_entry_chunk_slot_by_handoff_slot(entry_slot);
    const int32_t publication_unit_slot =
        convex_wasm_application_entry_publication_unit_slot_by_handoff_slot(
            entry_slot);
    if (convex_wasm_application_invocation_abi_by_slot(entry_slot) !=
            kSelectedInvocationAbiOfficialWrapper ||
        entry_chunk_slot < 0 || entry_chunk_slot >= chunk_slot_count ||
        publication_unit_slot < chunk_slot_count ||
        publication_unit_slot >= declared_application_unit_count ||
        publication_slots[publication_unit_slot] ||
        application_export_slots[entry_slot].exports != nullptr ||
        application_export_slots[entry_slot].unit_initialization_count != 0 ||
        pending_application_exports[entry_slot] != nullptr) {
      throw JSError(js, "Official chunk application entry topology is invalid");
    }
    publication_slots[publication_unit_slot] = true;
  }
}

void initialize_official_chunk_entry(Runtime &js,
                                     int32_t entry_slot,
                                     JSErrorPhase &js_error_phase) {
  if (entry_slot < 0 || entry_slot >= declared_application_entry_count ||
      application_global_facade == nullptr ||
      application_initializer_reporter == nullptr ||
      guest_initialization_error_constructors == nullptr) {
    throw JSError(js, "Official chunk entry initialization is invalid");
  }
  auto &application_slot = application_export_slots[entry_slot];
  if (application_slot.exports != nullptr ||
      application_slot.unit_initialization_count != 0 ||
      pending_application_exports[entry_slot] != nullptr) {
    throw JSError(js, "Official chunk entry was already initialized");
  }
  const int32_t chunk_slot_count =
      convex_wasm_application_chunk_slot_count();
  const int32_t entry_chunk_slot =
      convex_wasm_application_entry_chunk_slot_by_handoff_slot(entry_slot);
  const int32_t publication_unit_slot =
      convex_wasm_application_entry_publication_unit_slot_by_handoff_slot(
          entry_slot);
  if (chunk_slot_count <= 0 ||
      chunk_slot_count + declared_application_entry_count !=
          declared_application_unit_count ||
      entry_chunk_slot < 0 || entry_chunk_slot >= chunk_slot_count ||
      publication_unit_slot < chunk_slot_count ||
      publication_unit_slot >= declared_application_unit_count ||
      convex_wasm_application_invocation_abi_by_slot(entry_slot) !=
          kSelectedInvocationAbiOfficialWrapper) {
    throw JSError(js, "Official chunk entry topology is invalid");
  }
  try {
    (void)initialize_official_chunk_unit(js, entry_chunk_slot);
    js_error_phase = JSErrorPhase::InitializeOfficialEntryPublicationUnit;
    const SHUnitCreator publication_factory =
        convex_wasm_application_factory_by_unit_slot(publication_unit_slot);
    if (publication_factory == nullptr) {
      throw JSError(js, "Official entry publication factory is unavailable");
    }
    expose_official_entry_publication_bindings(
        js, entry_slot, publication_unit_slot, entry_chunk_slot);
    evaluate_application_initializer(js, publication_factory, publication_unit_slot);
    if (pending_application_exports[entry_slot] == nullptr ||
        !pending_application_exports[entry_slot]->isObject()) {
      throw JSError(js, "Official entry publication is incomplete");
    }
    application_slot.exports =
        std::move(pending_application_exports[entry_slot]);
    application_slot.unit_initialization_count = 1;
    clear_official_chunk_initialization_bindings(js);
  } catch (...) {
    official_chunk_initialization_dirty = true;
    clear_official_chunk_initialization_bindings(js);
    throw;
  }
}
#endif

void retain_bridge_bootstrap_and_application_bindings(Runtime &js) {
  if (bridge_bootstrap != nullptr || application_global_facade != nullptr ||
      application_initializer_reporter != nullptr ||
      guest_initialization_error_constructors != nullptr ||
      intrinsic_descriptor_state_validator != nullptr) {
    throw JSError(js, "Bridge bootstrap state was already retained");
  }

  auto global = js.global();
  auto retained_bootstrap =
      guest_function(js, global.getProperty(js, kCapabilityBootstrapBinding));
  auto facade = global.getProperty(js, kApplicationGlobalFacadeBinding);
  if (!facade.isObject()) {
    throw JSError(js, "Application global facade is invalid");
  }
  auto object_constructor = global.getPropertyAsObject(js, "Object");
  auto facade_is_extensible = object_constructor
                                  .getPropertyAsFunction(js, "isExtensible")
                                  .call(js, facade);
  auto facade_prototype = object_constructor
                              .getPropertyAsFunction(js, "getPrototypeOf")
                              .call(js, facade);
  if (!facade_is_extensible.isBool() || !facade_is_extensible.getBool() ||
      !facade_prototype.isNull()) {
    throw JSError(js, "Application global facade is not extensible and isolated");
  }
  auto retained_reporter = guest_function(
      js, global.getProperty(js, kApplicationInitializerReporterBinding));
  auto retained_intrinsic_descriptor_state_validator = guest_function(
      js, global.getProperty(js, kIntrinsicDescriptorStateValidatorBinding));
  auto retained_error_constructors =
      capture_guest_initialization_error_constructors(js);

  remove_hidden_global(js, kCapabilityBootstrapBinding);
  remove_hidden_global(js, kApplicationGlobalFacadeBinding);
  remove_hidden_global(js, kApplicationInitializerReporterBinding);
  remove_hidden_global(js, kIntrinsicDescriptorStateValidatorBinding);

  bridge_bootstrap = std::move(retained_bootstrap);
  intrinsic_descriptor_state_validator =
      std::move(retained_intrinsic_descriptor_state_validator);
  application_global_facade = std::make_unique<Value>(js, facade);
  application_initializer_reporter = std::move(retained_reporter);
  guest_initialization_error_constructors =
      std::move(retained_error_constructors);
}

void validate_intrinsic_descriptor_state(Runtime &js) {
  if (intrinsic_descriptor_state_validator == nullptr) {
    throw JSError(js, "Intrinsic descriptor validator is unavailable");
  }
  const auto valid = intrinsic_descriptor_state_validator->call(js);
  if (!valid.isBool() || !valid.getBool()) {
    throw JSError(js, "Intrinsic descriptor state is contaminated");
  }
}

void validate_runtime_support_installer(Runtime &js) {
  auto global = js.global();
  auto object_constructor = global.getPropertyAsObject(js, "Object");
  auto descriptor_value =
      object_constructor
          .getPropertyAsFunction(js, "getOwnPropertyDescriptor")
          .call(js, global,
                String::createFromAscii(js, kRuntimeSupportInstallerBinding));
  if (!descriptor_value.isObject()) {
    throw JSError(js, "Runtime-support installer is unavailable");
  }
  auto descriptor = descriptor_value.asObject(js);
  auto configurable = descriptor.getProperty(js, "configurable");
  auto enumerable = descriptor.getProperty(js, "enumerable");
  auto writable = descriptor.getProperty(js, "writable");
  auto installer = descriptor.getProperty(js, "value");
  if (!configurable.isBool() || !configurable.getBool() ||
      !enumerable.isBool() || enumerable.getBool() || !writable.isBool() ||
      writable.getBool()) {
    throw JSError(js, "Runtime-support installer descriptor is invalid");
  }
  (void)guest_function(js, installer);
  auto frozen = object_constructor.getPropertyAsFunction(js, "isFrozen")
                    .call(js, installer);
  if (!frozen.isBool() || !frozen.getBool()) {
    throw JSError(js, "Runtime-support installer is not frozen");
  }
}

void verify_runtime_support_installation(Runtime &js) {
  if (js.global().hasProperty(js, kRuntimeSupportInstallerBinding)) {
    throw JSError(js, "Runtime-support installer was retained after installation");
  }
}

void expose_application_initialization_bindings(Runtime &js, int32_t unit_slot) {
  if (application_global_facade == nullptr ||
      application_initializer_reporter == nullptr) {
    throw JSError(js, "Application initialization bindings are unavailable");
  }
  auto publisher = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "publishCompileProfile"),
      1,
      [](Runtime &js,
         const Value &,
         const Value *arguments,
         size_t count) -> Value {
        publish_compile_profile_output(js, arguments, count);
        return Value::undefined();
      });
  auto facade = Value(js, *application_global_facade);
  auto publisher_value = Value(js, publisher);
  auto reporter = Value(js, guest_initialization_reporter(js, unit_slot));
  define_hidden_global(js, kApplicationGlobalFacadeBinding, facade);
  define_hidden_global(js, kApplicationProfilePublisherBinding,
                       publisher_value);
  define_hidden_global(js, kApplicationInitializerReporterBinding, reporter);
}

void clear_application_initialization_bindings(Runtime &js) {
  remove_hidden_global(js, kApplicationGlobalFacadeBinding);
  remove_hidden_global(js, kApplicationProfilePublisherBinding);
  remove_hidden_global(js, kApplicationInitializerReporterBinding);
}

void install_guest_bridge(Runtime &js) {
  if (guest_bridge != nullptr) {
    return;
  }
  if (bridge_bootstrap == nullptr) {
    throw JSError(js, "Capability bootstrap is unavailable");
  }
  auto install = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "installCapabilityBridge"),
      10,
      [](Runtime &js,
         const Value &,
         const Value *arguments,
         size_t count) -> Value {
        if (count != 10) {
          throw JSError(js, "Capability bootstrap returned an invalid bridge");
        }
        if (guest_bridge != nullptr) {
          throw JSError(js, "Capability bridge was already installed");
        }
        guest_bridge = std::make_unique<GuestBridge>(GuestBridge{
            guest_function(js, arguments[0]),
            guest_function(js, arguments[1]),
            guest_function(js, arguments[2]),
            guest_function(js, arguments[3]),
            guest_function(js, arguments[4]),
            guest_function(js, arguments[5]),
            guest_function(js, arguments[6]),
            guest_function(js, arguments[7]),
            guest_function(js, arguments[8]),
            guest_function(js, arguments[9]),
        });
        return Value::undefined();
        });
  auto array_buffer_constructor = std::make_shared<Function>(
      js.global().getPropertyAsFunction(js, "ArrayBuffer"));
  auto define_property = std::make_shared<Function>(
      js.global()
          .getPropertyAsObject(js, "Object")
          .getPropertyAsFunction(js, "defineProperty"));
  auto object_constructor = js.global().getPropertyAsObject(js, "Object");
  auto value_intrinsics = std::make_shared<ValueAbiIntrinsics>(ValueAbiIntrinsics{
      object_constructor.getPropertyAsObject(js, "prototype"),
  });
  auto take_typed_value = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "takeTypedCapabilityValue"),
      2,
      [array_buffer_constructor, define_property](Runtime &js,
                                                   const Value &,
                                                   const Value *arguments,
                                                   size_t count) -> Value {
        if (count != 2) {
          throw JSError(js, "Typed host value arguments are invalid");
        }
        return take_typed_host_value(js,
                                     exact_positive_handle(js, arguments[0]),
                                     arguments[1],
                                     *array_buffer_constructor,
                                     *define_property);
      });
  auto set_typed_result = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "setTypedCapabilityResult"),
      2,
      [value_intrinsics](Runtime &js,
                         const Value &,
                         const Value *arguments,
                         size_t count) -> Value {
        if (count != 2 || !arguments[1].isObject()) {
          throw JSError(js, "Typed result arguments are invalid");
        }
        auto bytes = ValueAbiWriter(js, arguments[1], *value_intrinsics,
                                    ValueAbiMode::Value)
                         .encode(arguments[0]);
        convex_guest_value_result_binary(
            reinterpret_cast<const char *>(bytes.data()),
            static_cast<int32_t>(bytes.size()));
        return Value::undefined();
      });
  auto start_typed_get = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startTypedCapabilityGet"),
      3,
      [](Runtime &js,
         const Value &,
         const Value *arguments,
         size_t count) -> Value {
        if (count != 3 || !arguments[0].isString() ||
            (!arguments[1].isNull() && !arguments[1].isString()) ||
            !arguments[2].isBool()) {
          throw JSError(js, "Typed get arguments are invalid");
        }
        const std::string id = arguments[0].asString(js).utf8(js);
        const std::string table = arguments[1].isString()
                                      ? arguments[1].asString(js).utf8(js)
                                      : std::string();
        if (id.size() > kValueAbiMaximumFrameBytes ||
            table.size() > kValueAbiMaximumFrameBytes - id.size()) {
          throw JSError(js, "Typed get strings exceed the byte limit");
        }
        const int64_t capability = convex_capability_current();
        if (capability <= 0) {
          throw JSError(js, "Invocation capability is unavailable");
        }
        const int32_t handle = convex_capability_start_get(
            capability, id.data(), static_cast<int32_t>(id.size()),
            arguments[1].isString() ? table.data() : nullptr,
            static_cast<int32_t>(table.size()), arguments[2].getBool() ? 1 : 0);
        return Value(static_cast<double>(handle));
      });
  auto start_typed_string = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startTypedCapabilityString"),
      2,
      [](Runtime &js,
         const Value &,
         const Value *arguments,
         size_t count) -> Value {
        if (count != 2 || !arguments[0].isNumber() ||
            !arguments[1].isString()) {
          throw JSError(js, "Typed string operation arguments are invalid");
        }
        const double code_number = arguments[0].getNumber();
        if (code_number < 1 || code_number > 7 ||
            code_number != static_cast<int32_t>(code_number)) {
          throw JSError(js, "Typed string operation code is invalid");
        }
        const std::string value = arguments[1].asString(js).utf8(js);
        if (value.size() > kValueAbiMaximumFrameBytes) {
          throw JSError(js, "Typed string operation exceeds the byte limit");
        }
        const int64_t capability = convex_capability_current();
        if (capability <= 0) {
          throw JSError(js, "Invocation capability is unavailable");
        }
        const int32_t handle = convex_capability_start_string(
            capability, static_cast<int32_t>(code_number), value.data(),
            static_cast<int32_t>(value.size()));
        return Value(static_cast<double>(handle));
      });
  auto start_typed_write = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startTypedCapabilityWrite"),
      5,
      [value_intrinsics](Runtime &js,
                         const Value &,
                         const Value *arguments,
                         size_t count) -> Value {
        if (count != 5 || !arguments[0].isNumber() ||
            !arguments[4].isObject()) {
          throw JSError(js, "Typed write arguments are invalid");
        }
        const double kind_number = arguments[0].getNumber();
        if (kind_number < 1 || kind_number > 4 ||
            kind_number != static_cast<int32_t>(kind_number)) {
          throw JSError(js, "Typed write kind is invalid");
        }
        const int32_t kind = static_cast<int32_t>(kind_number);
        if ((kind == 1 && !arguments[1].isString()) ||
            (kind != 1 && !arguments[2].isString()) ||
            (kind == 1 && !arguments[2].isNull()) ||
            (!arguments[1].isNull() && !arguments[1].isString())) {
          throw JSError(js, "Typed write fields are invalid");
        }
        const std::string table = arguments[1].isString()
                                      ? arguments[1].asString(js).utf8(js)
                                      : std::string();
        const std::string id = arguments[2].isString()
                                   ? arguments[2].asString(js).utf8(js)
                                   : std::string();
        if (table.size() > kValueAbiMaximumFrameBytes ||
            id.size() > kValueAbiMaximumFrameBytes) {
          throw JSError(js, "Typed write string exceeds the byte limit");
        }
        std::vector<uint8_t> value_bytes;
        if (kind != 4) {
          value_bytes = ValueAbiWriter(
                            js, arguments[4], *value_intrinsics,
                            kind == 2 ? ValueAbiMode::Patch : ValueAbiMode::Value)
                            .encode(arguments[3]);
        }
        const int64_t capability = convex_capability_current();
        if (capability <= 0) {
          throw JSError(js, "Invocation capability is unavailable");
        }
        const int32_t handle = convex_capability_start_write(
            capability, kind, arguments[1].isString() ? table.data() : nullptr,
            static_cast<int32_t>(table.size()),
            arguments[2].isString() ? id.data() : nullptr,
            static_cast<int32_t>(id.size()),
            kind == 4 ? nullptr
                      : reinterpret_cast<const char *>(value_bytes.data()),
            static_cast<int32_t>(value_bytes.size()));
        return Value(static_cast<double>(handle));
      });
  auto start_typed_run_udf = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startTypedCapabilityRunUdf"),
      6,
      [value_intrinsics](Runtime &js,
                         const Value &,
                         const Value *arguments,
                         size_t count) -> Value {
        if (count != 6 || !arguments[0].isNumber() ||
            !arguments[1].isNumber() || !arguments[2].isString() ||
            !arguments[3].isObject() ||
            (!arguments[4].isNull() && !arguments[4].isObject()) ||
            !arguments[5].isObject()) {
          throw JSError(js, "Typed nested UDF arguments are invalid");
        }
        const double udf_type = arguments[0].getNumber();
        const double address_kind = arguments[1].getNumber();
        if ((udf_type != 1 && udf_type != 2 && udf_type != 3) ||
            (address_kind != 1 && address_kind != 2 && address_kind != 3)) {
          throw JSError(js, "Typed nested UDF operation codes are invalid");
        }
        const std::string address = arguments[2].asString(js).utf8(js);
        auto args_bytes = ValueAbiWriter(js, arguments[5], *value_intrinsics,
                                         ValueAbiMode::Value)
                              .encode(arguments[3]);
        std::vector<uint8_t> limits_bytes;
        if (arguments[4].isObject()) {
          limits_bytes = ValueAbiWriter(js, arguments[5], *value_intrinsics,
                                        ValueAbiMode::Value)
                             .encode(arguments[4]);
        }
        if (address.size() > kValueAbiMaximumFrameBytes ||
            args_bytes.size() > kValueAbiMaximumFrameBytes - address.size() ||
            limits_bytes.size() >
                kValueAbiMaximumFrameBytes - address.size() - args_bytes.size()) {
          throw JSError(js, "Typed nested UDF request exceeds the byte limit");
        }
        const int64_t capability = convex_capability_current();
        if (capability <= 0) {
          throw JSError(js, "Invocation capability is unavailable");
        }
        const int32_t handle = convex_capability_start_run_udf(
            capability, static_cast<int32_t>(udf_type),
            static_cast<int32_t>(address_kind), address.data(),
            static_cast<int32_t>(address.size()),
            reinterpret_cast<const char *>(args_bytes.data()),
            static_cast<int32_t>(args_bytes.size()),
            limits_bytes.empty()
                ? nullptr
                : reinterpret_cast<const char *>(limits_bytes.data()),
            static_cast<int32_t>(limits_bytes.size()));
        return Value(static_cast<double>(handle));
      });
  auto start_typed_schedule = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startTypedCapabilitySchedule"),
      6,
      [value_intrinsics](Runtime &js,
                         const Value &,
                         const Value *arguments,
                         size_t count) -> Value {
        if (count != 6 || !arguments[0].isNumber() ||
            !arguments[1].isNumber() || !arguments[2].isNumber() ||
            !arguments[3].isString() || !arguments[4].isObject() ||
            !arguments[5].isObject()) {
          throw JSError(js, "Typed schedule arguments are invalid");
        }
        const double kind = arguments[0].getNumber();
        const double time = arguments[1].getNumber();
        const double address_kind = arguments[2].getNumber();
        if ((kind != 1 && kind != 2) || !std::isfinite(time) ||
            (kind == 1 && time < 0.0) ||
            (address_kind != 1 && address_kind != 2 && address_kind != 3)) {
          throw JSError(js, "Typed schedule fields are invalid");
        }
        const std::string address = arguments[3].asString(js).utf8(js);
        auto args_bytes = ValueAbiWriter(js, arguments[5], *value_intrinsics,
                                         ValueAbiMode::Committed)
                              .encode(arguments[4]);
        if (address.empty() || address.size() > kValueAbiMaximumFrameBytes ||
            args_bytes.size() > kValueAbiMaximumFrameBytes - address.size()) {
          throw JSError(js, "Typed schedule request exceeds the byte limit");
        }
        const int64_t capability = convex_capability_current();
        if (capability <= 0) {
          throw JSError(js, "Invocation capability is unavailable");
        }
        const int32_t handle = convex_capability_start_schedule(
            capability, static_cast<int32_t>(kind), time,
            static_cast<int32_t>(address_kind), address.data(),
            static_cast<int32_t>(address.size()),
            reinterpret_cast<const char *>(args_bytes.data()),
            static_cast<int32_t>(args_bytes.size()));
        return Value(static_cast<double>(handle));
      });
  auto capture_query_value = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "captureTypedQueryValue"),
      2,
      [array_buffer_constructor, value_intrinsics](Runtime &js,
                                                    const Value &,
                                                    const Value *arguments,
                                                    size_t count) -> Value {
        if (count != 2 || !arguments[1].isObject()) {
          throw JSError(js, "Typed query value arguments are invalid");
        }
        auto bytes = ValueAbiWriter(js, arguments[1], *value_intrinsics,
                                    ValueAbiMode::Value)
                         .encode(arguments[0]);
        auto buffer = array_buffer_constructor
                          ->callAsConstructor(js, static_cast<double>(bytes.size()))
                          .asObject(js)
                          .getArrayBuffer(js);
        if (buffer.size(js) != bytes.size()) {
          throw JSError(js, "Typed query value buffer has an invalid size");
        }
        std::memcpy(buffer.data(js), bytes.data(), bytes.size());
        return Value(std::move(buffer));
      });
  auto start_typed_query = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startTypedCapabilityQuery"),
      3,
      [](Runtime &js, const Value &, const Value *arguments,
         size_t count) -> Value {
        if (count != 3 || !arguments[0].isObject() ||
            !arguments[1].isString()) {
          throw JSError(js, "Typed query arguments are invalid");
        }
        auto bytes = QueryAbiWriter(js).encode(arguments[0], arguments[1],
                                               arguments[2]);
        const int64_t capability = convex_capability_current();
        if (capability <= 0) {
          throw JSError(js, "Invocation capability is unavailable");
        }
        const int32_t handle = convex_capability_query_record(
            capability, reinterpret_cast<const char *>(bytes.data()),
            static_cast<int32_t>(bytes.size()));
        return Value(static_cast<double>(handle));
      });
  bridge_bootstrap->call(js, install, take_typed_value, set_typed_result,
                         start_typed_get, start_typed_string, start_typed_write,
                         start_typed_run_udf, start_typed_schedule,
                         start_typed_query, capture_query_value);
  if (guest_bridge == nullptr) {
    throw JSError(js, "Capability bootstrap did not install its bridge");
  }
  guest_bridge->start_typed_get =
      std::make_shared<Function>(std::move(start_typed_get));
  guest_bridge->start_typed_string =
      std::make_shared<Function>(std::move(start_typed_string));
  guest_bridge->start_typed_write =
      std::make_shared<Function>(std::move(start_typed_write));
  guest_bridge->start_typed_run_udf =
      std::make_shared<Function>(std::move(start_typed_run_udf));
  guest_bridge->start_typed_schedule =
      std::make_shared<Function>(std::move(start_typed_schedule));
  guest_bridge->start_typed_query =
      std::make_shared<Function>(std::move(start_typed_query));
  // Installation is one-shot. Keeping the bootstrap would retain authority
  // beyond the only lifecycle boundary where C++ is allowed to call it.
  bridge_bootstrap.reset();
}

void reset_runtime_state() {
  guest_bridge.reset();
  bridge_bootstrap.reset();
  intrinsic_descriptor_state_validator.reset();
  application_global_facade.reset();
  application_initializer_reporter.reset();
  guest_initialization_error_constructors.reset();
  guest_initialization_report_count = 0;
  compile_profile_output_slot.reset();
  for (auto &application_slot : application_export_slots) {
    application_slot.exports.reset();
    application_slot.unit_initialization_count = 0;
  }
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
  for (auto &unit_slot : chunk_application_unit_slots) {
    unit_slot.namespace_value.reset();
    unit_slot.state = ChunkApplicationUnitState::Uninitialized;
    unit_slot.published = false;
  }
  for (auto &pending_export : pending_application_exports) {
    pending_export.reset();
  }
  official_chunk_initialization_dirty = false;
#endif
  bridge_unit_initialization_count = 0;
  formatter_unit_initialization_count = 0;
  declared_application_entry_count = 0;
  declared_application_unit_count = 0;
  convex_wasm_clear_selected_entry();
  if (runtime != nullptr) {
    _sh_done(runtime);
    runtime = nullptr;
  }
}

bool retained_runtime_state_is_empty() {
  if (guest_bridge != nullptr || bridge_bootstrap != nullptr ||
      intrinsic_descriptor_state_validator != nullptr ||
      application_global_facade != nullptr ||
      application_initializer_reporter != nullptr ||
      guest_initialization_error_constructors != nullptr ||
      guest_initialization_report_count != 0 ||
      compile_profile_output_slot != nullptr ||
      bridge_unit_initialization_count != 0 ||
      formatter_unit_initialization_count != 0 ||
      declared_application_entry_count != 0 ||
      declared_application_unit_count != 0) {
    return false;
  }
  for (const auto &application_slot : application_export_slots) {
    if (application_slot.exports != nullptr ||
        application_slot.unit_initialization_count != 0) {
      return false;
    }
  }
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
  for (const auto &unit_slot : chunk_application_unit_slots) {
    if (unit_slot.namespace_value != nullptr ||
        unit_slot.state != ChunkApplicationUnitState::Uninitialized ||
        unit_slot.published) {
      return false;
    }
  }
  if (official_chunk_initialization_dirty) {
    return false;
  }
  for (const auto &pending_export : pending_application_exports) {
    if (pending_export != nullptr) {
      return false;
    }
  }
#endif
  return true;
}

bool retained_runtime_state_is_valid() {
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
  const int32_t chunk_slot_count =
      convex_wasm_application_chunk_slot_count();
  if (guest_bridge == nullptr || bridge_bootstrap != nullptr ||
      intrinsic_descriptor_state_validator == nullptr ||
      application_global_facade == nullptr ||
      application_initializer_reporter == nullptr ||
      guest_initialization_error_constructors == nullptr ||
      compile_profile_output_slot != nullptr ||
      bridge_unit_initialization_count != 1 ||
      formatter_unit_initialization_count != 1 ||
      declared_application_entry_count <= 0 ||
      declared_application_entry_count > kMaxApplicationEntrySlots ||
      declared_application_unit_count < 2 ||
      declared_application_unit_count > kMaxApplicationUnitSlots ||
      chunk_slot_count <= 0 ||
      official_chunk_initialization_dirty ||
      chunk_slot_count + declared_application_entry_count !=
          declared_application_unit_count) {
#else
  if (guest_bridge == nullptr || bridge_bootstrap != nullptr ||
      intrinsic_descriptor_state_validator == nullptr ||
      application_global_facade == nullptr ||
      application_initializer_reporter == nullptr ||
      guest_initialization_error_constructors == nullptr ||
      compile_profile_output_slot == nullptr ||
      !compile_profile_output_slot->closed ||
      compile_profile_output_slot->output != nullptr ||
      bridge_unit_initialization_count != 1 ||
      formatter_unit_initialization_count != 1 ||
      declared_application_entry_count <= 0 ||
      declared_application_entry_count > kMaxApplicationEntrySlots ||
      declared_application_unit_count <= 0 ||
      declared_application_unit_count > declared_application_entry_count) {
#endif
    return false;
  }
  for (int32_t entry_slot = 0; entry_slot < kMaxApplicationEntrySlots;
       ++entry_slot) {
    const auto &application_slot = application_export_slots[entry_slot];
    const bool declared = entry_slot < declared_application_entry_count;
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
    const bool initialized = application_slot.exports != nullptr ||
        application_slot.unit_initialization_count != 0;
    if (declared
            ? initialized &&
                  (application_slot.exports == nullptr ||
                   application_slot.unit_initialization_count != 1)
            : application_slot.exports != nullptr ||
                  application_slot.unit_initialization_count != 0) {
      return false;
    }
#else
    const bool initialized = application_slot.exports != nullptr ||
        application_slot.unit_initialization_count != 0;
    if (declared
            ? initialized &&
                  (application_slot.exports == nullptr ||
                   application_slot.unit_initialization_count != 1)
            : application_slot.exports != nullptr ||
                  application_slot.unit_initialization_count != 0) {
      return false;
    }
#endif
  }
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
  for (int32_t unit_slot = 0; unit_slot < kMaxApplicationUnitSlots;
       ++unit_slot) {
    const auto &unit = chunk_application_unit_slots[unit_slot];
    const bool chunk = unit_slot < chunk_slot_count;
    const bool initialized =
        unit.state == ChunkApplicationUnitState::Initialized;
    if (chunk
            ? initialized
                  ? !unit.published || unit.namespace_value == nullptr
                  : unit.state != ChunkApplicationUnitState::Uninitialized ||
                        unit.published || unit.namespace_value != nullptr
            : unit.state != ChunkApplicationUnitState::Uninitialized ||
                  unit.published || unit.namespace_value != nullptr) {
      return false;
    }
  }
  for (const auto &pending_export : pending_application_exports) {
    if (pending_export != nullptr) {
      return false;
    }
  }
#endif
  return true;
}

bool selected_entry_is_prepared(int32_t entry_slot) {
  if (entry_slot < 0 || entry_slot >= declared_application_entry_count) {
    return false;
  }
  const auto &application_slot = application_export_slots[entry_slot];
  return application_slot.exports != nullptr && application_slot.exports->isObject() &&
      application_slot.unit_initialization_count == 1;
}

bool preparation_bindings_are_absent(Runtime &js) {
  for (const char *binding : {
           kCapabilityBootstrapBinding,
           kRuntimeSupportInstallerBinding,
           kApplicationGlobalFacadeBinding,
           kApplicationProfilePublisherBinding,
           kApplicationInitializerReporterBinding,
           kIntrinsicDescriptorStateValidatorBinding,
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
           kOfficialChunkBeginBinding,
           kOfficialChunkPublishBinding,
           kOfficialChunkPublishEntryBinding,
           kOfficialChunkReadNamespaceBinding,
           kOfficialChunkReportThrownBinding,
           kOfficialChunkRequireBinding,
#endif
       }) {
    if (js.global().hasProperty(js, binding)) {
      return false;
    }
  }
  return true;
}

int32_t exact_i32(Runtime &js, const Value &value, const char *description) {
  if (!value.isNumber()) {
    throw JSError(js, description);
  }
  const double number = value.getNumber();
  if (number < std::numeric_limits<int32_t>::min() ||
      number > std::numeric_limits<int32_t>::max()) {
    throw JSError(js, description);
  }
  const auto integer = static_cast<int32_t>(number);
  if (static_cast<double>(integer) != number) {
    throw JSError(js, description);
  }
  return integer;
}

int64_t exact_positive_handle(Runtime &js, const Value &value) {
  if (!value.isNumber()) {
    throw JSError(js, "Capability request handle is invalid");
  }
  const double number = value.getNumber();
  if (number <= 0 || number > 9007199254740991.0) {
    throw JSError(js, "Capability request handle is invalid");
  }
  const auto handle = static_cast<int64_t>(number);
  if (static_cast<double>(handle) != number) {
    throw JSError(js, "Capability request handle is invalid");
  }
  return handle;
}

Object invocation_context(Runtime &js,
                          int64_t capability_identity,
                          const char *udf_kind,
                          const Value &commit_ts_placeholder) {
  auto start = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startCapabilityOperation"),
      1,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (count != 1) {
          throw JSError(js, "Capability start requires one request handle");
        }
        const int64_t request_handle = exact_positive_handle(js, arguments[0]);
        return Value(static_cast<double>(convex_capability_start_take(
            capability_identity, request_handle)));
      });
  auto sync = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "runSynchronousCapabilityOperation"),
      1,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (count != 1) {
          throw JSError(js, "Synchronous capability requires one request handle");
        }
        const int64_t request_handle = exact_positive_handle(js, arguments[0]);
        return Value(static_cast<double>(convex_capability_sync_take(
            capability_identity, request_handle)));
      });
  auto start_typed_get = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startBoundTypedCapabilityGet"),
      3,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (convex_capability_current() != capability_identity ||
            guest_bridge == nullptr ||
            guest_bridge->start_typed_get == nullptr) {
          throw JSError(js, "Invocation capability is stale");
        }
        return guest_bridge->start_typed_get->call(js, arguments, count);
      });
  auto start_scalar = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startBoundScalarCapability"),
      1,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (convex_capability_current() != capability_identity) {
          throw JSError(js, "Invocation capability is stale");
        }
        if (count != 1 || !arguments[0].isNumber()) {
          throw JSError(js, "Scalar capability code is invalid");
        }
        const double code_number = arguments[0].getNumber();
        if (code_number < 1 || code_number > 6 ||
            code_number != static_cast<int32_t>(code_number)) {
          throw JSError(js, "Scalar capability code is invalid");
        }
        return Value(static_cast<double>(convex_capability_start_scalar(
            capability_identity, static_cast<int32_t>(code_number))));
      });
  auto start_typed_string = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startBoundTypedCapabilityString"),
      2,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (convex_capability_current() != capability_identity ||
            guest_bridge == nullptr ||
            guest_bridge->start_typed_string == nullptr) {
          throw JSError(js, "Invocation capability is stale");
        }
        return guest_bridge->start_typed_string->call(js, arguments, count);
      });
  auto start_typed_write = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startBoundTypedCapabilityWrite"),
      5,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (convex_capability_current() != capability_identity ||
            guest_bridge == nullptr ||
            guest_bridge->start_typed_write == nullptr) {
          throw JSError(js, "Invocation capability is stale");
        }
        return guest_bridge->start_typed_write->call(js, arguments, count);
      });
  auto start_typed_run_udf = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startBoundTypedCapabilityRunUdf"),
      6,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (convex_capability_current() != capability_identity ||
            guest_bridge == nullptr ||
            guest_bridge->start_typed_run_udf == nullptr) {
          throw JSError(js, "Invocation capability is stale");
        }
        return guest_bridge->start_typed_run_udf->call(js, arguments, count);
      });
  auto start_typed_schedule = Function::createFromHostFunction(
      js,
      PropNameID::forAscii(js, "startBoundTypedCapabilitySchedule"),
      6,
      [capability_identity](Runtime &js,
                            const Value &,
                            const Value *arguments,
                            size_t count) -> Value {
        if (convex_capability_current() != capability_identity ||
            guest_bridge == nullptr ||
            guest_bridge->start_typed_schedule == nullptr) {
          throw JSError(js, "Invocation capability is stale");
        }
        return guest_bridge->start_typed_schedule->call(js, arguments, count);
      });
  Value context_arguments[] = {
      std::move(start),
      std::move(sync),
      Value(facebook::jsi::String::createFromAscii(js, udf_kind)),
      Value(js, commit_ts_placeholder),
      std::move(start_typed_get),
      std::move(start_scalar),
      std::move(start_typed_string),
      std::move(start_typed_write),
      std::move(start_typed_run_udf),
      std::move(start_typed_schedule),
  };
  return guest_bridge->create_context
      ->call(js,
             static_cast<const Value *>(context_arguments),
             size_t{10})
      .asObject(js);
}

}  // namespace

extern "C" int convex_wasm_udf_prepare_selected_entry(void) {
  const int32_t package_entry_count =
      convex_wasm_application_entry_count();
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT) || \
    defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
  const int32_t package_unit_count = convex_wasm_application_unit_count();
#else
  const int32_t package_unit_count = package_entry_count;
#endif
  const int32_t entry_slot = convex_wasm_selected_entry_slot();
  const char *export_name = convex_wasm_selected_handler_export_name();
  const char *udf_kind =
      handler_udf_kind(convex_wasm_selected_handler_udf_kind());
  const int32_t invocation_abi = convex_wasm_selected_invocation_abi();
  if (package_entry_count <= 0 ||
      package_entry_count > kMaxApplicationEntrySlots || entry_slot < 0 ||
      entry_slot >= package_entry_count ||
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
      package_unit_count < 2 ||
      package_unit_count > kMaxApplicationUnitSlots ||
      package_unit_count <= package_entry_count ||
#else
      package_unit_count <= 0 || package_unit_count > package_entry_count ||
#endif
      export_name == nullptr || udf_kind == nullptr ||
      !valid_invocation_abi(invocation_abi)) {
    convex_wasm_clear_selected_entry();
    return 8;
  }
  SelectedEntryLease selected_entry_lease;
  bool new_runtime = false;
  if (runtime == nullptr) {
    if (convex_typed_value_abi_v1() != 1) {
      convex_wasm_clear_selected_entry();
      return 8;
    }
    if (!retained_runtime_state_is_empty()) {
      reset_runtime_state();
      return 9;
    }
    runtime = initialize_runtime();
    if (runtime == nullptr) {
      return 1;
    }
    new_runtime = true;
  }

  auto &js = *reinterpret_cast<Runtime *>(_sh_get_hermes_runtime(runtime));
  auto js_error_phase = JSErrorPhase::ReserveCompileProfileOutput;
  bool initialized_selected_application = false;
  int32_t caught_status = 5;
  try {
    if (new_runtime) {
      declared_application_entry_count = package_entry_count;
      declared_application_unit_count = package_unit_count;
      js_error_phase = JSErrorPhase::ReserveCompileProfileOutput;
      reserve_compile_profile_output(js);
      js_error_phase = JSErrorPhase::InitializeBridgeUnit;
      if (!_sh_initialize_units(runtime, 1,
                                CONVEX_WASM_BRIDGE_EXPORTED_UNIT)) {
        reset_runtime_state();
        return static_cast<int32_t>(js_error_phase);
      }
      bridge_unit_initialization_count += 1;
      if (bridge_unit_initialization_count != 1) {
        reset_runtime_state();
        return 10;
      }
#if defined(CONVEX_WASM_FORMATTER_PARTIAL_INITIALIZATION_FIXTURE)
      record_fixture_initialization_event(kFixtureBridgeInitialized);
#endif
      js_error_phase = JSErrorPhase::ValidateRuntimeSupportInstaller;
      validate_runtime_support_installer(js);
      js_error_phase = JSErrorPhase::InitializeFormatterUnit;
#if defined(CONVEX_WASM_FORMATTER_PARTIAL_INITIALIZATION_FIXTURE)
      if (fixture_formatter_initialization_failure_armed) {
        fixture_formatter_initialization_failure_armed = false;
        record_fixture_initialization_event(
            kFixtureFormatterInitializationFailed);
        throw JSError(js, "Fixture forced runtime-support initialization failure");
      }
#endif
      if (!_sh_initialize_units(runtime, 1,
                                CONVEX_WASM_FORMATTER_EXPORTED_UNIT)) {
        reset_runtime_state();
        return static_cast<int32_t>(js_error_phase);
      }
      formatter_unit_initialization_count += 1;
      if (formatter_unit_initialization_count != 1) {
        reset_runtime_state();
        return 10;
      }
#if defined(CONVEX_WASM_FORMATTER_PARTIAL_INITIALIZATION_FIXTURE)
      record_fixture_initialization_event(kFixtureFormatterInitialized);
#endif
      js_error_phase = JSErrorPhase::VerifyRuntimeSupportInstallation;
      verify_runtime_support_installation(js);
      // Runtime support installs immutable built-ins before C++ retains the extensible facade.
      js_error_phase = JSErrorPhase::RetainBridgeBootstrap;
      retain_bridge_bootstrap_and_application_bindings(js);
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
      validate_official_chunk_application_topology(js);
#endif
    } else if (package_entry_count != declared_application_entry_count ||
               package_unit_count != declared_application_unit_count ||
               !retained_runtime_state_is_valid()) {
      reset_runtime_state();
      return 9;
    }

#if !defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
    if (!selected_entry_is_prepared(entry_slot)) {
      const int32_t initialization_slot =
#if defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
          0;
#else
          entry_slot;
#endif
#if defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
      for (int32_t application_entry_slot = 0;
           application_entry_slot < declared_application_entry_count;
           ++application_entry_slot) {
        if (application_export_slots[application_entry_slot].exports != nullptr ||
            application_export_slots[application_entry_slot].unit_initialization_count != 0) {
          reset_runtime_state();
          return 9;
        }
      }
#else
      auto &application_slot = application_export_slots[initialization_slot];
      if (application_slot.exports != nullptr ||
          application_slot.unit_initialization_count != 0) {
        reset_runtime_state();
        return 9;
      }
#endif
      const SHUnitCreator factory =
#if defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
          convex_wasm_application_factory_by_unit_slot(initialization_slot);
#else
          convex_wasm_application_factory_by_slot(initialization_slot);
#endif
      if (factory == nullptr) {
        reset_runtime_state();
        return 8;
      }
      js_error_phase = JSErrorPhase::OpenCompileProfileOutput;
      open_compile_profile_output(js);
      js_error_phase = JSErrorPhase::ExposeApplicationBindings;
      expose_application_initialization_bindings(js, initialization_slot);
      js_error_phase = JSErrorPhase::InitializeApplicationUnit;
      evaluate_application_initializer(js, factory, initialization_slot);
#if !defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
      application_slot.unit_initialization_count += 1;
      if (application_slot.unit_initialization_count != 1) {
        reset_runtime_state();
        return 10;
      }
#endif
#if defined(CONVEX_WASM_FORMATTER_PARTIAL_INITIALIZATION_FIXTURE)
      record_fixture_initialization_event(
          initialization_slot == 0 ? kFixtureApplicationAInitialized
                                   : kFixtureApplicationBInitialized);
#endif
      js_error_phase = JSErrorPhase::CloseCompileProfileOutput;
#if defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
      close_multi_entry_compile_profile_outputs(js);
      for (int32_t application_entry_slot = 0;
           application_entry_slot < declared_application_entry_count;
           ++application_entry_slot) {
        const int32_t initialization_invocation_abi =
            convex_wasm_application_invocation_abi_by_slot(application_entry_slot);
        if (initialization_invocation_abi !=
            kSelectedInvocationAbiOfficialWrapper) {
          throw JSError(js, "Multi-entry application invocation ABI is invalid");
        }
      }
#else
      close_compile_profile_output(js, initialization_slot);
      const int32_t initialization_invocation_abi =
          convex_wasm_application_invocation_abi_by_slot(initialization_slot);
      if (!valid_invocation_abi(initialization_invocation_abi)) {
        throw JSError(js, "Application invocation ABI is invalid");
      }
      if (initialization_invocation_abi ==
          kSelectedInvocationAbiLegacyHandler) {
        (void)selected_commit_ts_placeholder(js, initialization_slot);
      }
#endif
      js_error_phase = JSErrorPhase::ClearApplicationBindings;
      clear_application_initialization_bindings(js);
      initialized_selected_application = true;
    }
#endif
    if (new_runtime) {
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
      compile_profile_output_slot.reset();
#endif
      // Descriptor mismatches are not recoverable in a retained runtime.
      // Discard the complete slot rather than trying to restore application state.
      js_error_phase = JSErrorPhase::ValidateIntrinsicDescriptorState;
      validate_intrinsic_descriptor_state(js);
      js_error_phase = JSErrorPhase::InstallGuestBridge;
      install_guest_bridge(js);
      if (!retained_runtime_state_is_valid()) {
        reset_runtime_state();
        return 9;
      }
    }
#if !defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
    else if (initialized_selected_application) {
      js_error_phase = JSErrorPhase::ValidateIntrinsicDescriptorState;
      validate_intrinsic_descriptor_state(js);
      if (!retained_runtime_state_is_valid()) {
        reset_runtime_state();
        return 9;
      }
    }
#endif
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
    if (application_export_slots[entry_slot].exports == nullptr) {
      js_error_phase = JSErrorPhase::InitializeOfficialChunkUnit;
      initialize_official_chunk_entry(js, entry_slot, js_error_phase);
      // Incremental initialization has the same intrinsic boundary as cold
      // initialization. Retiring the Store prevents a failed entry from
      // observing or extending a retained partially initialized namespace.
      js_error_phase = JSErrorPhase::ValidateIntrinsicDescriptorState;
      validate_intrinsic_descriptor_state(js);
      if (!retained_runtime_state_is_valid()) {
        reset_runtime_state();
        return 9;
      }
    }
#endif
    if (!selected_entry_is_prepared(entry_slot) ||
        !retained_runtime_state_is_valid() ||
        !preparation_bindings_are_absent(js)) {
      reset_runtime_state();
      return 9;
    }
    js_error_phase = JSErrorPhase::ValidatePreparationAuthority;
    if (convex_capability_current() != 0) {
      reset_runtime_state();
      return static_cast<int32_t>(js_error_phase);
    }
    js_error_phase = JSErrorPhase::ValidatePreparationQuiescence;
    if (convex_async_operation_cancel_all() != 0) {
      reset_runtime_state();
      return static_cast<int32_t>(js_error_phase);
    }
    return 0;
  } catch (const JSError &) {
    caught_status = static_cast<int32_t>(js_error_phase);
  } catch (...) {
    caught_status = 5;
  }
  reset_runtime_state();
  return caught_status;
}

extern "C" int convex_wasm_udf_run(void) {
  const int32_t package_entry_count = convex_wasm_application_entry_count();
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT) || \
    defined(CONVEX_WASM_MULTI_ENTRY_APPLICATION_UNIT)
  const int32_t package_unit_count = convex_wasm_application_unit_count();
#else
  const int32_t package_unit_count = package_entry_count;
#endif
  const int32_t entry_slot = convex_wasm_selected_entry_slot();
  const char *export_name = convex_wasm_selected_handler_export_name();
  const char *udf_kind =
      handler_udf_kind(convex_wasm_selected_handler_udf_kind());
  const int32_t invocation_abi = convex_wasm_selected_invocation_abi();
  if (package_entry_count <= 0 ||
      package_entry_count > kMaxApplicationEntrySlots || entry_slot < 0 ||
      entry_slot >= package_entry_count ||
#if defined(CONVEX_WASM_CHUNK_APPLICATION_UNIT)
      package_unit_count < 2 ||
      package_unit_count > kMaxApplicationUnitSlots ||
      package_unit_count <= package_entry_count ||
#else
      package_unit_count <= 0 || package_unit_count > package_entry_count ||
#endif
      export_name == nullptr || udf_kind == nullptr ||
      !valid_invocation_abi(invocation_abi)) {
    convex_wasm_clear_selected_entry();
    return 8;
  }
  SelectedEntryLease selected_entry_lease;
  if (runtime == nullptr ||
      package_entry_count != declared_application_entry_count ||
      package_unit_count != declared_application_unit_count ||
      !retained_runtime_state_is_valid() ||
      !selected_entry_is_prepared(entry_slot)) {
    if (runtime != nullptr) {
      reset_runtime_state();
    }
    return 9;
  }

  auto &js = *reinterpret_cast<Runtime *>(_sh_get_hermes_runtime(runtime));
  auto js_error_phase = JSErrorPhase::ReadCapabilityIdentity;
  bool invocation_activated = false;
  int32_t caught_status = 5;
  try {
    const int64_t capability_identity = convex_capability_current();
    if (capability_identity == 0) {
      return 7;
    }
    js_error_phase = JSErrorPhase::ActivateSdkFacade;
    guest_bridge->activate_sdk->call(
        js, String::createFromAscii(js, udf_kind));
    invocation_activated = true;
    js_error_phase = JSErrorPhase::ReadInvocationRequest;
    auto request = guest_bridge->read_request->call(js);
    js_error_phase = JSErrorPhase::SelectHandler;
    auto selected_export =
        selected_application_export(js, entry_slot, export_name);
    js_error_phase = JSErrorPhase::InvokeHandler;
    if (invocation_abi == kSelectedInvocationAbiOfficialWrapper) {
      Value invocation_arguments[] = {
          Value(js, selected_export),
          std::move(request),
      };
      guest_bridge->invoke_registered_wrapper->call(
          js, static_cast<const Value *>(invocation_arguments), size_t{2});
    } else {
      js_error_phase = JSErrorPhase::CreateInvocationContext;
      auto commit_ts_placeholder =
          selected_commit_ts_placeholder(js, entry_slot);
      auto context = invocation_context(
          js, capability_identity, udf_kind, commit_ts_placeholder);
      Value invocation_arguments[] = {
          Value(js, selected_export),
          std::move(context),
          std::move(request),
      };
      js_error_phase = JSErrorPhase::InvokeHandler;
      guest_bridge->invoke->call(
          js, static_cast<const Value *>(invocation_arguments), size_t{3});
    }

    js_error_phase = JSErrorPhase::DrainInitialMicrotasks;
    if (!js.drainMicrotasks()) {
      throw InvocationFailure{2};
    }
    while (true) {
      js_error_phase = JSErrorPhase::ReadInvocationDone;
      if (guest_bridge->done->call(js).getBool()) {
        break;
      }
      const auto settle_operation = [&](int32_t operation_handle) {
        const int32_t completion_status =
            convex_async_operation_completion_status(operation_handle);
        const int64_t payload_handle =
            convex_async_operation_completion_take(operation_handle);
        js_error_phase = JSErrorPhase::SettleOperation;
        guest_bridge->settle->call(js,
                                   static_cast<double>(operation_handle),
                                   static_cast<double>(completion_status),
                                   static_cast<double>(payload_handle));
      };
      const int32_t operation_handle = convex_async_operation_wait_any();
      if (operation_handle <= 0) {
        throw InvocationFailure{3};
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
          throw InvocationFailure{3};
        }
        settle_operation(ready_operation_handle);
      }
      js_error_phase = JSErrorPhase::DrainOperationMicrotasks;
      if (!js.drainMicrotasks()) {
        throw InvocationFailure{2};
      }
    }
    js_error_phase = JSErrorPhase::CleanupInvocation;
    auto cleanup_result = guest_bridge->cleanup->call(js);
    js_error_phase = JSErrorPhase::ValidateCleanupResult;
    const int32_t guest_abandoned = exact_i32(
        js,
        cleanup_result,
        "Capability cleanup returned an invalid abandoned-operation count");
    invocation_activated = false;
    const int32_t host_abandoned = convex_async_operation_cancel_all();
    if (host_abandoned != guest_abandoned) {
      if (!retained_runtime_state_is_valid()) {
        reset_runtime_state();
      }
      return 6;
    }
    js_error_phase = JSErrorPhase::ReadInvocationStatus;
    const int32_t invocation_status = exact_i32(
        js,
        guest_bridge->status->call(js),
        "Capability invocation returned an invalid status");
    if (!retained_runtime_state_is_valid()) {
      reset_runtime_state();
    }
    return invocation_status;
  } catch (const JSError &) {
    caught_status = static_cast<int32_t>(js_error_phase);
  } catch (const InvocationFailure &failure) {
    caught_status = failure.status;
  } catch (...) {
    caught_status = 5;
  }
  if (invocation_activated && guest_bridge != nullptr) {
    try {
      auto cleanup_result = guest_bridge->cleanup->call(js);
      const int32_t guest_abandoned = exact_i32(
          js,
          cleanup_result,
          "Capability cleanup returned an invalid abandoned-operation count");
      const int32_t host_abandoned = convex_async_operation_cancel_all();
      if (host_abandoned != guest_abandoned) {
        reset_runtime_state();
        return 6;
      }
    } catch (...) {
      (void)convex_async_operation_cancel_all();
      reset_runtime_state();
      return static_cast<int32_t>(JSErrorPhase::CleanupInvocation);
    }
  }
  if (runtime != nullptr && !retained_runtime_state_is_valid()) {
    reset_runtime_state();
  }
  return caught_status;
}

extern "C" void convex_wasm_udf_destroy_runtime(void) {
  reset_runtime_state();
}

#if defined(CONVEX_WASM_FORMATTER_PARTIAL_INITIALIZATION_FIXTURE)
extern "C" int32_t
convex_wasm_fixture_arm_formatter_initialization_failure(void) {
  if (runtime != nullptr || !retained_runtime_state_is_empty() ||
      fixture_formatter_initialization_failure_armed ||
      fixture_initialization_trace_value != 0) {
    return -1;
  }
  fixture_formatter_initialization_failure_armed = true;
  return 0;
}

extern "C" int64_t convex_wasm_fixture_initialization_trace(void) {
  return static_cast<int64_t>(fixture_initialization_trace_value);
}
#endif
