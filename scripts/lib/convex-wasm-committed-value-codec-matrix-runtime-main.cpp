#include "convex_wasm_committed_value_codec_matrix_input.h"
#include "hermes/VM/static_h.h"
#include "jsi/jsi.h"

#include <climits>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <string>

extern "C" SHUnit *CONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_EXPORTED_UNIT(void);

namespace {

SHRuntime *initialize_runtime() {
  char program[] = "convex-wasm-committed-value-codec-matrix";
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

std::string stringify(
    facebook::jsi::Runtime &js,
    const facebook::jsi::Value &value) {
  auto json = js.global().getPropertyAsObject(js, "JSON");
  auto stringify = json.getPropertyAsFunction(js, "stringify");
  return stringify.call(js, value).getString(js).utf8(js);
}

struct GuestValueState {
  bool decode_called = false;
  bool encode_called = false;
  bool payload_copy_called = false;
  bool payload_len_called = false;
  bool payload_release_called = false;
  bool request_copy_called = false;
  bool request_len_called = false;
  bool result_called = false;
  bool valid = true;
  std::string result;
};

GuestValueState guest_value_state;

const std::string &request_payload() {
  static const std::string payload(
      reinterpret_cast<const char *>(
          convex_wasm_committed_value_codec_matrix_request),
      convex_wasm_committed_value_codec_matrix_request_len);
  return payload;
}

const std::string &expected_payload() {
  static const std::string payload(
      reinterpret_cast<const char *>(
          convex_wasm_committed_value_codec_matrix_expected),
      convex_wasm_committed_value_codec_matrix_expected_len);
  return payload;
}

int payload_length(const std::string &payload) {
  if (payload.size() > static_cast<size_t>(INT_MAX)) {
    guest_value_state.valid = false;
    return -1;
  }
  return static_cast<int>(payload.size());
}

int copy_payload(const std::string &payload, char *destination, int capacity) {
  const int length = payload_length(payload);
  if (length < 0 || capacity != length || (length != 0 && destination == nullptr)) {
    guest_value_state.valid = false;
    return -1;
  }
  if (length != 0) std::memcpy(destination, payload.data(), payload.size());
  return length;
}

void reset_guest_value_state() {
  guest_value_state = GuestValueState{};
}

bool guest_value_boundary_succeeded() {
  return guest_value_state.valid && guest_value_state.request_len_called &&
      guest_value_state.request_copy_called && guest_value_state.decode_called &&
      guest_value_state.encode_called && guest_value_state.payload_len_called &&
      guest_value_state.payload_copy_called &&
      guest_value_state.payload_release_called && guest_value_state.result_called &&
      guest_value_state.result == expected_payload();
}

}  // namespace

// The matrix replaces lowering's invocation block with its own guest-value
// boundary exercise. Static C still emits every other opaque bridge reference;
// neutral definitions keep both targets focused on this codec boundary.
extern "C" double convex_invocation_unix_timestamp_ms(void) { return 0; }
extern "C" long long convex_request_field(const char *, int) { return 0; }
extern "C" long long convex_db_get(int, long long) { return 0; }
extern "C" long long convex_db_normalize_id(int, long long) { return 0; }
extern "C" long long convex_async_batch_take(long long) { return 0; }
extern "C" int convex_async_operation_start_take(int, long long) { return 0; }
extern "C" int convex_async_operation_wait_any(void) { return 0; }
extern "C" int convex_async_operation_poll_ready(void) { return 0; }
extern "C" int convex_async_operation_completion_status(int) { return 0; }
extern "C" long long convex_async_operation_completion_take(int) { return 0; }
extern "C" int convex_async_operation_cancel_all(void) { return 0; }
extern "C" long long convex_capability_current(void) { return 0; }
extern "C" long long convex_capability_request_decode(const char *, int) { return 0; }
extern "C" void convex_capability_request_release(long long) {}
extern "C" int convex_capability_start_take(long long, long long) { return 0; }
extern "C" long long convex_capability_sync_take(long long, long long) { return 0; }
extern "C" void convex_crypto_subtle_digest_sha256(
    long long, const char *, int, char *, int) {}
extern "C" void convex_crypto_get_random_values(long long, char *, int) {}
extern "C" void convex_crypto_random_uuid(long long, char *, int) {}
extern "C" double convex_math_random(long long) { return 0; }
extern "C" int convex_async_query_stream_open_take(int, long long) { return 0; }
extern "C" int convex_async_query_stream_next(int) { return 0; }
extern "C" void convex_async_query_stream_close(int) {}
extern "C" long long convex_db_write(int, long long, long long) { return 0; }
extern "C" long long convex_scheduler_schedule(int, double, long long) { return 0; }
extern "C" int convex_host_secret_verify(int, const char *, int) { return 0; }
extern "C" long long convex_sha256_value(int, const char *, int) { return 0; }
extern "C" long long convex_query_start_value(int, long long) { return 0; }
extern "C" long long convex_query_start_utf8(int, const char *, int) { return 0; }
extern "C" long long convex_query_next(long long) { return 0; }
extern "C" int convex_value_type(long long) { return 0; }
extern "C" int convex_value_bool(long long) { return 0; }
extern "C" double convex_value_number(long long) { return 0; }
extern "C" int convex_value_string_len(long long) { return 0; }
extern "C" int convex_value_string_copy(long long, char *, int) { return 0; }
extern "C" long long convex_value_field(long long, const char *, int) { return 0; }
extern "C" void convex_value_release(long long) {}
extern "C" long long convex_value_null_new(void) { return 0; }
extern "C" long long convex_value_bool_new(int) { return 0; }
extern "C" long long convex_value_number_new(double) { return 0; }
extern "C" long long convex_value_string_new(const char *, int) { return 0; }
extern "C" long long convex_value_array_new(void) { return 0; }
extern "C" void convex_value_array_push(long long, long long) {}
extern "C" int convex_value_array_len(long long) { return 0; }
extern "C" long long convex_value_array_get(long long, int) { return 0; }
extern "C" long long convex_value_object_new(void) { return 0; }
extern "C" void convex_value_object_insert(long long, const char *, int, long long) {}
extern "C" int convex_guest_value_request_len(void) {
  guest_value_state.request_len_called = true;
  return payload_length(request_payload());
}
extern "C" int convex_guest_value_request_copy(char *destination, int capacity) {
  guest_value_state.request_copy_called = true;
  return copy_payload(request_payload(), destination, capacity);
}
extern "C" long long convex_guest_value_decode(const char *value, int value_len) {
  guest_value_state.decode_called = true;
  if (value_len < 0 || (value_len != 0 && value == nullptr) ||
      std::string(value, static_cast<size_t>(value_len)) != expected_payload()) {
    guest_value_state.valid = false;
    return 0;
  }
  return 1;
}
extern "C" long long convex_guest_value_encode(long long consuming_value_handle) {
  guest_value_state.encode_called = true;
  if (consuming_value_handle != 1 || !guest_value_state.decode_called) {
    guest_value_state.valid = false;
    return 0;
  }
  return 1;
}
extern "C" int convex_guest_value_payload_len(long long payload_handle) {
  guest_value_state.payload_len_called = true;
  if (payload_handle != 1 || !guest_value_state.decode_called) {
    guest_value_state.valid = false;
    return -1;
  }
  return payload_length(expected_payload());
}
extern "C" int convex_guest_value_payload_copy(
    long long payload_handle,
    char *destination,
    int capacity) {
  if (payload_handle != 1 || !guest_value_state.decode_called) {
    guest_value_state.valid = false;
    return -1;
  }
  guest_value_state.payload_copy_called = true;
  return copy_payload(expected_payload(), destination, capacity);
}
extern "C" void convex_guest_value_payload_release(long long payload_handle) {
  if (payload_handle != 1 || !guest_value_state.payload_copy_called) {
    guest_value_state.valid = false;
    return;
  }
  guest_value_state.payload_release_called = true;
}
extern "C" void convex_guest_value_result(const char *value, int value_len) {
  guest_value_state.result_called = true;
  if (value_len < 0 || (value_len != 0 && value == nullptr)) {
    guest_value_state.valid = false;
    return;
  }
  guest_value_state.result.assign(value, static_cast<size_t>(value_len));
}
extern "C" void convex_function_result(long long) {}
extern "C" void convex_developer_error(const char *, int, int) {}
extern "C" int convex_has_developer_error(void) { return 0; }
extern "C" void convex_profile_mark(int) {}

extern "C" int convex_wasm_committed_value_codec_matrix_run(void) {
  SHRuntime *runtime = initialize_runtime();
  if (runtime == nullptr) return 1;
  reset_guest_value_state();
  auto &js = *reinterpret_cast<facebook::jsi::Runtime *>(
      _sh_get_hermes_runtime(runtime));
  try {
    if (!_sh_initialize_units(
            runtime,
            1,
            CONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_EXPORTED_UNIT)) {
      _sh_done(runtime);
      return 2;
    }
    auto report = js.global().getProperty(
        js, "__convexWasmCommittedValueCodecMatrixReport");
    if (!report.isObject()) {
      _sh_done(runtime);
      return 4;
    }
    const std::string output = stringify(js, report);
    if (!guest_value_boundary_succeeded()) {
      std::fprintf(
          stderr,
          "Committed-value codec matrix boundary failed: request_len=%d request_copy=%d decode=%d encode=%d payload_len=%d payload_copy=%d payload_release=%d result=%d valid=%d\n",
          guest_value_state.request_len_called,
          guest_value_state.request_copy_called,
          guest_value_state.decode_called,
          guest_value_state.encode_called,
          guest_value_state.payload_len_called,
          guest_value_state.payload_copy_called,
          guest_value_state.payload_release_called,
          guest_value_state.result_called,
          guest_value_state.valid);
      std::fwrite(output.data(), 1, output.size(), stdout);
      std::fputc('\n', stdout);
      std::fflush(stdout);
      _sh_done(runtime);
      return 3;
    }
    std::fwrite(output.data(), 1, output.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
  } catch (const facebook::jsi::JSError &error) {
    std::fprintf(
        stderr,
        "Committed-value codec matrix JSI error: %.2048s\n",
        error.getMessage().c_str());
    _sh_done(runtime);
    return 5;
  } catch (...) {
    std::fputs("Committed-value codec matrix failed\n", stderr);
    _sh_done(runtime);
    return 6;
  }
  _sh_done(runtime);
  return 0;
}

#ifdef CONVEX_WASM_COMMITTED_VALUE_CODEC_MATRIX_HOST_MAIN
int main() {
  return convex_wasm_committed_value_codec_matrix_run();
}
#endif
