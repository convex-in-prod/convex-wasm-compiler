#include "convex_wasm_request_envelope_matrix_input.h"
#include "convex_wasm_request_envelope_matrix_runtime_contract.h"
#include "hermes/VM/static_h.h"
#include "jsi/jsi.h"

#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>

extern "C" SHUnit *CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_EXPORTED_UNIT(void);

namespace {

SHRuntime *initialize_runtime() {
  return _sh_init(
      convex_wasm_request_envelope_matrix_runtime_argument_count,
      convex_wasm_request_envelope_matrix_runtime_arguments);
}

std::string stringify(facebook::jsi::Runtime &js, const facebook::jsi::Value &value) {
  auto json = js.global().getPropertyAsObject(js, "JSON");
  auto stringify = json.getPropertyAsFunction(js, "stringify");
  return stringify.call(js, value).getString(js).utf8(js);
}

struct RequestEnvelopeState {
  int decoded = 0;
  int released = 0;
  bool valid = true;
};

RequestEnvelopeState request_envelope_state;

std::string expected_payload(int index) {
  const auto &input = convex_wasm_request_envelope_matrix_requests[index];
  return std::string(reinterpret_cast<const char *>(input.data), input.length);
}

bool request_boundary_succeeded() {
  return request_envelope_state.valid &&
      request_envelope_state.decoded == convex_wasm_request_envelope_matrix_request_count &&
      request_envelope_state.released == convex_wasm_request_envelope_matrix_request_count;
}

bool legacy_boundary_succeeded() {
  return request_envelope_state.valid && request_envelope_state.decoded == 0 &&
      request_envelope_state.released == 0;
}

}  // namespace

// Static C retains opaque bridge declarations from the generic lowering. This matrix reaches the
// request-handle boundary directly, so neutral definitions keep the target focused on that ABI.
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
extern "C" long long convex_capability_current(void) { return 1; }
extern "C" long long convex_capability_request_decode(const char *request, int request_len) {
  if (request_len < 0 ||
      request_envelope_state.decoded >= convex_wasm_request_envelope_matrix_request_count ||
      (request_len != 0 && request == nullptr) ||
      std::string(request, static_cast<size_t>(request_len)) !=
          expected_payload(request_envelope_state.decoded)) {
    request_envelope_state.valid = false;
    return 0;
  }
  request_envelope_state.decoded += 1;
  return request_envelope_state.decoded;
}
extern "C" void convex_capability_request_release(long long request_handle) {
  if (request_handle != request_envelope_state.released + 1 ||
      request_handle > request_envelope_state.decoded) {
    request_envelope_state.valid = false;
    return;
  }
  request_envelope_state.released += 1;
}
extern "C" int convex_capability_start_take(long long, long long) { return 0; }
extern "C" long long convex_capability_sync_take(long long, long long) { return 0; }
extern "C" void convex_crypto_subtle_digest_sha256(long long, const char *, int, char *, int) {}
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
extern "C" int convex_guest_value_request_len(void) { return 0; }
extern "C" int convex_guest_value_request_copy(char *, int) { return 0; }
extern "C" long long convex_guest_value_decode(const char *, int) { return 0; }
extern "C" long long convex_guest_value_encode(long long) { return 0; }
extern "C" int convex_guest_value_payload_len(long long) { return 0; }
extern "C" int convex_guest_value_payload_copy(long long, char *, int) { return 0; }
extern "C" void convex_guest_value_payload_release(long long) {}
extern "C" void convex_guest_value_result(const char *, int) {}
extern "C" void convex_function_result(long long) {}
extern "C" void convex_developer_error(const char *, int, int) {}
extern "C" int convex_has_developer_error(void) { return 0; }
extern "C" void convex_profile_mark(int) {}

extern "C" int convex_wasm_request_envelope_matrix_run(void) {
  SHRuntime *runtime = initialize_runtime();
  if (runtime == nullptr) return 1;
  request_envelope_state = RequestEnvelopeState{};
  auto &js = *reinterpret_cast<facebook::jsi::Runtime *>(_sh_get_hermes_runtime(runtime));
  try {
    if (!_sh_initialize_units(runtime, 1, CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_EXPORTED_UNIT)) {
      _sh_done(runtime);
      return 2;
    }
    auto report = js.global().getProperty(js, "__convexWasmRequestEnvelopeMatrixReport");
    if (!report.isObject()) {
      _sh_done(runtime);
      return 4;
    }
    const std::string output = stringify(js, report);
#if defined(CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_LEGACY_WHOLE_REQUEST_REJECTOR)
    if (!legacy_boundary_succeeded()) {
      std::fputs("Request-envelope matrix legacy boundary failed\n", stderr);
      _sh_done(runtime);
      return 3;
    }
    std::fwrite(output.data(), 1, output.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
#else
    if (!request_boundary_succeeded()) {
      std::fprintf(
          stderr,
          "Request-envelope matrix boundary failed: decoded=%d released=%d valid=%d\n",
          request_envelope_state.decoded,
          request_envelope_state.released,
          request_envelope_state.valid);
      std::fwrite(output.data(), 1, output.size(), stdout);
      std::fputc('\n', stdout);
      std::fflush(stdout);
      _sh_done(runtime);
      return 3;
    }
    std::fwrite(output.data(), 1, output.size(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
#endif
  } catch (const facebook::jsi::JSError &error) {
    std::fprintf(stderr, "Request-envelope matrix JSI error: %.2048s\n", error.getMessage().c_str());
    _sh_done(runtime);
    return 5;
  } catch (...) {
    std::fputs("Request-envelope matrix failed\n", stderr);
    _sh_done(runtime);
    return 6;
  }
  _sh_done(runtime);
  return 0;
}

#ifdef CONVEX_WASM_REQUEST_ENVELOPE_MATRIX_HOST_MAIN
int main() {
  return convex_wasm_request_envelope_matrix_run();
}
#endif
