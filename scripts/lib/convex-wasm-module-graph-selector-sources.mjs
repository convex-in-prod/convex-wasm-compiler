import {
  assertPlainObject,
  fail,
  requireManifestString,
} from "./convex-wasm-artifact-contract.mjs";

const MAX_MANIFEST_IDENTIFIER_BYTES = 256;
const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;

export function renderConvexWasmModuleGraphCommonFactoryAdapter(commonUnits) {
  if (!Array.isArray(commonUnits)) {
    fail("module graph common factory adapter requires an array");
  }
  const declarations = [];
  const wrappers = [];
  const symbols = new Set();
  for (const [index, common] of commonUnits.entries()) {
    assertPlainObject(common, `module graph common unit ${index}`);
    const sourceSymbol = requireManifestString(
      common.occurrence.unit.entrySymbol,
      `module graph common unit ${index} source factory`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    const stableSymbol = requireManifestString(
      common.factorySymbol,
      `module graph common unit ${index} stable factory`,
      MAX_MANIFEST_IDENTIFIER_BYTES,
      false
    );
    if (
      !IDENTIFIER_PATTERN.test(sourceSymbol) ||
      !IDENTIFIER_PATTERN.test(stableSymbol) ||
      symbols.has(stableSymbol)
    ) {
      fail(`module graph common unit ${index} has an invalid or duplicate factory symbol`);
    }
    symbols.add(stableSymbol);
    declarations.push(`extern SHUnit *${sourceSymbol}(void);`);
    wrappers.push(`SHUnit *${stableSymbol}(void) { return ${sourceSymbol}(); }`);
  }
  return `typedef struct SHUnit SHUnit;
${declarations.join("\n")}
${wrappers.join("\n")}
`;
}

function renderConvexWasmModuleGraphHostForwarders() {
  return `#include <stdint.h>
#define CONVEX_WASM_GRAPH_HOST_IMPORT(name) \\
  __attribute__((import_module("convex"), import_name(name)))
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_operation_cancel_all")
int32_t convex_wasm_graph_import_async_operation_cancel_all(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_operation_completion_status")
int32_t convex_wasm_graph_import_async_operation_completion_status(int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_operation_completion_take")
int64_t convex_wasm_graph_import_async_operation_completion_take(int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_operation_wait_any")
int32_t convex_wasm_graph_import_async_operation_wait_any(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_operation_poll_ready")
int32_t convex_wasm_graph_import_async_operation_poll_ready(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_capability_request_decode")
int64_t convex_wasm_graph_import_capability_request_decode(const char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_capability_request_release")
void convex_wasm_graph_import_capability_request_release(int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_capability_current")
int64_t convex_wasm_graph_import_capability_current(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_console_message")
int32_t convex_wasm_graph_import_console_message(int64_t, int32_t, const char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_capability_sync_take")
int64_t convex_wasm_graph_import_capability_sync_take(int64_t, int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_capability_start_take")
int32_t convex_wasm_graph_import_capability_start_take(int64_t, int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_capability_query_stream_open_take")
int32_t convex_wasm_graph_import_capability_query_stream_open_take(int64_t, int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_query_stream_next")
int32_t convex_wasm_graph_import_async_query_stream_next(int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_async_query_stream_close")
void convex_wasm_graph_import_async_query_stream_close(int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_crypto_subtle_digest_sha256")
void convex_wasm_graph_import_crypto_subtle_digest_sha256(
    int64_t, const char *, int32_t, const char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_crypto_get_random_values")
void convex_wasm_graph_import_crypto_get_random_values(int64_t, char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_crypto_random_uuid")
void convex_wasm_graph_import_crypto_random_uuid(int64_t, char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_developer_error")
void convex_wasm_graph_import_developer_error(const char *, int32_t, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_has_developer_error")
int32_t convex_wasm_graph_import_has_developer_error(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_invocation_unix_timestamp_ms")
double convex_wasm_graph_import_invocation_unix_timestamp_ms(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_math_random")
double convex_wasm_graph_import_math_random(int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_request_len")
int32_t convex_wasm_graph_import_guest_value_request_len(void);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_request_copy")
int32_t convex_wasm_graph_import_guest_value_request_copy(char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_encode")
int64_t convex_wasm_graph_import_guest_value_encode(int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_payload_len")
int32_t convex_wasm_graph_import_guest_value_payload_len(int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_payload_copy")
int32_t convex_wasm_graph_import_guest_value_payload_copy(int64_t, char *, int32_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_payload_release")
void convex_wasm_graph_import_guest_value_payload_release(int64_t);
CONVEX_WASM_GRAPH_HOST_IMPORT("convex_guest_value_result")
void convex_wasm_graph_import_guest_value_result(char *, int32_t);
int32_t convex_async_operation_cancel_all(void) {
  return convex_wasm_graph_import_async_operation_cancel_all();
}
int32_t convex_async_operation_completion_status(int32_t operation) {
  return convex_wasm_graph_import_async_operation_completion_status(operation);
}
int64_t convex_async_operation_completion_take(int32_t operation) {
  return convex_wasm_graph_import_async_operation_completion_take(operation);
}
int32_t convex_async_operation_wait_any(void) {
  return convex_wasm_graph_import_async_operation_wait_any();
}
int32_t convex_async_operation_poll_ready(void) {
  return convex_wasm_graph_import_async_operation_poll_ready();
}
int64_t convex_capability_request_decode(const char *request, int32_t length) {
  return convex_wasm_graph_import_capability_request_decode(request, length);
}
void convex_capability_request_release(int64_t request) {
  convex_wasm_graph_import_capability_request_release(request);
}
int64_t convex_capability_current(void) {
  return convex_wasm_graph_import_capability_current();
}
int32_t convex_console_message(
    int64_t capability, int32_t level, const char *messages, int32_t length) {
  return convex_wasm_graph_import_console_message(capability, level, messages, length);
}
int64_t convex_capability_sync_take(int64_t capability, int64_t request) {
  return convex_wasm_graph_import_capability_sync_take(capability, request);
}
int32_t convex_capability_start_take(int64_t capability, int64_t request) {
  return convex_wasm_graph_import_capability_start_take(capability, request);
}
int32_t convex_capability_query_stream_open_take(int64_t capability, int64_t request) {
  return convex_wasm_graph_import_capability_query_stream_open_take(capability, request);
}
int32_t convex_async_query_stream_next(int32_t stream) {
  return convex_wasm_graph_import_async_query_stream_next(stream);
}
void convex_async_query_stream_close(int32_t stream) {
  convex_wasm_graph_import_async_query_stream_close(stream);
}
void convex_crypto_subtle_digest_sha256(
    int64_t capability, const char *algorithm, int32_t algorithm_length,
    const char *input, int32_t input_length) {
  convex_wasm_graph_import_crypto_subtle_digest_sha256(
      capability, algorithm, algorithm_length, input, input_length);
}
void convex_crypto_get_random_values(int64_t capability, char *output, int32_t length) {
  convex_wasm_graph_import_crypto_get_random_values(capability, output, length);
}
void convex_crypto_random_uuid(int64_t capability, char *output, int32_t length) {
  convex_wasm_graph_import_crypto_random_uuid(capability, output, length);
}
void convex_developer_error(
    const char *message, int32_t length, int32_t host_operation_error) {
  convex_wasm_graph_import_developer_error(message, length, host_operation_error);
}
int32_t convex_has_developer_error(void) {
  return convex_wasm_graph_import_has_developer_error();
}
double convex_invocation_unix_timestamp_ms(void) {
  return convex_wasm_graph_import_invocation_unix_timestamp_ms();
}
double convex_math_random(int64_t capability) {
  return convex_wasm_graph_import_math_random(capability);
}
int32_t convex_guest_value_request_len(void) {
  return convex_wasm_graph_import_guest_value_request_len();
}
int32_t convex_guest_value_request_copy(char *destination, int32_t capacity) {
  return convex_wasm_graph_import_guest_value_request_copy(destination, capacity);
}
int64_t convex_guest_value_encode(int64_t consuming_value_handle) {
  return convex_wasm_graph_import_guest_value_encode(consuming_value_handle);
}
int32_t convex_guest_value_payload_len(int64_t payload_handle) {
  return convex_wasm_graph_import_guest_value_payload_len(payload_handle);
}
int32_t convex_guest_value_payload_copy(
    int64_t payload_handle, char *destination, int32_t capacity) {
  return convex_wasm_graph_import_guest_value_payload_copy(
      payload_handle, destination, capacity);
}
void convex_guest_value_payload_release(int64_t payload_handle) {
  convex_wasm_graph_import_guest_value_payload_release(payload_handle);
}
void convex_guest_value_result(char *payload, int32_t length) {
  convex_wasm_graph_import_guest_value_result(payload, length);
}
#undef CONVEX_WASM_GRAPH_HOST_IMPORT
`;
}

function renderConvexWasmModuleGraphStructuralTraps() {
  return `#include <stdint.h>
#define CONVEX_WASM_GRAPH_TRAP() __builtin_trap()
int32_t __syscall_chdir(int32_t a) { (void)a; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_chmod(int32_t a, int32_t b) { (void)a; (void)b; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_dup3(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_faccessat(int32_t a, int32_t b, int32_t c, int32_t d) { (void)a; (void)b; (void)c; (void)d; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_fallocate(int32_t a, int32_t b, int64_t c, int64_t d) { (void)a; (void)b; (void)c; (void)d; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_fstatfs64(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_ftruncate64(int32_t a, int64_t b) { (void)a; (void)b; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_getcwd(int32_t a, int32_t b) { (void)a; (void)b; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_getdents64(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_getuid32(void) { CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_linkat(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e) { (void)a; (void)b; (void)c; (void)d; (void)e; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_readlinkat(int32_t a, int32_t b, int32_t c, int32_t d) { (void)a; (void)b; (void)c; (void)d; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_renameat(int32_t a, int32_t b, int32_t c, int32_t d) { (void)a; (void)b; (void)c; (void)d; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_rmdir(int32_t a) { (void)a; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_statfs64(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_symlinkat(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
int32_t __syscall_utimensat(int32_t a, int32_t b, int32_t c, int32_t d) { (void)a; (void)b; (void)c; (void)d; CONVEX_WASM_GRAPH_TRAP(); }
int32_t _dlopen_js(int32_t a) { (void)a; CONVEX_WASM_GRAPH_TRAP(); }
int32_t _dlsym_js(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
void _emscripten_dlopen_js(int32_t a, int32_t b, int32_t c, int32_t d) { (void)a; (void)b; (void)c; (void)d; CONVEX_WASM_GRAPH_TRAP(); }
int32_t _msync_js(int32_t a, int32_t b, int32_t c, int32_t d, int32_t e, int64_t f) { (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; CONVEX_WASM_GRAPH_TRAP(); }
int32_t emscripten_promise_create(void) { CONVEX_WASM_GRAPH_TRAP(); }
void emscripten_promise_destroy(int32_t a) { (void)a; CONVEX_WASM_GRAPH_TRAP(); }
void emscripten_promise_resolve(int32_t a, int32_t b, int32_t c) { (void)a; (void)b; (void)c; CONVEX_WASM_GRAPH_TRAP(); }
#undef CONVEX_WASM_GRAPH_TRAP
`;
}

export { renderConvexWasmModuleGraphHostForwarders, renderConvexWasmModuleGraphStructuralTraps };
