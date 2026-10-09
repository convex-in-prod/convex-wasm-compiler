import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const vendor = new URL("../vendor/ada-4.0.0/", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("source.json", vendor), "utf8"));
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const expectedFiles = ["ada.h", "ada.cpp", "LICENSE-MIT", "LICENSE-APACHE", "urltestdata.json", "setters_tests.json"];
if (manifest.package !== "ada-url@4.0.0" ||
    manifest.archiveSha256 !== "c153db7a5a9f8a92a313dff0fecbbb28198542fc98bf024b961baf9896408347" ||
    JSON.stringify(Object.keys(manifest.files).sort()) !== JSON.stringify(expectedFiles.sort()) ||
    manifest.patch !== "retained-capacity.patch") {
  throw new Error("Native URL source manifest does not describe the pinned Ada package.");
}
const files = new Map();
for (const [name, identity] of Object.entries(manifest.files)) {
  const bytes = readFileSync(new URL(name, vendor));
  if (bytes.length !== identity.size || sha256(bytes) !== identity.sha256) {
    throw new Error(`Pinned native URL material ${name} has changed.`);
  }
  files.set(name, bytes.toString("utf8"));
}
if (sha256(readFileSync(new URL(manifest.patch, vendor))) !== manifest.patchSha256) {
  throw new Error("Pinned native URL capacity patch has changed.");
}
const bindingHeader = readFileSync(new URL("./convex-wasm-native-url.h", import.meta.url), "utf8");
const binding = readFileSync(new URL("./convex-wasm-native-url.cpp", import.meta.url), "utf8");

function replaceInclude(source, name, contents) {
  const directive = `#include "${name}"`;
  if (source.split(directive).length !== 2) {
    throw new Error(`Native URL source must include ${name} exactly once.`);
  }
  return source.replace(directive, () => contents.replace(/^#pragma once\s*/u, ""));
}

// Each cached object owns its full library source/header bytes. They are not
// added to the shared generated-C header set, so URL changes cannot invalidate
// unrelated application objects. The binding alone depends on Hermes headers.
const sources = Object.freeze([
  Object.freeze({
    name: "native-url-parser",
    includeRuntimeHeaders: false,
    source: replaceInclude(files.get("ada.cpp"), "ada.h", files.get("ada.h")),
  }),
  Object.freeze({
    name: "native-url-binding",
    includeRuntimeHeaders: true,
    source: replaceInclude(
      replaceInclude(binding, "convex-wasm-native-url.h", bindingHeader),
      "ada.h", files.get("ada.h")
    ),
  }),
]);

export const convexWasmNativeUrlSupportIdentity = Object.freeze({
  kind: "convex-wasm-native-url-support-v1",
  archiveSha256: manifest.archiveSha256,
  patchSha256: manifest.patchSha256,
  sources: Object.freeze(sources.map(({ name, source }) => Object.freeze({
    name, sha256: sha256(source), size: Buffer.byteLength(source),
  }))),
});
export const convexWasmNativeUrlSupportSha256 = sha256(JSON.stringify(convexWasmNativeUrlSupportIdentity));

export function convexWasmNativeUrlSupportObjectInputs(compileFlags) {
  return sources.map(({ name, includeRuntimeHeaders, source }) => ({
    fileName: `${name}.cpp`,
    flags: [...compileFlags, "-std=c++20", "-DADA_INCLUDE_URL_PATTERN=0", "-DSTATIC_HERMES"],
    identityPayload: { role: "base", unitRole: name },
    includeRuntimeHeaders,
    source,
    stage: `${name}-object`,
  }));
}
