import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const licenses = Object.freeze({
  adapter: Object.freeze({
    file: "ADAPTER-LICENSE.txt",
    sha256: "6ba2fab96121dba8364707e8eb3826ef3134682e2f73ec6ef86fdbc9f7454d61",
  }),
  icu: Object.freeze({
    file: "ICU-LICENSE.txt",
    sha256: "e55522d81edc687a341a4411e0776e54ca654e90147f354a90458aaced4116af",
  }),
});
for (const license of Object.values(licenses)) {
  const bytes = readFileSync(new URL(`../vendor/convex-wasm-native-intl/${license.file}`, import.meta.url));
  if (createHash("sha256").update(bytes).digest("hex") !== license.sha256) {
    throw new Error(`Pinned native Intl license differs: ${license.file}`);
  }
}

// Runtime archive digests authenticate the linked code and embedded dataset.
// This policy names the semantic inputs even when two builds differ in bytes.
export const convexWasmNativeIntlIdentity = Object.freeze({
  implementation: "static-hermes-icu-provider",
  kind: "convex-wasm-native-intl-v1",
  icuVersion: "78.2",
  cldrVersion: "48.0",
  data: Object.freeze({
    sha256: "a3d49eacd189624769dc77457c6aa1789a89219fb217a6d87d5b076c269aaf1f",
    bytes: 33_107_248,
    timeZoneVersion: "2025c",
  }),
  defaultLocale: "en-US",
  defaultTimeZone: "UTC",
  allocationFailure: "wasm-trap-and-instance-discard",
  licenses,
});
