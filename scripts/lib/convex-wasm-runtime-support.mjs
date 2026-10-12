import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { convexWasmNativeUrlSupportIdentity } from "./convex-wasm-native-url-support.mjs";

const BROWSER_BUNDLE_SHA256 = "c6a687251b8df8bce919ae2b40b7c3f0ecae02b630fdfe0ce58d6a6fb260a389";
const browserBundle = readFileSync(
  new URL("../vendor/convex-wasm-runtime-support/browser-bundle.js.txt", import.meta.url),
  "utf8"
);
const licenseIdentities = Object.freeze({
  "domexception@4.0.0": Object.freeze({
    file: "domexception-4.0.0-LICENSE.txt",
    sha256: "ed71a70f6fae0f721d7d1ed623e842c442b9625ed74930edff98d22257ca727c",
  }),
  "punycode@2.3.1": Object.freeze({
    file: "punycode-2.3.1-LICENSE-MIT.txt",
    sha256: "483acb265f182907d1caf6cff9c16c96f31325ed23792832cc5d8b12d5f88c8a",
  }),
  "tr46@5.1.1": Object.freeze({
    file: "tr46-5.1.1-LICENSE.md",
    sha256: "499d6d466d064e0460427967a344e2a32fcb86ea8c6cd1a285ec4f1fa03fba67",
  }),
  "webidl-conversions@7.0.0": Object.freeze({
    file: "webidl-conversions-7.0.0-LICENSE.md",
    sha256: "a889cc4dbee2ae172c179856b25d75b0b7a5a136e1b97109b9b590b2ff1a879c",
  }),
  "whatwg-url@14.2.0": Object.freeze({
    file: "whatwg-url-14.2.0-LICENSE.txt",
    sha256: "db480f236292a093e77a83c35431a8496624e1e664a3547768a9ce2bdde39877",
  }),
});
const materialIdentities = Object.freeze({});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

if (sha256(browserBundle) !== BROWSER_BUNDLE_SHA256) {
  throw new Error("Pinned Convex Wasm runtime-support browser bundle identity is stale.");
}
for (const [packageName, license] of Object.entries(licenseIdentities)) {
  const source = readFileSync(
    new URL(`../vendor/convex-wasm-runtime-support/${license.file}`, import.meta.url)
  );
  if (sha256(source) !== license.sha256) {
    throw new Error(`Pinned ${packageName} license identity is stale.`);
  }
}
for (const [name, material] of Object.entries(materialIdentities)) {
  const bytes = readFileSync(
    new URL(`../vendor/convex-wasm-runtime-support/${material.file}`, import.meta.url)
  );
  if (bytes.length !== material.size || sha256(bytes) !== material.sha256) {
    throw new Error(`Pinned Convex Wasm runtime-support material ${name} is stale.`);
  }
  if (material.sourceFile !== undefined) {
    const source = readFileSync(
      new URL(`../vendor/convex-wasm-runtime-support/${material.sourceFile}`, import.meta.url)
    );
    if (source.length !== material.sourceSize || sha256(source) !== material.sourceSha256) {
      throw new Error(`Pinned Convex Wasm runtime-support source material ${name} is stale.`);
    }
  }
}

export const convexWasmRuntimeSupportIdentity = Object.freeze({
  browserBundleSha256: BROWSER_BUNDLE_SHA256,
  bundler: Object.freeze({ package: "esbuild@0.27.0", target: "es2020" }),
  globals: Object.freeze(["DOMException", "URL", "URLSearchParams"]),
  kind: "convex-wasm-shared-untyped-runtime-support-v4",
  nativeUrl: convexWasmNativeUrlSupportIdentity,
  licenses: licenseIdentities,
  materials: materialIdentities,
  packages: Object.freeze({
    DOMException: Object.freeze({
      package: "domexception@4.0.0",
      packageIntegrity:
        "sha512-A2is4PLG+eeSfoTMA95/s4pvAoSo2mKtiM5jlHkAVewmiO8ISFTFKZjH7UAM1Atli/OT/7JHOrJRJiMKUZKYBw==",
    }),
    URL: Object.freeze({
      package: "whatwg-url@14.2.0",
      packageIntegrity:
        "sha512-De72GdQZzNTUBBChsXueQUnPKDkg/5A5zp7pFDuQAj5UFoENpiACU0wlCvzpAGnTkj++ihpKwKyYewn/XNUbKw==",
    }),
    URLSearchParams: Object.freeze({
      package: "whatwg-url@14.2.0",
      packageIntegrity:
        "sha512-De72GdQZzNTUBBChsXueQUnPKDkg/5A5zp7pFDuQAj5UFoENpiACU0wlCvzpAGnTkj++ihpKwKyYewn/XNUbKw==",
    }),
    dependencies: Object.freeze({
      "punycode@2.3.1":
        "sha512-vYt7UD1U9Wg6138shLtLOvdAu+8DsC/ilFtEVHcH+wydcSpNE20AfSOduf6MkRFahL5FY7X1oU7nKVZFtfq8Fg==",
      "tr46@5.1.1":
        "sha512-hdF5ZgjTqgAntKkklYw0R03MG2x/bSzTtkxmIRw/sTNV8YXsCJ1tfLAX23lhxhHJlEf3CRCOCGGWw3vI3GaSPw==",
      "webidl-conversions@7.0.0":
        "sha512-VwddBukDzu71offAQR975unBIGqfKZpM+8ZX6ySk8nYhVoo5CYaZyzt3YBvYtRtO+aoGlqxPg/B87NGVZ/fu6g==",
    }),
  }),
});

export const convexWasmRuntimeSupportIdentitySha256 = sha256(
  JSON.stringify(convexWasmRuntimeSupportIdentity)
);

export function renderConvexWasmRuntimeSupportUnit() {
  return browserBundle;
}
