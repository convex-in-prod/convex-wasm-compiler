import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import esbuild from "esbuild";

const write = process.argv.includes("--write");
const repositoryRoot = new URL("../", import.meta.url);
const repositoryRootPath = fileURLToPath(repositoryRoot);
const outputUrl = new URL(
  "./vendor/convex-wasm-runtime-support/browser-bundle.js.txt",
  import.meta.url
);
const objectInspectSourceUrl = new URL(
  "./vendor/object-inspect-1.13.4/index.js.txt",
  import.meta.url
);
const objectInspectSource = await readFile(objectInspectSourceUrl, "utf8");
const intlSource = await readFile(
  new URL("./vendor/convex-wasm-runtime-support/intl-subset.js.txt", import.meta.url),
  "utf8"
);
const intlTimeZoneData = await readFile(
  new URL("./vendor/convex-wasm-runtime-support/iana-tzdata-2026c.json", import.meta.url),
  "utf8"
);
const unsupportedAsyncIteratorPrototype =
  "const AsyncIteratorPrototype = Object.getPrototypeOf(Object.getPrototypeOf(async function* () {}).prototype);";

async function loadTargetWebIdlUtilities(path) {
  const source = await readFile(path, "utf8");
  const occurrences = source.split(unsupportedAsyncIteratorPrototype).length - 1;
  if (occurrences !== 1) {
    throw new Error(`Target Web IDL utilities changed their async-iterator fallback: ${path}`);
  }
  // URL and DOMException never consume this Web IDL registry slot. Keep it
  // absent because the target parser does not support async generators.
  return source.replace(
    unsupportedAsyncIteratorPrototype,
    "const AsyncIteratorPrototype = undefined;"
  );
}
const entrySource = String.raw`
import inspect from "convex-wasm-object-inspect";
import {createIntl} from "convex-wasm-intl-subset";
import timeZoneData from "convex-wasm-iana-time-zone-data";
import DOMException from "domexception";
import {URL, URLSearchParams} from "whatwg-url";

globalThis.__convexWasmApplicationInstallRuntimeSupport(Object.freeze({
  consoleFormatter: inspect,
  DOMException,
  Intl: createIntl(timeZoneData),
  URL,
  URLSearchParams,
}));
`;

const result = await esbuild.build({
  absWorkingDir: repositoryRootPath,
  bundle: true,
  format: "iife",
  legalComments: "none",
  minify: true,
  platform: "browser",
  plugins: [
    {
      name: "convex-wasm-object-inspect",
      setup(build) {
        build.onResolve({ filter: /^convex-wasm-intl-subset$/ }, () => ({
          namespace: "convex-wasm-intl-subset",
          path: "convex-wasm-intl-subset",
        }));
        build.onResolve({ filter: /^convex-wasm-iana-time-zone-data$/ }, () => ({
          namespace: "convex-wasm-iana-time-zone-data",
          path: "convex-wasm-iana-time-zone-data",
        }));
        build.onResolve({ filter: /^convex-wasm-object-inspect$/ }, () => ({
          namespace: "convex-wasm-object-inspect",
          path: "object-inspect@1.13.4",
        }));
        build.onResolve(
          { filter: /^\.\/util\.inspect$/, namespace: "convex-wasm-object-inspect" },
          () => ({
            namespace: "convex-wasm-object-inspect-util",
            path: "disabled-util-inspect",
          })
        );
        build.onLoad({ filter: /.*/, namespace: "convex-wasm-object-inspect" }, () => ({
          contents: objectInspectSource,
          loader: "js",
        }));
        build.onLoad({ filter: /.*/, namespace: "convex-wasm-object-inspect-util" }, () => ({
          contents: "module.exports = {};",
          loader: "js",
        }));
        build.onLoad({ filter: /.*/, namespace: "convex-wasm-intl-subset" }, () => ({
          contents: intlSource,
          loader: "js",
        }));
        build.onLoad({ filter: /.*/, namespace: "convex-wasm-iana-time-zone-data" }, () => ({
          contents: `export default ${intlTimeZoneData}`,
          loader: "js",
        }));
        build.onLoad(
          { filter: /node_modules\/(?:domexception|whatwg-url)\/lib\/utils\.js$/ },
          async ({ path }) => ({ contents: await loadTargetWebIdlUtilities(path), loader: "js" })
        );
      },
    },
  ],
  stdin: {
    contents: entrySource,
    resolveDir: repositoryRootPath,
    sourcefile: "convex-wasm-runtime-support-entry.js",
  },
  target: "es2020",
  write: false,
});

if (result.outputFiles.length !== 1) {
  throw new Error("Convex Wasm runtime support must produce exactly one browser bundle.");
}
const generated = result.outputFiles[0].text;
if (write) {
  await writeFile(outputUrl, generated);
} else {
  const existing = await readFile(outputUrl, "utf8");
  if (existing !== generated) {
    throw new Error("Convex Wasm runtime-support browser bundle is stale; rerun with --write.");
  }
}
