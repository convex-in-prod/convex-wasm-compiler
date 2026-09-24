import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { canonicalJson, fingerprintJson } from "./convex-wasm-artifact-contract.mjs";
import { convexWasmOfficialOutputSourceMembershipIdentitySha256 } from "./convex-wasm-native-symbol-identity.mjs";
import {
  authenticateDeploymentOutputClosureProjectionGraphSession,
  buildConvexWasmDeploymentOutputClosures,
  canDeferConvexWasmDeploymentOutputClosureAuthentication,
  createConvexWasmDeploymentOutputClosureAuthentication,
  projectConvexWasmDeploymentOutputChunkGraph,
  selectConvexWasmDeploymentOutputClosure,
} from "./convex-wasm-output-closure.mjs";

const digest = (character) => character.repeat(64);

function closureGraphSession(graph) {
  return { ...graph, graphTemplate: { metafile: graph.metafile, repoRoot: "/fixture" } };
}

function fixtureDeploymentOutputModule(path, { sourceMap = undefined } = {}) {
  const source = `// exact deployment output module ${path}\nexport const fixture = ${JSON.stringify(
    path
  )};\n`;
  const exactModule = {
    path,
    source,
    ...(sourceMap === undefined ? {} : { sourceMap }),
  };
  const parsedSourceMap = sourceMap === undefined ? undefined : JSON.parse(sourceMap);
  const identity = {
    environment: "isolate",
    moduleSha256: createHash("sha256")
      .update(source)
      .update(sourceMap ?? "")
      .digest("hex"),
    path,
    sourceMap:
      sourceMap === undefined
        ? null
        : {
            sha256: createHash("sha256").update(sourceMap).digest("hex"),
            size: Buffer.byteLength(sourceMap),
            sourcesContentCount: Array.isArray(parsedSourceMap.sourcesContent)
              ? parsedSourceMap.sourcesContent.filter((value) => value !== null).length
              : 0,
            sourcesCount: Array.isArray(parsedSourceMap.sources)
              ? parsedSourceMap.sources.length
              : 0,
          },
    sourceMembershipSha256:
      parsedSourceMap === undefined
        ? null
        : convexWasmOfficialOutputSourceMembershipIdentitySha256({
            sourceRoot: parsedSourceMap.sourceRoot,
            sources: parsedSourceMap.sources,
          }),
    sourceSha256: createHash("sha256").update(source).digest("hex"),
    sourceSize: Buffer.byteLength(source),
  };
  return { exactModule, identity };
}

function fixtureDeploymentOutputModuleMaps(paths) {
  const bundleModulesByPath = new Map();
  const deploymentOutputModulesByPath = new Map();
  for (const path of paths) {
    const sourceMap = `${JSON.stringify({
      mappings: "",
      names: [],
      sources: [`convex/${path.replace(/\.js$/u, ".ts")}`],
      sourcesContent: [],
      version: 3,
    })}\n`;
    const module = fixtureDeploymentOutputModule(path, { sourceMap });
    bundleModulesByPath.set(path, module.identity);
    deploymentOutputModulesByPath.set(path, module.exactModule);
  }
  return { bundleModulesByPath, deploymentOutputModulesByPath };
}

function fixtureDeploymentOutputGraph({ entries, importsByModulePath = new Map(), inputs }) {
  const entryModulePaths = entries.map(({ modulePath }) => modulePath);
  const modulePaths = [
    ...new Set([
      ...entryModulePaths,
      ...importsByModulePath.keys(),
      ...[...importsByModulePath.values()].flatMap((imports) =>
        imports.filter(({ external = false }) => !external).map(({ path }) => path)
      ),
    ]),
  ].sort();
  const moduleMaterial = fixtureDeploymentOutputModuleMaps(modulePaths);
  const entryByModulePath = new Map(entries.map((entry) => [entry.modulePath, entry]));
  const metafile = {
    inputs,
    outputs: Object.fromEntries(
      modulePaths.map((modulePath) => {
        const entry = entryByModulePath.get(modulePath);
        return [
          `out/${modulePath}`,
          {
            ...(entry === undefined ? {} : { entryPoint: entry.entryPath }),
            imports: (importsByModulePath.get(modulePath) ?? []).map(
              ({ external = false, kind = "import-statement", path }) => ({
                external,
                kind,
                path: external ? path : `out/${path}`,
              })
            ),
          },
        ];
      })
    ),
  };
  const runtimeModulePathByEntry = new Map(
    entries.map(({ entryPath, modulePath }) => [entryPath, modulePath])
  );
  const deploymentOutput = buildConvexWasmDeploymentOutputClosures({
    bundleModulesByPath: moduleMaterial.bundleModulesByPath,
    entryPaths: entries.map(({ entryPath }) => entryPath),
    metafile,
    repoRoot: "/fixture",
    runtimeModulePathByEntry,
  });
  return {
    ...moduleMaterial,
    metafile,
    deploymentOutputClosureByEntry: deploymentOutput.closures,
    deploymentOutputMetafileSha256: deploymentOutput.metafileSha256,
    runtimeModulePathByEntry,
  };
}

test("deployment output imports resolve direct, relative, and absolute paths identically", () => {
  const repoRoot = "/fixture";
  const { bundleModulesByPath } = fixtureDeploymentOutputModuleMaps(["entry.js", "shared.js"]);
  const runtimeModulePathByEntry = new Map([["convex/entry.ts", "entry.js"]]);
  let expectedClosureContents;

  for (const importedPath of ["out/shared.js", "./shared.js", "/fixture/out/shared.js"]) {
    const metafile = {
      inputs: {},
      outputs: {
        "out/entry.js": {
          entryPoint: "convex/entry.ts",
          imports: [{ external: false, kind: "import-statement", path: importedPath }],
        },
        "out/shared.js": { imports: [] },
      },
    };
    const { closures, metafileSha256 } = buildConvexWasmDeploymentOutputClosures({
      bundleModulesByPath,
      entryPaths: ["convex/entry.ts"],
      metafile,
      repoRoot,
      runtimeModulePathByEntry,
    });
    const closure = closures.get("convex/entry.ts");
    const { metafileSha256: closureMetafileSha256, sha256, ...closureContents } = closure;

    assert.equal(metafileSha256, fingerprintJson(metafile));
    assert.equal(closureMetafileSha256, metafileSha256);
    assert.equal(sha256, fingerprintJson({ ...closureContents, metafileSha256 }));
    assert.deepEqual(
      closureContents,
      expectedClosureContents ?? {
        entryModulePath: "entry.js",
        imports: [
          {
            external: false,
            importerPath: "entry.js",
            kind: "import-statement",
            path: "shared.js",
          },
        ],
        kind: "convex-wasm-deployment-output-closure-v1",
        modules: [bundleModulesByPath.get("entry.js"), bundleModulesByPath.get("shared.js")],
      }
    );
    expectedClosureContents = closureContents;
  }
});

test("deployment output closures share detached admitted records with unchanged canonical digests", () => {
  const graph = fixtureDeploymentOutputGraph({
    entries: [
      { entryPath: "convex/first.ts", modulePath: "first.js" },
      { entryPath: "convex/second.ts", modulePath: "second.js" },
    ],
    importsByModulePath: new Map([
      ["first.js", [{ path: "shared.js" }]],
      ["second.js", [{ path: "shared.js" }]],
      ["shared.js", [{ external: true, path: 'external/雪"\\module' }]],
    ]),
    inputs: {},
  });
  const first = graph.deploymentOutputClosureByEntry.get("convex/first.ts");
  const second = graph.deploymentOutputClosureByEntry.get("convex/second.ts");
  assert.strictEqual(first.modules[1], second.modules[1]);
  assert.strictEqual(first.imports[1], second.imports[1]);
  assert.notStrictEqual(first.modules[1], graph.bundleModulesByPath.get("shared.js"));
  assert.equal(Object.isFrozen(first.modules[1].sourceMap), true);
  assert.equal(Object.isFrozen(first.imports[1]), true);
  const original = structuredClone(first);
  graph.bundleModulesByPath.get("shared.js").sourceMap.sha256 = digest("9");
  graph.bundleModulesByPath.get("shared.js").sourceSha256 = digest("8");
  assert.deepEqual(first, original);
  for (const closure of [first, second]) {
    const { sha256, ...identity } = closure;
    assert.equal(sha256, fingerprintJson(identity));
    assert.equal(Object.isFrozen(closure), true);
    assert.equal(Object.isFrozen(closure.modules), true);
    assert.equal(Object.isFrozen(closure.imports), true);
  }
});

test("deployment output closure canonical bytes preserve sorted imports and cyclic traversal", () => {
  const entryModulePath = 'entry雪"\n.js';
  const entryPath = 'convex/entry雪"\n.ts';
  const graph = fixtureDeploymentOutputGraph({
    entries: [{ entryPath, modulePath: entryModulePath }],
    importsByModulePath: new Map([
      [
        entryModulePath,
        [
          { external: true, kind: "z", path: "shared.js" },
          { external: true, kind: "a", path: "shared.js" },
          { kind: "a", path: "shared.js" },
          { path: "a.js" },
        ],
      ],
      ["a.js", [{ path: "shared.js" }]],
      ["shared.js", [{ path: entryModulePath }]],
    ]),
    inputs: {},
  });
  const { sha256, ...identity } = graph.deploymentOutputClosureByEntry.get(entryPath);
  assert.deepEqual(
    identity.modules.map(({ path }) => path),
    [entryModulePath, "a.js", "shared.js"]
  );
  assert.deepEqual(identity.imports.slice(0, 4), [
    { external: false, importerPath: entryModulePath, kind: "import-statement", path: "a.js" },
    { external: false, importerPath: entryModulePath, kind: "a", path: "shared.js" },
    { external: true, importerPath: entryModulePath, kind: "a", path: "shared.js" },
    { external: true, importerPath: entryModulePath, kind: "z", path: "shared.js" },
  ]);
  assert.equal(sha256, createHash("sha256").update(canonicalJson(identity)).digest("hex"));
});

test("deployment output import resolution preserves direct output key priority", () => {
  const { bundleModulesByPath } = fixtureDeploymentOutputModuleMaps([
    "entry.js",
    "../shared.js",
    "shared.js",
  ]);
  const { closures } = buildConvexWasmDeploymentOutputClosures({
    bundleModulesByPath,
    entryPaths: ["convex/entry.ts"],
    metafile: {
      inputs: {},
      outputs: {
        "out/entry.js": {
          entryPoint: "convex/entry.ts",
          imports: [{ external: false, kind: "import-statement", path: "shared.js" }],
        },
        "shared.js": { imports: [] },
        "/fixture/out/shared.js": { imports: [] },
      },
    },
    repoRoot: "/fixture",
    runtimeModulePathByEntry: new Map([["convex/entry.ts", "entry.js"]]),
  });

  assert.deepEqual(
    closures.get("convex/entry.ts").modules.map(({ path }) => path),
    ["entry.js", "../shared.js"]
  );
});

test("deployment output closures bind module identity paths to their map keys", () => {
  const { bundleModulesByPath } = fixtureDeploymentOutputModuleMaps(["entry.js"]);
  bundleModulesByPath.set("entry.js", {
    ...bundleModulesByPath.get("entry.js"),
    path: "other.js",
  });

  assert.throws(
    () =>
      buildConvexWasmDeploymentOutputClosures({
        bundleModulesByPath,
        entryPaths: ["convex/entry.ts"],
        metafile: {
          inputs: {},
          outputs: {
            "out/entry.js": { entryPoint: "convex/entry.ts", imports: [] },
          },
        },
        repoRoot: "/fixture",
        runtimeModulePathByEntry: new Map([["convex/entry.ts", "entry.js"]]),
      }),
    /deployment output module identity path disagrees with map key entry\.js/u
  );
});

test("deployment output import resolution rejects ambiguous normalized paths", () => {
  const { bundleModulesByPath } = fixtureDeploymentOutputModuleMaps(["entry.js"]);
  const ambiguousOutputPaths = [
    ["out/shared.js", "/fixture/out/shared.js"],
    ["/fixture/shared.js", "/fixture/out/shared.js"],
  ];

  for (const outputPaths of ambiguousOutputPaths) {
    const outputs = {
      "out/entry.js": {
        entryPoint: "convex/entry.ts",
        imports: [{ external: false, kind: "import-statement", path: "./shared.js" }],
      },
    };
    for (const outputPath of outputPaths) {
      outputs[outputPath] = { imports: [] };
    }

    assert.throws(
      () =>
        buildConvexWasmDeploymentOutputClosures({
          bundleModulesByPath,
          entryPaths: ["convex/entry.ts"],
          metafile: { inputs: {}, outputs },
          repoRoot: "/fixture",
          runtimeModulePathByEntry: new Map([["convex/entry.ts", "entry.js"]]),
        }),
      /esbuild output import \.\/shared\.js from out\/entry\.js matches multiple outputs/u
    );
  }
});

test("selects and authenticates an exact output closure from a separate graph session", () => {
  const graphSession = closureGraphSession(
    fixtureDeploymentOutputGraph({
      entries: [{ entryPath: "convex/entry.ts", modulePath: "entry.js" }],
      importsByModulePath: new Map([["entry.js", [{ path: "shared.js" }]]]),
      inputs: {},
    })
  );
  const authentication = createConvexWasmDeploymentOutputClosureAuthentication(graphSession);
  const selected = selectConvexWasmDeploymentOutputClosure({
    authentication,
    entryPath: "convex/entry.ts",
    graphSession,
  });
  assert.deepEqual(selected.modules.map(({ identity }) => identity.path), ["entry.js", "shared.js"]);
  assert.equal(selected.identity.sha256, fingerprintJson({
    entryModulePath: selected.identity.entryModulePath,
    imports: selected.identity.imports,
    kind: selected.identity.kind,
    metafileSha256: selected.identity.metafileSha256,
    modules: selected.identity.modules,
  }));
  assert.strictEqual(
    selectConvexWasmDeploymentOutputClosure({
      authentication,
      entryPath: "convex/entry.ts",
      graphSession,
    }),
    selected
  );
});

test("rejects output bytes changed after the closure identity was built", () => {
  const graphSession = closureGraphSession(
    fixtureDeploymentOutputGraph({
      entries: [{ entryPath: "convex/entry.ts", modulePath: "entry.js" }],
      inputs: {},
    })
  );
  graphSession.deploymentOutputModulesByPath.get("entry.js").source = "changed source";
  assert.throws(
    () => selectConvexWasmDeploymentOutputClosure({ entryPath: "convex/entry.ts", graphSession }),
    /bytes disagree with its authenticated identity/u
  );
});

test("exact producer graph authority is revoked when an output map changes", () => {
  const graphSession = closureGraphSession(
    fixtureDeploymentOutputGraph({
      entries: [{ entryPath: "convex/entry.ts", modulePath: "entry.js" }],
      inputs: {},
    })
  );
  for (const identity of graphSession.bundleModulesByPath.values()) {
    Object.freeze(identity.sourceMap);
    Object.freeze(identity);
  }
  for (const module of graphSession.deploymentOutputModulesByPath.values()) Object.freeze(module);
  authenticateDeploymentOutputClosureProjectionGraphSession(graphSession);
  const authentication = createConvexWasmDeploymentOutputClosureAuthentication(graphSession);
  assert.equal(
    canDeferConvexWasmDeploymentOutputClosureAuthentication({ authentication, graphSession }),
    true
  );
  const chunkGraph = projectConvexWasmDeploymentOutputChunkGraph({ authentication, graphSession });
  assert.deepEqual(chunkGraph.entries, [
    { entryPath: "convex/entry.ts", entryModulePath: "entry.js" },
  ]);
  graphSession.bundleModulesByPath.set("entry.js", {
    ...graphSession.bundleModulesByPath.get("entry.js"),
  });
  assert.equal(
    canDeferConvexWasmDeploymentOutputClosureAuthentication({ authentication, graphSession }),
    false
  );
});
