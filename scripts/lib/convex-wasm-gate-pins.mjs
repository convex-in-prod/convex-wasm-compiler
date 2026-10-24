export const gateRevisions = Object.freeze({
  emsdk: "dfb9d1a46c3bb8f52e1e6324be23123b9d73c190",
  // Historical provenance of the checked-in global probe, not a checkout pin.
  hermes: "40441111c9e369d1b87c0b0d1fa009b72539d70a",
  wasmtime: "ba13bdffaa34c4cfa6af8ceb58275e761593a885",
});

// The development branch is a rewritten patch train. Its append-only history
// retains the recipe; the resulting tree identifies source independently of
// commit ordering and committer timestamps.
export const hermesSource = Object.freeze({
  repository: "https://github.com/convex-in-prod/hermes.git",
  historyRevision: "87c007fa2777f46084ea246ea8e7aada6b284450",
  upstreamRevision: "e760a68ab717963f82757983c75ec7fd63910d77",
  tree: "573bb6c7243475f8d4a1fdad16386efc167ee4af",
});

export const wasmtimeRepository = "https://github.com/convex-in-prod/wasmtime";

export const emscriptenVersion = "6.0.5";
