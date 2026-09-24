const projectedNativeApplicationDescriptors = new WeakSet();
const localProfileSummariesByNativeApplicationDescriptor = new WeakMap();
const javascriptLoadersByProjectedPhysicalUnit = new WeakMap();

// Only the official-output chunk validator calls this after constructing a detached immutable
// projection from its privately branded application unit. Consumers get only an exact-object
// membership check, so clones, accessor objects, and independently frozen values stay untrusted.
export function retainProjectedConvexWasmOfficialOutputChunkNativeApplicationDescriptor(value) {
  projectedNativeApplicationDescriptors.add(value);
  return value;
}

export function isProjectedConvexWasmOfficialOutputChunkNativeApplicationDescriptor(value) {
  return projectedNativeApplicationDescriptors.has(value);
}

export function retainProjectedConvexWasmOfficialOutputChunkJavascriptLoader(
  descriptor,
  physicalUnit,
  load
) {
  if (
    !projectedNativeApplicationDescriptors.has(descriptor) ||
    !descriptor.units.includes(physicalUnit) ||
    typeof load !== "function" ||
    javascriptLoadersByProjectedPhysicalUnit.has(physicalUnit)
  ) {
    throw new Error("official-output chunk JavaScript loader lacks projection provenance");
  }
  javascriptLoadersByProjectedPhysicalUnit.set(physicalUnit, { descriptor, load });
}

export async function loadProjectedConvexWasmOfficialOutputChunkJavascript(
  descriptor,
  physicalUnit
) {
  const retained = javascriptLoadersByProjectedPhysicalUnit.get(physicalUnit);
  if (
    !projectedNativeApplicationDescriptors.has(descriptor) ||
    retained?.descriptor !== descriptor ||
    !descriptor.units.includes(physicalUnit)
  ) {
    throw new Error("official-output chunk JavaScript lacks projection provenance");
  }
  const javascript = await retained.load();
  if (typeof javascript !== "string" || javascript.length === 0 || javascript.includes("\0")) {
    throw new Error("official-output chunk JavaScript loader returned invalid source");
  }
  return javascript;
}

export function retainProjectedConvexWasmOfficialOutputChunkLocalProfileSummaries(
  descriptor,
  localProfiles
) {
  if (
    !projectedNativeApplicationDescriptors.has(descriptor) ||
    !Array.isArray(localProfiles) ||
    localProfiles.length !== descriptor.entries.length
  ) {
    throw new Error(
      "official-output chunk local profiles lack authenticated projection provenance"
    );
  }
  const summaries = new Map(
    localProfiles.map((localProfile, index) => {
      const entry = descriptor.entries[index];
      if (
        localProfile.identity.applicationUnit !== descriptor.applicationIdentity ||
        localProfile.identity.selectedEntry.entryPath !== entry.entryPath ||
        localProfile.identity.selectedEntry.modulePath !== entry.modulePath
      ) {
        throw new Error("official-output chunk local profile changed before provenance retention");
      }
      return [
        entry.entryPath,
        Object.freeze({
          dependencyGraphSha256: localProfile.identity.dependencyGraphSha256,
          javascript: localProfile.identity.output.javascript,
          metafileSha256: localProfile.identity.metafileSha256,
          sha256: localProfile.sha256,
          sourceMap: localProfile.identity.output.sourceMap,
        }),
      ];
    })
  );
  localProfileSummariesByNativeApplicationDescriptor.set(descriptor, summaries);
}

export function projectedConvexWasmOfficialOutputChunkLocalProfileSummary(descriptor, entryPath) {
  return localProfileSummariesByNativeApplicationDescriptor.get(descriptor)?.get(entryPath);
}
