import { createHash } from "node:crypto";

import { canonicalJson } from "./convex-wasm-artifact-contract.mjs";

function identity(bytes) {
  if (bytes.length === 0) throw new Error("Runtime-content conformance material must be nonempty");
  return { sha256: createHash("sha256").update(bytes).digest("hex"), size: bytes.length };
}

// Both maintained producers use their existing private-file admission boundary here. Drain all
// reads before propagating failure, so candidate cleanup cannot race unfinished conformance work.
export async function certifyRuntimeContentProducer(
  {
    authorityPath,
    cacheRoot,
    conformanceAuthorityPath,
    conformanceSourcePackagePath,
    helper,
    producerIdentity,
    report,
    sourceEnvelope,
    sourceEnvelopeBytes,
    sourcePackagePath,
    startPushBytes,
    startPushPath,
  },
  { assertHelperCurrent, createPreactivationAuthority, publishCertificate, readMaterial }
) {
  const external = report.externalDepsPackage ?? null;
  const provisionalProducerCertificate = {
    externalDepsPackage:
      external === null
        ? null
        : {
            sha256: external.sha256,
            size: external.size,
            storageKey: external.storageKey,
          },
    identity: producerIdentity,
  };
  await assertHelperCurrent();
  const conformance = await createPreactivationAuthority({
    authorityOutputPath: conformanceAuthorityPath,
    externalDepsPackagePath: external?.path,
    helper,
    producerCertificate: provisionalProducerCertificate,
    sourceEnvelope,
    sourceEnvelopeBytes,
    sourcePackageOutputPath: conformanceSourcePackagePath,
    startPushBytes,
    startPushPath,
  });
  await assertHelperCurrent();
  const reads = await Promise.allSettled([
    readMaterial(authorityPath, 64 * 1024 * 1024, "backend-certified deployed-runtime authority"),
    readMaterial(
      conformanceAuthorityPath,
      64 * 1024 * 1024,
      "helper-derived deployed-runtime authority"
    ),
    readMaterial(
      sourcePackagePath,
      Number.MAX_SAFE_INTEGER,
      "backend-certified source package"
    ).then(identity),
    readMaterial(
      conformanceSourcePackagePath,
      Number.MAX_SAFE_INTEGER,
      "helper-derived source package"
    ).then(identity),
  ]);
  const failures = reads.filter((result) => result.status === "rejected");
  if (failures.length !== 0) {
    throw new AggregateError(
      failures.map((result) => result.reason),
      "runtime-authority producer conformance authentication failed"
    );
  }
  const [
    backendAuthorityBytes,
    conformanceAuthorityBytes,
    backendSourcePackage,
    conformanceSourcePackage,
  ] = reads.map((result) => result.value);
  if (
    !backendAuthorityBytes.equals(conformanceAuthorityBytes) ||
    canonicalJson(backendSourcePackage) !== canonicalJson(conformanceSourcePackage) ||
    // Matching local outputs alone cannot certify a different package named by the backend report.
    backendSourcePackage.sha256 !== report.sourcePackage?.sha256 ||
    backendSourcePackage.size !== report.sourcePackage?.size ||
    conformance.authoritySha256 !== report.authoritySha256 ||
    conformance.sourcePackageRuntimeContentSha256 !== report.sourcePackageRuntimeContentSha256
  ) {
    throw new Error(
      "canonical preactivation helper does not conform to the disposable backend producer"
    );
  }
  return publishCertificate({
    backendAuthoritySha256: report.authoritySha256,
    cacheRoot,
    expectedIdentity: producerIdentity,
    externalDepsPackagePath: external?.path,
    externalDepsStorageKey: external?.storageKey,
    request: identity(startPushBytes),
    runtimeContentSha256: report.sourcePackageRuntimeContentSha256,
    sourcePackage: backendSourcePackage,
  });
}
