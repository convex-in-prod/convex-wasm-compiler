import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { certifyRuntimeContentProducer } from "./source-producer-conformance.mjs";

for (const mismatch of [
  "none",
  "authority bytes",
  "package bytes",
  "report digest",
  "report size",
  "missing report package",
  "authority digest",
  "runtime digest",
]) {
  test(`producer conformance checks every backend output: ${mismatch}`, async () => {
    const packageBytes = Buffer.from("source package");
    const sourcePackage = {
      sha256: createHash("sha256").update(packageBytes).digest("hex"),
      size: packageBytes.length,
    };
    const report = {
      authoritySha256: "a".repeat(64),
      sourcePackage,
      sourcePackageRuntimeContentSha256: "b".repeat(64),
    };
    if (mismatch === "report digest")
      report.sourcePackage = { ...sourcePackage, sha256: "c".repeat(64) };
    if (mismatch === "report size")
      report.sourcePackage = { ...sourcePackage, size: sourcePackage.size + 1 };
    if (mismatch === "missing report package") delete report.sourcePackage;
    let publication;
    const operation = certifyRuntimeContentProducer(
      {
        authorityPath: "backend-authority",
        cacheRoot: "cache",
        conformanceAuthorityPath: "helper-authority",
        conformanceSourcePackagePath: "helper-package",
        helper: {},
        producerIdentity: {},
        report,
        sourceEnvelope: {},
        sourceEnvelopeBytes: Buffer.from("envelope"),
        sourcePackagePath: "backend-package",
        startPushBytes: Buffer.from("request"),
        startPushPath: "request",
      },
      {
        assertHelperCurrent: async () => {},
        createPreactivationAuthority: async () => ({
          authoritySha256: (mismatch === "authority digest" ? "c" : "a").repeat(64),
          sourcePackageRuntimeContentSha256: (mismatch === "runtime digest" ? "c" : "b").repeat(64),
        }),
        async publishCertificate(value) {
          publication = value;
          return value;
        },
        async readMaterial(path) {
          if (path === "helper-authority" && mismatch === "authority bytes")
            return Buffer.from("wrong");
          if (path === "helper-package" && mismatch === "package bytes")
            return Buffer.from("wrong");
          return path.endsWith("package") ? packageBytes : Buffer.from("authority");
        },
      }
    );
    if (mismatch === "none") {
      await operation;
      assert.deepEqual(publication.sourcePackage, sourcePackage);
    } else {
      await assert.rejects(operation, /does not conform/u);
      assert.equal(publication, undefined);
    }
  });
}

test("conformance failure drains every material read before rejecting", async () => {
  let releasePackage;
  const packageRead = new Promise((resolve) => {
    releasePackage = resolve;
  });
  let signalReadStarted;
  const readStarted = new Promise((resolve) => {
    signalReadStarted = resolve;
  });
  let settled = false;
  const operation = certifyRuntimeContentProducer(
    {
      authorityPath: "backend-authority",
      cacheRoot: "cache",
      conformanceAuthorityPath: "helper-authority",
      conformanceSourcePackagePath: "helper-package",
      helper: {},
      producerIdentity: {},
      report: {},
      sourceEnvelope: {},
      sourceEnvelopeBytes: Buffer.from("envelope"),
      sourcePackagePath: "backend-package",
      startPushBytes: Buffer.from("request"),
      startPushPath: "request",
    },
    {
      assertHelperCurrent: async () => {},
      createPreactivationAuthority: async () => ({}),
      publishCertificate: () => assert.fail("failed conformance cannot publish"),
      async readMaterial(path) {
        if (path === "backend-authority") throw new Error("authority read failed");
        if (path === "helper-package") {
          signalReadStarted();
          return packageRead;
        }
        return Buffer.from("fixture");
      },
    }
  );
  const checked = assert.rejects(operation, (error) => {
    assert.ok(error instanceof AggregateError);
    assert.equal(error.errors[0].message, "authority read failed");
    settled = true;
    return true;
  });
  await readStarted;
  assert.equal(settled, false);
  releasePackage(Buffer.from("fixture"));
  await checked;
});
