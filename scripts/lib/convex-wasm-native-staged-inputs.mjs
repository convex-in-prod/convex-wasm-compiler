import { promises as fs } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";

import {
  assertPlainObject,
  compareStrings,
  fail,
  requirePositiveInteger,
  requireSha256,
  requireString,
} from "./convex-wasm-artifact-contract.mjs";
import { hashPrivateRegularFile, mapBounded } from "./convex-wasm-artifact-material.mjs";

const STAGED_INPUT_COMPONENT = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;

export function normalizeNativeStagedInputs(inputs, description) {
  if (!Array.isArray(inputs) || inputs.length === 0) {
    fail(`${description} requires staged input files`);
  }
  const normalized = inputs.map((input) => {
    assertPlainObject(input, `${description} staged input`);
    const name = requireString(input.name, `${description} staged input name`);
    if (name.split("/").some((component) => !STAGED_INPUT_COMPONENT.test(component))) {
      fail(`${description} staged input name must stay inside the work directory`);
    }
    const path = requireString(input.path, `${description} staged input ${name} path`);
    if (!isAbsolute(path) || resolve(path) !== path) {
      fail(`${description} staged input ${name} path must be normalized and absolute`);
    }
    return {
      name,
      path,
      sha256: requireSha256(input.sha256, `${description} staged input ${name} SHA-256`),
      size: requirePositiveInteger(input.size, `${description} staged input ${name} byte size`),
    };
  }).sort((left, right) => compareStrings(left.name, right.name));
  const names = new Set(normalized.map(({ name }) => name));
  if (names.size !== normalized.length) {
    fail(`${description} staged input names must be unique`);
  }
  for (const { name } of normalized) {
    const components = name.split("/");
    for (let count = 1; count < components.length; count += 1) {
      if (names.has(components.slice(0, count).join("/"))) {
        fail(`${description} staged input names must not overlap as a file and directory`);
      }
    }
  }
  return normalized;
}

export async function authenticateNativeStagedInputs(inputs, description) {
  await mapBounded(inputs, 4, async (input) => {
    const digest = await hashPrivateRegularFile(
      input.path,
      input.size,
      `${description} source input ${input.name}`
    );
    if (digest.size !== input.size || digest.sha256 !== input.sha256) {
      fail(`${description} source input ${input.name} does not match its identity`);
    }
  });
}

export async function copyNativeStagedInputs(inputs, description, workPath) {
  await mapBounded(inputs, 4, async (input) => {
    const destination = join(workPath, input.name);
    await fs.mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await fs.copyFile(input.path, destination);
    await fs.chmod(destination, 0o600);
    const digest = await hashPrivateRegularFile(
      destination,
      input.size,
      `${description} staged input ${input.name}`
    );
    if (digest.size !== input.size || digest.sha256 !== input.sha256) {
      fail(`${description} staged input ${input.name} does not match its identity`);
    }
  });
}
