import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

function reviewedHelper(value: unknown) {
  return value;
}

export const unreviewedApplyReturn = unknownConsumer(
  reviewedHelper.apply(undefined, [getIndexFields])
);
