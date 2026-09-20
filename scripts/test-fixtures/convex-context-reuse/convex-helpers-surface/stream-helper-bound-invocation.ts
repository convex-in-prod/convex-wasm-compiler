import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

function reviewedHelper(value: unknown) {
  return value;
}

export const unreviewedBoundInvocation = unknownConsumer(
  reviewedHelper.bind(undefined, getIndexFields)()
);
