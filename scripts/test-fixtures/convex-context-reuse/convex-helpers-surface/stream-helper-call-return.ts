import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

function reviewedHelper(value: unknown) {
  return value;
}

export const unreviewedCallReturn = unknownConsumer(reviewedHelper.call(undefined, getIndexFields));
