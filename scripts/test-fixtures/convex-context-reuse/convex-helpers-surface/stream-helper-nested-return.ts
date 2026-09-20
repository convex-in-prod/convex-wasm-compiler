import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

function innerReviewedHelper(value: unknown) {
  return value;
}

function outerReviewedHelper(value: unknown) {
  return innerReviewedHelper(value);
}

export const unreviewedNestedHelperReturn = unknownConsumer(outerReviewedHelper(getIndexFields));
