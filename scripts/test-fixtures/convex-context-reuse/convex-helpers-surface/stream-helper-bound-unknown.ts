import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

function reviewedHelper(value: unknown) {
  return value;
}

const boundReviewedHelper = reviewedHelper.bind(undefined, getIndexFields);

export const unreviewedBoundHelper = unknownConsumer(boundReviewedHelper);
