import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

function reviewedHelper(value: unknown) {
  return unknownConsumer(value);
}

export const unreviewedUnknownHelperParameter = reviewedHelper(getIndexFields);
