import { getIndexFields } from "convex-helpers/server/stream";

function hasReviewedHelper(value: unknown) {
  return value !== undefined;
}

export const unreviewedHelperParameter = hasReviewedHelper(getIndexFields);
