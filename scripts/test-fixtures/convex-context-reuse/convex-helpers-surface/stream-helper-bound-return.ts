import { getIndexFields } from "convex-helpers/server/stream";

function reviewedHelper() {
  return getIndexFields.bind(undefined);
}

export const unreviewedBoundHelperReturn = reviewedHelper();
