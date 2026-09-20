import { getIndexFields } from "convex-helpers/server/stream";

function reviewedHelper() {
  return getIndexFields;
}

export const unreviewedHelperReturn = reviewedHelper();
