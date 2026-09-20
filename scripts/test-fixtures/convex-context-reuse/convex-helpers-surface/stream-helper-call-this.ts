import { getIndexFields } from "convex-helpers/server/stream";

function reviewedHelper() {
  return true;
}

export const unreviewedHelperThis = reviewedHelper.call(getIndexFields);
