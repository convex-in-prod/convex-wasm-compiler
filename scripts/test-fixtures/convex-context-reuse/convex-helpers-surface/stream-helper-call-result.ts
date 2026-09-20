import { getIndexFields } from "convex-helpers/server/stream";

function reviewedCallResult() {
  return getIndexFields("table", "by_field", {});
}

export const reviewedHelperCallResult = reviewedCallResult();
