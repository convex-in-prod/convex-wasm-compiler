import { getIndexFields } from "convex-helpers/server/stream";

export function retainReviewedBinding(target: { helper?: unknown }) {
  target.helper = getIndexFields;
}
