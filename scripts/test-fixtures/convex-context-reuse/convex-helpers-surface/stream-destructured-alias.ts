import { getIndexFields } from "convex-helpers/server/stream";

const { helper: indexFields } = { helper: getIndexFields };

export const reviewedDestructuredStreamResult = indexFields("table", "by_field", {});
