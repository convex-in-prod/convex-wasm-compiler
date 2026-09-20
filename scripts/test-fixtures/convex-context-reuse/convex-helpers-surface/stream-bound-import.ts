import { getIndexFields } from "convex-helpers/server/stream";

const boundIndexFields = getIndexFields.bind(undefined);

export const escapedBoundImportResult = boundIndexFields("table", "by_field", {});
