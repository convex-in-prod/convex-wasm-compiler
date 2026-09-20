import { getIndexFields } from "convex-helpers/server/stream";

declare const target: { helper?: unknown };

for (target.helper of [getIndexFields]) {
}
