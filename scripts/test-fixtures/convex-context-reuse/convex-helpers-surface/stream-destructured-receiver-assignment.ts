import { getIndexFields } from "convex-helpers/server/stream";

declare const target: { helper?: unknown };

({ helper: target.helper } = { helper: getIndexFields });
