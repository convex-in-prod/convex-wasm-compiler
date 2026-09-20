import { getIndexFields } from "convex-helpers/server/stream";

const escaped: { helper?: typeof getIndexFields } = {};
const helperMember = "prototype";

for (escaped.helper of [getIndexFields]) {
  (escaped.helper as unknown as Record<string, unknown>)[helperMember];
}
