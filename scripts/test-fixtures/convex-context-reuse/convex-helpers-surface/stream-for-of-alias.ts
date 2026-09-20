import { getIndexFields } from "convex-helpers/server/stream";

const helperMember = "prototype";

for (const escaped of [getIndexFields]) {
  escaped[helperMember];
}
