import { z } from "zod";

const schemaMethod = "meta";

export const unreviewedDynamicDirectSchemaMember = z.string()[schemaMethod]({
  description: "retained metadata",
});
