import { z } from "zod";

const schemaMethod = "register";

function createSchema() {
  return z.string();
}

export const unreviewedDynamicReturnedSchemaMember = createSchema()[schemaMethod]({});
