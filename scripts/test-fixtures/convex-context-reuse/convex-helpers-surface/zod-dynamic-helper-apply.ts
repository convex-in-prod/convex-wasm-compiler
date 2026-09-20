import { z } from "zod";

const schemaMethod = "describe";

function attachDescription(schema: ReturnType<typeof z.string>) {
  return schema[schemaMethod]("retained metadata");
}

export const unreviewedDynamicAppliedHelper = attachDescription.apply(undefined, [z.string()]);
