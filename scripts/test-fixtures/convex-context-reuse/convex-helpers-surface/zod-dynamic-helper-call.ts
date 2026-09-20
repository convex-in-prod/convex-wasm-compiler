import { z } from "zod";

const schemaMethod = "meta";

function attachMetadata(schema: ReturnType<typeof z.string>) {
  return schema[schemaMethod]({ description: "retained metadata" });
}

export const unreviewedDynamicCalledHelper = attachMetadata.call(undefined, z.string());
