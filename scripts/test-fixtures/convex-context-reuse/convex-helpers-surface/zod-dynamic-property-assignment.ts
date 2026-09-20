import { z } from "zod";

const schemaMethod = "describe";
const holder: { schema?: ReturnType<typeof z.string> } = {};
holder.schema = z.string();

export const unreviewedDynamicPropertyAssignedSchemaMember =
  holder.schema[schemaMethod]("retained metadata");
