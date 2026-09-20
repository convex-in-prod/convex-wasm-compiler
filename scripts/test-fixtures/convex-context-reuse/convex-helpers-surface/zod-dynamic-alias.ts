import { z } from "zod";

const schema = z.string();
const schemaMethod = "describe";

export const unreviewedDynamicAliasedSchemaMember = schema[schemaMethod]("retained metadata");
