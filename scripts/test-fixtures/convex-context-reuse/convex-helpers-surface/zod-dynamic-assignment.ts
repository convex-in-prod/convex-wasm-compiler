import { z } from "zod";

const schemaMethod = "describe";
let schema;
schema = z.string();

export const unreviewedDynamicAssignedSchemaMember = schema[schemaMethod]("retained metadata");
