import { z } from "zod";

const schemaMethod = "describe";
const holder: { schema: ReturnType<typeof z.string> | undefined } = { schema: z.string() };
const schema = (holder.schema ||= undefined);

export const unreviewedDynamicLogicalAssignmentMember = schema[schemaMethod]("retained metadata");
