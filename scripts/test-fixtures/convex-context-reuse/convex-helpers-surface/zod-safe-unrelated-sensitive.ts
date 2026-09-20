import { z } from "zod";

const unrelated = { meta: "local metadata" };

export const reviewedSchemaWithUnrelatedMetadata = {
  metadata: unrelated.meta,
  schema: z.string(),
};
