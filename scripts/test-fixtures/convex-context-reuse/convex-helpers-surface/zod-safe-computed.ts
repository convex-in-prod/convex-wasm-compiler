import { z } from "zod";

const schema = z.object({ value: z.string() });
const unrelated = { value: "reviewed" };
const unrelatedKey = "value";
const unrelatedZodNamedProperty = { z: "ordinary value" };
const unrelatedZodNamedPropertyKey = "z";

export const reviewedSchemaAndComputedValue = {
  parsed: schema.parse({ value: "safe" }),
  unrelated: unrelated[unrelatedKey],
  unrelatedZodNamedProperty: unrelatedZodNamedProperty[unrelatedZodNamedPropertyKey],
};
