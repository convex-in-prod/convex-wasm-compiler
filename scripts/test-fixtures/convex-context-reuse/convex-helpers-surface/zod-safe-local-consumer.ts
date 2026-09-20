import { z } from "zod";

const schema = z.object({ value: z.string() });

function parse(candidate: { safeParse(value: unknown): unknown }, input: unknown) {
  const parsed = candidate.safeParse(input);
  return parsed;
}

const parsed = parse(schema, { value: "safe" });
const values = [parsed];
const index = 0;

export const ordinaryComputedResult = values[index];
