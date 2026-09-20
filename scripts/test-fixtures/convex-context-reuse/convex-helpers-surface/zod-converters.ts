import {
  zodOutputToConvex as outputToConvex,
  zodToConvex as toConvex,
} from "convex-helpers/server/zod4";

const schema = {};

export const reviewedZodConverterResults = {
  output: outputToConvex(schema),
  input: toConvex(schema),
};
