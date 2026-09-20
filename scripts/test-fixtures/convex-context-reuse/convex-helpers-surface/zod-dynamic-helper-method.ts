import { z } from "zod";

const schemaMethod = "meta";
const passthrough = {
  parse(schema: ReturnType<typeof z.string>) {
    return schema;
  },
};
const schema = passthrough.parse(z.string());

export const unreviewedDynamicLocalParseMember = schema[schemaMethod]({
  description: "retained metadata",
});
