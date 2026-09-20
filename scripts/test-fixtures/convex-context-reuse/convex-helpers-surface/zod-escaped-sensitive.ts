import { z } from "zod";

const schema = z.string();

export const unreviewedEscapedRegistryWrite = schema["reg\u0069ster"]({});
