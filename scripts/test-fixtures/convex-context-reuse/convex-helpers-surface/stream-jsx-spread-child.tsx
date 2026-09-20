import { getIndexFields } from "convex-helpers/server/stream";

declare function UnknownConsumer(props: { children: unknown }): unknown;

export const escapedJsxSpreadChild = <UnknownConsumer>{...getIndexFields}</UnknownConsumer>;
