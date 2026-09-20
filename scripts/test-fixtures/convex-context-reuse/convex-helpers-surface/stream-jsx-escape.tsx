import { getIndexFields } from "convex-helpers/server/stream";

declare function UnknownConsumer(props: { value: unknown }): unknown;

export const escapedJsxProperty = <UnknownConsumer value={getIndexFields} />;
