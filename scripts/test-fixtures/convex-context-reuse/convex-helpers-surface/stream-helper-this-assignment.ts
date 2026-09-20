import { getIndexFields } from "convex-helpers/server/stream";

declare const unknownConsumer: (value: unknown) => unknown;

const holder = {
  store(value: unknown) {
    const receiver = this;
    receiver.value = value;
  },
  value: undefined as unknown,
};

holder.store(getIndexFields);
export const unreviewedHelperThisAssignment = unknownConsumer(holder.value);
