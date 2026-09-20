import { query } from "./_generated/server";

let sharedCounter = 0;

export const selected = query({
  args: {},
  handler: async () => {
    sharedCounter += 1;
    return sharedCounter;
  },
});
