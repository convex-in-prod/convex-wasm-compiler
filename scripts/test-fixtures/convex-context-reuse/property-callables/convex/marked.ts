export const experimental_reuseContext = true;

const helpers = {
  start() {
    setTimeout(() => undefined, 1);
  },
  async startAsync() {
    setInterval(() => undefined, 1);
  },
  get value() {
    queueMicrotask(() => undefined);
    return 1;
  },
};

helpers.start();
helpers.startAsync();
void helpers.value;
