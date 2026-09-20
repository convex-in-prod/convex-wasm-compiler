const applicationState = {
  context: undefined as unknown,
  method: undefined as unknown,
  rememberContext(value: unknown): void {
    this.context = value;
  },
  rememberMethod(value: unknown): void {
    this.method = value;
  },
};

export const rememberContext = applicationState.rememberContext.bind(applicationState);
export const rememberMethod = applicationState.rememberMethod.bind(applicationState);

class RetainedSlot {
  value: unknown;

  remember(value: unknown): void {
    this.value = value;
  }
}

const retainedSlot = new RetainedSlot();
export const rememberWithClass = retainedSlot.remember.bind(retainedSlot);
