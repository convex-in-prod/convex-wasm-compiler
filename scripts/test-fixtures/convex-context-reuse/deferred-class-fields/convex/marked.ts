export const experimental_reuseContext = true;

class Deferred {
  field = setTimeout(() => undefined, 1);
}

export const deferred = Deferred;
