export const experimental_reuseContext = true;

class ImmediateClass {
  field = setTimeout(() => undefined, 1);

  constructor() {
    setTimeout(() => undefined, 1);
  }
}

new ImmediateClass();

const ImmediateExpression = class {
  constructor() {
    queueMicrotask(() => undefined);
  }
};

new ImmediateExpression();

const ReflectOnlyClass = class {
  field = setTimeout(() => undefined, 1);
};

Reflect.construct(ReflectOnlyClass, []);

new (class {
  constructor() {
    setTimeout(() => undefined, 1);
  }
})();
