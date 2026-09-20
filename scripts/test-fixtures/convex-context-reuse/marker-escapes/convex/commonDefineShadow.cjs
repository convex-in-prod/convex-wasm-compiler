const Object = { defineProperties: () => undefined };

Object.defineProperties(exports, {
  experimental_reuseContext: { value: true, enumerable: true },
});

const Reflect = { set: () => undefined };
Reflect.set(exports, "experimental_reuseContext", true);
const shadowedSet = Reflect.set;
shadowedSet(exports, "experimental_reuseContext", true);

{
  const Object = { defineProperties: { call: () => undefined } };
  Object.defineProperties.call(exports, {
    experimental_reuseContext: { value: true, enumerable: true },
  });
}
