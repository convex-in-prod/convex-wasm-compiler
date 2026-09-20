export const experimental_reuseContext = true;

function namedInitializer() {
  setTimeout(() => undefined, 1);
}
namedInitializer();

const arrowInitializer = () => {
  queueMicrotask(() => undefined);
};
arrowInitializer();

Reflect.apply(
  () => {
    setInterval(() => undefined, 1);
  },
  undefined,
  []
);

Reflect.construct(function ImmediateConstructor() {
  setImmediate(() => undefined);
}, []);

new Promise(() => {
  requestAnimationFrame(() => undefined);
});

const deferred = (() => {
  setTimeout(() => undefined, 1);
}).bind(undefined);
void deferred;

(() => {
  queueMicrotask(() => undefined);
}).bind(undefined)();

const boundInitializer = (() => {
  setInterval(() => undefined, 1);
}).bind(undefined);
boundInitializer();

globalThis.setTimeout(() => undefined, 1);

async function asyncInitializer() {}
asyncInitializer();

function noTimer() {}
const possibleTimer = globalThis.contextReuseUseTimer ? globalThis.setTimeout : noTimer;
possibleTimer(() => undefined, 1);

function boundAliasInitializer() {
  setTimeout(() => undefined, 1);
}
const boundAlias = boundAliasInitializer.bind(undefined);
boundAlias();
