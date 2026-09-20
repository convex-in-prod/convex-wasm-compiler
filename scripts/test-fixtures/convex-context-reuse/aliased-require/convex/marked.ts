export const experimental_reuseContext = true;

const load = require;
load("./not-a-static-edge");
const boundLoad = require.bind(undefined);
boundLoad("./not-a-static-edge");
require.call(undefined, "./not-a-static-edge");
Reflect.apply(require, undefined, ["./not-a-static-edge"]);
globalThis.require("./not-a-static-edge");
Reflect.construct(require, ["./not-a-static-edge"]);
(0, require)("./not-a-static-edge");
const holder = { load: require };
holder.load("./not-a-static-edge");
const assignedHolder = {};
assignedHolder.load = require;
assignedHolder.load("./not-a-static-edge");
new require("./not-a-static-edge");
new (require.bind(undefined))("./not-a-static-edge");
const spreadHolder = { ...{ load: require } };
spreadHolder.load("./not-a-static-edge");
module.require("./not-a-static-edge");
require`./not-a-static-edge`;
const { load: destructuredLoad } = { load: require };
destructuredLoad("./not-a-static-edge");
const [arrayLoad] = [require];
arrayLoad("./not-a-static-edge");
const { nested: nestedHolder } = { nested: { load: require } };
nestedHolder.load("./not-a-static-edge");

function invokeShadowedHolder(): void {
  const holder = { load: () => undefined };
  holder.load("./not-a-static-edge");
}

invokeShadowedHolder();

function invokeShadowedGlobalThis(): void {
  const globalThis = { require: () => undefined };
  globalThis.require("./not-a-static-edge");
}

invokeShadowedGlobalThis();

function invokeShadowedModule(): void {
  const module = { require: () => undefined };
  module.require("./not-a-static-edge");
}

invokeShadowedModule();
