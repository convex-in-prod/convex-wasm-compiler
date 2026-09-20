export const experimental_reuseContext = true;

const objectPrototype = Object.prototype;
const { prototype: arrayPrototype } = Array;
const { defineProperty } = Object;

export function retain(): void {
  Object.prototype.toString = () => "[context-reuse-direct]";
  delete Array.prototype.push;
  Object.defineProperty(Map.prototype, "contextReuseDirect", { value: true });
  objectPrototype.toString = () => "[context-reuse-alias]";
  delete arrayPrototype.push;
  defineProperty(Map.prototype, "contextReuseDestructured", { value: true });
}
