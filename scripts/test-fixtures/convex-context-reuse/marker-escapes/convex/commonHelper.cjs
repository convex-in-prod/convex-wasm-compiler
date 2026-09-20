function defineExports(target, definitions) {
  Object.defineProperties(target, definitions);
}

defineExports(exports, {
  experimental_reuseContext: { value: true, enumerable: true },
});
