export const experimental_reuseContext = true;

// An ordinary function owns its invocation-local `arguments` object.
export function ordinary(value: string): void {
  arguments.ordinary = value;
  const arrow = (): void => {
    // Arrows inherit the nearest ordinary function's arguments object.
    arguments.arrow = value;
  };
  arrow();
  function nested(): void {
    // A nested ordinary function owns a distinct invocation-local object.
    arguments.nested = value;
  }
  nested();
}

// A top-level ESM arrow has no ordinary function owner. The unresolved `arguments` name remains
// a global reference and must not be treated as an invocation-local binding.
const topLevelArrow = (): void => {
  arguments.esm = true;
};
topLevelArrow();
