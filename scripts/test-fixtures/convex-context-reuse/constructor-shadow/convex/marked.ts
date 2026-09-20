class Map {
  readonly value = "not the global Map constructor";
}

export const experimental_reuseContext = true;
export const shadowedConstructor = new Map();
