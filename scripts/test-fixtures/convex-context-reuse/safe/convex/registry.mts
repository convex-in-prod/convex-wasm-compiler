const registry = new Map<string, string>();

// context-reuse-check-suppress module-state-write: Populated once during deterministic module evaluation and read-only during query execution.
registry.set("fixture", "registered");

export const registeredValue = registry.get("fixture");
