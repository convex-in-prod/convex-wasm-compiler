const first = new Map<string, string>();
const second = new Map<string, string>();

export const experimental_reuseContext = true;

// context-reuse-check-suppress module-state-write: Both writes were reviewed together but are distinct finding sites.
(first.set("fixture", "first"), second.set("fixture", "second"));
