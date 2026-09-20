export const experimental_reuseContext = true;

// context-reuse-check-suppress malformed
const malformedSuppressionTarget = "safe";

// context-reuse-check-suppress unknown-rule: This literal reason names no known checker rule.
const unknownSuppressionTarget = "safe";

// context-reuse-check-suppress module-state-write: This literal reason has no matching write on the next line.
const unusedSuppressionTarget = "safe";

// context-reuse-check-suppressions are checker documentation, not a declaration.
const suppressionCommentMention = "safe";
const suppressionSyntaxMention = "context-reuse-check-suppress is checker syntax";

void [
  malformedSuppressionTarget,
  suppressionCommentMention,
  suppressionSyntaxMention,
  unknownSuppressionTarget,
  unusedSuppressionTarget,
];
