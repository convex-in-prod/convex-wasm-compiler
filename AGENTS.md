# Repository guidance

## Keep the repository generic

- Treat all tracked files, commit messages, pull-request text, workflow logs,
  release notes, and generated artifacts as public material.
- Do not add downstream application source, operator configuration, deployment
  identities, credentials, local absolute paths, private incident evidence, or
  provider-specific fixtures.
- Keep application module selection and runtime deployment policy outside this
  repository.
- Use generic fixtures that exercise compiler or precompiler contracts without
  naming a downstream consumer.

## Preserve native-package portability

- Build release binaries on the matching operating system and architecture.
- Keep build inputs pinned and source identities reproducible.
- Do not weaken source, target, toolchain, or artifact authentication to make a
  local build pass.
- Keep the compiler and precompiler usable without a downstream repository
  checkout.

## Keep changes focused

- Fail on malformed required inputs and broken internal invariants.
- Prefer direct implementations over one-call wrappers.
- Add regression coverage for compiler and artifact-contract fixes.
- Format only intentionally changed Rust files.
