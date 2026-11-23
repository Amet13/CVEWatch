# 5. Version comparison by scheme, `unknown` on failure

Date: 2026-11-23. Status: accepted.

## Context

"Is 7.2.5 inside 7.2.0 to 7.2.6?" has no single answer. Debian, RPM, semver,
PEP 440 and vendor versions (FortiOS, Windows builds) all order differently.
A wrong comparison gives a wrong verdict, and a missed vulnerability costs more
than a false alarm. A generic range string such as the purl `vers:` spec would
make every source go through one text format that we would parse again.

## Decision

- Each catalog product names a versioning scheme (`dotted`, `semver`, `calver`,
  `debian`, `rpm`, `apk`, `pep440`, or a named custom scheme). `unpatched-core`
  has one parser and comparator per scheme.
- Internally a range is a structured `Constraint` (lower and upper bound, each
  inclusive or exclusive, plus an optional fixed version). We do not use `vers:`
  as an internal format. Constraints are rendered to plain text for humans.
- If a version or a bound cannot be parsed in the product's scheme, the
  verdict is `unknown` with the reason. We never guess and never fall back to
  another scheme.
- Each parser has property tests (the order is total and transitive) and a
  fuzz target.

## Consequences

- Adding a product with an odd versioning means adding a scheme, with tests.
- Rare formats produce `unknown` findings until a scheme exists. That is
  visible and fixable, which a silent wrong answer is not.
- The `vers:` spec may still be read at the edges (OSV) and converted into
  constraints there.
