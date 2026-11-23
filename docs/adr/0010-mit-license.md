# 10. MIT license

Date: 2026-11-23. Status: accepted.

## Context

The repository has been MIT-licensed since CVEWatch. Rust projects often use
"MIT OR Apache-2.0". The Apache patent grant matters little for a tool that
reads public data and has no patented algorithms.

## Decision

The code stays under the MIT license, so the history keeps one license. Data
from sources keeps its own terms, listed in `NOTICE`. Dependencies must have a
license on the `deny.toml` allow list (permissive licenses, and MPL-2.0 for
dependencies only).

## Consequences

- No relicensing and no contributor sign-off needed.
- No explicit patent grant. If a contributor needs one, that is a reason to
  reopen this decision.
