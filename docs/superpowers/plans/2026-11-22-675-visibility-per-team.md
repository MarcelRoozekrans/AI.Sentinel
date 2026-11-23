# Show activity per team, names only with an approval reference (#675) Implementation Plan

**Goal:** The endpoints for blocked calls and the audit trail show activity per team without names by default. Names need the node's names setting, which requires an approval reference such as a DPIA (ADR-239).

**Issue:** #675, milestone "Controlled from a central server". Depends on #660.

**Spec:** Outline document `6888019f-3202-4ea3-93a7-213cc8811bf0` ("AI.Sentinel: be controlled from Themis.NET") and its approved design, Outline document `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91` ("AI.Sentinel: central server control, design", Status: approved). Read both with the Outline connector before writing code. Where they differ, the design wins; where the design and an accepted ADR differ, the ADR wins. #653 and #657 are replaced by the design and are not a source.

## Global Constraints

- Read `AGENTS.md` and the product-line standards it links before changing anything. Build sessions do not use superpowers.
- A failing test first for every behaviour change; see it fail before writing the code.
- One commit per task, Conventional Commits. No `Co-Authored-By` trailer, no "Generated with" line, no session links, no nested parentheses in a commit body.
- Every new setting is optional and off by default. With none of the new settings, AI.Sentinel behaves exactly as before (Spec AC 8): the existing test suite passes unchanged.
- New public API is approved only when it is additive, optional, off by default and asked for by the Spec or the design. A breaking change, or API outside that scope, is a step to park.
- Native AOT: the hook CLIs and any new tool build and publish without trimming or AOT warnings. No runtime reflection.
- `TreatWarningsAsErrors` is on. Do not add or widen a suppression.
- Nothing sent to the server or written to the audit carries a token, a command line, a path or tool input, except where the design allows it.
- New tests go in `tests/AI.Sentinel.Tests` under the test class names this plan gives, so the checks below find them.
- Run `dotnet format whitespace . --folder --verify-no-changes` before each push.
- The PR body says `Closes #675` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- Without the names setting, the endpoints return activity per team with no developer names or codes that identify a person. `TeamVisibilityTests`.
- The names setting is per node in the node configuration and is refused without an approval reference. `TeamVisibilityTests`.
- A team view needs at least 3 people; a smaller team shows only as part of the node above it. `TeamVisibilityTests`.
- Each record is stamped with the visibility in force when it was stored. `TeamVisibilityTests`.
- Turning names off hides them at once, also in records stored while it was on. `TeamVisibilityTests`.
- A developer still sees their own decisions. `TeamVisibilityTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Names setting

- [ ] Read the names setting per node; refuse it without an approval reference.
- [ ] Failing tests first in `TeamVisibilityTests`.
- [ ] Commit.

### Task 2: Minimum team size and stamping

- [ ] Fold teams under 3 people into the node above; stamp records with the visibility in force; hide names at once when turned off.
- [ ] Commit.

### Task 3: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*TeamVisibilityTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
