# Roles from identity-provider groups, scoped per node (#674) Implementation Plan

**Goal:** The server part knows who may do what on which node. Roles come from identity-provider groups bound to nodes in the node configuration that #664 reads (ADR-109, ADR-232). The approval, pause and read endpoints use this check.

**Issue:** #674, milestone "Controlled from a central server". Depends on #664.

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
- The PR body says `Closes #674` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- Three roles: administrator on the organisation, team lead on a team, developer for everyone else. A role applies to its node and the nodes below it. `NodeRoleTests`.
- The node configuration binds identity-provider groups to a role on a node; the signed-in user's groups come from the token. The developer is the token's subject claim and the groups its `groups` claim; both claim names are optional settings with those defaults. A test maps both from a validated token. `NodeRoleTests`.
- A check answers whether a user may act on a node, and on a session, through the repository that session belongs to. `NodeRoleTests`.
- A team lead of one team is refused on another team's sessions; an administrator is allowed on every node; a developer is allowed only on their own decisions. `NodeRoleTests`.
- A change of the configuration folder changes the bindings without a restart. `NodeRoleTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Bindings and roles

- [x] Read group-to-role bindings from the node configuration; map the developer and groups from the validated token's claims; resolve a user's roles from those groups, applying down the tree.
- [x] Failing tests first in `NodeRoleTests`.
- [x] Commit.

### Task 2: Check

- [x] Add the role-on-node and role-on-session check for endpoints; reload on folder change.
- [x] Commit.

### Task 3: Document it

- [x] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [x] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*NodeRoleTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
