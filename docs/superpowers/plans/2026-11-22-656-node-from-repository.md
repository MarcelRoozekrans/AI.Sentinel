# Apply the policy of the node that owns the repository (#656) Implementation Plan

**Goal:** The policy that applies to a tool call comes from the node that owns the repository, not from the developer's team (ADR-232, ADR-246). The repository is the git remote of the working directory. `SENTINEL_HOOK_TEAM` is not built. A local `SENTINEL_HOOK_POLICY_DIR` is evaluated next to the signed profile and combined strictest-wins, so it can only tighten.

**Issue:** #656, milestone "Controlled from a central server". Depends on #658.

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
- The PR body says `Closes #656` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- The hook reads the git remote of the working directory and uses the cached signed profile for that repository; the policy input carries `repository` and `node`. `RepositoryNodePolicyTests`.
- Two repositories owned by different nodes with different policies get different outcomes for the same tool call. `RepositoryNodePolicyTests`.
- A tool call that the organisation's policy denies is denied in every repository, including one whose node's bundle tries to allow it. `RepositoryNodePolicyTests`.
- Strict repository mode is on by default: a repository no node owns, or a folder outside git, gets only the organisation's top-level rules and sends no events. The plugin says so at session start. `StrictRepositoryModeTests`.
- With a server configured and `SENTINEL_HOOK_POLICY_DIR` set, both are evaluated and the strictest outcome wins; the local folder cannot loosen the profile. `RepositoryNodePolicyTests`.
- The hook decides this from cached data only, without network traffic. `RepositoryNodePolicyTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Repository from git remote

- [x] Read the git remote of the working directory without starting `git` on every call where a cached value will do; fill `repository` and `node` in the input.
- [x] Failing tests first in `RepositoryNodePolicyTests`.
- [x] Commit.

### Task 2: Strict repository mode

- [x] Unowned repository or no git: organisation top-level rules only, no events, a notice at session start.
- [x] Tests in `StrictRepositoryModeTests`.
- [x] Commit.

### Task 3: Local folder next to the profile

- [x] Evaluate `SENTINEL_HOOK_POLICY_DIR` next to the profile and combine strictest-wins.
- [x] Commit.

### Task 4: Document it

- [x] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [x] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*RepositoryNodePolicyTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*StrictRepositoryModeTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
