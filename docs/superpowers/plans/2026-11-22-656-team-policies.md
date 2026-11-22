# Team policies with the organization policy as a floor (#656) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A team's `teams/<team>.rego` is evaluated beside `org.rego`, with `SENTINEL_HOOK_TEAM` naming the team, and the results merge strictest-wins.

**Issue:** #656, milestone "Controlled from a central server". Depends on #655.

**Spec:** Outline document `6888019f-3202-4ea3-93a7-213cc8811bf0` ("AI.Sentinel: be controlled from Themis.NET") and its approved design, Outline document `b4b02d34-d3a1-4141-b5a0-4d51bcba7d91` ("AI.Sentinel: central server control, design", Status: approved). Read both with the Outline connector before writing code. Where they differ, the design wins. The decisions are also on GitHub in the closing comments of #653 and #657.

## Global Constraints

- Read `AGENTS.md` and the product-line standards it links before changing anything.
- A failing test first for every behaviour change; see it fail before writing the code.
- One commit per task, Conventional Commits. No `Co-Authored-By` trailer, no "Generated with" line, no session links, no nested parentheses in a commit body.
- Every new setting is optional and off by default. With none of the new settings, AI.Sentinel behaves exactly as before (Spec AC 8): the existing test suite passes unchanged.
- New public API is approved only when it is additive, optional, off by default and asked for by the Spec or the design. A breaking change, or API outside that scope, is a step to park.
- Native AOT: the hook CLIs and any new tool build and publish without trimming or AOT warnings. No runtime reflection.
- `TreatWarningsAsErrors` is on. Do not add or widen a suppression.
- New tests go in `tests/AI.Sentinel.Tests` under the test class names this plan gives, so the checks below find them.
- Run `dotnet format whitespace . --folder --verify-no-changes` before each push.
- The PR body says `Closes #656` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- Two teams with different Rego policies get different outcomes for the same tool call. `RegoTeamPolicyTests`.
- A tool call that the organization's policy denies is denied for every team, including a team whose policy allows it explicitly. `RegoTeamPolicyTests`.
- Per severity, the strictest action of org, team and environment applies. `RegoTeamPolicyTests`.
- A named team without a `teams/<team>.rego` file gets the organization policy alone, and the policy input carries the team name. `RegoTeamPolicyTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Load the team policy

- [ ] Load `teams/<team>.rego` when `SENTINEL_HOOK_TEAM` is set; compile failure blocks PreToolUse as in #654.
- [ ] Commit.

### Task 2: Merge results

- [ ] Evaluate org and team separately and merge: denied if either denies, approval if either requires it, strictest action per severity.
- [ ] Tests per rule above.
- [ ] Commit.

### Task 3: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*RegoTeamPolicyTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
