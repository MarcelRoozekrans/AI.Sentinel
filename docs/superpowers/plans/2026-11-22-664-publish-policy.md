# Server publishes organization and team policy to the local processes (#664) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The server part compiles the organization and team policies with the built-in compiler from #633 and pushes them over the SSE stream; the local process stores them as the last known policy.

**Issue:** #664, milestone "Controlled from a central server". Depends on #656, #659, #660 and #663.

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
- The PR body says `Closes #664` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- Two teams with different Rego policies on the server get different outcomes for the same tool call, and a tool call that the organization's policy denies is denied for every team. `PolicyPublishingTests`.
- The team of a PC follows from the signed-in developer's groups, mapped to a team on the server. `PolicyPublishingTests`.
- While the server is unreachable, a hook still denies a tool call that matches a blocking rule in the last known policy. `PolicyPublishingTests`.
- A policy that does not compile on the server is rejected there and never pushed. `PolicyPublishingTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Server-side compile and store

- [ ] Accept organization and team policy over the HTTP API, compile with the built-in compiler, reject on error.
- [ ] Failing tests first.
- [ ] Commit.

### Task 2: Group-to-team mapping

- [ ] Map identity-provider groups to teams in server configuration; pick the team for a developer from their token.
- [ ] Commit.

### Task 3: Push and store

- [ ] Push compiled policy for the developer's team over SSE; the local process writes it to the state folder.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*PolicyPublishingTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
