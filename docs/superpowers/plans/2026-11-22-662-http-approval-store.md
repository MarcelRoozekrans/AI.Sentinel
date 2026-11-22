# Approval store reachable over HTTP (#662) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server endpoints through which hooks create and read approval requests, and an `http` backend in the approval config that uses them.

**Issue:** #662, milestone "Controlled from a central server". Depends on #658 and #660.

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
- The PR body says `Closes #662` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- An approval raised by a hook on one PC can be listed and approved over HTTP on the server, and the hook on that PC acts on the decision when the agent retries. `HttpApprovalStoreTests`.
- Denial over HTTP is acted on the same way. `HttpApprovalStoreTests`.
- While the server is unreachable, or the local process is not running, a hook denies a tool call that needs approval with a message that the server is unreachable. `HttpApprovalStoreTests`.
- Without a central product, a team can run the server part on its own and approve and deny over its HTTP API. `HttpApprovalStoreTests`.
- With `backend` other than `http`, approvals behave as before. Existing suite.

## Tasks

### Task 1: Server approval API

- [ ] Add create, read, list, approve and deny endpoints backed by the host's approval store, behind the configurable authorization policy.
- [ ] Failing tests first.
- [ ] Commit.

### Task 2: `http` backend

- [ ] Add `backend: "http"` with the server URL to the approval config; the hook creates and reads requests through it with the token from #659 and a short timeout.
- [ ] Commit.

### Task 3: Unreachable

- [ ] Map an unreachable server or missing process to a deny with the agreed message.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*HttpApprovalStoreTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
