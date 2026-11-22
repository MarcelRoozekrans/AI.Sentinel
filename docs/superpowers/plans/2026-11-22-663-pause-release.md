# Pause and release a session from the server (#663) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A team lead pauses and releases a session over the server's HTTP API; the server pushes it over Server-Sent Events to the local process, which updates `pause.json`; the hook denies while paused.

**Issue:** #663, milestone "Controlled from a central server". Depends on #658 and #660.

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
- The PR body says `Closes #663` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- While a session is paused, each tool call from that session is denied with a message that the team lead paused it and that the agent must wait for release. After release, calls proceed. `SessionPauseTests`.
- A call already running when the pause arrives completes. `SessionPauseTests`.
- A pause takes effect on the PC within 1 second of the API call, measured end to end against a test server. `SessionPauseTests`.
- A hook reads the pause state without network traffic. `SessionPauseTests`.
- The SSE connection reconnects after a drop and resyncs the current pause state. `SessionPauseTests`.
- Without a central product, a team can pause and release over the server's HTTP API. `SessionPauseTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Server pause API and SSE stream

- [ ] Add pause, release and list endpoints and an SSE stream per developer with a heartbeat, behind the configurable authorization policy.
- [ ] Failing tests first.
- [ ] Commit.

### Task 2: Local process subscription

- [ ] Subscribe with the token, write `pause.json` atomically on every event, reconnect with backoff and resync.
- [ ] Commit.

### Task 3: Hook deny

- [ ] Deny PreToolUse for a paused session with the agreed message.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*SessionPauseTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
