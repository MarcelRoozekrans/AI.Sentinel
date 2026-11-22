# Local process sends findings, blocked calls and approval requests to the server (#661) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The local process reads the local SQLite audit from a stored cursor and sends new entries to the server's ingest endpoint, catching up after an outage.

**Issue:** #661, milestone "Controlled from a central server". Depends on #658 and #660. The queue design is the closing comment of #657.

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
- The PR body says `Closes #661` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- With a server configured, each finding, blocked call, approval request and redaction a hook produces is sent to it. `AuditForwardingQueueTests`.
- Findings produced while the server is unreachable reach the server once it is reachable again, in order and once. `AuditForwardingQueueTests`.
- A failed send never makes a hook deny a tool call: hooks do not send anything themselves. `AuditForwardingQueueTests`.
- The queue is bounded by `SENTINEL_HOOK_AUDIT_MAX_MB`; entries pruned before they were sent are reported as a gap with a count. `AuditForwardingQueueTests`.
- With none of the new settings, nothing is sent. Existing suite.

## Tasks

### Task 1: Cursor reader

- [ ] Read entries after a stored cursor from the local audit file; persist the cursor after a successful send.
- [ ] Failing tests first.
- [ ] Commit.

### Task 2: Sender with backoff

- [ ] Send batches with the token from #659; retry with backoff while unreachable.
- [ ] Commit.

### Task 3: Gap reporting

- [ ] Detect pruning past the cursor and send a gap with the count.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*AuditForwardingQueueTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
