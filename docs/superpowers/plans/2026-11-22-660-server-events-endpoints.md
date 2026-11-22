# Server endpoints: receive hook events and serve blocked calls and the audit trail (#660) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add to `AI.Sentinel.AspNetCore` an endpoint that receives audit entries from developer PCs and endpoints that read blocked calls and the audit trail.

**Issue:** #660, milestone "Controlled from a central server". Depends on nothing in this milestone.

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
- The PR body says `Closes #660` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- Blocked calls and audit entries can be read over HTTP, filterable by session, developer and time. `ServerEventEndpointTests`.
- Entries received from a PC keep their hash-chain fields, source and session, and record which developer sent them. `ServerEventEndpointTests`.
- Receiving the same entry twice stores it once. `ServerEventEndpointTests`.
- A received batch can report a gap with a count of entries pruned before they were sent, and the gap is readable. `ServerEventEndpointTests`.
- The endpoints use the host's ASP.NET Core authorization with a configurable policy name, as the dashboard does; an unauthenticated request is refused. `ServerEventEndpointTests`.
- With none of the new settings, the dashboard and its endpoints behave as before. Existing suite.

## Tasks

### Task 1: Ingest endpoint

- [ ] Add the mapping extension and an ingest endpoint for a batch of audit entries; dedupe by entry id or hash.
- [ ] Failing tests first with `WebApplicationFactory` or a `TestServer`.
- [ ] Commit.

### Task 2: Read endpoints

- [ ] Add endpoints for blocked calls and the audit trail with paging and filters.
- [ ] Commit.

### Task 3: Authorization

- [ ] Require the configurable authorization policy on every new endpoint.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ServerEventEndpointTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
