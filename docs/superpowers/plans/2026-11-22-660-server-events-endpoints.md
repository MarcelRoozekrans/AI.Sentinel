# Receive allowlisted hook events and serve blocked calls and the audit trail (#660) Implementation Plan

**Goal:** Add to `AI.Sentinel.AspNetCore` an endpoint that receives events from developer PCs, and endpoints that read blocked calls and the audit trail. What the server keeps follows a field allowlist with per-organisation pseudonyms and a retention period (ADR-240, ADR-247). The dashboard's `GET /api/export.ndjson` reads only the store of the app that hosts it; nothing receives events from another machine today.

**Issue:** #660, milestone "Controlled from a central server". Depends on #674.

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
- The PR body says `Closes #660` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- The ingest endpoint keeps only the allowlisted fields: tool kind, outcome, policies, policy version, where decided, node, CLI, session, detector and severity for findings, redaction counts, and reason text when sent. It counts the names of any other field and drops their values. `ServerEventIngestTests`.
- Identities are replaced on arrival with a per-organisation code; the key for those codes is kept apart from the event store. `ServerEventIngestTests`.
- Retention is set per organisation, defaulting to 90 days for events and 13 months for daily counts; older data is deleted. `ServerEventIngestTests`.
- Receiving the same event twice stores it once. `ServerEventIngestTests`.
- A received batch can report a gap with a count of events pruned before they were sent, and the gap is readable. `ServerEventIngestTests`.
- Blocked calls and audit entries can be read over HTTP, filterable by node, session and time, per team without names (#675 adds the names setting). `ServerEventReadTests`.
- The endpoints use the host's ASP.NET Core authorization with a configurable policy name for sign-in, and the role-on-node check from #674: a team lead reads their node, a developer reads their own decisions. `ServerEventReadTests`.
- With none of the new settings, the dashboard and its endpoints behave as before. Existing suite.

## Tasks

### Task 1: Ingest with allowlist

- [ ] Add the ingest endpoint; keep allowlisted fields, count other field names, deduplicate, accept gap reports.
- [ ] Failing tests first in `ServerEventIngestTests`.
- [ ] Commit.

### Task 2: Pseudonyms and retention

- [ ] Replace identities with a per-organisation code, key kept apart from the store; delete by retention per organisation.
- [ ] Commit.

### Task 3: Read endpoints

- [ ] Serve blocked calls and the audit trail per team without names, filterable by node, session and time, behind the configurable authorization policy and #674's check.
- [ ] Tests in `ServerEventReadTests`.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ServerEventIngestTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ServerEventReadTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
