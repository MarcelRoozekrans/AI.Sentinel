# Resident process forwards allowlisted events to the server (#661) Implementation Plan

**Goal:** The resident process reads the local SQLite audit from a stored cursor and sends events to the server's ingest endpoint (#660), catching up after an outage. Hooks send nothing themselves (ADR-004, ADR-231). An event never carries the command, paths or tool input (ADR-240).

**Issue:** #661, milestone "Controlled from a central server". Depends on #659 and #660.

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
- The PR body says `Closes #661` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- With a server configured, each finding, decision, approval request and redaction count a hook records is sent as an event with the allowlisted fields only: event id, tool kind, outcome, policies, policy version, where decided, node, CLI, session, detector and severity for findings, and redaction counts. `EventForwardingTests`.
- Reason text is sent only when the node turns on detailed logging for the repository. The plugin then redacts paths, URLs, email addresses and quoted values first, and drops the reason when it appears to contain a secret. `ReasonRedactionTests`.
- No events are sent for a repository in strict repository mode (#656). `EventForwardingTests`.
- Events produced while the server is unreachable reach it once it is reachable again, in order and once. `EventForwardingTests`.
- A failed send never affects a decision. `EventForwardingTests`.
- The queue is bounded by the existing `SENTINEL_HOOK_AUDIT_MAX_MB` cap; entries pruned before they were sent are reported as a gap with a count. The event id is a UUID stored with the audit entry when the hook writes it, so a resend carries the same id. With the cap at 0 nothing is pruned: every unsent entry waits for the server and no gap is reported. `EventForwardingTests`.
- With none of the new settings, nothing is sent. Existing suite.

## Tasks

### Task 1: Cursor and send

- [ ] Store an event id with each local audit entry; read the local SQLite audit from a stored cursor and send allowlisted events in order, once; report pruned entries as a gap.
- [ ] Failing tests first in `EventForwardingTests`, including a resend that keeps its event id and an outage with `SENTINEL_HOOK_AUDIT_MAX_MB=0` that loses nothing and reports no gap.
- [ ] Commit.

### Task 2: Detailed logging

- [ ] Send reason text only with detailed logging on; redact paths, URLs, email addresses and quoted values; drop a reason that looks like a secret.
- [ ] Tests in `ReasonRedactionTests`.
- [ ] Commit.

### Task 3: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*EventForwardingTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ReasonRedactionTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
