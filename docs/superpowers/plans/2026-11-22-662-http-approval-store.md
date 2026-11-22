# Approval store reachable over HTTP (#662) Implementation Plan

**Goal:** Add server endpoints through which the resident process creates and reads approval requests, and an `http` backend in the approval config that uses them, so an approval raised on a developer's PC is decided on the server.

**Issue:** #662, milestone "Controlled from a central server". Depends on #659, #674 and #672.

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
- The PR body says `Closes #662` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- An approval raised by a hook on one PC can be listed and approved over HTTP on the server, and the hook on that PC acts on the decision when the agent retries. `HttpApprovalStoreTests`.
- A denial over HTTP is acted on the same way. `HttpApprovalStoreTests`.
- Until a grant exists the call is **deny**, with a message that it waits for approval. While the server is unreachable it is denied with a message that the server is unreachable. `HttpApprovalStoreTests`.
- Only an administrator, or a team lead of the node that owns the session's repository, can approve or deny (#674). `HttpApprovalStoreTests`.
- Each approve and deny is written to the audit log of #672 with its channel. `HttpApprovalStoreTests`.
- An approval request carries the tool input after AI.Sentinel's existing redaction, so the approver sees what they approve, and is deleted 30 days after it is decided. `HttpApprovalStoreTests`.
- Without a central product, a team can run the server part on its own and approve and deny over its HTTP API. `HttpApprovalStoreTests`.
- With a `backend` other than `http`, approvals behave as before. Existing suite.

## Tasks

### Task 1: Server endpoints

- [ ] Add create, list, approve and deny endpoints with #674's check; write approve and deny to #672's log; keep redacted tool input and delete 30 days after decision.
- [ ] Failing tests first in `HttpApprovalStoreTests`.
- [ ] Commit.

### Task 2: `http` backend

- [ ] Add the `http` backend to the approval config, going through the resident process; deny until a grant exists, with the unreachable message when the server cannot be reached.
- [ ] Commit.

### Task 3: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*HttpApprovalStoreTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
