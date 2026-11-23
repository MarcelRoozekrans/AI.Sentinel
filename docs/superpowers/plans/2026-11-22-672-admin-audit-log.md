# Append-only audit log of administrative actions, verifiable offline (#672) Implementation Plan

**Goal:** The server part records every administrative action in a log that cannot be changed afterwards and that an auditor can verify without the server (ADR-241). The approval, pause and publish issues write to it.

**Issue:** #672, milestone "Controlled from a central server". Depends on #671.

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
- The PR body says `Closes #672` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- An entry records the action (approve, deny, pause, release, publish, rejected publish, rollback), who did it, when, the target, and the channel it came through (web, MCP, git). `AdminAuditLogTests`.
- Entries are hash-chained per organisation, building on `AuditHashChain` and `AuditChainVerification` in `src/AI.Sentinel/Audit`. `AdminAuditLogTests`.
- The store is append-only: an update or delete is refused, and a test shows it. `AdminAuditLogTests`.
- The log can be exported per organisation over HTTP, behind the host's authorization. `AdminAuditLogTests`.
- An export ends with a head, the entry count, the last hash and the export time, signed with the deployment's Ed25519 key as in #671. `AdminAuditLogTests`.
- A `sentinel` command verifies an export offline, chain included, and names the first entry that breaks it. It checks the signed head against a pinned public key, so an export with its newest entries cut off fails. It prints the signed count and export time; given a checkpoint the auditor took earlier (a count and hash), it also rejects an export that is older than the checkpoint or does not contain it. `AdminAuditVerifyCommandTests`.
- An entry never holds file contents or secrets. `AdminAuditLogTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Entry and chain

- [ ] Add the entry with action, actor, time, target and channel, chained per organisation with `AuditHashChain`.
- [ ] Failing tests first in `AdminAuditLogTests`.
- [ ] Commit.

### Task 2: Append-only store

- [ ] Add the store; updates and deletes are refused, shown by a test.
- [ ] Commit.

### Task 3: Export endpoint

- [ ] Add the export per organisation behind the host's authorization policy; end it with the head, entry count, last hash and export time, signed with the deployment's key through #671.
- [ ] Commit.

### Task 4: Offline verify command

- [ ] Add a `sentinel` command that verifies an export with `AuditChainVerification` and names the first broken entry, and checks the signed head against a pinned public key.
- [ ] Accept an optional checkpoint (count and hash from an earlier export or verify run) and reject an export that is older or does not contain it.
- [ ] Tests in `AdminAuditVerifyCommandTests`, including an export with its last entry removed, and an older complete export checked against a newer checkpoint; both fail.
- [ ] Commit.

### Task 5: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*AdminAuditLogTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*AdminAuditVerifyCommandTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
