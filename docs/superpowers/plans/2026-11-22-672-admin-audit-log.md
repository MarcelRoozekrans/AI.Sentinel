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
- The log can be exported per organisation over HTTP, behind the host's authorization with the organisation as the resource, so a caller not allowed on that organisation is refused; #674 adds the administrator check. `AdminAuditLogTests`.
- An export ends with a head, the entry count, the last hash, the export time and the organisation, signed with the deployment's Ed25519 key as in #671. `AdminAuditLogTests`.
- A `sentinel` command verifies an export offline, chain included, and names the first entry that breaks it. It checks the signed head against a pinned public key, so an export with its newest entries cut off fails. It prints the signed count and export time; given a checkpoint the auditor took earlier (a count, hash and export time), it also rejects an export that is older than the checkpoint or does not contain it. It rejects an export for another organisation than the one asked for. `AdminAuditVerifyCommandTests`.
- An entry never holds file contents or secrets. `AdminAuditLogTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Entry and chain

- [x] Add the entry with action, actor, time, target and channel, chained per organisation with `AuditHashChain`.
- [x] Failing tests first in `AdminAuditLogTests`.
- [x] Commit.

### Task 2: Append-only store

- [x] Add the store; updates and deletes are refused, shown by a test.
- [x] Commit.

### Task 3: Export endpoint

- [x] Add the export per organisation behind the host's authorization policy; authorize with the organisation as the resource; end it with the head, entry count, last hash, export time and organisation, signed with the deployment's key through #671.
- [x] Commit.

### Task 4: Offline verify command

- [x] Add a `sentinel` command that verifies an export with `AuditChainVerification` and names the first broken entry, and checks the signed head against a pinned public key.
- [x] Accept an optional checkpoint (count, hash and export time from an earlier export or verify run) and reject an export that is older or does not contain it. Take the expected organisation and reject an export for another.
- [x] Tests in `AdminAuditVerifyCommandTests`, including an export with its last entry removed, and an older complete export checked against a newer checkpoint, the same entries exported before the checkpoint's time, and an export for another organisation; all fail. In `AdminAuditLogTests`, a caller refused on organisation B asks for its export and is denied.
- [x] Commit.

### Task 5: Document it

- [x] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [x] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*AdminAuditLogTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*AdminAuditVerifyCommandTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
