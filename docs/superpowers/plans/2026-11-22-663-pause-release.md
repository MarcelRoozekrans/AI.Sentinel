# Pause and release a session from the server (#663) Implementation Plan

**Goal:** A team lead pauses and releases a session over the server's HTTP API. The server pushes it over Server-Sent Events to the resident process, which applies it in every decision it answers and writes it to its state folder; a hook evaluating in-process reads it from there. A paused call is denied with a message that tells the agent to hand control back to the developer instead of retrying.

**Issue:** #663, milestone "Controlled from a central server". Depends on #659, #674 and #672.

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
- The PR body says `Closes #663` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- While a session is paused, each tool call from that session is denied with a message that the team lead paused it and that the agent must wait for release. After release, calls proceed. `SessionPauseTests`.
- A call already running when the pause arrives completes. `SessionPauseTests`.
- A pause takes effect on the PC within 1 second of the API call, measured end to end against a test server. `SessionPauseTests`.
- A hook reads the pause state without network traffic. `SessionPauseTests`.
- The SSE connection reconnects after a drop and resyncs the current pause state. `SessionPauseTests`.
- The SSE stream also announces each published configuration. The resident process fetches the signed profile (#664) at start, on that announcement, after every reconnect, and before the cached one expires: a day before, or halfway through its lifetime when that is shorter, and at once when that point has passed. A failed fetch is retried with bounded backoff; until one succeeds the last valid profile stays in force. A fetched profile is verified (#671), written to the cache and replaces the warm module, so the next decision uses it. A configuration published while the process was disconnected is in force after it reconnects. `ProfileRefreshTests`.
- A pause names a session, not a person, so a team lead can pause a session whose developer's name is hidden. `SessionPauseTests`.
- Only an administrator, or a team lead of the node that owns the session's repository, can pause or release (#674). Each pause and release is written to the audit log of #672 with its channel. `SessionPauseTests`.
- Without a central product, a team can pause and release over the server's HTTP API. `SessionPauseTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Server pause API and SSE stream

- [ ] Add pause, release and list endpoints and an SSE stream with a heartbeat, with #674's check; write each action to #672's log. A pause names a session.
- [ ] Failing tests first in `SessionPauseTests`.
- [ ] Commit.

### Task 2: Resident process subscription

- [ ] Subscribe with the token, apply pauses in every decision, write the pause state atomically, reconnect with backoff and resync.
- [ ] Announce each published configuration on the stream; fetch the profile at start, on the announcement, after a reconnect, and a day before expiry or halfway through a shorter lifetime, at once when that point has passed. Retry a failed fetch with bounded backoff and keep the last valid profile meanwhile. Verify the fetched profile, write it to the cache as #658 does, and swap the warm module.
- [ ] Tests in `ProfileRefreshTests`: a configuration published during a disconnect is used by the next resident decision; a fetch that fails once after a reconnect succeeds on retry without another trigger; a profile with a lifetime under a day is refreshed before it expires.
- [ ] Commit.

### Task 3: Hook deny

- [ ] Deny PreToolUse for a paused session with the agreed message, also on in-process evaluation.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*SessionPauseTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ProfileRefreshTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
