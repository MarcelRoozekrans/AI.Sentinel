# Resident local process with the signed profile cache and the pause state (#658) Implementation Plan

**Goal:** Add the resident local process: one per user, part of the plugin. It keeps the compiled module warm and answers decisions for the hooks, holds the signed profile cache (#671) and the pause state, and later keeps the connection to the server. The hooks read its state from disk, without network traffic.

**Issue:** #658, milestone "Controlled from a central server". Depends on #655 and #671.

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
- The PR body says `Closes #658` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- A hook that finds no running process, by a single-instance lock, starts it detached and evaluates that call in-process. `ResidentProcessLifecycleTests`.
- Only one process runs per user; it exits after 30 idle minutes. No OS service is installed. `ResidentProcessLifecycleTests`.
- Evaluation order: the resident process answers first; if it does not answer within its budget, the hook evaluates the cached module in-process; if that fails too, the server is asked once a server exists. The whole decision fits 50 ms per call. `EvaluationOrderTests`.
- Each decision records where it was made: resident, in-process or server. `EvaluationOrderTests`.
- The process writes the signed profile cache and the pause state to the per-user state folder with write-then-rename; a hook never reads a half-written file. `ResidentProcessStateTests`.
- A cached profile is used offline until it expires; a profile that fails its signature check, has expired, or names another organisation or repository is not used. What happens then is #673. `ResidentProcessStateTests`.
- While the server is unreachable, a hook still denies a tool call that matches a deny rule in the last valid signed profile. `ResidentProcessStateTests`.
- A hook reads the pause state without network traffic, and a paused session's calls are denied. `ResidentProcessStateTests`.
- The process ships inside the existing Native AOT hook packages, so no new download is needed. AOT publish check.
- With none of the new settings, no process is started and behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Lifecycle

- [x] Add the resident mode to the hook binary: single-instance lock, detached start, 30-minute idle exit, no OS service.
- [x] Failing tests first in `ResidentProcessLifecycleTests`.
- [x] Commit.

### Task 2: Local channel

- [x] Answer decisions for hooks over a per-user local channel with a budget; fall back to in-process evaluation.
- [x] Record where each decision was made.
- [x] Tests in `EvaluationOrderTests`, including the 50 ms budget.
- [x] Commit.

### Task 3: State folder

- [x] Write the profile cache and pause state with write-then-rename; hooks read them without network traffic and verify the profile per #671.
- [x] Tests in `ResidentProcessStateTests`.
- [x] Commit.

### Task 4: Document it

- [x] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [x] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ResidentProcessLifecycleTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ResidentProcessStateTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*EvaluationOrderTests*/*"`
- test: `dotnet publish src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj -c Release -r linux-x64 -warnaserror`
- test: `dotnet publish src/AI.Sentinel.Copilot.Cli/AI.Sentinel.Copilot.Cli.csproj -c Release -r linux-x64 -warnaserror`
- test: `dotnet test AI.Sentinel.slnx -c Release`
