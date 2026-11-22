# Local process holds the last known policy and the pause state (#658) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the long-running local process and the state folder it writes, which the hooks read without network traffic.

**Issue:** #658, milestone "Controlled from a central server". Depends on #656. The design for the process is the closing comment of #657.

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
- The PR body says `Closes #658` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- A hook that finds no running process, by the single-instance lock file, spawns it detached and handles that call as "server unreachable". `LocalAgentLifecycleTests`.
- Only one process runs per user; it exits after 30 idle minutes, tested with a fake clock. `LocalAgentLifecycleTests`.
- The process writes the compiled policy and `pause.json` to the per-user state folder with write-then-rename; a hook never reads a half-written file. `LocalAgentStateTests`.
- While the server is unreachable, a hook still denies a tool call that matches a blocking rule in the last known policy. `LocalAgentStateTests`.
- A hook reads the pause state without network traffic, shown by a test that fails on any socket use. `LocalAgentStateTests`.
- With none of the new settings, no process is started and behaviour is unchanged. `LocalAgentLifecycleTests` plus the existing suite.

## Tasks

### Task 1: State folder contract

- [ ] Define the per-user state folder per OS, the file names and the atomic write; hooks read the last known policy from it in preference to `SENTINEL_HOOK_POLICY_DIR` when a server is configured.
- [ ] Failing tests first.
- [ ] Commit.

### Task 2: Process host

- [ ] Add the process as a Native AOT tool, single instance by lock file, idle exit after 30 minutes on an injectable clock.
- [ ] Commit.

### Task 3: Lazy start from the hooks

- [ ] When a server is configured and the lock is free, the hook spawns the process detached and handles the call as server unreachable.
- [ ] Tests with the spawn behind an interface.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*LocalAgentLifecycleTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*LocalAgentStateTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
