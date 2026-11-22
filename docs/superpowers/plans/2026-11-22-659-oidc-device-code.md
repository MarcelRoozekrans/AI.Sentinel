# Sign in to the server with an OIDC device code (#659) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The developer signs in once from the CLI with an OIDC device code; the local process holds and refreshes the token and uses it on every server request.

**Issue:** #659, milestone "Controlled from a central server". Depends on #658.

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
- The PR body says `Closes #659` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test named in the tasks.

- A developer can sign in with a device code from the CLI, against any OIDC provider that supports the device authorization grant. `DeviceCodeSignInTests` with a fake provider.
- The local process sends the token on every request to the server. `DeviceCodeSignInTests`.
- The token is refreshed without a new sign-in until the refresh token expires, then the process reports that sign-in is needed and behaves as server unreachable. `DeviceCodeSignInTests`.
- The token is never written to the audit, logs or any destination but the server, and is stored with the OS user's file permissions only. `DeviceCodeSignInTests`.
- The server reads the developer and their groups from the token. `DeviceCodeSignInTests`.
- A magic link is out of scope.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Device-code flow

- [ ] Implement discovery, the device authorization request and polling with an injectable HTTP handler; failing tests first.
- [ ] Commit.

### Task 2: Token storage and refresh

- [ ] Store the tokens in the state folder readable only by the user; refresh before expiry.
- [ ] Commit.

### Task 3: CLI command

- [ ] Add a sign-in command to the managed `sentinel` CLI or the process tool that prints the verification URL and code.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that the setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*DeviceCodeSignInTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
