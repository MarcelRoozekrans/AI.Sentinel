# Evaluate a local Rego policy folder in the hook CLIs (#654) Implementation Plan

**Goal:** `sentinel-hook` and `sentinel-copilot-hook` evaluate the Rego files in `SENTINEL_HOOK_POLICY_DIR` against each PreToolUse call and act on the outcome. This is the policy a PC uses without a server; with a server it is combined with the signed profile in #656 and can only tighten (ADR-007).

**Issue:** #654, milestone "Controlled from a central server". Depends on #633, #669 and #670. If #633 names no working route, or no route fits 50 ms per call, this issue waits for review.

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
- The PR body says `Closes #654` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- The PC compiles the folder itself, unsigned, as one level, with the route #633 chose. `RegoPolicyDenyTests`.
- The policy is package `sentinel` and gets the input from #669. It returns one of the five outcomes from #670, with a reason; the strictest across policy and the existing sources wins. A command the #669 parser marks unparseable gets at least **ask**, even when the policy returns **allow**. `RegoPolicyDenyTests`.
- With a Rego policy configured, a hook denies a tool call that matches a deny rule, and the agent sees the rule's reason. `RegoPolicyDenyTests`.
- The decision is recorded in the local audit with its reason, the policies that caused it and the policy version, like other blocks. `RegoPolicyDenyTests`.
- A policy folder that cannot be read or compiled blocks PreToolUse with an internal-error reason. `RegoPolicyLoadFailureTests`.
- A bundle that uses a builtin reaching outside the process is refused when compiled; met at runtime, it denies with a reason that names the builtin. `RegoPolicyLoadFailureTests`.
- The whole decision, from building the input through evaluation to combining the outcome, stays within 50 ms per call, measured in a test on the CI runners. `RegoPolicyDenyTests`.
- With `SENTINEL_HOOK_POLICY_DIR` unset, the hooks behave exactly as before. Existing suite.

## Tasks

### Task 1: Read and compile the folder

- [x] Read `SENTINEL_HOOK_POLICY_DIR` in both hook configs; compile it with the route from #633, validating builtins.
- [x] Failing tests first.
- [x] Commit.

### Task 2: Evaluate and combine

- [x] Evaluate against the #669 input; combine the outcome with the existing sources and with the parser's unparseable result (**ask**, #669) through #670's strictest-wins.
- [x] Tests in `RegoPolicyDenyTests`, including an unparseable command under an allowing policy that gives **ask**, and a budget test on the CI runners that times the whole decision, not evaluation alone.
- [x] Commit.

### Task 3: Failures

- [x] A folder that cannot be read or compiled blocks PreToolUse with an internal-error reason; a runtime builtin call denies and names it.
- [x] Tests in `RegoPolicyLoadFailureTests`.
- [x] Commit.

### Task 4: Document it

- [x] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [x] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*RegoPolicyDenyTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*RegoPolicyLoadFailureTests*/*"`
- test: `dotnet publish src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj -c Release -r linux-x64 -warnaserror`
- test: `dotnet publish src/AI.Sentinel.Copilot.Cli/AI.Sentinel.Copilot.Cli.csproj -c Release -r linux-x64 -warnaserror`
- test: `dotnet test AI.Sentinel.slnx -c Release`
