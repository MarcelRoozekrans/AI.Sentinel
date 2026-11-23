# Five decision outcomes in the hook CLIs, mapped per CLI (#670) Implementation Plan

**Goal:** Give the hook CLIs one set of decision outcomes that policy, the approval config and the `SENTINEL_HOOK_ON_*` variables all produce, and map it onto what each CLI can express (ADR-234). Today a hook has Block, Warn and Allow.

**Issue:** #670, milestone "Controlled from a central server".

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
- The PR body says `Closes #670` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- There are five outcomes, strictest first: **deny**, **ask**, **guidance**, **allow**, **defer**. When several sources give an outcome for one call, the strictest wins. `DecisionOutcomeTests`.
- The severity actions map as Block to deny, Warn to guidance, Allow to defer. `SENTINEL_HOOK_ON_*` keep their values and their current effect. `CliOutcomeMappingTests`.
- **allow** and **defer** emit no permission decision, so the CLI's own permission prompt still applies. `CliOutcomeMappingTests`.
- **guidance** lets the call run and passes the advice to the agent where the CLI can return context; where it cannot, the hook behaves as today for Warn. `CliOutcomeMappingTests`.
- **ask** uses the CLI's own ask where it has one. Where the CLI cannot ask, or the run is headless, **ask** becomes **deny** with instructions: explain the command and why it is needed, then let the developer run it or a policy owner allow it. `CliOutcomeMappingTests`.
- Every decision carries a reason, the sources that caused it, and a policy version field (empty until policy exists). The local audit records them. `DecisionOutcomeTests`.
- The docs give a table per CLI (Claude Code, Copilot CLI) of how each outcome is expressed. Docs.
- With none of the new settings, each hook gives the same output for the same input as before; the existing tests pass unchanged. Existing suite.

## Tasks

### Task 1: Outcome type and strictest-wins

- [ ] Add the five outcomes with their order, a combine operation, and the decision record with reason, sources and policy version.
- [ ] Failing tests first in `DecisionOutcomeTests`.
- [ ] Commit.

### Task 2: Map the severity actions

- [ ] Map Block, Warn and Allow onto deny, guidance and defer inside the hooks without changing their output.
- [ ] Commit.

### Task 3: Per-CLI output

- [ ] Emit each outcome per CLI: no permission decision for allow and defer, context for guidance, ask where the CLI can, deny with instructions where it cannot or the run is headless.
- [ ] Tests in `CliOutcomeMappingTests` per CLI.
- [ ] Record reason, sources and policy version in the local audit.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*DecisionOutcomeTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*CliOutcomeMappingTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
