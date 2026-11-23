# Set severity outcomes from the Rego policy (#655) Implementation Plan

**Goal:** The policy sets the action per finding severity on the hook CLIs, in place of or next to `SENTINEL_HOOK_ON_*`. The actions are outcomes from #670: Block is deny, Warn is guidance, Allow is defer, and the policy may also use ask or allow. Policy and variables combine strictest-wins (ADR-234).

**Issue:** #655, milestone "Controlled from a central server". Depends on #654.

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
- The PR body says `Closes #655` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- The same Rego policy sets the outcome for a finding by severity on a CLI host. `RegoSeverityActionTests`.
- When the policy and a `SENTINEL_HOOK_ON_*` variable both set an outcome for a severity, the stricter applies; the docs say so. A variable that is not set does not count: its built-in default applies only when the policy sets no outcome for that severity. `RegoSeverityActionTests`.
- Severity defaults carried in a profile (#671) are read the same way, so #658 can use them. `RegoSeverityActionTests`.
- With no policy, `SENTINEL_HOOK_ON_*` behave exactly as before. Existing suite.

## Tasks

### Task 1: Severity outcomes from policy

- [ ] Read the outcome per severity from the policy result; combine with `SENTINEL_HOOK_ON_*` strictest-wins. Keep whether each variable was set, since `HookConfig.FromEnvironment` fills in defaults such as Block for High; a default must not override the policy.
- [ ] Test a policy that sets **guidance** for High with `SENTINEL_HOOK_ON_HIGH` unset: the outcome is **guidance**.
- [ ] Failing tests first in `RegoSeverityActionTests`.
- [ ] Commit.

### Task 2: Profile severity defaults

- [ ] Read severity defaults from a #671 profile the same way.
- [ ] Commit.

### Task 3: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*RegoSeverityActionTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
