# Run the server part without a central product (#666) Implementation Plan

**Goal:** A team that has no central product runs AI.Sentinel's server part on its own. This adds a sample host under `samples/` and a docs page that take a team from an empty host to approving, denying, pausing and releasing over the HTTP API.

**Issue:** #666, milestone "Controlled from a central server". Depends on #661, #662, #663, #664 and #675.

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
- The PR body says `Closes #666` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- Without a central product installed, a team can run the server part on its own and approve, deny, pause and release over its HTTP API by following the docs page with the sample host; a test drives the sample through those four actions. `StandaloneServerSampleTests`.
- The docs page shows how the policy folder is kept up to date from a git checkout of the protected branch, for example with a git-sync sidecar, and how the signing key reaches the host at startup. Docs.
- It shows the identity-provider setup for the device-code sign-in and the group-to-role bindings. Docs.
- It shows how to export the audit log and verify it offline with the `sentinel` command. Docs.
- The docs page states that every new setting is optional and that, without them, AI.Sentinel behaves exactly as before. Docs.

## Tasks

### Task 1: Sample host

- [ ] Add `samples/AI.Sentinel.ServerSample` with the server endpoints, a policy folder, signing key from configuration, sign-in and authorization configured.
- [ ] Commit.

### Task 2: Smoke test

- [ ] Add `StandaloneServerSampleTests` that hosts the sample in-process and runs approve, deny, pause and release.
- [ ] Commit.

### Task 3: Docs page

- [ ] Add the page under `website/docs`: policy folder kept up to date by a git checkout or git-sync sidecar, signing key, identity provider and role bindings, audit export and offline verify. Link it from the README.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*StandaloneServerSampleTests*/*"`
- test: `dotnet build samples/AI.Sentinel.ServerSample/AI.Sentinel.ServerSample.csproj -c Release`
- test: `dotnet test AI.Sentinel.slnx -c Release`
