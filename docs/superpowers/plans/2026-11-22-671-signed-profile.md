# Signed policy profile with pinned server keys (#671) Implementation Plan

**Goal:** The PC must only enforce policy that the organisation's server produced. The server signs each profile, and the plugin pins the server's keys at sign-in and rejects anything else (ADR-233). This issue builds the profile format, signing and verification as library code that #658 and #664 use.

**Issue:** #671, milestone "Controlled from a central server".

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
- The PR body says `Closes #671` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- A profile holds organisation, repository, node, configuration version, module hash and module, `fail_mode`, severity defaults, logging switches, issue time and expiry. `SignedProfileTests`.
- It is signed with Ed25519 over a canonical JSON form; the same profile always gives the same bytes to sign. `SignedProfileTests`.
- Verification accepts a profile signed by a pinned key, or by a new key endorsed by a pinned key, and rejects any other signature, a changed byte, an expired profile, and a profile whose organisation or repository does not match the ones asked for. Each rejection has its own reason. `SignedProfileTests`, `ProfileKeyPinningTests`.
- The default lifetime is 7 days and can be set per organisation. `SignedProfileTests`.
- The signing side takes its key from the deployment at startup, never fetches it at runtime and never stores it. It can hold an old and a new key side by side for rotation, and endorse the new one with the old. `ProfileKeyPinningTests`.
- The Ed25519 implementation runs under Native AOT without warnings on Windows, Linux and macOS. If no such implementation fits, this issue waits for review with that finding. AOT publish check.
- Nothing uses the profile yet; with none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Profile and canonical form

- [ ] Add the profile record and its canonical JSON form with a source-generated context.
- [ ] Failing tests first in `SignedProfileTests`: same profile, same bytes.
- [ ] Commit.

### Task 2: Sign and verify

- [ ] Choose an Ed25519 implementation that publishes under Native AOT without warnings; name the choice and why in the PR body. If none fits, stop and report it on the issue.
- [ ] Extend `tests/AI.Sentinel.Aot.Probe` to sign and verify a profile, since no CLI uses the profile yet and trimming would drop it. Add a step to the native workflow matrix that AOT-publishes and runs the probe on Windows, Linux and macOS.
- [ ] Sign and verify; reject a changed byte, an expired profile and a mismatched organisation or repository, each with its own reason.
- [ ] Commit.

### Task 3: Key pinning and rotation

- [ ] Pin keys; accept a key endorsed by a pinned one; hold old and new signing keys side by side. Keys come from the deployment at startup.
- [ ] Tests in `ProfileKeyPinningTests`.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*SignedProfileTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ProfileKeyPinningTests*/*"`
- test: `dotnet publish tests/AI.Sentinel.Aot.Probe/AI.Sentinel.Aot.Probe.csproj -c Release -r linux-x64 -warnaserror`
- test: `dotnet test AI.Sentinel.slnx -c Release`
