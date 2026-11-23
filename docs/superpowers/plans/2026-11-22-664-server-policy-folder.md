# Compile, validate and sign policy read from a folder (#664) Implementation Plan

**Goal:** The server part reads policy and node configuration from a folder on disk, compiles it into one module, validates it, and signs a profile per repository that the resident process fetches (ADR-107, ADR-236, ADR-233). Policy never arrives over HTTP. A central product fills that folder from the protected branch of a git repository; a standalone deployment keeps a git checkout of that branch there, for example with a git-sync sidecar.

**Issue:** #664, milestone "Controlled from a central server". Depends on #633, #654, #671, #672 and #659.

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
- The PR body says `Closes #664` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- The folder holds the Rego bundles and the node configuration: the nodes (organisation and teams in this version), which repositories belong to which node, which identity-provider groups bind to which role on which node, and per-node settings such as `fail_mode`, profile lifetime and detailed logging. `PolicyFolderTests`.
- On every change of the folder, the server compiles all bundles of that configuration version into one module identified by its hash. `PolicyFolderTests`.
- The server compiles only one complete version: it waits for changes to settle, hashes every file, compiles, and hashes again; when the hashes differ it retries and publishes nothing. The docs say the filler must swap the folder atomically, as git-sync does. `PolicyFolderTests`.
- Validation refuses a bundle that uses a builtin reaching outside the process, and a bundle below the organisation that defines an allow rule. `PolicyValidationTests`.
- A configuration that fails validation is not published; the last good one stays in force, and the rejection is written to the audit log of #672. A published configuration is written there too. `PolicyValidationTests`.
- The server signs a profile per repository with the key the deployment gives it at startup, and serves it to a signed-in developer of the organisation. `ProfileServingTests`.
- No endpoint accepts policy or node configuration. `ProfileServingTests`.
- While the server is unreachable, a hook still denies a tool call that matches a deny rule in the last valid signed profile. `ProfileServingTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Read the folder

- [ ] Read bundles and node configuration from a configured folder; watch it for changes, debounce them, and compile only when the file hashes before and after the read match.
- [ ] Failing tests first in `PolicyFolderTests`, including a file changed during the read: nothing mixed is published.
- [ ] Commit.

### Task 2: Compile and validate

- [ ] Compile all bundles of a configuration version into one module with its hash; refuse outside-reaching builtins and allow rules below the organisation; keep the last good configuration; write publish and rejected publish to #672's log.
- [ ] Tests in `PolicyValidationTests`.
- [ ] Commit.

### Task 3: Sign and serve

- [ ] Sign a profile per repository with the deployment's key and serve it to a signed-in developer; no endpoint accepts policy.
- [ ] Tests in `ProfileServingTests`.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*PolicyFolderTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*PolicyValidationTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*ProfileServingTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
