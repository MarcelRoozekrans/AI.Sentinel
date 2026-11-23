# Sign in with an OIDC device code, refresh token in the OS keychain (#659) Implementation Plan

**Goal:** The developer signs in once from the CLI through the organisation's identity provider with an OIDC device code. The resident process holds and refreshes the token and sends it on every server request, so the server knows which developer a hook belongs to. A token per PC is not used: it identifies a machine, not a person. The refresh token is a secret and never lands in a plain file (ADR-005, ADR-230).

**Issue:** #659, milestone "Controlled from a central server". Depends on #658.

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
- The PR body says `Closes #659` and lists which acceptance criterion each test covers.

## Acceptance criteria

From the issue. Each has a test or check named after it.

- A developer signs in with a device code from the CLI, against any OIDC provider that supports the device authorization grant. `DeviceCodeSignInTests`.
- At sign-in the plugin pins the server's public keys for #671. `DeviceCodeSignInTests`.
- The refresh token goes into the OS keychain: Windows Credential Manager, macOS Keychain, Linux Secret Service. Where none exists, such as headless Linux, it is held in memory only by the resident process, and the developer signs in again after the process restarts. It is never written to a file. `TokenStorageTests`.
- The resident process sends the access token on every request to the server and refreshes it without a new sign-in until the refresh token expires; then it reports that sign-in is needed. A provider that issues no refresh token still signs in: the access token is used until it expires, and then the process reports that sign-in is needed. `DeviceCodeSignInTests`.
- A token never appears in the audit, logs or any destination but the identity provider and the server. `TokenStorageTests`.
- The server reads the developer and their groups from the token. The host validates the token; #674 maps its subject and groups claims and tests that. `DeviceCodeSignInTests`.
- With none of the new settings, behaviour is unchanged. Existing suite.

## Tasks

### Task 1: Device code sign-in

- [ ] Add a sign-in command using the device authorization grant against a configured issuer; pin the server keys at sign-in.
- [ ] Failing tests first in `DeviceCodeSignInTests` against a fake provider.
- [ ] Commit.

### Task 2: Token storage

- [ ] Store the refresh token in Windows Credential Manager, macOS Keychain or Linux Secret Service; fall back to memory in the resident process. Never a file.
- [ ] Tests in `TokenStorageTests`, including a check that nothing is written to disk.
- [ ] Commit.

### Task 3: Use and refresh

- [ ] Send the access token on server requests, refresh it, and report when sign-in is needed. Without a refresh token, use the access token until it expires, then report that sign-in is needed; test it in `DeviceCodeSignInTests`. Keep tokens out of audit and logs.
- [ ] Commit.

### Task 4: Document it

- [ ] Update the README and the docs page under `website/docs` that covers this area; state that every new setting is optional and off by default.
- [ ] Commit as `docs`.


## Checks

- build: `dotnet build AI.Sentinel.slnx -c Release`
- test: `dotnet format whitespace . --folder --verify-no-changes`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*DeviceCodeSignInTests*/*"`
- test: `dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*TokenStorageTests*/*"`
- test: `dotnet test AI.Sentinel.slnx -c Release`
