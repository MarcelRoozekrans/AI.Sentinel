# Native AOT Release Binaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Releases ship Native AOT builds of `sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp`, as RID-specific .NET tool packages on NuGet and as attested archives on the GitHub release.

**Architecture:** The three CLI projects become net10.0-only RID tool packages. They are AOT for four RIDs, with an `any` framework-dependent fallback. One reusable workflow, `native-cli.yml`, packs each RID package on its native runner, extracts the binary, smoke-tests it and archives it. The PR check and the release both call it, so a PR exercises exactly the bits a release ships. The release pushes the RID packages before the pointer packages.

**Tech Stack:** .NET 10 SDK (RID-specific tools), GitHub Actions (reusable workflows, `actions/attest-build-provenance`), PowerShell 7 smoke script.

**Spec:** `docs/superpowers/specs/2026-10-31-aot-release-binaries-design.md`

## Global Constraints

- RIDs: `linux-x64` on `ubuntu-latest`, `linux-arm64` on `ubuntu-24.04-arm`, `osx-arm64` on `macos-latest`, `win-x64` on `windows-latest`, plus the `any` fallback.
- `ToolPackageRuntimeIdentifiers` = `linux-x64;linux-arm64;osx-arm64;win-x64;any`.
- The three CLIs target `net10.0` only. Every library keeps `net8.0;net10.0`. `AI.Sentinel.Cli` is unchanged.
- Package IDs and `ToolCommandName`s are unchanged.
- Archive name: `<command>-<version>-<rid>.tar.gz` for Linux/macOS, `.zip` for win-x64. The archive contains only the binary, renamed to `<command>` (`<command>.exe` on Windows).
- The pointer and all RID packages carry the same version. RID and `any` packages are pushed before the pointer packages.
- `gh release upload --clobber`; `dotnet nuget push --skip-duplicate`.
- The breaking commit is `feat!:` with a `BREAKING CHANGE:` footer. No nested parentheses in commit bodies. No Claude trailer, "Generated with" line or session link anywhere.
- On the VM: never AOT-publish locally and never `dotnet test` the solution. Run the test DLLs with `-noclass "*DetectorRegistrationTrimTests"`. AOT legs are verified in CI only.
- Package versions stay pinned exactly, and actions stay pinned at the major tags the repo already uses (`actions/checkout@v7`, `actions/setup-dotnet@v6`).

## Review Focus

1. **A pointer package pushed while one of its RID packages is missing.** Every user on that RID gets a failed install. The release push order and the `needs:` chain must make this impossible. Task 4 verifies it by checking the job graph and the push steps.
2. **`dotnet tool install` resolving to the `any` package on a native RID.** The user silently gets the slow build. Task 3's `tool-install` job asserts that the installed tool is native.
3. **The `any` package on a platform without a native build.** It must still run on the .NET 10 runtime: invariant globalization off, SQLite native libs present. Task 1 installs the locally packed `any` package and runs the smoke script against it.
4. **Smoke on Linux/macOS binaries.** No `.exe` and no execute bit after extraction from a `.nupkg` (zip). The script must `chmod +x` and must not glob on `*.exe`. Task 2 runs the script on Linux.
5. **The net8.0 test leg after the CLI references become conditional.** The CLI test files must be excluded, so the net8.0 build doesn't fail. A silently shrunk net10.0 leg is a failure too. Task 1 compares test counts before and after.

---

### Task 1: CLIs become net10.0 RID tool packages

**Files:**
- Create: `eng/NativeTool.props`
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj`, `src/AI.Sentinel.Copilot.Cli/AI.Sentinel.Copilot.Cli.csproj`, `src/AI.Sentinel.Mcp.Cli/AI.Sentinel.Mcp.Cli.csproj`
- Modify: `tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj`

**Interfaces:**
- Produces: a plain `dotnet pack <cli>` yields the pointer `<Id>.<v>.nupkg`. `dotnet pack <cli> -r <rid>` yields `<Id>.<rid>.<v>.nupkg`. `dotnet pack <cli> -r any -p:PublishAot=false` yields `<Id>.any.<v>.nupkg`. Inside a RID package, the binary is at `tools/net10.0/<rid>/<AssemblyName>[.exe]`.

- [ ] **Step 1: Record the baseline test counts.** Build `tests/AI.Sentinel.Tests` and run the net8.0 and net10.0 DLLs with `-noclass "*DetectorRegistrationTrimTests"`. Note the total for each. Expected: the counts are noted, all pass.
- [ ] **Step 2: Create `eng/NativeTool.props`.** It sets:
  - `TargetFrameworks` empty and `TargetFramework` `net10.0`, the same pattern as `tests/AI.Sentinel.Aot.Probe`, because `Directory.Build.props` sets `TargetFrameworks`;
  - `PackAsTool` `true`;
  - `PublishAot` `true`, but only when it is not already set from outside (`Condition="'$(PublishAot)' == ''"`), so that `-p:PublishAot=false` wins;
  - `ToolPackageRuntimeIdentifiers` as in Global Constraints;
  - `InvariantGlobalization` `true` when `PublishAot` is `true`.
- [ ] **Step 3: Update the three CLI projects.** Import the props file. Remove `TargetFrameworks`, the conditional `PackAsTool` and `InvariantGlobalization`. Keep `ToolCommandName`, `PackageId` and the IL2104 `NoWarn` with its comment.
- [ ] **Step 4: Update the test project.** In `AI.Sentinel.Tests.csproj`, give the three CLI `ProjectReference`s `Condition="'$(TargetFramework)' == 'net10.0'"`. Add `<Compile Remove>` for net8.0 covering the 11 files that use CLI types:
  - `Mcp/McpAuditTests.cs`, `Mcp/McpCliTests.cs`, `Mcp/ResourceReadInterceptorTests.cs`, `Mcp/CliSeverityFlagsTests.cs`;
  - `Copilot/CopilotHookCliTests.cs`, `Copilot/CopilotHookCliFailClosedTests.cs`, `Copilot/CopilotHookCliAuditTests.cs`;
  - `ClaudeCode/HookCliTests.cs`, `ClaudeCode/HookCliFailClosedTests.cs`, `ClaudeCode/HookWireFormatTests.cs`, `ClaudeCode/HookCliAuditTests.cs`.

  If one of these files uses only library types, keep it on net8.0 and drop it from the list.
- [ ] **Step 5: Build.** `dotnet build AI.Sentinel.slnx -c Release`. Expected: 0 warnings, 0 errors. AOT and trim analyzers now run on the CLIs. Fix any new IL warning at its source; do not add it to `NoWarn`.
- [ ] **Step 6: Run the tests.** Run both DLLs as in Step 1. Expected: net10.0 total unchanged, net8.0 total lower by exactly the tests in the removed files, all pass.
- [ ] **Step 7: Check the packs, without AOT.** For `src/AI.Sentinel.ClaudeCode.Cli`, run `dotnet pack -c Release -p:PackageVersion=0.0.0-local -o /tmp/p456` and `dotnet pack -c Release -r any -p:PublishAot=false -p:PackageVersion=0.0.0-local -o /tmp/p456`. Expected: `AI.Sentinel.ClaudeCode.Cli.0.0.0-local.nupkg` and `AI.Sentinel.ClaudeCode.Cli.any.0.0.0-local.nupkg`. The pointer's `tools/net10.0/any/DotnetToolSettings.xml` lists the five RIDs.
- [ ] **Step 8: Check that the `any` package runs.** Run `dotnet tool install AI.Sentinel.ClaudeCode.Cli --version 0.0.0-local --tool-path /tmp/t456 --add-source /tmp/p456`. Expected: this fails or falls through on linux-x64, because the linux-x64 RID package is not in the source. Record which. Then install from the `any` package alone with `--add-source` and pipe `{"session_id":"x","prompt":"hello"}` into `sentinel-hook user-prompt-submit`. Expected: exit 0. If the CLI cannot install `any` on a RID it has a native entry for, keep this check for Task 2's script run and note the finding in the commit body.
- [ ] **Step 9: Commit.**

```bash
git commit -m "feat!: ship sentinel-hook, sentinel-copilot-hook and sentinel-mcp as RID-specific AOT tools

The three CLI tool packages are now .NET 10 RID-specific tools: Native AOT
for linux-x64, linux-arm64, osx-arm64 and win-x64, with a framework-dependent
any fallback. The net8.0 test leg no longer builds the CLI tests.

BREAKING CHANGE: AI.Sentinel.ClaudeCode.Cli, AI.Sentinel.Copilot.Cli and
AI.Sentinel.Mcp.Cli target net10.0 only and need the .NET 10 SDK to install."
```

### Task 2: Shared smoke script

**Files:**
- Create: `eng/smoke-native.ps1`

**Interfaces:**
- Produces: `pwsh eng/smoke-native.ps1 -Binary <path> -Kind <hook|copilot-hook|mcp>`. It exits 0 on pass and non-zero with an `::error::` line on fail. On non-Windows it runs `chmod +x` on the binary first.

- [ ] **Step 1: Write the script.** Port the checks from the Smoke test step in `.github/workflows/aot-publish.yml`, unchanged:
  - MCP: exit 1 and `Usage` on the error output;
  - hooks: exit 0 on a benign prompt and the SQLite file is created; exit 2 on `ignore all previous instructions`; the NDJSON file contains `SEC-01`; no `audit:` in the output;
  - the `user-prompt-submit` / `user-prompt-submitted` fallback becomes explicit per `-Kind`: `hook` uses `user-prompt-submit`, `copilot-hook` uses `user-prompt-submitted`.

  Temp paths come from `$env:RUNNER_TEMP`, falling back to `[IO.Path]::GetTempPath()`. Also check size: warn above 20 MB.
- [ ] **Step 2: Run the script against the framework-dependent tools.** Install `sentinel-hook`, `sentinel-copilot-hook` and `sentinel-mcp` from locally packed `any` packages into `/tmp/t456` (as in Task 1 Step 8). Run the script with the matching `-Kind` on each command shim. Expected: all three pass.
- [ ] **Step 3: Check the failure path.** Run the script with `-Kind hook` against the `sentinel-mcp` shim. Expected: non-zero exit with an `::error::` line.
- [ ] **Step 4: Commit.** Message: `ci: add a cross-platform smoke script for the native CLIs`.

### Task 3: Reusable native workflow and the PR check

**Files:**
- Create: `.github/workflows/native-cli.yml`
- Modify: `.github/workflows/aot-publish.yml`

**Interfaces:**
- Consumes: `eng/smoke-native.ps1` (Task 2); pack commands (Task 1).
- Produces: `native-cli.yml`, `on: workflow_call`.
  - Input: `version` (string, required).
  - Artifacts: `native-<cli>-<rid>`, each holding `<Id>.<rid>.<version>.nupkg` and the archive.
  - Matrix: `cli` ∈ `{ClaudeCode.Cli/sentinel-hook/hook, Copilot.Cli/sentinel-copilot-hook/copilot-hook, Mcp.Cli/sentinel-mcp/mcp}` × the four RIDs and runners from Global Constraints, using `include` entries for `rid` + `os`.
  - Permissions: `contents: read`, `id-token: write`, `attestations: write`.
  - Input `attest` (boolean, default `false`): attest only when it is `true`.

- [ ] **Step 1: Write `native-cli.yml`.** Steps per leg:
  1. checkout and setup-dotnet with `global-json-file: global.json`;
  2. `dotnet pack src/AI.Sentinel.<cli>/AI.Sentinel.<cli>.csproj -c Release -r <rid> -p:PackageVersion=<version> -p:Version=<version> -o out`;
  3. extract `tools/net10.0/<rid>/` from the RID `.nupkg` (`unzip`, or `Expand-Archive` on Windows);
  4. copy the AOT binary to `<command>[.exe]`;
  5. `pwsh eng/smoke-native.ps1 -Binary <path> -Kind <kind>`;
  6. archive it under the Global Constraints name;
  7. `actions/attest-build-provenance` on the archive when `attest` is true;
  8. `actions/upload-artifact` of the `.nupkg` and the archive.
- [ ] **Step 2: Rewrite `aot-publish.yml`.** Job `native` calls `native-cli.yml` with `version: 0.0.0-ci.${{ github.run_number }}` and `attest: false`. Keep the MCP nested-JSON round-trip as job `mcp-roundtrip`, which needs `native`, runs on `windows-latest`, downloads `native-Mcp.Cli-win-x64`, extracts the archive and runs the existing round-trip script against `sentinel-mcp.exe`. The script itself is unchanged, apart from its binary-path lookup.
- [ ] **Step 3: Add job `tool-install`.** It needs `native` and runs on `ubuntu-latest`:
  1. download all `native-*-linux-x64` artifacts;
  2. pack the pointer and `any` packages for the three CLIs with the same version;
  3. `dotnet tool install <Id> --version <version> --tool-path tools --add-source <folder>` for each;
  4. assert that `tools/.store/<id-lowercase>/<version>/` contains no `AI.Sentinel.*.Cli.dll`, which proves the native package was chosen;
  5. run `eng/smoke-native.ps1` on each `tools/<command>`.
- [ ] **Step 4: Lint.** Run `actionlint .github/workflows/native-cli.yml .github/workflows/aot-publish.yml`, installing actionlint into `/tmp` if needed. Expected: no findings.
- [ ] **Step 5: Commit.** Message: `ci: build, smoke and install the native CLIs on four runners`.
- [ ] **Step 6: CI gate.** Run `dotnet format whitespace . --folder --verify-no-changes`, CI's first step. Expected: no changes. Then ask Marcel before pushing. After his yes, push the branch and open a draft PR. Expected: 12 `native` legs, `mcp-roundtrip` and `tool-install` all green. Fix failures in this task's files, plus Task 1/2 files if a leg exposes an AOT or script defect. Tell Marcel that the required check names changed to `native / native (...)`, `mcp-roundtrip` and `tool-install`.

### Task 4: Release workflow

**Files:**
- Modify: `.github/workflows/release-please.yml`

**Interfaces:**
- Consumes: `native-cli.yml` (Task 3), called with `version: ${{ needs.release-please.outputs.version }}` and `attest: true`.

- [ ] **Step 1: Add job `native`.** It needs `release-please`, runs only `if: release_created`, and has `uses: ./.github/workflows/native-cli.yml` with `id-token: write` and `attestations: write` permissions.
- [ ] **Step 2: Change job `publish`.** It now has `needs: [release-please, native]`. Keep the existing build, test and library pack loop, minus the three CLIs. Add:
  - for each CLI: `dotnet pack` (the pointer) and `dotnet pack -r any -p:PublishAot=false` into `./nupkg-pointer` and `./nupkg-rid`;
  - `actions/download-artifact` with `pattern: native-*` and `merge-multiple: true` into `./native`, with the RID `.nupkg` files moved to `./nupkg-rid`;
  - push step 1: `./nupkg-rid/*.nupkg`;
  - push step 2: `./nupkg/*.nupkg` and `./nupkg-pointer/*.nupkg`;
  - `sha256sum` over `./native/*.tar.gz ./native/*.zip` into `SHA256SUMS`;
  - `actions/attest-build-provenance` on `SHA256SUMS`;
  - `gh release upload --clobber` of the archives, `SHA256SUMS` and every `.nupkg`.

  `publish` gets `id-token: write`, `attestations: write` and `contents: write`.
- [ ] **Step 3: Lint and check the graph.** Run actionlint on `release-please.yml`. Then confirm by reading the file:
  - no push step runs before `native` has succeeded;
  - pointer packages appear only in push step 2;
  - the release-please guard job and the token minting are untouched.

  Expected: all three hold.
- [ ] **Step 4: Commit.** Message: `ci: release native CLI packages and attested archives`.

### Task 5: Docs

**Files:**
- Modify: `website/docs/integrations/claude-code.md`, `website/docs/integrations/copilot.md`, `website/docs/integrations/mcp-proxy.md`, `README.md`

- [ ] **Step 1: Update the install sections.** In all four files, `dotnet tool install` needs the .NET 10 SDK, and the native build is chosen automatically on linux-x64, linux-arm64, osx-arm64 and win-x64. Other platforms get the framework-dependent build.
- [ ] **Step 2: Replace the claude-code.md "Native binary (faster cold start)" section** with "Native binary without the .NET SDK":
  - download `<command>-<version>-<rid>` from the GitHub release;
  - `sha256sum -c SHA256SUMS --ignore-missing`;
  - `gh attestation verify <archive> --repo MarcelRoozekrans/AI.Sentinel`;
  - extract it and point the hook `command` at the path;
  - macOS `xattr -d com.apple.quarantine`, Windows `Unblock-File`;
  - a one-line local `dotnet publish -p:PublishAot=true` recipe for other RIDs.

  `copilot.md` and `mcp-proxy.md` link to this section instead of copying it.
- [ ] **Step 3: Add a migration note** in claude-code.md under the install section: a machine with only the .NET 8 SDK installs the .NET 10 SDK, or uses the release binary, which needs no runtime.
- [ ] **Step 4: Build the docs.** Run `npm ci && npm run build` in `website/`. Expected: build passes with no broken-link errors.
- [ ] **Step 5: Commit.** Message: `docs: native install path for the hook and MCP CLIs`.
