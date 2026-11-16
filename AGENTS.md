# AGENTS.md: AI.Sentinel

AI.Sentinel is security monitoring middleware for `IChatClient` (Microsoft.Extensions.AI). It scans
prompts and responses with detectors, applies an intervention action, and writes an audit trail. It
ships as NuGet libraries (`AI.Sentinel` core plus AspNetCore dashboard, Sqlite, Approvals, OpenTelemetry,
AzureSentinel and Detectors.Sdk) and as three Native AOT tools: `sentinel-hook` (Claude Code),
`sentinel-copilot-hook` and `sentinel-mcp`. The `sentinel` CLI is a managed tool.

## Layout

- Only `src/` ships. `tests/`, `benchmarks/`, `samples/` and `tools/` do not.
- `tools/AI.Sentinel.ComplianceEval` is outside `AI.Sentinel.slnx` on purpose: running it downloads a
  model. CI builds it so it cannot drift from the internals it reads.
- `samples/` and `benchmarks/` have their own `Directory.Build.props` that clears `TargetFrameworks`,
  so each project sets its own `TargetFramework`.
- `src/AI.Sentinel.ClaudeCode.Cli`, `Copilot.Cli` and `Mcp.Cli` target `net10.0` only and share
  `eng/NativeTool.props`. `AI.Sentinel.Tests` therefore compiles out the CLI test files on `net8.0`
  (see the `Compile Remove` items in its csproj): a new CLI test file needs the same entry.
- `artifacts/` is ignored; local pack output can go there.
- `website/` is the Docusaurus docs site, built by `docs.yml` only.

## Build and test

Prerequisites: `global.json` pins SDK `11.0.100` with `rollForward: latestMinor`, so SDK 10 does not
satisfy it. It also selects the Microsoft.Testing.Platform runner for `dotnet test`. Libraries and tests
target `net8.0`, `net10.0` and `net11.0` (most `src/` libraries also `net9.0`), so the .NET 8, 10 and
11 runtimes must be installed; test projects do not target `net9.0`. `AI.Sentinel.Tests` sets `RollForward` to `LatestMajor`;
the other test projects do not. The AOT jobs also need the .NET 10 SDK. No other `global.json` exists.

CI job `build-test` in `.github/workflows/ci.yml`:

```bash
dotnet format whitespace . --folder --verify-no-changes
dotnet restore AI.Sentinel.slnx
dotnet build AI.Sentinel.slnx --no-restore -c Release
dotnet build tools/AI.Sentinel.ComplianceEval/AI.Sentinel.ComplianceEval.csproj -c Release
dotnet test AI.Sentinel.slnx --no-build -c Release --verbosity normal --coverage --coverage-output-format cobertura --coverage-settings coverage.config.xml --results-directory TestResults
```

The next step, the `Coverage gate` action from ci-baseline, is not a plain command: it merges
`TestResults/**/*.cobertura.xml` and fails below 80 percent line coverage. The sequence above
produces the reports but does not reproduce the gate.

CI job `ndjson-windows` in `ci.yml` (the NDJSON forwarder locking needs Windows file sharing):

```bash
dotnet build tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj -c Release
dotnet test --project tests/AI.Sentinel.Tests/AI.Sentinel.Tests.csproj --no-build -c Release --filter-query "/*/*/*Ndjson*/*" --filter-query "/*/*/*/*Ndjson*"
```

CI job `tool-install` in `.github/workflows/aot-publish.yml` packs the pointer package of each CLI. The
native RID packages are built by `native-cli.yml` on a runner per OS, so they do not reproduce locally.
Pointer package check, run from the repo root:

```bash
SHA=$(git rev-parse --short HEAD); dotnet pack src/AI.Sentinel.Mcp.Cli/AI.Sentinel.Mcp.Cli.csproj -c Release -p:PackageVersion=9.9.9-local.$SHA -p:Version=9.9.9-local.$SHA -o /tmp/sentinel-feed
```

Inner loop, not run by any CI job. `dotnet test` on a project is a Microsoft.Testing.Platform run, so
the project goes in `--project` and tests are selected with `--filter-query`:

```bash
dotnet test --project tests/AI.Sentinel.Detectors.Sdk.Tests/AI.Sentinel.Detectors.Sdk.Tests.csproj -c Release -f net10.0 --filter-query "/*/*/*Builder*/*"
```

Build with `-f net10.0` when you only need one target. The docs site builds with `npm install` and
`npm run build` in `website/` (job `build` in `docs.yml`, Node 26).

Do not build `benchmarks/AI.Sentinel.Benchmarks` expecting success: no CI job builds it, and on main it
fails to compile (`MessageBuilder.TruncateIfNeeded` and the `escalationClient` parameter of
`DetectionPipeline` no longer exist). Issue #612 tracks the fix; give no run command until it lands.

## Conventions and gotchas

- `TreatWarningsAsErrors` is on, with Meziantou, Roslynator, ErrorProne.NET and ZeroAlloc analyzers in
  `Directory.Build.props`. `EPS06` and `EPC12` are silenced repo-wide because they fire only in
  generated `*.g.cs`. `EPS05` is silenced on `net11.0` only, for System.Text.Json generator output.
  Do not widen either suppression.
- `Directory.Build.targets` rejects a floating (`3.3.*`) or exact-range (`[1.2.3]`) `PackageReference`
  version. Use a plain `1.2.3`: a range lands in the nuspec as an exact pin and breaks consumers (#425, #604).
- `Microsoft.AspNetCore.TestHost` is referenced twice in `AI.Sentinel.Tests.csproj`, once per target
  framework condition: `8.0.x` for `net8.0`, `10.0.x` otherwise. Keep the `net8.0` line in 8.x.
- `Directory.Build.props` sets `ZeroAllocAuthorizationRegistration` to `internal`. A shipped package must
  not export the generated registration (CS0121, issues #493 and #512).
- Single-framework projects: `benchmarks/`, `samples/`,
  `tools/AI.Sentinel.ComplianceEval` and `tests/AI.Sentinel.Aot.Probe` each target a single framework, and
  the three hook and MCP CLIs target `net10.0` only.
- `tests/AI.Sentinel.Aot.Probe` is a `PublishAot` project on `net11.0` and is part of the solution.

<!-- org-core:start sha256=08a88996bc9165f888fc0260607cfd0670cae128c323e16707c6b452ee66222d (generated from docker-nuc scripts/agents-md/org-core-personal.md; do not edit here) -->
## Org rules

These rules hold in every public MarcelRoozekrans repo.

### Commits and releases

- Conventional Commits. release-please reads them on the default branch, and the changelog sections
  in `release-please-config.json` decide which types count. The standard: `feat`, `fix`, `perf`,
  `deps` and `revert` open or update the release PR; `docs`, `test`, `refactor`, `build`, `ci`,
  `chore` and `style` do not, unless the commit is breaking or has a `Release-As:` footer. The
  release happens when that PR merges. A breaking change needs `!` or a `BREAKING CHANGE:` footer.
- A commit body never contains nested parentheses. release-please cannot parse them and silently
  drops the whole commit from the changelog, while the workflow still reports success.
- After merging a commit that should release, check that it appears in the release-please PR.

### Branches and pull requests

- Every change goes through a branch and a pull request. Never push to the default branch directly.
- A PR body says what the diff does, and nothing the diff does not do.
- Fix review findings in the PR under review, including small ones. File an issue only for a finding
  that belongs to other code, needs a design decision, is its own piece of work, or waits on
  something external.

### CI

- The .NET repos call the shared workflows of `MarcelRoozekrans/ci-baseline`, pinned to `@v1`, never
  `@main`.
- Its coverage gate fails the build when line coverage drops below the floor of 80%, and Codecov
  fails a PR that lowers project coverage by more than 1 percentage point. New code comes with
  tests.
- A repo with a lower floor documents the reason and links the issue that raises it.
<!-- org-core:end -->
