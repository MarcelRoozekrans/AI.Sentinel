# CLI Audit Recording Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Claude Code hook, the Copilot hook and the MCP proxy record every audit entry to one shared, size-capped, hash-chained SQLite file by default, tagged with their source, and `sentinel dashboard` shows that file in the existing dashboard.

**Architecture:**
- `AuditEntry` gains a hashed `Source` field.
- `SqliteAuditStore` becomes safe for several writer processes: it reads the chain head and sequence inside `BEGIN IMMEDIATE`.
- An internal `LocalAudit` helper in `AI.Sentinel.Sqlite`, shared by the three CLIs, does four jobs:
  - turns env vars into a store that tags the source and never throws;
  - adds tracking forwarders;
  - collects any problems;
  - flushes before the process exits.
- `AI.Sentinel.Cli` hosts the existing dashboard over the file.

**Tech Stack:** .NET 8/9, Microsoft.Data.Sqlite, ASP.NET Core minimal hosting, System.CommandLine 2.0, xUnit v3 on Microsoft.Testing.Platform.

**Spec:** `docs/superpowers/specs/2026-10-13-cli-audit-recording-design.md`

## Global Constraints

- Default database path: `Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ai-sentinel", "audit.db")`.
- Env vars:
  - The hooks read `SENTINEL_HOOK_AUDIT_SQLITE`, `SENTINEL_HOOK_AUDIT_NDJSON` and `SENTINEL_HOOK_AUDIT_MAX_MB`.
  - The MCP proxy reads the same three with the `SENTINEL_MCP_` prefix.
  - `..._AUDIT_SQLITE=off`, compared case-insensitively, disables SQLite and uses the in-memory ring buffer.
- Size cap: 100 MB by default; `MAX_MB=0` means no cap.
- Source values: `claude-code`, `copilot`, `mcp`. In-process apps leave it `null`.
- Busy timeout for CLI writers: 2 seconds. Forwarder flush before exit: at most 2 seconds.
- On Unix, the audit directory is created 0700 and the database file 0600.
- `sentinel dashboard` listens only on `127.0.0.1`. The default port is 5170. It never appends entries and runs no retention or size cap.
- **An audit failure never changes an allow, block or warn decision.** It never appears in a hook's stderr on Block or Warn unless verbose output is on.
- This ships in 3.0.0. Before merging, confirm release PR #346 is still unmerged. If 3.0.0 has already been released, stop and ask.
- Analyzers treat warnings as errors. Tests use `TestContext.Current.CancellationToken` and pass a `StringComparer.Ordinal` to string `Assert.NotEqual` calls.
- No nested parentheses in commit message bodies, and no session URLs.

## Review Focus

1. **Audit path is a directory, or unwritable.** The hook still blocks with exit code 2, and stderr holds only the block reason. The test goes in Task 5.
2. **Two writers interleave on one file.** The result is one intact chain with unique sequences. The test goes in Task 2.
3. **A hook process exits right after appending with NDJSON configured.** The NDJSON line is on disk when `RunAsync` returns. The test goes in Task 5.
4. **`MAX_MB` is not a number, or is negative.** The default of 100 applies and a problem is reported; nothing crashes. The test goes in Task 4.
5. **`sentinel dashboard` is pointed at a missing file.** It exits 1 with a message, and no file is created. The test goes in Task 8.

---

### Task 1: `Source` on `AuditEntry`, hashed and forwarded

**Files:**
- Modify: `src/AI.Sentinel/Audit/AuditEntry.cs`
- Create: `src/AI.Sentinel/Audit/AuditSources.cs`
- Modify: `src/AI.Sentinel/Audit/AuditHashChain.cs` (`ComputeHash`)
- Modify: `src/AI.Sentinel.OpenTelemetry/OpenTelemetryAuditForwarder.cs:39-48`
- Test: `tests/AI.Sentinel.Tests/Audit/AuditHashChainTests.cs`, `tests/AI.Sentinel.OpenTelemetry.Tests/OpenTelemetryAuditForwarderTests.cs`

**Interfaces:**
- Produces:
  - `AuditEntry(..., string? PolicyCode = null, string? SessionId = null, string? Source = null)`.
  - `public static class AuditSources { public const string ClaudeCode = "claude-code"; public const string Copilot = "copilot"; public const string Mcp = "mcp"; }`.

- [ ] **Step 1: Write the failing tests**
  - Add `"Source"` to `TamperedFields` in `AuditHashChainTests`, with the case `"Source" => original with { Source = "mcp" }`. The original entry gets `Source = AuditSources.ClaudeCode`.
  - Add `ComputeHash_DistinguishesNullFromEmptySource`.
  - Add an OTel test `SendAsync_MapsSourceAndSessionId`. It asserts that the scope contains `audit.source = "copilot"` and `audit.session_id = "s1"`. `audit.session_id` is a pre-existing gap in the same mapping, fixed here.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `dotnet test --project tests/AI.Sentinel.Tests -f net10.0 -- --filter-class "*AuditHashChainTests"`. Expected: compile error, `Source` not found.
- [ ] **Step 3: Implement.**
  - Add the trailing `Source` parameter.
  - In `ComputeHash`, add `AppendString(sha, entry.Source)` after `SessionId`.
  - Add the two OTel scope keys.
  - Update the `ComputeHash` XML doc's field list.
- [ ] **Step 4: Run the tests.** Run both test projects. Expected: PASS. NDJSON and Azure serialise the whole record, so they need no change.
- [ ] **Step 5: Commit** as `feat(audit): record which tool wrote each audit entry`.

### Task 2: SQLite schema v5 and multi-process writers

**Files:**
- Modify: `src/AI.Sentinel.Sqlite/SqliteSchema.cs`
- Modify: `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs` (`AppendAsync`, the INSERT, the SELECT column list, `ReadEntry`)
- Test: `tests/AI.Sentinel.Sqlite.Tests/SqliteAuditStoreTests.cs`, `tests/AI.Sentinel.Sqlite.Tests/SqliteSchemaV5MigrationTests.cs` (new)
- Modify: the tests asserting `Assert.Equal(4, version)`, so they assert 5

**Interfaces:**
- Consumes: `AuditEntry.Source` from Task 1.
- Produces: `SqliteSchema.CurrentVersion = 5`; a nullable `source TEXT` column.

- [ ] **Step 1: Write the failing tests.**
  - `Source_RoundTrips`: append with `Source = "mcp"`; the queried entry equals the stored one.
  - `TwoStoresOnOneFile_FormOneIntactChain`: two `SqliteAuditStore` instances on the same path append 100 entries each, interleaved with `Task.WhenAll`. Then `VerifyAsync` is intact with 200 entries, and `SELECT COUNT(DISTINCT sequence)` returns 200.
  - `V4Db_MigratesToV5_AddingSource`: seed a v4 database; after opening, the version is 5 and the `source` column exists and is nullable.
  - `ConcurrentFirstOpen_OfV4Db_Succeeds`: two stores construct on the same v4 file in parallel, and both succeed.
- [ ] **Step 2: Run the tests and confirm they fail.** Run `dotnet test --project tests/AI.Sentinel.Sqlite.Tests -f net10.0`. Expected: the two-store test fails on a duplicate sequence or a broken chain; the others fail on version or column.
- [ ] **Step 3: Implement.**
  - **`AppendAsync`:** inside the existing transaction, which is `BEGIN IMMEDIATE`, read `SELECT hash FROM audit_chain_head WHERE id = 1` and `SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_entries`. Link and insert with those values. Delete the `_sequence` and `_lastHash` fields and `LoadHighestSequence` / `LoadLastHash`.
  - **`InitializeAsync`:**
    - Set the WAL pragma outside the transaction, because SQLite rejects it inside one.
    - Then open `BEGIN IMMEDIATE`, re-read `user_version` inside it, and run every pending step on that transaction.
    - `MigrateV3ToV4Async` takes the transaction as a parameter instead of opening its own.
    - Set `user_version` and commit.
    - The fresh-schema path runs in the same transaction.
  - **New `MigrateV4ToV5Async`:** `ALTER TABLE audit_entries ADD COLUMN source TEXT;`, and add `source` to `AuditEntriesColumns`.
  - **Comments:** update the single-writer comment in `SqliteSchema.cs` to say multiple processes are supported.
- [ ] **Step 4: Run the tests.** Run the full Sqlite test project. Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(sqlite): support several writer processes and store the entry source`.

### Task 3: Size cap and busy timeout options for short-lived writers

**Files:**
- Modify: `src/AI.Sentinel.Sqlite/SqliteAuditStoreOptions.cs`, `src/AI.Sentinel.Sqlite/SqliteAuditStore.cs` (constructor, `EnforceSizeCap`)
- Test: `tests/AI.Sentinel.Sqlite.Tests/SqliteAuditStoreTests.cs`

**Interfaces:**
- Produces three new public options on `SqliteAuditStoreOptions`:
  - `TimeSpan BusyTimeout { get; set; } = TimeSpan.FromSeconds(30)`, which maps to the connection string's `DefaultTimeout`.
  - `bool EnforceSizeCapOnOpen { get; set; }`
  - `bool VacuumAfterTrim { get; set; } = true`

- [ ] **Step 1: Write the failing tests.**
  - `EnforceSizeCapOnOpen_TrimsAnOverCapFileWithoutVacuum`:
    - Fill a file without a cap, then reopen it with the cap at about 60% of the used bytes, `EnforceSizeCapOnOpen = true` and `VacuumAfterTrim = false`.
    - After the constructor returns, used bytes, computed as `(page_count - freelist_count) * page_size`, are at or under the cap.
    - The newest entry is present and the chain verifies.
  - `EnforceSizeCapOnOpen_DoesNothingUnderCap`: the entry count is unchanged.
  - `BusyTimeout_GivesUpQuickly`: a raw connection holds `BEGIN IMMEDIATE`; a store with `BusyTimeout = 1s` throws `SqliteException` from `AppendAsync` in under 5 seconds.
- [ ] **Step 2: Run the tests and confirm they fail.** Expected: compile errors on the new options.
- [ ] **Step 3: Implement.**
  - Measure size in `EnforceSizeCap` as used bytes, not as file length.
  - Skip `VACUUM` and the checkpoint when `VacuumAfterTrim` is false.
  - When `EnforceSizeCapOnOpen` is set, call it once in the constructor under the write lock.
  - The existing `MaxDatabaseSizeBytes_TrimsOldestEntries_AndShrinksFile` must still pass.
- [ ] **Step 4: Run the tests.** Run the Sqlite test project. Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(sqlite): trim on open and bound the busy wait for short-lived writers`.

### Task 4: `LocalAudit`, the shared CLI audit setup

**Files:**
- Create in `src/AI.Sentinel.Sqlite/Local/`:
  - `LocalAuditSettings.cs`
  - `LocalAudit.cs`
  - `LocalAuditSession.cs`
  - `SourceTaggingAuditStore.cs`
  - `TrackingAuditForwarder.cs`
- Modify: `src/AI.Sentinel.Sqlite/AI.Sentinel.Sqlite.csproj` to add InternalsVisibleTo for `AI.Sentinel.ClaudeCode.Cli`, `AI.Sentinel.Copilot.Cli`, `AI.Sentinel.Mcp.Cli` and `AI.Sentinel.Cli`.
- Test: `tests/AI.Sentinel.Sqlite.Tests/LocalAuditTests.cs`

**Interfaces:**
- Produces (all `internal`):
  - `sealed record LocalAuditSettings(string? DatabasePath, string? NdjsonPath, long? MaxDatabaseSizeBytes)`. A `null` `DatabasePath` means SQLite is off, and a `null` cap means no cap.
  - `static class LocalAudit` with:
    - `string DefaultDatabasePath()`
    - `LocalAuditSettings ReadSettings(IReadOnlyDictionary<string, string?> env, string prefix, string defaultDatabasePath, ICollection<string> problems)`. `prefix` is `"SENTINEL_HOOK_"` or `"SENTINEL_MCP_"`.
    - `LocalAuditSession Open(LocalAuditSettings settings, string source)`
  - `sealed class LocalAuditSession : IAsyncDisposable` with:
    - `IAuditStore Store`
    - `IReadOnlyList<IAuditForwarder> Forwarders`
    - `IReadOnlyList<string> Problems`
    - `Task FlushAsync(TimeSpan timeout)`
  - `sealed class SourceTaggingAuditStore(IAuditStore inner, string source, Action<string> reportProblem) : IAuditStore`. `AppendAsync` sets `Source` and delegates. On any exception it reports and returns the tagged entry unlinked; it never throws. `QueryAsync` delegates.
  - `sealed class TrackingAuditForwarder(IAuditForwarder inner) : IAuditForwarder, IAsyncDisposable`, which counts the entries it has finished sending: `long EntriesSent`.
  - `FlushAsync(timeout)` waits until every `TrackingAuditForwarder.EntriesSent` reaches the number of `AppendAsync` calls `Store` has seen, or until the timeout. **Do not wait on "in-flight sends".** `AuditForwarding` starts each send inside `Task.Run`, so a send may not have reached the forwarder yet when the flush begins, and an in-flight check would see nothing and return early.

- [ ] **Step 1: Write the failing tests.**
  - `ReadSettings_Defaults`: no vars → the default path, no NDJSON, `100L * 1024 * 1024`.
  - `ReadSettings_Off`: `SENTINEL_HOOK_AUDIT_SQLITE=OFF` → `DatabasePath == null`.
  - `ReadSettings_MaxMbZero_MeansNoCap` → `null`.
  - `ReadSettings_BadMaxMb_UsesDefaultAndReportsAProblem` with `"abc"` and `"-5"`.
  - `ReadSettings_UsesThePrefix`: `SENTINEL_MCP_AUDIT_NDJSON` is read only with the `SENTINEL_MCP_` prefix.
  - `Open_CreatesTheDatabaseAndTagsTheSource`: an append through `Store` reads back with `Source == "mcp"`, and the chain verifies.
  - `Open_OnUnix_CreatesPrivateDirectoryAndFile`: skipped on Windows; asserts directory `0700` and file `0600` via `File.GetUnixFileMode`.
  - `Open_PathIsADirectory_FallsBackToRingBufferAndReportsAProblem`: `Store` still accepts appends and `Problems` has one entry.
  - `Store_AppendFailure_IsReportedNotThrown`: the inner store throws; the append returns and `Problems` grows.
  - `FlushAsync_WaitsForASendThatHasNotStartedYet`: use a forwarder whose `SendAsync` waits 300 ms before recording. Append, then flush immediately. The forwarder has recorded the entry when `FlushAsync` returns.
  - `FlushAsync_WaitsForNdjsonLines`: after an append through `Store` and `AppendAndForwardAsync`, then `FlushAsync`, the NDJSON file has one line. Call `AuditForwarding` the same way the writers do, adding InternalsVisibleTo from core to `AI.Sentinel.Sqlite.Tests` if needed.
- [ ] **Step 2: Run the tests and confirm they fail.** Expected: compile errors.
- [ ] **Step 3: Implement.**
  - `Open` creates the directory with `Directory.CreateDirectory(path, UnixFileMode.UserRead | UserWrite | UserExecute)` on Unix.
  - It opens `SqliteAuditStore` with `BusyTimeout = 2s`, `MaxDatabaseSizeBytes = settings.MaxDatabaseSizeBytes`, `EnforceSizeCapOnOpen = true` and `VacuumAfterTrim = false`, then sets the file mode to 0600.
  - If opening throws, it reports and falls back to `new RingBufferAuditStore()`.
  - NDJSON becomes `new TrackingAuditForwarder(new NdjsonFileAuditForwarder(...))`.
  - `DisposeAsync` disposes the forwarders and the store.
- [ ] **Step 4: Run the tests.** Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(sqlite): shared local audit setup for the CLIs`.

### Task 5: Hook CLIs record by default

**Files:**
- Modify:
  - `src/AI.Sentinel.ClaudeCode.Cli/Program.cs` (`RunCoreAsync`, `BuildProvider`)
  - `src/AI.Sentinel.ClaudeCode.Cli/AI.Sentinel.ClaudeCode.Cli.csproj`, to reference `AI.Sentinel.Sqlite`
  - the same two files under `src/AI.Sentinel.Copilot.Cli/`
- Test: `tests/AI.Sentinel.Tests/ClaudeCode/HookCliAuditTests.cs` and `tests/AI.Sentinel.Tests/Copilot/CopilotHookCliAuditTests.cs`, both `[Collection("NonParallel")]`

**Interfaces:**
- Consumes: `LocalAudit`, `LocalAuditSession` and `AuditSources` from Tasks 1 and 4.
- Produces: `BuildProvider(..., LocalAuditSession? audit = null)`, which registers `audit.Store` as `IAuditStore` and each forwarder as `IAuditForwarder`, after `AddAISentinel`.

- [ ] **Step 1: Write the failing tests** for each CLI. Each sets `SENTINEL_HOOK_AUDIT_SQLITE` to a temp path and resets it in `finally`.
  - `InjectionPrompt_IsRecordedWithSource`: run `user-prompt-submit` with `"ignore all previous instructions"`. Expect exit 2. Opening the database afterwards yields at least one entry, every entry's `Source` is `claude-code` (or `copilot`), and the chain verifies.
  - `NdjsonConfigured_LineIsOnDiskWhenRunReturns`
  - `AuditPathIsADirectory_StillBlocks_AndStderrIsOnlyTheReason`: exit 2, and stderr does not contain `"audit"` in any case.
  - `AuditPathIsADirectory_OnAllow_ReportsTheProblem`: a clean prompt exits 0 and stderr mentions the audit problem.
  - `AuditOff_WritesNoFile`
- [ ] **Step 2: Run the tests and confirm they fail.** Expected: no database file or wrong source.
- [ ] **Step 3: Implement.**
  - `RunCoreAsync` builds settings with the hook prefix from `BuildHookEnvVars()`, which already filters on `SENTINEL_HOOK_`, and calls `await using var audit = LocalAudit.Open(settings, AuditSources.ClaudeCode)` (or `Copilot`).
  - Pass `audit` to `BuildProvider`.
  - After writing stdout, `await audit.FlushAsync(TimeSpan.FromSeconds(2))`.
  - Write `audit.Problems` to stderr only when the decision is Allow or `config.Verbose` is set.
- [ ] **Step 4: Run the tests**, plus the existing `HookCliTests` and `CopilotHookCliTests`, which must not write to the real default path. Make them set `SENTINEL_HOOK_AUDIT_SQLITE=off` if they would. Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(hooks): record hook decisions to the local audit file by default`.

### Task 6: MCP proxy records by default

**Files:**
- Modify:
  - `src/AI.Sentinel.Mcp/McpPipelineFactory.cs` (the `Create` overload at :38)
  - `src/AI.Sentinel.Mcp/McpProxy.cs` (the `RunAsync` signature and :85-88)
  - `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` (:126 and :169)
  - `src/AI.Sentinel.Mcp.Cli/ProxyCommand.cs`
  - `src/AI.Sentinel.Mcp.Cli/AI.Sentinel.Mcp.Cli.csproj`, to reference `AI.Sentinel.Sqlite`
  - `src/AI.Sentinel/AssemblyAttributes.cs`, to add InternalsVisibleTo `AI.Sentinel.Mcp`
- Test: `tests/AI.Sentinel.Tests/Mcp/McpAuditTests.cs`

**Interfaces:**
- Consumes: `LocalAudit` from Task 4, and the internal `AuditForwarding.AppendAndForwardAsync`.
- Produces:
  - `McpPipelineFactory.Create(..., IAuditStore? auditStore = null, IReadOnlyList<IAuditForwarder>? forwarders = null)`. A supplied store replaces the ring buffer, and the forwarders go to `SentinelPipeline`.
  - `McpProxy.RunAsync(..., IAuditStore? auditStore = null, IReadOnlyList<IAuditForwarder>? forwarders = null)`.
  - `ToolCallInterceptor.Create(..., IReadOnlyList<IAuditForwarder>? forwarders = null)`.

- [ ] **Step 1: Write the failing tests.**
  - `Factory_UsesTheSuppliedStoreAndForwarders`: an injection in `ScanMessagesAsync` lands in the supplied store and in a `RecordingAuditForwarder`.
  - `ToolCallDeny_IsForwarded`: use the existing MCP authorization test setup with a deny guard. The AUTHZ-DENY entry reaches the forwarder.
  - `ProxyCommand_ReadsMcpAuditVars`: drive `ProxyCommand` with `SENTINEL_MCP_AUDIT_SQLITE` set to a temp path against the existing fake target used in `McpProxyTests`. After shutdown the file exists and its entries have `Source == "mcp"`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
  - `ProxyCommand` opens `LocalAudit` with the `SENTINEL_MCP_` prefix and `AuditSources.Mcp`, and passes the store and forwarders down.
  - In its `finally`, flush for 2 seconds, then dispose.
  - Write `Problems` through `StderrLogger` as event `audit_unavailable`. MCP stderr is not model-facing, so problems are always reported.
  - `ToolCallInterceptor` uses `AppendAndForwardAsync`.
- [ ] **Step 4: Run the tests**, plus all of `tests/AI.Sentinel.Tests/Mcp`. Make existing proxy tests set `SENTINEL_MCP_AUDIT_SQLITE=off` if they would touch the real default path. Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(mcp): record proxy decisions to the local audit file by default`.

### Task 7: Dashboard shows and filters the source

**Files:**
- Modify:
  - `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs`: `LiveFeedAsync`, `RenderFeedRow`, `FilterAuditEntries`, `ExportNdjsonAsync`, and the empty-state `colspan`
  - `src/AI.Sentinel.AspNetCore/wwwroot/index.html`: the header row at :67, the feed URL builder at :115-160 and the URL state at :135-150
- Test: `tests/AI.Sentinel.Tests/AspNetCore/DashboardSourceTests.cs`

**Interfaces:**
- Produces: query parameter `source`, matched with ordinal-ignore-case equality, on both `/api/feed` and `/api/export.ndjson`. `FilterAuditEntries(entries, category, q, session, source)`.

- [ ] **Step 1: Write the failing tests**, using the `BuildHostAsync` pattern from `DashboardExportTests`.
  - `Feed_ShowsTheSourceColumn`: the row HTML contains `claude-code`.
  - `Feed_FilteredBySource`: `?source=mcp` returns only the mcp row.
  - `Export_FilteredBySource`.
  - `Feed_EntryWithoutSource_RendersEmptyCell`.
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
  - Add a Source column after Detector, so the empty-state `colspan` becomes 7.
  - Clicking a source cell sets the filter, the same way the session link works; follow the session-link delegation and pill pattern.
  - Mirror `source` into the page URL.
  - `TrendAsync` keeps ignoring filters.
- [ ] **Step 4: Run the tests**, plus all of `tests/AI.Sentinel.Tests/AspNetCore`. Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(dashboard): show and filter audit entries by source`.

### Task 8: `sentinel dashboard`

**Files:**
- Create: `src/AI.Sentinel.Cli/DashboardCommand.cs`
- Modify: `src/AI.Sentinel.Cli/Program.cs`, to register it
- Modify: `src/AI.Sentinel.Cli/AI.Sentinel.Cli.csproj`, adding `<FrameworkReference Include="Microsoft.AspNetCore.App" />`, references to `AI.Sentinel.AspNetCore` and `AI.Sentinel.Sqlite`, and a package `Description` mentioning the ASP.NET Core runtime
- Test: `tests/AI.Sentinel.Tests/Cli/DashboardCommandTests.cs`

**Interfaces:**
- Consumes: `LocalAudit.DefaultDatabasePath()`.
- Produces:
  - `DashboardCommand.Build(): Command`, with options `--db` (defaults to the default path) and `--port` (defaults to 5170).
  - `DashboardCommand.StartAsync(string dbPath, int port, TextWriter stdout, TextWriter stderr, CancellationToken ct): Task<RunningDashboard?>`, which returns `null` after writing an error.
  - `sealed class RunningDashboard : IAsyncDisposable { Uri Url; Task WaitForShutdownAsync(CancellationToken ct); }`.
  - `DashboardCommand.RunAsync(...)`, which returns an exit code.

- [ ] **Step 1: Write the failing tests.**
  - `Start_ServesTheFeedFromAnExistingFile`: seed a temp database with two entries. Start with `port: 0`, GET `{Url}api/feed`, and expect 200 with both detector IDs.
  - `Start_MissingFile_ReturnsNullAndCreatesNothing`
  - `Start_DoesNotAppend`: the entry count is unchanged after start, two feed requests and dispose.
  - `Start_PrintsChainVerification`: stdout contains `intact` and `2 entries`.
  - `Start_PortInUse_ReturnsNullWithMessage`
- [ ] **Step 2: Run the tests and confirm they fail.**
- [ ] **Step 3: Implement.**
  - Use `WebApplication.CreateSlimBuilder`, listening on `http://127.0.0.1:{port}`.
  - Register `services.AddSingleton<IAuditStore>(new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = dbPath }))`, with no retention, no cap and no `IApprovalStore`.
  - `app.MapAISentinel("/ai-sentinel")`, and map `/` to redirect there.
  - `Url` is `http://127.0.0.1:{actualPort}/ai-sentinel/`.
  - Before starting, check `File.Exists`.
  - Run `AuditHashChain.VerifyAsync` once and print either `Audit chain intact: N entries` or `Audit chain broken at entry {id}`.
- [ ] **Step 4: Run the tests.** Expected: all PASS.
- [ ] **Step 5: Commit** as `feat(cli): sentinel dashboard serves the local audit file`.

### Task 9: Docs and the AOT workflow

**Files:**
- Modify:
  - `website/docs/integrations/claude-code.md` (the Audit destination section and the Programmatic sample at :118-122)
  - `website/docs/integrations/copilot.md:85-91`
  - `website/docs/integrations/mcp-proxy.md` (a new Audit section)
  - `website/docs/audit-forwarders/sqlite.md` (multi-process writers, the new options)
  - `website/docs/core-concepts/audit-store.md` (`AuditEntry` gets `Source`)
  - `README.md` (the Art. 12 row and the CLI section)
  - `.github/workflows/aot-publish.yml`

- [ ] **Step 1: Update the docs** to the Global Constraints values.
  - Replace the Programmatic sample with `new HookAdapter(provider, config).HandleAsync(evt, input, ct)`.
  - Remove the "single-writer" statements about the audit store.
- [ ] **Step 2: Update the AOT workflow.**
  - Add `src/AI.Sentinel.Sqlite/**` to the path filters.
  - In the hook smoke test, set `SENTINEL_HOOK_AUDIT_SQLITE` to a file under `$env:RUNNER_TEMP` and assert that it exists afterwards. That proves SQLite works in the native binary.
- [ ] **Step 3: Verify.**
  - Build the docs: `cd website && npm ci && npm run build`. Expected: `[SUCCESS]` and no broken links. Remove `node_modules`, `build` and `.docusaurus` afterwards.
  - Run `dotnet test --solution AI.Sentinel.slnx`. Expected: all pass.
  - Run `DetectorDocumentationTests`. Expected: pass.
- [ ] **Step 4: Commit** as `docs: document local audit recording and sentinel dashboard`.
