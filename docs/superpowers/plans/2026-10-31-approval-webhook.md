# Approval webhook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The three CLIs POST a webhook once per newly created approval request, configured by `notifyUrl` in the approval config.

**Architecture:** The stores mark the creating call with `ApprovalState.Pending.IsNew`. An internal `NotifyingApprovalStore` decorator, applied inside `ApprovalStoreAuditing.Wrap` when an `ApprovalNotifierSettings` is registered, awaits a POST with a 3 s timeout when it sees `IsNew`. The Entra PIM store gains the pending-request lookup it lacks, so it stops creating duplicates.

**Tech Stack:** .NET 10 / net8.0 libraries, xunit v3, System.Text.Json source generation, Microsoft Graph SDK, SQLite.

**Spec:** `docs/superpowers/specs/2026-10-31-approval-webhook-design.md`

## Global Constraints

- Public API change is exactly one additive member: `public bool IsNew { get; init; }` on `ApprovalState.Pending`. Every other new type is `internal`.
- POST timeout 3 s, fixed. No retries. The response body is never read.
- A webhook failure never throws out of `EnsureRequestAsync` and never changes the returned state.
- Logs name the endpoint only through `SafeHttp.Describe`, plus the request id. Never header values, never the payload.
- JSON through a source-generated `JsonSerializerContext`; the CLIs are AOT-published.
- Commit subjects conventional; bodies have no nested parentheses, no Co-Authored-By trailer, no Claude signature.
- Before every push: `dotnet format whitespace . --folder --verify-no-changes`.
- On the VM: never `dotnet test` the solution and never AOT-publish. Build, then run test DLLs directly, for AI.Sentinel.Tests with `-noclass "*DetectorRegistrationTrimTests"`.

## Review Focus

- A `notifyUrl` whose `${VAR}` is unset expands to an empty or relative string: the load must fail with a message naming `notifyUrl`, not pass a broken URI to the notifier. Test in Task 3.
- A webhook endpoint that accepts the connection and never answers: the call must return after about 3 s with the inner state. Test in Task 4 with a handler that waits on the token.
- Arguments containing a JSON string with an API key nested two levels deep: the key must not appear in the POSTed body. Test in Task 4.
- A `grantScope: call` rule with backend `entra-pim` and a `notifyUrl`: the startup rejection must still fire through the new wrapper. Test in Task 5.
- Two hook processes racing on one SQLite file: exactly one POST. Covered in Task 1 by two store instances on one file seeing exactly one `IsNew`.

---

### Task 1: `Pending.IsNew` in core, in-memory and SQLite

**Files:**
- Modify: `src/AI.Sentinel/Approvals/ApprovalState.cs`
- Modify: `src/AI.Sentinel/Approvals/InMemoryApprovalStore.cs` (create path near line 63-82)
- Modify: `src/AI.Sentinel.Approvals.Sqlite/SqliteApprovalStore.cs` (insert path near line 91-94)
- Test: `tests/AI.Sentinel.Tests/Approvals/InMemoryApprovalStoreTests.cs`, `tests/AI.Sentinel.Approvals.Sqlite.Tests/SqliteApprovalStoreTests.cs`
- Modify: `PublicAPI.Unshipped.txt` of AI.Sentinel if the project tracks it

**Interfaces:**
- Produces: `ApprovalState.Pending.IsNew` (`bool`, `init`). XML doc: true only on the `EnsureRequestAsync` call that created the request; `WaitForDecisionAsync` and every reuse return false; a store that does not set it gets no notifications.

- [ ] **Step 1: Write failing tests**

In-memory:
- `EnsureRequest_NewRequest_IsNew`: first call → `Assert.True(((ApprovalState.Pending)state).IsNew)`.
- `EnsureRequest_Reuse_IsNotNew`: second call, same caller and policy → same `RequestId`, `IsNew` false.
- `EnsureRequest_AfterDenial_IsNewAgain`: deny, observe the `Denied`, call again → new `RequestId`, `IsNew` true.
- `WaitForDecision_Pending_IsNotNew`: wait with a 10 ms timeout on a pending request → `Pending` with `IsNew` false.

SQLite, same four, plus:
- `EnsureRequest_TwoStoresOneFile_ExactlyOneIsNew`: two `SqliteApprovalStore` instances on one temp file call `EnsureRequestAsync` concurrently with the same caller and policy → both `Pending`, same `RequestId`, `Assert.Single` of the two with `IsNew`.

- [ ] **Step 2: Run, verify they fail** (`IsNew` does not exist: compile error)

Build, then run both test DLLs with `-method "*IsNew*"`. Expected: build fails on `IsNew`.

- [ ] **Step 3: Add the property and set it on the create paths only**

`with { IsNew = true }` on the `Pending` returned right after the insert or entry add. `StateOf` and `RowToState` stay unchanged.

- [ ] **Step 4: Run, verify pass**, then the full test classes of both stores.

- [ ] **Step 5: Commit**: `feat(approvals): Pending.IsNew marks the call that created a request`

### Task 2: Entra PIM finds a pending request before creating one

**Files:**
- Modify: `src/AI.Sentinel.Approvals.EntraPim/IGraphRoleClient.cs`, `MicrosoftGraphRoleClient.cs`, `EntraPimApprovalStore.cs` (step 3 near line 108-117)
- Create: `src/AI.Sentinel.Approvals.EntraPim/PendingRoleRequest.cs`
- Test: `tests/AI.Sentinel.Approvals.EntraPim.Tests/EntraPimApprovalStoreTests.cs`; update `FakeGraphRoleClient` there and `NoopGraphRoleClient` in `GrantScopeTests.cs`

**Interfaces:**
- Produces: `internal sealed record PendingRoleRequest(string RequestId, DateTimeOffset CreatedAt);`
- Produces: `IGraphRoleClient.GetPendingActivationRequestAsync(string principalId, string roleId, CancellationToken ct) : ValueTask<PendingRoleRequest?>`.

- [ ] **Step 1: Write failing tests**
- `EnsureRequest_PendingRequestExists_ReturnsItWithoutCreating`: fake returns `PendingRoleRequest("pim-1", t0)` → `Pending("pim-1", <portal url>, t0)`, `IsNew` false, `CreateActivationRequestAsync` call count 0.
- `EnsureRequest_NoPendingRequest_CreatesAndIsNew`: fake returns null → create called once, `IsNew` true.
- `EnsureRequest_PendingLookupFails_MapsLikeOtherGraphErrors`: fake throws the same 403 exception shape the existing tests use for `IsEligibleAsync` → the same `Denied` that test expects, create not called.
- `EnsureRequest_ActiveGrant_SkipsPendingLookup`: active assignment → `Active`, lookup call count 0.

- [ ] **Step 2: Run, verify fail** (compile error on the new interface member).

- [ ] **Step 3: Implement**

Store: after the eligibility check, call the lookup; when it returns a request, return `Pending(r.RequestId, BuildPortalUrl(r.RequestId), r.CreatedAt)`. Graph client: `RoleManagement.Directory.RoleAssignmentScheduleRequests.GetAsync` with filter `principalId eq '<p>' and roleDefinitionId eq '<r>' and action eq 'selfActivate'`, both values through `EscapeOData`, wrapped in `WithGraphRetryAsync`, `Select` `id,status,createdDateTime`; pick the newest whose status passes the store's `IsPendingStatus`. Make `IsPendingStatus` `internal static` so the client reuses it rather than copying the list. Filter on status client-side, because Graph's support for `status` in `$filter` on this collection is not documented.

- [ ] **Step 4: Run, verify pass**, then the whole EntraPim test DLL.

- [ ] **Step 5: Commit**: `fix(approvals-entra-pim): return the pending activation request instead of creating another`

### Task 3: Notification keys in the approval config

**Files:**
- Modify: `src/AI.Sentinel/Approvals/Configuration/ApprovalConfig.cs`, `ApprovalConfigLoader.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Configuration/ApprovalConfigLoaderTests.cs`

**Interfaces:**
- Produces on `ApprovalConfig`, as `init` properties so the 5 existing positional constructions keep compiling:
  `Uri? NotifyUrl`, `IReadOnlyDictionary<string, string> NotifyHeaders` (default empty, ordinal keys), `bool NotifyIncludeArgs`, `Uri? DashboardUrl`.

- [ ] **Step 1: Write failing tests**
- `Parse_NotifyKeys_Populated`: all four keys set → values as given; `NotifyHeaders["Authorization"] == "Bearer x"`.
- `Parse_NoNotifyKeys_Defaults`: `NotifyUrl` null, headers empty, `NotifyIncludeArgs` false, `DashboardUrl` null.
- `Parse_NotifyUrl_Invalid_Throws` (theory): `""`, `"relative/path"`, `"ftp://x"`, `"not a url"` → `InvalidOperationException` whose message contains `notifyUrl`.
- `Parse_DashboardUrl_Invalid_Throws`: `"relative"` → message contains `dashboardUrl`.
- `Parse_NotifyHeadersWithoutUrl_Throws` and `Parse_NotifyIncludeArgsWithoutUrl_Throws`: message names the key and `notifyUrl`.
- `Parse_NotifyHeaders_NonString_Throws`: `{"X-A": 1}` → message contains `notifyHeaders['X-A']`.
- `Parse_NotifyHeaders_ContentType_Throws` (theory over `Content-Type`, `content-length`) and `Parse_NotifyHeaders_InvalidName_Throws` (`"Bad Name"`).
- `Load_ExpandsEnvInNotifyUrlAndHeaders`: env vars set via the existing test helper → expanded values.
- `Load_UnsetEnvInNotifyUrl_Throws`: `"${UNSET_458_VAR}"` → message contains `notifyUrl`. Check what the expander does with an unset var first; the test asserts the load fails either way.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** parsing and validation in `Parse` and `Validate`, with messages in the loader's existing style (`notifyUrl must be an absolute http or https URL. Got: '<value>'`). Validate header names with `new HttpRequestMessage().Headers.TryAddWithoutValidation` rejecting false, plus the explicit `Content-Type` and `Content-Length` check, both case-insensitive.

- [ ] **Step 4: Run, verify pass**, then the full loader test class.

- [ ] **Step 5: Commit**: `feat(approvals): notifyUrl, notifyHeaders, notifyIncludeArgs and dashboardUrl config keys`

### Task 4: `NotifyingApprovalStore` and the payload

**Files:**
- Create: `src/AI.Sentinel/Approvals/Notifications/ApprovalNotifierSettings.cs`, `ApprovalNotification.cs` (payload record and builder), `ApprovalNotificationJsonContext.cs`, `NotifyingApprovalStore.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Notifications/NotifyingApprovalStoreTests.cs`

**Interfaces:**
- Produces: `internal sealed record ApprovalNotifierSettings(Uri Url, IReadOnlyDictionary<string, string> Headers, bool IncludeArgs, Uri? DashboardUrl) { public static ApprovalNotifierSettings? FromConfig(ApprovalConfig config); }`, returning null when `NotifyUrl` is null.
- Produces: `internal class NotifyingApprovalStore : IApprovalStore, IApprovalStoreDecorator` and `internal sealed class NotifyingApprovalAdminStore : NotifyingApprovalStore, IApprovalAdmin`, which forwards `IApprovalAdmin` to the inner store. Constructor `(IApprovalStore inner, ApprovalNotifierSettings settings, HttpMessageHandler handler, ILogger? logger)`; production passes a shared `SocketsHttpHandler`.
- Produces: `internal static IApprovalStore NotifyingApprovalStore.Wrap(IApprovalStore inner, ApprovalNotifierSettings settings, ILogger? logger)`, which picks the admin variant when `inner is IApprovalAdmin`.
- Produces: `internal interface IApprovalStoreDecorator { IApprovalStore Inner { get; } }` in `src/AI.Sentinel/Approvals/IApprovalStoreDecorator.cs`. Task 5 adds it to `AuditingApprovalStore`.

Payload JSON, camelCase, nulls omitted: `text, requestId, tool, callerId, policy, requestedAt, approvalUrl, dashboardUrl, args`. `requestedAt` round-trip ISO 8601. `text` = `$"Approval needed: {tool} for {callerId} ({policy})."`, then `" " + link` when there is one. The link is `DashboardUrl`; otherwise `ApprovalUrl` when its scheme is `http` or `https`; otherwise none.

- [ ] **Step 1: Write failing tests**, with a recording fake `HttpMessageHandler` and the in-memory store as inner:
- `NewRequest_PostsOnce`: one request recorded, method POST, URI `settings.Url`, content type `application/json`.
- `ReusedRequest_DoesNotPost`: second `EnsureRequestAsync` → still one recorded request.
- `WaitForDecision_DoesNotPost`.
- `Payload_Fields`: parse the body; `requestId`, `tool`, `callerId`, `policy`, `requestedAt`, `approvalUrl == "sentinel://approve/<id>"`; no `args` property; no `dashboardUrl` when unset.
- `Text_LinksDashboardWhenSet`: `DashboardUrl = https://dash.example.com/` → `text` ends with `https://dash.example.com/`, and `dashboardUrl` is present.
- `Text_LinksHttpApprovalUrlWhenNoDashboard`: inner fake returns `Pending` with `https://portal.example.com/x` and `IsNew` → the text ends with that URL. With `sentinel://…` and no dashboard → the text ends with `(<policy>).`.
- `Headers_Sent`: `Authorization: Bearer t` present on the request.
- `IncludeArgs_RedactsSecretsAndPii`: args `{"cmd":"curl -H 'Authorization: Bearer sk-ant-api03-<40 chars>'","nested":{"to":"alice@example.com"}}` → body contains `"cmd"` and `"to"`, does not contain the key or the address, and contains `[EMAIL_`.
- `Failure_Status500_ReturnsInnerStateAndLogs`, `Failure_Exception_ReturnsInnerStateAndLogs`: the returned state equals the inner one; one warning logged; the log text contains neither the header value nor the URL query string when `Url` has `?token=s3cret`.
- `Failure_Timeout_ReturnsWithinBudget`: handler awaits `Task.Delay(Infinite, token)` → returns `Pending` within 5 s wall clock, and a warning is logged. Uses the real 3 s timeout, so mark it as the one slow test in this class.
- `CallerCancelled_PropagatesCancellation_NoWarning`: cancel the caller token while the handler waits → `OperationCanceledException`, no warning.
- `AdminVariant_ForwardsAdmin`: wrap an in-memory store, which implements `IApprovalAdmin` → result `is IApprovalAdmin`, and `ApproveAsync` through it settles the inner request.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement.** The timeout is a linked `CancellationTokenSource` with `CancelAfter(3 s)` per request, so a caller cancellation is told apart from the timeout by checking the caller token. Redaction: `new RedactionSession([new CredentialExposureDetector(), new PiiLeakageDetector()]).RedactJsonValues(args)`. Dispose the response without reading it.

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit**: `feat(approvals): post a webhook when an approval request is created`

### Task 5: Wire the notifier through DI and the three CLIs

**Files:**
- Modify: `src/AI.Sentinel/Approvals/ApprovalStoreAuditing.cs` (`Wrap`), `AuditingApprovalStore.cs` (implement `IApprovalStoreDecorator`, where `Inner` already exists), `src/AI.Sentinel/ServiceCollectionExtensions.cs` (`RejectCallScopedGrantsOnRoleActivationStore`, line ~342)
- Modify: `src/AI.Sentinel/Approvals/Configuration/ApprovalBackendSelector.cs`
- Modify: `src/AI.Sentinel.ClaudeCode.Cli/Program.cs` (~line 370-390), `src/AI.Sentinel.Copilot.Cli/Program.cs` (same block), `src/AI.Sentinel.Mcp.Cli/ProxyCommand.cs` (store registration after line ~254)
- Test: `tests/AI.Sentinel.Tests/Approvals/ApprovalStoreRegistrationTests.cs`, `tests/AI.Sentinel.Approvals.EntraPim.Tests/GrantScopeTests.cs`, `tests/AI.Sentinel.Tests/ClaudeCode/HookCliTests.cs`, `tests/AI.Sentinel.Tests/Copilot/CopilotHookCliTests.cs`, `tests/AI.Sentinel.Tests/Mcp/McpCliTests.cs`

**Interfaces:**
- Consumes: `ApprovalNotifierSettings.FromConfig`, `NotifyingApprovalStore.Wrap`, `IApprovalStoreDecorator` (Task 4).
- Produces: `internal static void ApprovalBackendSelector.AddNotifier(IServiceCollection services, ApprovalConfig config)`, which registers the settings singleton when `FromConfig` returns one, and otherwise does nothing.
- Produces: `internal static IApprovalStore ApprovalStoreAuditing.Unwrap(IApprovalStore store)`, which follows `IApprovalStoreDecorator.Inner` to the first non-decorator.

`Wrap(sp, inner)`: first `inner = NotifyingApprovalStore.Wrap(inner, settings, logger)` when `sp.GetService<ApprovalNotifierSettings>()` is set. That happens before the no-audit-store early return, so the notifier applies with or without auditing. The `Memories` lookup keeps keying on the original inner store.

- [ ] **Step 1: Write failing tests**
- `Registration_WithNotifierSettings_WrapsStore`: `AddAISentinel` with an approval binding plus a registered `ApprovalNotifierSettings` → `Unwrap(resolved)` is `InMemoryApprovalStore`, and the chain contains a `NotifyingApprovalStore`. Run once with an audit store registered and once without.
- `Registration_WithoutNotifierSettings_NoNotifier`: the chain has no `NotifyingApprovalStore`.
- `Registration_AdminStillResolvable_WithNotifier`: `IApprovalAdmin` resolves, and an approve through it settles the request.
- `GrantScopeCall_RejectedWithNotifier` in GrantScopeTests: the existing rejection test plus a registered `ApprovalNotifierSettings` → same exception.
- One test per CLI file, `ApprovalConfig_WithNotifyUrl_PostsOnNewRequest`: point `notifyUrl` at a local `HttpListener` on a free loopback port, backend `sqlite` on a temp file, and trigger an approval-gated call through the CLI's existing in-process test entry point → exactly one request received with the expected `tool`. Follow how each file already drives an approval-gated call.

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** `Unwrap`, the decorator interface on `AuditingApprovalStore`, the `Wrap` change, `RejectCallScopedGrantsOnRoleActivationStore` using `Unwrap`, `AddNotifier`, and one `ApprovalBackendSelector.AddNotifier(services, approvalConfig)` call in each CLI where the backend store is registered, guarded by `approvalConfig is not null`.

- [ ] **Step 4: Run, verify pass**: the three CLI test classes, the registration tests and the EntraPim DLL.

- [ ] **Step 5: Commit**: `feat(cli): wire the approval webhook into sentinel-hook, sentinel-copilot-hook and sentinel-mcp`

### Task 6: Docs

**Files:**
- Modify: `website/docs/approvals/cli-config.md`; `website/docs/approvals/entra-pim.md` or the closest PIM page, if one exists
- Modify: the CHANGELOG only if the repo edits it by hand; release-please owns it otherwise

- [ ] **Step 1:** Add a "Notify on new requests" section: a table of the four keys with types and defaults, the payload example from the spec, a Slack example (`notifyUrl` = incoming webhook URL), an ntfy example (`notifyUrl: https://ntfy.sh/<topic>`, `notifyHeaders.Authorization: "Bearer ${NTFY_TOKEN}"`, with the note that ntfy shows the raw JSON body as the message text), the redaction behaviour of `notifyIncludeArgs`, the 3 s, no-retry failure behaviour, and the note that the link is the dashboard base URL until per-request pages exist. On the PIM page, one line saying a second call during a pending activation now returns that request.
- [ ] **Step 2:** Build the site only if the repo has a docs build in CI that checks links; otherwise check the relative links by hand.
- [ ] **Step 3: Commit**: `docs(approvals): document the approval webhook`
