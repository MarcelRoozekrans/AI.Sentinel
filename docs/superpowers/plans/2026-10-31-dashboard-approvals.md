# Dashboard approvals (#453) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sentinel dashboard` approves and denies SQLite approval requests, with identity from a trusted forward-auth proxy or the local OS user, decisions audited, cross-site POSTs refused, and a per-request page the webhook links to.

**Architecture:** The shared `DashboardHandlers` (AI.Sentinel.AspNetCore) gain a CSRF check and a per-request page, so every host gets them. AI.Sentinel.Cli loads the CLI approval config, opens the audit file writable only when approvals are on, registers the SQLite approval store through `AddSentinelSqliteApprovalStore` (so the existing auditing wrapper records decisions), and puts an internal identity middleware in front of `MapAISentinel`. The webhook text link becomes per request for the `sqlite` backend.

**Tech Stack:** .NET 8/10, ASP.NET Core minimal APIs, System.CommandLine 2.0, Microsoft.Data.Sqlite, xunit v3, `Microsoft.AspNetCore.TestHost`.

**Spec:** `docs/superpowers/specs/2026-10-31-dashboard-approvals-design.md`

## Global Constraints

- Default user header: `X-Auth-Request-User`. Default bind: `127.0.0.1`. Path prefix stays `/ai-sentinel`.
- Header value accepted only when: exactly one value, non-empty after trim, at most 256 characters, no control characters (`char.IsControl`).
- Authentication types: `TrustedProxy` and `LocalApprover`. Local approver name: `Environment.UserName`.
- Trust is decided on `HttpContext.Connection.RemoteIpAddress` only (IPv4-mapped IPv6 normalised with `MapToIPv4`); never `X-Forwarded-For`.
- Redaction on the detail page: `new RedactionSession([new CredentialExposureDetector(), new PiiLeakageDetector()]).RedactJsonValues(args)`, the call `ApprovalNotification.Create` uses.
- Default deny reason stays `denied via dashboard`.
- Without approvals the audit file is opened with `SqliteAuditStore.OpenReadOnly`, exactly as today. With approvals: `new SqliteAuditStore(new SqliteAuditStoreOptions { DatabasePath = db })`, no retention, no size cap, only after `File.Exists(db)`.
- Never print header values, config secrets or `notifyUrl` in output or logs.
- Every commit: conventional subject, no Claude trailer or links, no nested parentheses in the body. One commit per task.
- Before every commit: `dotnet format whitespace . --folder --verify-no-changes`.
- Tests: build, then run `dotnet tests/AI.Sentinel.Tests/bin/Debug/net10.0/AI.Sentinel.Tests.dll -noclass "*DetectorRegistrationTrimTests"` (with `-class` to narrow). Never `dotnet test` the solution, never AOT-publish. Three `DashboardCommandTests` fail locally on main too when the whole class runs in Release; compare against main before blaming the branch.

## Review Focus

1. **A proxy on the same host while `--local-approver` is set.** Mutual exclusion of the flags is the only guard; the parse test in Task 4 pins it, and the middleware test in Task 5 pins that the user header is ignored in local mode.
2. **`--bind 0.0.0.0` or `::` without a proxy.** Both are non-loopback and must be refused; Task 4 has a theory over `0.0.0.0`, `::`, `192.168.1.10`.
3. **Approving a request that someone else just settled.** The second click must not write a second audit entry or throw a 500. Task 6 end-to-end test approves twice and counts `APPROVED` entries.
4. **A request id with URL-special characters** (`/`, `?`, `%`) on the detail page and in the webhook link. Task 2 and Task 3 each have a test with id `a/b?c%d`.
5. **`SENTINEL_APPROVAL_CONFIG` set in the environment for an `in-memory` or broken config** while the user only wants to browse the audit log. In-memory from env → note + approvals off; broken file → exit 1 with the path. Task 6 tests both.

---

### Task 1: Refuse cross-site approve and deny POSTs

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs` (`ApproveAsync`, `DenyAsync`)
- Test: `tests/AI.Sentinel.Tests/AspNetCore/DashboardApprovalsTests.cs`

**Interfaces:**
- Produces: `private static bool IsCrossSite(HttpRequest request)` in `DashboardHandlers`, called first in both POST handlers, before the authentication check. Later tasks reuse it for nothing else.

- [ ] **Step 1: Write the failing tests** in `DashboardApprovalsTests`, using the existing `BuildHostAsync(store, authenticatedAs: "ops-bob")` helper and an `InMemoryApprovalStore` with one pending request:
  - `Approve_CrossSiteFetchMetadata_Returns403AndLeavesPending`: header `Sec-Fetch-Site: cross-site` → 403; `store.ListPendingAsync` still has the request.
  - `Approve_SameSiteFetchMetadata_Returns403` (`same-site`).
  - `Deny_MismatchedOrigin_Returns403`: `Origin: https://evil.example` → 403.
  - `Approve_NullOrigin_Returns403`: `Origin: null` → 403.
  - `Approve_SameOriginFetchMetadata_Succeeds`: `Sec-Fetch-Site: same-origin` → 200 and request Active.
  - `Approve_SecFetchSiteNone_Succeeds` (`none`).
  - `Approve_MatchingOrigin_Succeeds`: `Origin: http://localhost` (TestServer's base address) → 200.
  - `Approve_NoBrowserHeaders_Succeeds`: neither header → 200 (scripts keep working).
  - `Approve_CrossSite_ViaUseAISentinel_Returns403`: the same check through a host built with `UseAISentinel` (add a small builder overload or a second helper; the existing tests show the host shape).
  - `Approve_CrossSite_Anonymous_Returns403NotUnauthorized`: cross-site is checked before authentication.
- [ ] **Step 2: Run them** (`-class "AI.Sentinel.Tests.AspNetCore.DashboardApprovalsTests"`). Expected: the 403 tests fail with 200 or 401.
- [ ] **Step 3: Implement `IsCrossSite`**: `Sec-Fetch-Site` present → cross-site unless the value is `same-origin` or `none` (ordinal, case-insensitive). Else `Origin` present → cross-site when it is `null`, does not parse as an absolute URI, or its scheme, host and port do not equal `Request.Scheme` + `Request.Host` (default ports applied). Else not cross-site. On cross-site: 403 with body `Cross-site approval requests are refused.` and return.
- [ ] **Step 4: Run the class.** Expected: all pass, including the existing tests.
- [ ] **Step 5: Format check, commit** `fix(dashboard): refuse cross-site approve and deny requests`. Body: why (cookie-based forward auth makes a cross-site POST arrive authenticated), what is checked, that scripts without browser headers are unaffected.

### Task 2: Per-request approval page

**Files:**
- Create: `src/AI.Sentinel/Approvals/ExternalApprovalPortal.cs`
- Modify: `src/AI.Sentinel.AspNetCore/DashboardHandlers.cs` (new `ApprovalPageAsync`; `ListApprovalsAsync` row link and marker check)
- Modify: `src/AI.Sentinel.AspNetCore/ApplicationBuilderExtensions.cs` (map `GET /approvals/{id}` in both methods)
- Modify: `src/AI.Sentinel.AspNetCore/wwwroot/sentinel.css` (detail page styles, reuse existing tokens)
- Test: `tests/AI.Sentinel.Tests/AspNetCore/DashboardApprovalPageTests.cs`

**Interfaces:**
- Produces: `internal sealed class ExternalApprovalPortal` in namespace `AI.Sentinel.Approvals`, no members. Registered as a singleton by a host whose approvals are made elsewhere (Task 6 registers it for `entra-pim`). `ListApprovalsAsync` and `ApprovalPageAsync` treat `GetService<ExternalApprovalPortal>() is not null` with no store exactly like a non-admin store: the "managed externally (Entra PIM portal)" message.
- Produces: route `GET {prefix}/approvals/{id}` → `DashboardHandlers.ApprovalPageAsync(HttpContext)`.

- [ ] **Step 1: Write the failing tests** (host built like `DashboardApprovalsTests`, `InMemoryApprovalStore`, request with args `{"path":"/etc/x","apiKey":"sk-live-0123456789abcdefghijklmn"}` and justification `<b>why</b>`):
  - `Page_Pending_ShowsFieldsAndRedactedArgs`: 200, `text/html`; contains tool, caller, policy, requested-at in `yyyy-MM-ddTHH:mm:ssZ`, `&lt;b&gt;why&lt;/b&gt;`, `/etc/x`; does not contain `sk-live-0123456789abcdefghijklmn`; contains `btn-approve` and `btn-deny` and a `name="reason"` input.
  - `Page_HasNoStoreCacheControl`: `Cache-Control` contains `no-store`.
  - `Page_UnknownId_SaysNoLongerPending`: 200, contains `no longer pending`, no `btn-approve`.
  - `Page_SettledId_SaysNoLongerPending`: approve first, then GET.
  - `Page_NoStore_Returns404`: body contains `No approval store configured`.
  - `Page_NonAdminStore_ShowsExternalMessage` and `Page_ExternalPortalMarker_ShowsExternalMessage`; `ListApprovals_ExternalPortalMarker_RendersExternalMessage`.
  - `Page_IdWithUrlSpecialCharacters_Resolves`: a store stub whose pending id is `a/b?c%d`; GET `approvals/` + `Uri.EscapeDataString(id)` → shows the request; the buttons' `hx-post` use the escaped id.
  - `ListApprovals_RowLinksToPage`: row contains `href="approvals/` + escaped id + `"`.
  - `Page_MappedByUseAISentinel`: same 200 through `UseAISentinel`.
- [ ] **Step 2: Run them.** Expected: 404s and missing markup.
- [ ] **Step 3: Implement.** `ApprovalPageAsync` finds the request by scanning `IApprovalAdmin.ListPendingAsync` for an ordinal id match (route value is already unescaped). Render with a `StringBuilder` and the existing `HtmlEncode`, as the panel does; full HTML page that links `static/sentinel.css` and loads htmx the way `index.html` does, with a link back to `./` (relative to the prefix: the page is at `{prefix}/approvals/{id}`, so use `../` for the stylesheet, back link and `hx-post="../api/approvals/{id}/approve"`). Args are serialized indented after redaction and HTML-encoded inside `<pre>`. Approve/Deny swap a status line in place of the buttons (`Approved.` / `Denied.`); Deny posts `reason` via `hx-include` of the input. Set `Cache-Control: no-store` on every response of this handler.
- [ ] **Step 4: Run the new class and `DashboardApprovalsTests`.** Expected: all pass.
- [ ] **Step 5: Format check, commit** `feat(dashboard): page per approval request with redacted arguments`.

### Task 3: Webhook text links to the request page

**Files:**
- Modify: `src/AI.Sentinel/Approvals/Notifications/ApprovalNotifierSettings.cs`
- Modify: `src/AI.Sentinel/Approvals/Notifications/ApprovalNotification.cs`
- Test: `tests/AI.Sentinel.Tests/Approvals/Notifications/` (the existing notification payload tests; add to the file that tests `ApprovalNotification.Create`)

**Interfaces:**
- Produces: `ApprovalNotifierSettings` gains a fifth positional parameter `bool LinkToRequestPage`. `FromConfig` sets it to `string.Equals(config.Backend, "sqlite", StringComparison.Ordinal)`. Update every constructor call site (grep).

- [ ] **Step 1: Write the failing tests:**
  - `Text_Sqlite_LinksToRequestPage`: `DashboardUrl = https://dash.example.com/ai-sentinel/`, id `req-1` → text ends with ` https://dash.example.com/ai-sentinel/approvals/req-1`.
  - `Text_Sqlite_DashboardUrlWithoutTrailingSlash_GetsOne`: `https://dash.example.com/ai-sentinel` → `.../ai-sentinel/approvals/req-1`.
  - `Text_Sqlite_EscapesRequestId`: id `a/b?c%d` → `approvals/a%2Fb%3Fc%25d`.
  - `Text_EntraPim_Unchanged`: `LinkToRequestPage = false` → link is `DashboardUrl` as today.
  - `Payload_DashboardUrl_StaysConfiguredValue`: payload `dashboardUrl` unchanged for sqlite.
  - `FromConfig_SqliteBackend_LinksToRequestPage` / `FromConfig_EntraPimBackend_DoesNot`.
- [ ] **Step 2: Run them.** Expected: fail.
- [ ] **Step 3: Implement** in `ApprovalNotification.Create`: when `LinkToRequestPage` and `DashboardUrl` is set, link = base (`AbsoluteUri` with a `/` appended when it does not end in one) + `approvals/` + `Uri.EscapeDataString(pending.RequestId)`. Otherwise today's rule.
- [ ] **Step 4: Run the notification tests and `NotifyingApprovalStoreTests`.** Expected: pass.
- [ ] **Step 5: Format check, commit** `feat(approvals): webhook text links to the request page for sqlite`.

### Task 4: Dashboard options and their validation

**Files:**
- Create: `src/AI.Sentinel.Cli/DashboardSettings.cs`
- Modify: `src/AI.Sentinel.Cli/DashboardCommand.cs` (options, validation, bind address)
- Test: `tests/AI.Sentinel.Tests/Cli/DashboardOptionsTests.cs`

**Interfaces:**
- Produces:
  ```csharp
  internal sealed record DashboardSettings(string DbPath, int Port)
  {
      public IPAddress Bind { get; init; } = IPAddress.Loopback;
      public string? ApprovalConfigPath { get; init; }
      public bool ApprovalConfigExplicit { get; init; }
      public IReadOnlyList<IPNetwork> TrustedProxies { get; init; } = [];
      public string UserHeader { get; init; } = "X-Auth-Request-User";
      public bool LocalApprover { get; init; }
  }
  ```
  `DashboardCommand.StartAsync(DashboardSettings settings, TextWriter stdout, TextWriter stderr, CancellationToken ct)` (internal); the existing public `StartAsync(string, int, ...)` and `RunAsync` delegate to it with `new DashboardSettings(dbPath, port)`. `internal static Command Build(Func<string> defaultDatabasePath, Func<string?> approvalConfigFromEnvironment)`; the existing overloads pass `() => Environment.GetEnvironmentVariable("SENTINEL_APPROVAL_CONFIG")`. Blank env value counts as unset.
- Options: `--bind <ip>`, `--approval-config <path>`, `--trusted-proxy <cidr>` (`AllowMultipleArgumentsPerToken = false`, repeatable), `--user-header <name>`, `--local-approver` (bool flag). A bare IP for `--trusted-proxy` becomes `/32` or `/128`.

- [ ] **Step 1: Write the failing tests** (parse via `Build(...)` with a temp default db path and a stub env func, invoke with `InvocationConfiguration` writers like `DashboardCommandTests` does; assert exit code 1 and a stderr substring, no stack trace):
  - Theory `NonLoopbackBind_WithoutTrustedProxy_IsRefused` over `0.0.0.0`, `::`, `192.168.1.10` → mentions `--trusted-proxy`.
  - `Bind_NotAnIp_IsRefused` (`localhost`).
  - `TrustedProxy_NotACidr_IsRefused` (`10.0.0.0/33`, `abc`).
  - `UserHeader_WithoutTrustedProxy_IsRefused`; `UserHeader_InvalidToken_IsRefused` (`X Auth`).
  - `LocalApprover_WithTrustedProxy_IsRefused`; `LocalApprover_WithNonLoopbackBind_IsRefused`.
  - `Settings_Defaults`: a helper `internal static DashboardSettings ReadSettings(ParseResult)` is unit-tested directly: bind `127.0.0.1`, header `X-Auth-Request-User`, no proxies, no config.
  - `Settings_ApprovalConfigFlagWinsOverEnvironment` (`ApprovalConfigExplicit == true`); `Settings_ApprovalConfigFromEnvironment` (`false`); `Settings_BlankEnvironment_IsNoConfig`.
  - `Settings_BareProxyAddress_IsSingleHost`: `10.1.2.3` → `10.1.2.3/32`; `::1` → `/128`.
  - `Start_BindsTheGivenLoopbackAddress`: `Bind = IPAddress.IPv6Loopback` → `dashboard.Url` host is `[::1]` and a GET of `api/stats` succeeds. (Skip with `Assert.Skip` when IPv6 loopback is unavailable.)
- [ ] **Step 2: Run them.** Expected: fail (unknown options).
- [ ] **Step 3: Implement** the options with validators on the command (`cmd.Validators.Add`) for cross-option rules, `ReadSettings`, and `UseUrls` built from `Bind` (bracket IPv6). The printed URL uses the bound address and port. Keep every existing message and test passing.
- [ ] **Step 4: Run `DashboardOptionsTests` and `DashboardCommandTests`.** Expected: pass (bar the three known local Release failures, if run in Release).
- [ ] **Step 5: Format check, commit** `feat(cli): bind, trusted-proxy and local-approver options for sentinel dashboard`.

### Task 5: Approver identity middleware

**Files:**
- Create: `src/AI.Sentinel.Cli/ApproverIdentityMiddleware.cs`
- Test: `tests/AI.Sentinel.Tests/Cli/ApproverIdentityMiddlewareTests.cs`

**Interfaces:**
- Consumes: `DashboardSettings.TrustedProxies`, `UserHeader`, `LocalApprover`.
- Produces: `internal static class ApproverIdentityMiddleware { internal static IApplicationBuilder UseApproverIdentity(this IApplicationBuilder app, DashboardSettings settings); }`. A no-op when neither proxies nor `LocalApprover` are set.

- [ ] **Step 1: Write the failing tests.** `TestServer` host with the middleware and one endpoint that returns `ctx.User.Identity.IsAuthenticated`, `Name` and `AuthenticationType`; set the remote address with a tiny middleware ahead of it (`ctx.Connection.RemoteIpAddress = ...`) driven by a test header such as `X-Test-Remote`:
  - `Proxy_InRange_WithHeader_IsAuthenticated` (`10.0.0.5` in `10.0.0.0/24`, header `alice`) → `alice`, `TrustedProxy`.
  - `Proxy_IPv4MappedRemote_IsInRange` (`::ffff:10.0.0.5`).
  - `Proxy_OutOfRange_WithHeader_IsAnonymous` (`10.0.1.5`).
  - Theory `Proxy_InRange_BadHeader_IsAnonymous`: missing, empty, whitespace, two values, 257 chars, contains `\u0001`.
  - `Proxy_CustomHeaderName_IsUsed` (`Remote-User`) and the default header is then ignored.
  - `Proxy_TrimsHeaderValue` (`"  alice "` → `alice`).
  - `Local_Loopback_IsOsUser` → `Environment.UserName`, `LocalApprover`; `Local_IPv6Loopback_IsOsUser`.
  - `Local_NonLoopback_IsAnonymous`.
  - `Local_IgnoresUserHeader`: loopback with `X-Auth-Request-User: mallory` → still the OS user.
  - `NeitherMode_UserHeaderIgnored`.
- [ ] **Step 2: Run them.** Expected: fail to compile, then fail.
- [ ] **Step 3: Implement.** Build the principal as `new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.Name, name)], authenticationType))`. Do not log header values.
- [ ] **Step 4: Run the class.** Expected: pass.
- [ ] **Step 5: Format check, commit** `feat(cli): approver identity from a trusted proxy header or the local user`.

### Task 6: Wire approvals into `sentinel dashboard`

**Files:**
- Modify: `src/AI.Sentinel.Cli/AI.Sentinel.Cli.csproj` (ProjectReference `AI.Sentinel.Approvals.Sqlite`)
- Modify: `src/AI.Sentinel.Cli/DashboardCommand.cs` (config load, audit open mode, DI, middleware, redirect, startup line, class doc comment)
- Modify: `src/AI.Sentinel.Cli/RunningDashboard.cs` (also owns the approval store; dispose it after the app, before the audit store)
- Test: `tests/AI.Sentinel.Tests/Cli/DashboardApprovalsCommandTests.cs`

**Interfaces:**
- Consumes: `DashboardSettings` and `StartAsync(DashboardSettings, ...)` (Task 4), `UseApproverIdentity` (Task 5), `ExternalApprovalPortal` (Task 2), `ApprovalConfigLoader.Load(string)`, `AddSentinelSqliteApprovalStore`.
- Behaviour by backend: `sqlite` → approvals on; `entra-pim` → register `ExternalApprovalPortal`, audit stays read-only, no Graph; `in-memory` → error when `ApprovalConfigExplicit`, else note and off; `none` → note and off. Load failure → stderr `Could not load the approval config <path>: <message>`, return null.
- Startup line after `Dashboard: <url>`, one of: `Approvals: off`, `Approvals: off (<reason>)`, `Approvals: managed in Entra PIM`, `Approvals: sqlite <databasePath>, approver from <header> via <cidr list>`, `Approvals: sqlite <databasePath>, approver is the local user <name>`, `Approvals: sqlite <databasePath>, no approver configured, so approve and deny are refused`.
- Approvals on: verify the schema first by opening and disposing `SqliteAuditStore.OpenReadOnly(db)` (keeps today's older-schema refusal), then open the writable store with default options. `MapGet("/approvals/{id}", ...)` at the root redirects to `/ai-sentinel/approvals/{escaped id}`.

- [ ] **Step 1: Write the failing tests** (real Kestrel on port 0 like `DashboardCommandTests`; temp audit file seeded the way that class seeds; temp `approvals.json` with `"backend":"sqlite"` and a temp `databasePath`; create a pending request with a `SqliteApprovalStore` over the same file):
  - `Sqlite_LocalApprover_ApproveIsRecordedOnceInTheAuditChain`: approve via HTTP POST → 200; the request is Active with `approver_id` = `Environment.UserName` (read with `SqliteApprovalStore` or SQL); the audit file has exactly one new entry with `PolicyCode == "APPROVED"`; `AuditHashChain.VerifyAsync` intact. POST again → no second `APPROVED` entry, no 500.
  - `Sqlite_TrustedProxy_DenyRecordsHeaderUserAndReason`: `TrustedProxies = [127.0.0.1/32]`, header `X-Auth-Request-User: carol`, form `reason=too risky` → Denied, approver `carol`, one `DENIED` entry.
  - `Sqlite_NoApproverConfigured_ApproveIs401AndAuditUnchanged`.
  - `Sqlite_PanelListsThePendingRequest`: `api/approvals` contains the tool name.
  - `NoApprovalConfig_AuditFileStaysReadOnly`: the existing `Start_DoesNotAppend` shape still holds; plus `stdout` contains `Approvals: off`.
  - `EntraPim_ShowsExternalMessage_AndDoesNotWrite`: config `backend: entra-pim` with a tenant id → panel shows `PIM portal`; audit file unchanged.
  - `InMemory_Explicit_ExitsWithError`; `InMemory_FromEnvironment_NotesAndContinues` (stdout `Approvals: off (`).
  - `TrustedProxyWithoutApprovals_NotesNothingToApprove`: proxy set, no config → starts, stdout `Approvals: off (no approval config, so --trusted-proxy has nothing to approve)`.
  - `BrokenConfig_ReturnsNullWithPath`: invalid JSON → null, stderr contains the path.
  - `OlderAuditSchema_WithApprovals_StillRefused`: reuse `SetUserVersion` from `DashboardCommandTests` (move it to a shared test helper if needed).
  - `RootApprovalLink_RedirectsUnderThePrefix`: GET `/approvals/a%2Fb` without following redirects → 302 to `/ai-sentinel/approvals/a%2Fb`.
  - `StartupLine_NeverPrintsHeaderValues`: `stdout` has no header value from any request (trivially; assert the line format for the proxy case).
  - `Dispose_ReleasesTheApprovalDatabase`: after `DisposeAsync`, deleting `approvals.db` succeeds.
- [ ] **Step 2: Run them.** Expected: fail.
- [ ] **Step 3: Implement.** Register `IAuditStore` and then `AddSentinelSqliteApprovalStore(o => o.DatabasePath = config.DatabasePath!)`. `app.UseApproverIdentity(settings)` before `MapAISentinel`. Resolve the `SqliteApprovalStore` singleton once after `Build()` so `RunningDashboard` can dispose it. Update the `DashboardCommand` doc comment: read-only only without approvals.
- [ ] **Step 4: Run `DashboardApprovalsCommandTests`, `DashboardCommandTests`, `DashboardOptionsTests`, `ApproverIdentityMiddlewareTests`.** Expected: pass (bar the three known local Release failures).
- [ ] **Step 5: Format check, commit** `feat(cli): approve and deny from sentinel dashboard`.

### Task 7: Docs

**Files:**
- Modify: `website/docs/integrations/claude-code.md`, `website/docs/integrations/copilot.md`, `website/docs/integrations/mcp-proxy.md` (wherever they say the dashboard shows no approvals panel)
- Modify: `website/docs/getting-started/dashboard.md` (CLI dashboard options)
- Modify: `website/docs/approvals/dashboard.md` (CLI dashboard as a host, identity modes, forward-auth example with oauth2-proxy `X-Auth-Request-User` and Authelia `Remote-User`, the CSRF rule, the detail page)
- Modify: `website/docs/approvals/cli-config.md` (`dashboardUrl` includes the prefix, example `https://dash.example.com/ai-sentinel/`; per-request link for sqlite; payload table row for `text`)
- Modify: `README.md` if it describes `sentinel dashboard` as read-only

- [ ] **Step 1: Grep** `rg -n "no approvals panel|read-only|sentinel dashboard|dashboardUrl" website/docs README.md` and update every hit that the change makes wrong.
- [ ] **Step 2: Build the site check** the project uses, if any is cheap (`npm run build` in `website/` only if `node_modules` exists; otherwise skip and say so in the commit body).
- [ ] **Step 3: Format check, commit** `docs: approvals in sentinel dashboard`.
