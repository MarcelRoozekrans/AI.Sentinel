# Tool-Call Authorization (`IToolCallGuard`) Design

**Date:** 2026-04-25

---

## Problem

Microsoft.Extensions.AI ships no authorization story for LLM tool invocations. Every detector AI.Sentinel runs answers "is this content malicious?" — none answers "is this caller allowed to invoke this tool with these arguments?" The four surfaces AI.Sentinel currently sits on (in-process `FunctionInvokingChatClient`, Claude Code hook, Copilot hook, MCP proxy) all reach the same gap: a permitted-but-dangerous tool can be called by anyone the host hands the keys to.

## Goal

Ship `IToolCallGuard` — an RBAC-style preventive control evaluated at every tool-call boundary across all four surfaces. Authorization runs *before* the existing detection layer, returns binary `Allow | Deny`, and emits audit entries through the existing `IAuditStore` pipeline. Designed to share identity primitives (`ISecurityContext`, `IAuthorizationPolicy`, `[Authorize]`) with the planned `ZeroAlloc.Mediator.Authorization` extension so users write one policy class for both worlds.

---

## Architecture

```
Tool call (any surface)
       │
       ▼
  ┌──────────────────────────────────────┐
  │  IToolCallGuard.AuthorizeAsync(ctx)  │   ← runs first, fast path
  │   • resolves ISecurityContext        │
  │   • looks up policy(s) for tool name │
  │   • calls IAuthorizationPolicy       │
  │   • returns Allow / Deny             │
  └──────────────────────────────────────┘
       │
       ├── Deny ──► AuditEntry(DetectorId="AUTHZ-DENY") ──► surface-specific block
       │              + Mediator notification (if Alert+ configured)
       │
       └── Allow ──► existing SentinelPipeline.RunAsync (detection)
                       │
                       ├── threat detected ──► quarantine/alert (existing flow)
                       └── clean ──► tool executes
```

Three new conceptual layers:

| Layer | Lives in | Responsibility |
|---|---|---|
| **Identity** (`ISecurityContext`, `AnonymousSecurityContext`, `ClaimsPrincipalSecurityContext`) | `AI.Sentinel` core (Claims one in `AI.Sentinel.AspNetCore`) | "Who is calling?" |
| **Policy** (`IAuthorizationPolicy`, `[AuthorizationPolicy]`, `ToolCallAuthorizationPolicy` base) | `AI.Sentinel` core | "Are they allowed?" |
| **Binding** (`[Authorize]`, `RequireToolPolicy`, `IToolCallGuard`) | `AI.Sentinel` core | "Which policies guard which tools?" |

**Key design properties:**

- Guard runs **before** detection on every surface — same placement everywhere.
- Same `IAuthorizationPolicy` interface as the planned `ZeroAlloc.Mediator.Authorization` — one policy class, both worlds.
- Default behaviour when no policies are registered: **Allow everything**. Drop-in upgrade for existing AI.Sentinel users (no breaking changes). Opt-in security model.
- Default behaviour for tools with no `RequireToolPolicy` binding when policies *are* registered: configurable via `opts.DefaultToolPolicy = Allow | Deny`. Default is `Allow`.
- Policy registration via ZeroAlloc.Inject `[Singleton]` (consistent with detectors) — source-gen handles DI.

**Decisions explicitly deferred to backlog:**

- **PIM-style approval workflow** (`RequireApproval` decision, `IApprovalStore`, time-bound grants, dashboard Approve/Deny UI). Strictly additive — adding it later doesn't break the v1 binary contract.
- **Async `IsAuthorized`**. The interface is sync to mirror ZeroAlloc Mediator.Authorization. Async support is a v2 question to be answered jointly across both packages.
- **Source-gen-driven policy name lookup**. Reflection-cached at startup is fine for v1.

---

## Core Types

### Identity layer (`AI.Sentinel.Authorization` namespace, ships in core `AI.Sentinel`)

```csharp
public interface ISecurityContext
{
    string Id { get; }                                  // stable caller ID — user, agent, service
    IReadOnlySet<string> Roles { get; }                 // role membership
    IReadOnlyDictionary<string, string> Claims { get; } // optional — tenant, scope, sub
}

public sealed class AnonymousSecurityContext : ISecurityContext
{
    public static readonly AnonymousSecurityContext Instance = new();
    public string Id => "anonymous";
    public IReadOnlySet<string> Roles { get; } = new HashSet<string>();
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>();
}
```

`ClaimsPrincipalSecurityContext` lives in `AI.Sentinel.AspNetCore` — wraps `ClaimsPrincipal`, exposes `Roles` from `ClaimTypes.Role` and `Claims` from all other claim types.

### Tool-call context (derived)

```csharp
public interface IToolCallSecurityContext : ISecurityContext
{
    string ToolName { get; }
    JsonElement Args { get; }
}
```

### Policy layer

```csharp
public interface IAuthorizationPolicy
{
    bool IsAuthorized(ISecurityContext ctx);
}

[AttributeUsage(AttributeTargets.Class)]
public sealed class AuthorizationPolicyAttribute(string name) : Attribute
{
    public string Name { get; } = name;
}

// Ergonomic base for tool-call-aware policies (only sees IToolCallSecurityContext)
public abstract class ToolCallAuthorizationPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) =>
        ctx is IToolCallSecurityContext tc ? IsAuthorized(tc) : true;
    protected abstract bool IsAuthorized(IToolCallSecurityContext ctx);
}
```

### Binding layer

```csharp
[AttributeUsage(AttributeTargets.Method)]
public sealed class AuthorizeAttribute(string policyName) : Attribute
{
    public string PolicyName { get; } = policyName;
}

public enum ToolPolicyDefault { Allow, Deny }

public static class SentinelOptionsAuthorizationExtensions
{
    public static SentinelOptions RequireToolPolicy(this SentinelOptions opts,
        string toolNameOrPattern, string policyName);

    public static SentinelOptions DefaultToolPolicy(this SentinelOptions opts,
        ToolPolicyDefault behaviour);
}
```

### Guard

```csharp
public sealed record AuthorizationDecision(bool Allowed, string? PolicyName, string? Reason)
{
    public static readonly AuthorizationDecision Allow = new(true, null, null);
    public static AuthorizationDecision Deny(string policyName, string reason) =>
        new(false, policyName, reason);
}

public interface IToolCallGuard
{
    ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default);
}

[Singleton(As = typeof(IToolCallGuard))]
internal sealed class DefaultToolCallGuard : IToolCallGuard
{
    // Resolves IAuthorizationPolicy by name from registered policies (DI).
    // Looks up tool name via wildcard match (`*` suffix only) → policy name(s).
    // Falls back to opts.DefaultToolPolicy.
}
```

**Wildcard match rules:** `*` only at end. `delete_*` matches `delete_user`, `delete_account`. No regex, no `?`, no character classes. If multiple patterns match, all matching policies must allow (logical AND). Order is irrelevant.

### Exception (in-process surface)

```csharp
public sealed class ToolCallAuthorizationException(AuthorizationDecision decision)
    : SentinelException($"Tool call denied by policy '{decision.PolicyName}': {decision.Reason}")
{
    public AuthorizationDecision Decision { get; } = decision;
}
```

---

## Per-Surface Integration

The four surfaces look different on the outside but follow the same shape: resolve `ISecurityContext`, build `IToolCallSecurityContext`, call `IToolCallGuard.AuthorizeAsync`, branch on the decision.

### In-process (`FunctionInvokingChatClient`)

New `ChatClientBuilder` extension:

```csharp
builder.Services.AddChatClient(pipeline =>
    pipeline.UseAISentinel()                          // existing — detection layer
            .UseToolCallAuthorization()                // new — guard layer
            .UseFunctionInvocation()                   // existing M.E.AI built-in
            .Use(new OpenAIChatClient(...)));
```

`UseToolCallAuthorization()` registers a delegating `IChatClient` that intercepts function-invocation tool calls. Resolves `ISecurityContext` from DI (`IServiceProvider.GetService<ISecurityContext>() ?? AnonymousSecurityContext.Instance`).

**Caller-context registration patterns:**
- AspNetCore: `services.AddScoped<ISecurityContext, ClaimsPrincipalSecurityContext>()` (auto-wired by `AI.Sentinel.AspNetCore`)
- Background worker / CLI: `services.AddSingleton<ISecurityContext>(_ => new SimpleSecurityContext("system", roles: ["service"]))`
- Otherwise: `AnonymousSecurityContext`

**Deny → throw `ToolCallAuthorizationException`** (subclass of `SentinelException`).

**Attribute discovery:** `[Authorize("admin-only")]` on a method gets picked up at `AIFunction` registration time. We hook into Microsoft.Extensions.AI's function metadata (the function's `AdditionalProperties` or by reading the underlying `MethodInfo`). At startup, `[Authorize]` on a method translates to a `RequireToolPolicy(funcName, policyName)` binding — same internal table as the explicit binding API.

### Claude Code hook (`AI.Sentinel.ClaudeCode`)

`HookAdapter.HandleAsync` already branches on `HookEvent.PreToolUse`. Extension:

```csharp
if (evt == HookEvent.PreToolUse)
{
    var caller = config.CallerContextProvider?.Invoke(input) ?? AnonymousSecurityContext.Instance;
    var decision = await guard.AuthorizeAsync(caller, input.ToolName!, input.ToolInput!, ct);
    if (!decision.Allowed)
    {
        await audit.AppendAsync(AuditEntry.AuthorizationDeny(...), ct);
        return new HookOutput(HookDecision.Block,
            $"Authorization denied by policy '{decision.PolicyName}': {decision.Reason}");
    }
    // existing detection scan continues
}
```

`HookConfig` gains:
```csharp
public Func<HookInput, ISecurityContext>? CallerContextProvider { get; set; }
```

Default `null` → `AnonymousSecurityContext`. Documented patterns: identity from `Environment.UserName`; identity from a config file path / env var.

### Copilot hook (`AI.Sentinel.Copilot`)

Identical shape to Claude Code — same `CallerContextProvider` extension on `CopilotHookConfig`, same flow inside `CopilotHookAdapter.HandleAsync`. Different only in input record type (`CopilotHookInput` vs `HookInput`).

### MCP proxy (`AI.Sentinel.Mcp`)

`ToolCallInterceptor` already wraps `tools/call`. Extension at the start:

```csharp
var caller = callerContextResolver?.Invoke(request) ?? AnonymousSecurityContext.Instance;
var decision = await guard.AuthorizeAsync(caller, request.Name, ToJsonElement(request.Arguments), ct);
if (!decision.Allowed)
{
    await audit.AppendAsync(AuditEntry.AuthorizationDeny(...), ct);
    throw new McpException(McpErrorCode.InvalidRequest,
        $"Authorization denied by policy '{decision.PolicyName}': {decision.Reason}");
}
// existing pre-scan continues
```

Caller-context resolution for MCP — three sources, in order of precedence:
1. Custom `Func<CallToolRequestParams, ISecurityContext>` registered via DI (most flexibility)
2. Env vars `SENTINEL_MCP_CALLER_ID`, `SENTINEL_MCP_CALLER_ROLES` (comma-separated) — set by parent process when launching the proxy
3. Falls back to `AnonymousSecurityContext`

Trade-off: MCP is the surface where caller identity is hardest to do well — the protocol has no built-in caller identity field. Env-var path is the pragmatic default.

### Symmetry summary

| Surface | Caller resolution default | Deny semantics |
|---|---|---|
| In-process | `IServiceProvider.GetService<ISecurityContext>()` → Anonymous | throw `ToolCallAuthorizationException` |
| Claude Code | `HookConfig.CallerContextProvider` → Anonymous | `HookOutput(Block, reason)` |
| Copilot | `CopilotHookConfig.CallerContextProvider` → Anonymous | `HookOutput(Block, reason)` |
| MCP proxy | DI provider → env vars → Anonymous | `McpException(InvalidRequest, reason)` |

All four call the exact same `IToolCallGuard.AuthorizeAsync` and emit the same `AuditEntry` shape.

---

## Audit, Dashboard, and Observability

**Audit shape — reuse existing `AuditEntry`:**

```csharp
public static class AuditEntryExtensions
{
    public static AuditEntry AuthorizationDeny(
        AgentId sender, AgentId receiver, SessionId session,
        string callerId, IReadOnlySet<string> roles,
        string toolName, string policyName, string reason)
    => new()
    {
        Timestamp  = DateTime.UtcNow,
        DetectorId = new DetectorId("AUTHZ-DENY"),
        Severity   = Severity.High,
        Summary    = $"Caller '{callerId}' (roles: [{string.Join(",", roles)}]) " +
                     $"denied for tool '{toolName}' by policy '{policyName}': {reason}",
        // Hash + PreviousHash chained as today
    };
}
```

Why reuse `AuditEntry`:
- Ring buffer, persistence (`IAuditStore`), dashboard rendering all work unchanged
- Hash chain for tamper-evidence applies the same way
- One audit feed for "things that happened at the boundary" — denials sit alongside detection hits naturally
- Filtering by `DetectorId.StartsWith("AUTHZ-")` separates authz events when needed

**Severity = `High` for every deny.** A policy denial isn't "maybe-suspicious" — it's "the system explicitly refused this." High maps to existing `OnHigh` action; `OnHigh = Alert` produces Mediator notifications for free.

**No allow-events in audit.** Allows are silent. Denies are loud. Future option in backlog: `opts.AuditAllows = true` for compliance.

**Dashboard:** Existing live feed already renders any `AuditEntry`. Two small additions:

1. New "Authorization" filter chip alongside existing category chips (filters by `DetectorId.StartsWith("AUTHZ-")`)
2. Distinct row colour / icon for `AUTHZ-DENY` entries

**Mediator notifications:** Existing `InterventionEngine` publishes `DetectionNotification` for any audit entry tied to an intervention. AUTHZ-DENY entries flow through this path automatically. Plugins filter by `entry.DetectorId == "AUTHZ-DENY"`.

**Telemetry:** `[Instrument("ai.sentinel")]` on `IToolCallGuard` interface — source-gen emits OpenTelemetry spans (duration, decision, policy name as span attributes).

**No new `IGuardLog` interface** — explicitly rejected. Reusing `IAuditStore` is the right answer.

---

## Registration, Defaults, Error Handling

### Policy registration

```csharp
[Singleton(As = typeof(IAuthorizationPolicy), AllowMultiple = true)]
[AuthorizationPolicy("admin-only")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("admin");
}
```

`[Singleton]` drives DI registration via ZeroAlloc.Inject source-gen — zero manual wiring. `[AuthorizationPolicy("admin-only")]` is the *name* the binding API and `[Authorize]` attribute look up. At pipeline construction, `DefaultToolCallGuard` enumerates all registered `IAuthorizationPolicy` instances once and builds a name → policy dictionary (cached for the process lifetime).

### Tool→policy bindings — three sources, merged at startup

```csharp
// 1. Explicit binding API on SentinelOptions
opts.RequireToolPolicy("Bash",         "admin-only");
opts.RequireToolPolicy("delete_*",     "admin-only");
opts.RequireToolPolicy("send_payment", "finance");

// 2. [Authorize] on AIFunction methods (in-process surface only)
[Authorize("admin-only")]
public string DeleteUser(string id) { ... }
// → translated to RequireToolPolicy("DeleteUser", "admin-only") at AIFunction registration

// 3. opts.DefaultToolPolicy = ToolPolicyDefault.Allow | Deny
//    Applied when no pattern matches.
```

**If multiple patterns match a tool name, all matching policies must allow** (logical AND). Order is irrelevant.

### Defaults

| Setting | Default | Rationale |
|---|---|---|
| `opts.DefaultToolPolicy` | `Allow` | Drop-in upgrade for existing AI.Sentinel users — adding the package doesn't break anyone |
| Caller context (any surface) when no provider configured | `AnonymousSecurityContext.Instance` | Same: no breakage. Roles set is empty, so policies referencing roles deny — but only if a user wrote a policy |
| Guard registration | Always wired by `AddAISentinel()` | With no bindings + Allow default, every call is allowed; cost is one dictionary lookup |

### Startup warnings (via existing `ILogger<SentinelPipeline>`)

```csharp
if (opts.DefaultToolPolicy == ToolPolicyDefault.Deny && !registered.Any())
    logger.LogWarning("AI.Sentinel: DefaultToolPolicy=Deny but no IAuthorizationPolicy implementations are registered — every tool call will be denied.");

if (bindings.Any() && callerContextResolver is null)
    logger.LogWarning("AI.Sentinel: tool-call policies are configured, but no ISecurityContext provider is registered — all calls will resolve as Anonymous and policies referencing roles will deny.");

if (bindings.Any(b => !registered.ContainsKey(b.PolicyName)))
    logger.LogError("AI.Sentinel: RequireToolPolicy(...) references unknown policy '{Name}'. This binding will deny every matching call.");
```

### Error handling

| Situation | Behaviour |
|---|---|
| Policy class throws | **Deny** (fail-closed). Audit entry includes exception type. Logged at `LogError`. Exception is *not* propagated. Rationale: a buggy policy must never crash the host. |
| Policy name in binding doesn't resolve | **Deny** (fail-closed). Logged once at startup as `LogError`. Per-call: silent deny + audit entry referencing the missing policy. |
| `IsAuthorized` runs long (network, DB) | Allowed. Policies that need I/O are legitimate (tenant lookup). Guard does not enforce a timeout. Future enhancement: optional `opts.PolicyTimeout` with deny-on-timeout. |
| `IsAuthorized` async (returns `Task<bool>`) | Not supported in v1. Sync interface mirrors ZeroAlloc Mediator.Authorization. Policies needing I/O cache results or block synchronously. |

**Constraint to flag:** Sync `IsAuthorized` is the only meaningful constraint inherited from the ZeroAlloc shape. Forces tenant-lookup-style policies to either pre-cache or block synchronously. For the four current surfaces, sync is fine.

---

## Test Strategy

### Unit tests (`tests/AI.Sentinel.Tests/Authorization/`)

- `DefaultToolCallGuard_NoPoliciesRegistered_AllowsByDefault`
- `DefaultToolCallGuard_ExactToolMatch_UsesBoundPolicy`
- `DefaultToolCallGuard_WildcardMatch_UsesBoundPolicy` (`delete_*` matches `delete_user`)
- `DefaultToolCallGuard_MultipleMatchingPolicies_AllMustAllow` (logical AND)
- `DefaultToolCallGuard_NoMatch_UsesDefaultToolPolicy` (Allow + Deny variants)
- `DefaultToolCallGuard_PolicyThrows_FailsClosed_ReturnsDeny`
- `DefaultToolCallGuard_BindingReferencesUnknownPolicy_ReturnsDeny`
- `DefaultToolCallGuard_AnonymousCaller_PolicyReferencingRoles_Denies`
- `DefaultToolCallGuard_ToolCallContext_PolicyAccessesArgs` (verify `IToolCallSecurityContext` cast)

### Policy class tests

- `AdminOnlyPolicy_AdminCaller_Allows` / `_NonAdminCaller_Denies`
- Sample arg-aware: `NoSystemPathsPolicy_BashWithSystemPath_Denies` / `_AllowsOtherPaths`

### Identity context tests

- `AnonymousSecurityContext_HasEmptyRolesAndClaims`
- `ClaimsPrincipalSecurityContext_RoleClaimsExposedAsRoles` (in `AI.Sentinel.AspNetCore.Tests`)
- `ClaimsPrincipalSecurityContext_NonRoleClaimsExposedAsClaims`

### Per-surface integration tests

| Surface | Test class | Scenarios |
|---|---|---|
| In-process | `tests/AI.Sentinel.Tests/Integration/InProcessAuthorizationTests.cs` | `[Authorize]`-attributed AIFunction denies/allows; deny throws `ToolCallAuthorizationException`; `RequireToolPolicy` binding takes effect; `ISecurityContext` resolved from DI |
| Claude Code | `tests/AI.Sentinel.ClaudeCode.Tests/AuthorizationTests.cs` | `PreToolUse` deny → `HookOutput(Block, ...)`; `CallerContextProvider` invoked; default Anonymous → policy referencing roles denies |
| Copilot | `tests/AI.Sentinel.Copilot.Tests/AuthorizationTests.cs` | Same as Claude Code (parallel structure) |
| MCP proxy | `tests/AI.Sentinel.Mcp.Tests/AuthorizationTests.cs` | `tools/call` deny → `McpException(InvalidRequest)`; env-var caller resolution; DI provider takes precedence over env |

### Audit + dashboard tests

- `AuditEntry.AuthorizationDeny_HasCorrectShape` (DetectorId = `AUTHZ-DENY`, Severity = High, Summary contains caller + tool + policy)
- `RingBufferAuditStore_StoresAuthDenies_AlongsideDetections`
- Dashboard render test for the `AUTHZ-DENY` filter chip

### Test helpers (new)

```csharp
internal sealed class TestSecurityContext(string id, params string[] roles) : ISecurityContext
{
    public string Id { get; } = id;
    public IReadOnlySet<string> Roles { get; } = new HashSet<string>(roles);
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>();
}

internal sealed class TestToolCallSecurityContext(ISecurityContext inner, string toolName, JsonElement args)
    : IToolCallSecurityContext { ... }
```

### Coverage targets

- `DefaultToolCallGuard`: 100% line coverage (small class, all paths matter)
- Per-surface integration: at least 1 deny + 1 allow path per surface, exercising the actual surface entrypoint

### Explicitly NOT tested in v1

- Approval workflows (deferred to backlog)
- Policy timeout behaviour
- Async policy support
- Source-gen-driven policy name lookup (still reflection-cached for v1)

---

## Future Work (Backlog Items)

To be added to `docs/BACKLOG.md` as follow-ups:

1. **PIM-style approval workflow** — `RequireApproval` decision, `IApprovalStore` (in-memory + persistent backends), time-bound grants with TTL, dashboard Approve/Deny UI with justification, Mediator pending-approval notification, per-surface wait strategies. Strictly additive to the binary v1 contract.
2. **`ZeroAlloc.Authorization.Abstractions`** — extract `ISecurityContext`, `IAuthorizationPolicy`, `[Authorize]`, `[AuthorizationPolicy]` into a shared package once `ZeroAlloc.Mediator.Authorization` ships, so both AI.Sentinel and Mediator depend on the same primitives.
3. **Async `IAuthorizationPolicy`** — `Task<bool> IsAuthorizedAsync(ISecurityContext)`. Coordinate with ZeroAlloc.Mediator.Authorization design before adding.
4. **Source-gen-driven policy name lookup** — replace startup reflection scan with a generated `name → factory` table for cold-start performance.
5. **Policy timeout** — `opts.PolicyTimeout` with deny-on-timeout for I/O-bound policies.
6. **`opts.AuditAllows`** — opt-in compliance mode that audits every Allow (not just Deny).
