# Tool-Call Authorization (`IToolCallGuard`) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship `IToolCallGuard` — RBAC-style preventive control evaluated at every tool-call boundary across all four AI.Sentinel surfaces (in-process `FunctionInvokingChatClient`, Claude Code hook, Copilot hook, MCP proxy), reusing the same `IAuthorizationPolicy` + `ISecurityContext` shape planned for `ZeroAlloc.Mediator.Authorization`.

**Architecture:** Three-layer model — identity (`ISecurityContext`), policy (`IAuthorizationPolicy` classes registered via DI), binding (`[Authorize]` attribute or `RequireToolPolicy(...)` API). The guard runs *before* the existing detection pipeline on every surface; binary `Allow | Deny` decisions; denials become standard `AuditEntry` rows with `DetectorId = "AUTHZ-DENY"`. Defaults to Allow when no policies are registered (drop-in upgrade).

**Tech Stack:** .NET 9, `Microsoft.Extensions.AI`, ZeroAlloc.Inject `[Singleton]` for DI source-gen, xUnit for tests. Reuses existing `AuditEntry`, `IAuditStore`, `InterventionEngine`, and ZeroAlloc.Telemetry infrastructure.

**Reference:** [docs/plans/2026-04-25-tool-call-authorization-design.md](2026-04-25-tool-call-authorization-design.md) — full design rationale and decision log.

---

## Task 1: Identity layer — `ISecurityContext` + `AnonymousSecurityContext` + `IToolCallSecurityContext`

**Files:**
- Create: `src/AI.Sentinel/Authorization/ISecurityContext.cs`
- Create: `src/AI.Sentinel/Authorization/AnonymousSecurityContext.cs`
- Create: `src/AI.Sentinel/Authorization/IToolCallSecurityContext.cs`
- Create: `tests/AI.Sentinel.Tests/Helpers/TestSecurityContext.cs`
- Create: `tests/AI.Sentinel.Tests/Helpers/TestToolCallSecurityContext.cs`
- Create: `tests/AI.Sentinel.Tests/Authorization/SecurityContextTests.cs`

**Step 1: Write the failing tests**

```csharp
// tests/AI.Sentinel.Tests/Authorization/SecurityContextTests.cs
using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class SecurityContextTests
{
    [Fact]
    public void AnonymousSecurityContext_HasEmptyRolesAndClaims()
    {
        var ctx = AnonymousSecurityContext.Instance;
        Assert.Equal("anonymous", ctx.Id);
        Assert.Empty(ctx.Roles);
        Assert.Empty(ctx.Claims);
    }

    [Fact]
    public void AnonymousSecurityContext_InstanceIsSingleton()
    {
        Assert.Same(AnonymousSecurityContext.Instance, AnonymousSecurityContext.Instance);
    }
}
```

**Step 2: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "SecurityContextTests"
```
Expected: fail — `AI.Sentinel.Authorization` namespace not found.

**Step 3: Create `ISecurityContext`**

```csharp
// src/AI.Sentinel/Authorization/ISecurityContext.cs
namespace AI.Sentinel.Authorization;

/// <summary>Caller identity for authorization decisions. Mirrors the shape planned for ZeroAlloc.Mediator.Authorization.</summary>
public interface ISecurityContext
{
    /// <summary>Stable caller identifier — user, agent, or service name.</summary>
    string Id { get; }

    /// <summary>Role membership of the caller. Empty for anonymous callers.</summary>
    IReadOnlySet<string> Roles { get; }

    /// <summary>Optional claims (tenant, scope, sub, etc.). Empty by default.</summary>
    IReadOnlyDictionary<string, string> Claims { get; }
}
```

**Step 4: Create `AnonymousSecurityContext`**

```csharp
// src/AI.Sentinel/Authorization/AnonymousSecurityContext.cs
namespace AI.Sentinel.Authorization;

/// <summary>Singleton anonymous caller — no Id, no roles, no claims. Default when no provider configured.</summary>
public sealed class AnonymousSecurityContext : ISecurityContext
{
    public static readonly AnonymousSecurityContext Instance = new();
    private AnonymousSecurityContext() { }

    public string Id => "anonymous";
    public IReadOnlySet<string> Roles { get; } = new HashSet<string>();
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>();
}
```

**Step 5: Create `IToolCallSecurityContext`**

```csharp
// src/AI.Sentinel/Authorization/IToolCallSecurityContext.cs
using System.Text.Json;

namespace AI.Sentinel.Authorization;

/// <summary>Tool-call-specific extension of <see cref="ISecurityContext"/>. Adds tool name + args for arg-aware policies.</summary>
public interface IToolCallSecurityContext : ISecurityContext
{
    /// <summary>Name of the tool being invoked.</summary>
    string ToolName { get; }

    /// <summary>Tool arguments as a JSON element.</summary>
    JsonElement Args { get; }
}
```

**Step 6: Create test helpers**

```csharp
// tests/AI.Sentinel.Tests/Helpers/TestSecurityContext.cs
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Tests.Helpers;

internal sealed class TestSecurityContext(string id, params string[] roles) : ISecurityContext
{
    public string Id { get; } = id;
    public IReadOnlySet<string> Roles { get; } = new HashSet<string>(roles);
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>();
}
```

```csharp
// tests/AI.Sentinel.Tests/Helpers/TestToolCallSecurityContext.cs
using System.Text.Json;
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Tests.Helpers;

internal sealed class TestToolCallSecurityContext(ISecurityContext inner, string toolName, JsonElement args)
    : IToolCallSecurityContext
{
    public string Id => inner.Id;
    public IReadOnlySet<string> Roles => inner.Roles;
    public IReadOnlyDictionary<string, string> Claims => inner.Claims;
    public string ToolName { get; } = toolName;
    public JsonElement Args { get; } = args;
}
```

**Step 7: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "SecurityContextTests"
```
Expected: 2 pass.

**Step 8: Commit**

```bash
git add src/AI.Sentinel/Authorization/ISecurityContext.cs \
        src/AI.Sentinel/Authorization/AnonymousSecurityContext.cs \
        src/AI.Sentinel/Authorization/IToolCallSecurityContext.cs \
        tests/AI.Sentinel.Tests/Helpers/TestSecurityContext.cs \
        tests/AI.Sentinel.Tests/Helpers/TestToolCallSecurityContext.cs \
        tests/AI.Sentinel.Tests/Authorization/SecurityContextTests.cs
git commit -m "feat(authz): ISecurityContext + AnonymousSecurityContext + IToolCallSecurityContext"
```

---

## Task 2: Policy layer — `IAuthorizationPolicy` + `[AuthorizationPolicy]` + `ToolCallAuthorizationPolicy` base

**Files:**
- Create: `src/AI.Sentinel/Authorization/IAuthorizationPolicy.cs`
- Create: `src/AI.Sentinel/Authorization/AuthorizationPolicyAttribute.cs`
- Create: `src/AI.Sentinel/Authorization/ToolCallAuthorizationPolicy.cs`
- Create: `tests/AI.Sentinel.Tests/Authorization/ToolCallAuthorizationPolicyTests.cs`

**Step 1: Write failing tests**

```csharp
// tests/AI.Sentinel.Tests/Authorization/ToolCallAuthorizationPolicyTests.cs
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class ToolCallAuthorizationPolicyTests
{
    private sealed class DenyBashPolicy : ToolCallAuthorizationPolicy
    {
        protected override bool IsAuthorized(IToolCallSecurityContext ctx) =>
            ctx.ToolName != "Bash";
    }

    [Fact]
    public void NonToolCallContext_AlwaysAllowed()
    {
        var policy = new DenyBashPolicy();
        var caller = new TestSecurityContext("user");
        Assert.True(policy.IsAuthorized(caller));
    }

    [Fact]
    public void ToolCallContext_PolicyAppliesNormally()
    {
        var policy = new DenyBashPolicy();
        var inner  = new TestSecurityContext("user");
        var args   = JsonDocument.Parse("{}").RootElement;
        var bash   = new TestToolCallSecurityContext(inner, "Bash", args);
        var read   = new TestToolCallSecurityContext(inner, "Read", args);
        Assert.False(policy.IsAuthorized(bash));
        Assert.True(policy.IsAuthorized(read));
    }
}
```

**Step 2: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "ToolCallAuthorizationPolicyTests"
```
Expected: fail — `IAuthorizationPolicy`, `ToolCallAuthorizationPolicy` not found.

**Step 3: Create `IAuthorizationPolicy`**

```csharp
// src/AI.Sentinel/Authorization/IAuthorizationPolicy.cs
namespace AI.Sentinel.Authorization;

/// <summary>Pluggable authorization rule. Same shape as planned ZeroAlloc.Mediator.Authorization — one policy class works for both worlds.</summary>
public interface IAuthorizationPolicy
{
    /// <summary>Returns true if the caller is allowed. For tool calls, downcast <paramref name="ctx"/> to <see cref="IToolCallSecurityContext"/> for tool name + args.</summary>
    bool IsAuthorized(ISecurityContext ctx);
}
```

**Step 4: Create `[AuthorizationPolicy]` attribute**

```csharp
// src/AI.Sentinel/Authorization/AuthorizationPolicyAttribute.cs
namespace AI.Sentinel.Authorization;

/// <summary>Names a policy so it can be referenced from <see cref="AuthorizeAttribute"/> and <c>RequireToolPolicy(...)</c>.</summary>
[AttributeUsage(AttributeTargets.Class)]
public sealed class AuthorizationPolicyAttribute(string name) : Attribute
{
    public string Name { get; } = name;
}
```

**Step 5: Create `ToolCallAuthorizationPolicy` base**

```csharp
// src/AI.Sentinel/Authorization/ToolCallAuthorizationPolicy.cs
namespace AI.Sentinel.Authorization;

/// <summary>Ergonomic base for arg-aware tool-call policies. Allows automatically when context is not a tool call.</summary>
public abstract class ToolCallAuthorizationPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) =>
        ctx is IToolCallSecurityContext tc ? IsAuthorized(tc) : true;

    protected abstract bool IsAuthorized(IToolCallSecurityContext ctx);
}
```

**Step 6: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "ToolCallAuthorizationPolicyTests"
```
Expected: 2 pass.

**Step 7: Commit**

```bash
git add src/AI.Sentinel/Authorization/IAuthorizationPolicy.cs \
        src/AI.Sentinel/Authorization/AuthorizationPolicyAttribute.cs \
        src/AI.Sentinel/Authorization/ToolCallAuthorizationPolicy.cs \
        tests/AI.Sentinel.Tests/Authorization/ToolCallAuthorizationPolicyTests.cs
git commit -m "feat(authz): IAuthorizationPolicy + ToolCallAuthorizationPolicy base + [AuthorizationPolicy]"
```

---

## Task 3: Binding + Guard core — `[Authorize]`, `AuthorizationDecision`, `IToolCallGuard`, `DefaultToolCallGuard`

**Files:**
- Create: `src/AI.Sentinel/Authorization/AuthorizeAttribute.cs`
- Create: `src/AI.Sentinel/Authorization/ToolPolicyDefault.cs`
- Create: `src/AI.Sentinel/Authorization/AuthorizationDecision.cs`
- Create: `src/AI.Sentinel/Authorization/IToolCallGuard.cs`
- Create: `src/AI.Sentinel/Authorization/ToolCallPolicyBinding.cs` (internal record)
- Create: `src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs`
- Create: `tests/AI.Sentinel.Tests/Authorization/DefaultToolCallGuardTests.cs`

**Step 1: Write failing tests** (cover the full unit-test list from the design)

```csharp
// tests/AI.Sentinel.Tests/Authorization/DefaultToolCallGuardTests.cs
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class DefaultToolCallGuardTests
{
    private static readonly JsonElement EmptyArgs = JsonDocument.Parse("{}").RootElement;

    [AuthorizationPolicy("admin-only")]
    private sealed class AdminOnly : IAuthorizationPolicy
    {
        public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("admin");
    }

    [AuthorizationPolicy("always-deny")]
    private sealed class AlwaysDeny : IAuthorizationPolicy
    {
        public bool IsAuthorized(ISecurityContext ctx) => false;
    }

    [AuthorizationPolicy("throws")]
    private sealed class Throws : IAuthorizationPolicy
    {
        public bool IsAuthorized(ISecurityContext ctx) => throw new InvalidOperationException("boom");
    }

    private static DefaultToolCallGuard Build(
        ToolPolicyDefault @default,
        IEnumerable<(string pattern, string policyName)>? bindings = null,
        IEnumerable<IAuthorizationPolicy>? policies = null)
    {
        bindings ??= [];
        policies ??= [];
        var policyByName = policies
            .Select(p => (Name: p.GetType().GetCustomAttributes(typeof(AuthorizationPolicyAttribute), false)
                .Cast<AuthorizationPolicyAttribute>().Single().Name, Policy: p))
            .ToDictionary(t => t.Name, t => t.Policy);
        return new DefaultToolCallGuard(
            bindings.Select(b => new ToolCallPolicyBinding(b.pattern, b.policyName)).ToList(),
            policyByName,
            @default,
            logger: null);
    }

    [Fact]
    public async Task NoPoliciesRegistered_AllowsByDefault()
    {
        var guard = Build(ToolPolicyDefault.Allow);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "anything", EmptyArgs);
        Assert.True(d.Allowed);
    }

    [Fact]
    public async Task ExactToolMatch_UsesBoundPolicy_AllowedForAdmin()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "admin-only")],
            policies: [new AdminOnly()]);
        var caller = new TestSecurityContext("alice", "admin");
        var d = await guard.AuthorizeAsync(caller, "Bash", EmptyArgs);
        Assert.True(d.Allowed);
    }

    [Fact]
    public async Task ExactToolMatch_UsesBoundPolicy_DeniedForNonAdmin()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "admin-only")],
            policies: [new AdminOnly()]);
        var caller = new TestSecurityContext("bob");
        var d = await guard.AuthorizeAsync(caller, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
        Assert.Equal("admin-only", d.PolicyName);
    }

    [Fact]
    public async Task WildcardMatch_DeleteUnderscoreStarMatchesDeleteUser()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("delete_*", "admin-only")],
            policies: [new AdminOnly()]);
        var caller = new TestSecurityContext("bob");
        var d = await guard.AuthorizeAsync(caller, "delete_user", EmptyArgs);
        Assert.False(d.Allowed);
    }

    [Fact]
    public async Task MultipleMatchingPolicies_AllMustAllow()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "admin-only"), ("*", "always-deny")],
            policies: [new AdminOnly(), new AlwaysDeny()]);
        var caller = new TestSecurityContext("alice", "admin");
        var d = await guard.AuthorizeAsync(caller, "Bash", EmptyArgs);
        Assert.False(d.Allowed); // always-deny blocks even though admin-only allows
        Assert.Equal("always-deny", d.PolicyName);
    }

    [Fact]
    public async Task NoMatch_UsesDefaultToolPolicy_Allow()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "admin-only")],
            policies: [new AdminOnly()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Read", EmptyArgs);
        Assert.True(d.Allowed);
    }

    [Fact]
    public async Task NoMatch_UsesDefaultToolPolicy_Deny()
    {
        var guard = Build(ToolPolicyDefault.Deny,
            bindings: [("Bash", "admin-only")],
            policies: [new AdminOnly()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Read", EmptyArgs);
        Assert.False(d.Allowed);
    }

    [Fact]
    public async Task PolicyThrows_FailsClosed_ReturnsDeny()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "throws")],
            policies: [new Throws()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
        Assert.Contains("throws", d.PolicyName);
    }

    [Fact]
    public async Task BindingReferencesUnknownPolicy_ReturnsDeny()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "ghost-policy")],
            policies: []);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
        Assert.Equal("ghost-policy", d.PolicyName);
    }

    [Fact]
    public async Task AnonymousCaller_PolicyReferencingRoles_Denies()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "admin-only")],
            policies: [new AdminOnly()]);
        var d = await guard.AuthorizeAsync(AnonymousSecurityContext.Instance, "Bash", EmptyArgs);
        Assert.False(d.Allowed);
    }

    [AuthorizationPolicy("no-system-paths")]
    private sealed class NoSystemPaths : ToolCallAuthorizationPolicy
    {
        protected override bool IsAuthorized(IToolCallSecurityContext ctx)
        {
            if (ctx.ToolName != "Bash") return true;
            if (!ctx.Args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String) return true;
            var path = p.GetString();
            return path is null || (!path.StartsWith("/etc/") && !path.StartsWith("/sys/"));
        }
    }

    [Fact]
    public async Task ToolCallContext_PolicyAccessesArgs()
    {
        var guard = Build(ToolPolicyDefault.Allow,
            bindings: [("Bash", "no-system-paths")],
            policies: [new NoSystemPaths()]);
        var caller = AnonymousSecurityContext.Instance;
        var bad   = JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement;
        var good  = JsonDocument.Parse("""{"path":"/tmp/foo"}""").RootElement;
        Assert.False((await guard.AuthorizeAsync(caller, "Bash", bad)).Allowed);
        Assert.True((await guard.AuthorizeAsync(caller, "Bash", good)).Allowed);
    }
}
```

**Step 2: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "DefaultToolCallGuardTests"
```
Expected: fail — types not found.

**Step 3: Create `[Authorize]` attribute**

```csharp
// src/AI.Sentinel/Authorization/AuthorizeAttribute.cs
namespace AI.Sentinel.Authorization;

/// <summary>Binds a method (exposed as an <c>AIFunction</c>) to a named <see cref="IAuthorizationPolicy"/>.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class AuthorizeAttribute(string policyName) : Attribute
{
    public string PolicyName { get; } = policyName;
}
```

**Step 4: Create `ToolPolicyDefault` enum**

```csharp
// src/AI.Sentinel/Authorization/ToolPolicyDefault.cs
namespace AI.Sentinel.Authorization;

/// <summary>Behaviour when a tool-call has no matching <c>RequireToolPolicy(...)</c> binding.</summary>
public enum ToolPolicyDefault
{
    /// <summary>Allow the call (default — drop-in safety for existing AI.Sentinel users).</summary>
    Allow,
    /// <summary>Deny the call. Combined with explicit bindings, gives strict deny-by-default semantics.</summary>
    Deny,
}
```

**Step 5: Create `AuthorizationDecision`**

```csharp
// src/AI.Sentinel/Authorization/AuthorizationDecision.cs
namespace AI.Sentinel.Authorization;

/// <summary>Result of a tool-call authorization check.</summary>
public sealed record AuthorizationDecision(bool Allowed, string? PolicyName, string? Reason)
{
    /// <summary>Singleton for the allow path — never allocates.</summary>
    public static readonly AuthorizationDecision Allow = new(true, null, null);

    /// <summary>Builds a deny decision with the policy name and reason that produced it.</summary>
    public static AuthorizationDecision Deny(string policyName, string reason) =>
        new(false, policyName, reason);
}
```

**Step 6: Create `IToolCallGuard` interface**

```csharp
// src/AI.Sentinel/Authorization/IToolCallGuard.cs
using System.Text.Json;

namespace AI.Sentinel.Authorization;

/// <summary>Evaluates whether a tool call is authorized for the given caller. Runs before the detection pipeline.</summary>
public interface IToolCallGuard
{
    ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default);
}
```

**Step 7: Create internal `ToolCallPolicyBinding` record**

```csharp
// src/AI.Sentinel/Authorization/ToolCallPolicyBinding.cs
namespace AI.Sentinel.Authorization;

internal sealed record ToolCallPolicyBinding(string Pattern, string PolicyName)
{
    public bool Matches(string toolName)
    {
        if (Pattern.EndsWith('*'))
            return toolName.StartsWith(Pattern[..^1], StringComparison.Ordinal);
        return Pattern == toolName;
    }
}
```

**Step 8: Create `DefaultToolCallGuard`**

```csharp
// src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ZeroAlloc.Inject;

namespace AI.Sentinel.Authorization;

/// <summary>Default tool-call guard. Resolves bindings → policies, fails closed on errors.</summary>
[Singleton(As = typeof(IToolCallGuard))]
internal sealed class DefaultToolCallGuard(
    IReadOnlyList<ToolCallPolicyBinding> bindings,
    IReadOnlyDictionary<string, IAuthorizationPolicy> policiesByName,
    ToolPolicyDefault @default,
    ILogger<DefaultToolCallGuard>? logger) : IToolCallGuard
{
    public ValueTask<AuthorizationDecision> AuthorizeAsync(
        ISecurityContext caller,
        string toolName,
        JsonElement args,
        CancellationToken ct = default)
    {
        var matching = bindings.Where(b => b.Matches(toolName)).ToList();

        if (matching.Count == 0)
        {
            return ValueTask.FromResult(@default == ToolPolicyDefault.Allow
                ? AuthorizationDecision.Allow
                : AuthorizationDecision.Deny("default", "No matching policy and DefaultToolPolicy is Deny"));
        }

        var ctx = new ToolCallContextWrapper(caller, toolName, args);

        foreach (var binding in matching)
        {
            if (!policiesByName.TryGetValue(binding.PolicyName, out var policy))
            {
                logger?.LogError("Policy '{PolicyName}' is bound to '{Pattern}' but not registered — denying.", binding.PolicyName, binding.Pattern);
                return ValueTask.FromResult(AuthorizationDecision.Deny(binding.PolicyName,
                    $"Policy '{binding.PolicyName}' is not registered"));
            }

            bool allowed;
            try
            {
                allowed = policy.IsAuthorized(ctx);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Policy '{PolicyName}' threw — failing closed (deny).", binding.PolicyName);
                return ValueTask.FromResult(AuthorizationDecision.Deny(binding.PolicyName,
                    $"Policy threw {ex.GetType().Name}"));
            }

            if (!allowed)
            {
                return ValueTask.FromResult(AuthorizationDecision.Deny(binding.PolicyName,
                    "Policy denied"));
            }
        }

        return ValueTask.FromResult(AuthorizationDecision.Allow);
    }

    private sealed class ToolCallContextWrapper(ISecurityContext inner, string toolName, JsonElement args)
        : IToolCallSecurityContext
    {
        public string Id => inner.Id;
        public IReadOnlySet<string> Roles => inner.Roles;
        public IReadOnlyDictionary<string, string> Claims => inner.Claims;
        public string ToolName { get; } = toolName;
        public JsonElement Args { get; } = args;
    }
}
```

**Step 9: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "DefaultToolCallGuardTests"
```
Expected: 11 pass.

**Step 10: Commit**

```bash
git add src/AI.Sentinel/Authorization/AuthorizeAttribute.cs \
        src/AI.Sentinel/Authorization/ToolPolicyDefault.cs \
        src/AI.Sentinel/Authorization/AuthorizationDecision.cs \
        src/AI.Sentinel/Authorization/IToolCallGuard.cs \
        src/AI.Sentinel/Authorization/ToolCallPolicyBinding.cs \
        src/AI.Sentinel/Authorization/DefaultToolCallGuard.cs \
        tests/AI.Sentinel.Tests/Authorization/DefaultToolCallGuardTests.cs
git commit -m "feat(authz): IToolCallGuard + DefaultToolCallGuard + binding resolver + AuthorizationDecision"
```

---

## Task 4: SentinelOptions integration + DI registration + startup warnings + ToolCallAuthorizationException

**Files:**
- Modify: `src/AI.Sentinel/SentinelOptions.cs` — add internal `_authorizationBindings` list, `DefaultToolPolicy` property
- Create: `src/AI.Sentinel/Authorization/SentinelOptionsAuthorizationExtensions.cs`
- Create: `src/AI.Sentinel/Authorization/ToolCallAuthorizationException.cs`
- Modify: `src/AI.Sentinel/ServiceCollectionExtensions.cs` — register `IToolCallGuard` + emit startup warnings
- Create: `tests/AI.Sentinel.Tests/Authorization/SentinelOptionsAuthorizationTests.cs`

**Step 1: Write failing tests**

```csharp
// tests/AI.Sentinel.Tests/Authorization/SentinelOptionsAuthorizationTests.cs
using AI.Sentinel.Authorization;
using Xunit;

namespace AI.Sentinel.Tests.Authorization;

public class SentinelOptionsAuthorizationTests
{
    [Fact]
    public void DefaultToolPolicy_DefaultsToAllow()
    {
        var opts = new SentinelOptions();
        Assert.Equal(ToolPolicyDefault.Allow, opts.DefaultToolPolicy);
    }

    [Fact]
    public void RequireToolPolicy_AddsBinding()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only");
        var bindings = opts.GetAuthorizationBindings();
        Assert.Single(bindings);
        Assert.Equal("Bash", bindings[0].Pattern);
        Assert.Equal("admin-only", bindings[0].PolicyName);
    }

    [Fact]
    public void RequireToolPolicy_AllowsMultipleBindings()
    {
        var opts = new SentinelOptions();
        opts.RequireToolPolicy("Bash", "admin-only")
            .RequireToolPolicy("delete_*", "admin-only");
        Assert.Equal(2, opts.GetAuthorizationBindings().Count);
    }

    [Fact]
    public void ToolCallAuthorizationException_HasDecision()
    {
        var d = AuthorizationDecision.Deny("admin-only", "missing role");
        var ex = new ToolCallAuthorizationException(d);
        Assert.Same(d, ex.Decision);
        Assert.Contains("admin-only", ex.Message);
    }
}
```

**Step 2: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "SentinelOptionsAuthorizationTests"
```
Expected: fail — properties/types not found.

**Step 3: Modify `SentinelOptions`**

Add to `src/AI.Sentinel/SentinelOptions.cs` after the existing properties:

```csharp
// add: using AI.Sentinel.Authorization;
private readonly List<ToolCallPolicyBinding> _authorizationBindings = new();

/// <summary>Behaviour when a tool call has no matching policy binding. Defaults to <see cref="ToolPolicyDefault.Allow"/>.</summary>
public ToolPolicyDefault DefaultToolPolicy { get; set; } = ToolPolicyDefault.Allow;

/// <summary>Internal access for the guard at construction time.</summary>
internal IReadOnlyList<ToolCallPolicyBinding> GetAuthorizationBindings() => _authorizationBindings;

/// <summary>Internal hook for <c>RequireToolPolicy</c> extension.</summary>
internal void AddAuthorizationBinding(ToolCallPolicyBinding binding) => _authorizationBindings.Add(binding);
```

**Step 4: Create extension methods**

```csharp
// src/AI.Sentinel/Authorization/SentinelOptionsAuthorizationExtensions.cs
namespace AI.Sentinel.Authorization;

public static class SentinelOptionsAuthorizationExtensions
{
    /// <summary>Binds a tool name (or wildcard pattern with <c>*</c> suffix) to a named <see cref="IAuthorizationPolicy"/>.</summary>
    public static SentinelOptions RequireToolPolicy(this SentinelOptions opts, string toolNameOrPattern, string policyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(toolNameOrPattern);
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);
        opts.AddAuthorizationBinding(new ToolCallPolicyBinding(toolNameOrPattern, policyName));
        return opts;
    }
}
```

**Step 5: Create `ToolCallAuthorizationException`**

```csharp
// src/AI.Sentinel/Authorization/ToolCallAuthorizationException.cs
namespace AI.Sentinel.Authorization;

/// <summary>Thrown by the in-process surface when a tool call is denied by an <see cref="IAuthorizationPolicy"/>.</summary>
public sealed class ToolCallAuthorizationException(AuthorizationDecision decision)
    : SentinelException($"Tool call denied by policy '{decision.PolicyName}': {decision.Reason}")
{
    public AuthorizationDecision Decision { get; } = decision;
}
```

**Step 6: Modify `ServiceCollectionExtensions.AddAISentinel`** to register the guard and emit warnings

In `src/AI.Sentinel/ServiceCollectionExtensions.cs`, find `AddAISentinel` and after the existing `services.AddSingleton(opts)` line add:

```csharp
// add: using AI.Sentinel.Authorization;
services.AddSingleton<IToolCallGuard>(sp =>
{
    var policies = sp.GetServices<IAuthorizationPolicy>().ToList();
    var policyByName = new Dictionary<string, IAuthorizationPolicy>();
    foreach (var p in policies)
    {
        var attr = p.GetType().GetCustomAttributes(typeof(AuthorizationPolicyAttribute), false)
            .Cast<AuthorizationPolicyAttribute>().SingleOrDefault();
        if (attr is null) continue;
        policyByName[attr.Name] = p;
    }

    var bindings = opts.GetAuthorizationBindings();
    var logger = sp.GetService<ILogger<DefaultToolCallGuard>>();
    var pipelineLogger = sp.GetService<ILogger<SentinelPipeline>>();

    EmitStartupWarnings(opts, bindings, policyByName, pipelineLogger);

    return new DefaultToolCallGuard(bindings, policyByName, opts.DefaultToolPolicy, logger);
});

static void EmitStartupWarnings(
    SentinelOptions opts,
    IReadOnlyList<ToolCallPolicyBinding> bindings,
    IReadOnlyDictionary<string, IAuthorizationPolicy> policiesByName,
    ILogger<SentinelPipeline>? logger)
{
    if (logger is null) return;

    if (opts.DefaultToolPolicy == ToolPolicyDefault.Deny && policiesByName.Count == 0)
        logger.LogWarning("AI.Sentinel: DefaultToolPolicy=Deny but no IAuthorizationPolicy implementations are registered — every tool call will be denied.");

    foreach (var binding in bindings)
    {
        if (!policiesByName.ContainsKey(binding.PolicyName))
            logger.LogError("AI.Sentinel: RequireToolPolicy(\"{Pattern}\", \"{Policy}\") references unknown policy '{Policy}'. This binding will deny every matching call.",
                binding.Pattern, binding.PolicyName, binding.PolicyName);
    }
}
```

**Step 7: Run all tests**

```
dotnet test tests/AI.Sentinel.Tests
```
Expected: all existing + 4 new pass.

**Step 8: Commit**

```bash
git add src/AI.Sentinel/SentinelOptions.cs \
        src/AI.Sentinel/Authorization/SentinelOptionsAuthorizationExtensions.cs \
        src/AI.Sentinel/Authorization/ToolCallAuthorizationException.cs \
        src/AI.Sentinel/ServiceCollectionExtensions.cs \
        tests/AI.Sentinel.Tests/Authorization/SentinelOptionsAuthorizationTests.cs
git commit -m "feat(authz): SentinelOptions integration + DI registration + startup warnings + ToolCallAuthorizationException"
```

---

## Task 5: Audit integration — `AuditEntry.AuthorizationDeny` extension

**Files:**
- Create: `src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs`
- Create: `tests/AI.Sentinel.Tests/Audit/AuditEntryAuthorizationExtensionsTests.cs`

**Step 1: Write failing tests**

```csharp
// tests/AI.Sentinel.Tests/Audit/AuditEntryAuthorizationExtensionsTests.cs
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Xunit;

namespace AI.Sentinel.Tests.Audit;

public class AuditEntryAuthorizationExtensionsTests
{
    [Fact]
    public void AuthorizationDeny_HasCorrectShape()
    {
        var entry = AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId("user"),
            receiver: new AgentId("assistant"),
            session: SessionId.New(),
            callerId: "alice",
            roles: new HashSet<string> { "user" },
            toolName: "Bash",
            policyName: "admin-only",
            reason: "missing role 'admin'");

        Assert.Equal(new DetectorId("AUTHZ-DENY"), entry.DetectorId);
        Assert.Equal(Severity.High, entry.Severity);
        Assert.Contains("alice", entry.Summary);
        Assert.Contains("Bash", entry.Summary);
        Assert.Contains("admin-only", entry.Summary);
        Assert.Contains("missing role", entry.Summary);
    }
}
```

**Step 2: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "AuditEntryAuthorizationExtensionsTests"
```
Expected: fail — type not found.

**Step 3: Implement the extension**

```csharp
// src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs
using AI.Sentinel.Domain;

namespace AI.Sentinel.Audit;

public static class AuditEntryAuthorizationExtensions
{
    /// <summary>Builds an <see cref="AuditEntry"/> for a tool-call authorization denial.</summary>
    public static AuditEntry AuthorizationDeny(
        AgentId sender,
        AgentId receiver,
        SessionId session,
        string callerId,
        IReadOnlySet<string> roles,
        string toolName,
        string policyName,
        string reason)
    => new()
    {
        Timestamp  = DateTime.UtcNow,
        SenderId   = sender,
        ReceiverId = receiver,
        SessionId  = session,
        DetectorId = new DetectorId("AUTHZ-DENY"),
        Severity   = Severity.High,
        Summary    = $"Caller '{callerId}' (roles: [{string.Join(",", roles)}]) " +
                     $"denied for tool '{toolName}' by policy '{policyName}': {reason}",
    };
}
```

> **Note:** verify the actual `AuditEntry` shape in `src/AI.Sentinel/Audit/AuditEntry.cs` first — adjust property names if `Sender`, `Receiver`, `Session` are different. The hash chain is computed by `IAuditStore.AppendAsync`, not here.

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "AuditEntryAuthorizationExtensionsTests"
```
Expected: 1 pass.

**Step 5: Commit**

```bash
git add src/AI.Sentinel/Audit/AuditEntryAuthorizationExtensions.cs \
        tests/AI.Sentinel.Tests/Audit/AuditEntryAuthorizationExtensionsTests.cs
git commit -m "feat(authz): AuditEntry.AuthorizationDeny extension for AUTHZ-DENY entries"
```

---

## Task 6: Sample policies — `AdminOnlyPolicy` + `NoSystemPathsPolicy`

**Files:**
- Create: `src/AI.Sentinel/Authorization/Policies/AdminOnlyPolicy.cs`
- Create: `src/AI.Sentinel/Authorization/Policies/NoSystemPathsPolicy.cs`
- Create: `tests/AI.Sentinel.Tests/Authorization/Policies/AdminOnlyPolicyTests.cs`
- Create: `tests/AI.Sentinel.Tests/Authorization/Policies/NoSystemPathsPolicyTests.cs`

> **Decision:** ship two sample policies inside the core package as **opt-in DI registrations** (not auto-registered). Users who want them call `services.AddSingleton<IAuthorizationPolicy, AdminOnlyPolicy>()`. They are reference implementations and the test target for the surface integrations.

**Step 1: Write failing tests**

```csharp
// tests/AI.Sentinel.Tests/Authorization/Policies/AdminOnlyPolicyTests.cs
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Policies;

public class AdminOnlyPolicyTests
{
    [Fact]
    public void AdminCaller_Allowed()
    {
        var p = new AdminOnlyPolicy();
        Assert.True(p.IsAuthorized(new TestSecurityContext("alice", "admin")));
    }

    [Fact]
    public void NonAdminCaller_Denied()
    {
        var p = new AdminOnlyPolicy();
        Assert.False(p.IsAuthorized(new TestSecurityContext("bob", "user")));
    }
}
```

```csharp
// tests/AI.Sentinel.Tests/Authorization/Policies/NoSystemPathsPolicyTests.cs
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Policies;

public class NoSystemPathsPolicyTests
{
    [Fact]
    public void Bash_WithSystemPath_Denies()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice", "admin"),
            "Bash", JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement);
        Assert.False(p.IsAuthorized(ctx));
    }

    [Fact]
    public void Bash_WithSafePath_Allows()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice"),
            "Bash", JsonDocument.Parse("""{"path":"/tmp/foo"}""").RootElement);
        Assert.True(p.IsAuthorized(ctx));
    }

    [Fact]
    public void OtherTool_AlwaysAllowed()
    {
        var p = new NoSystemPathsPolicy();
        var ctx = new TestToolCallSecurityContext(new TestSecurityContext("alice"),
            "Read", JsonDocument.Parse("""{"path":"/etc/passwd"}""").RootElement);
        Assert.True(p.IsAuthorized(ctx));
    }
}
```

**Step 2: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "AdminOnlyPolicyTests|NoSystemPathsPolicyTests"
```

**Step 3: Implement `AdminOnlyPolicy`**

```csharp
// src/AI.Sentinel/Authorization/Policies/AdminOnlyPolicy.cs
namespace AI.Sentinel.Authorization.Policies;

/// <summary>Reference policy: allows callers with the <c>admin</c> role. Opt-in via DI registration.</summary>
[AuthorizationPolicy("admin-only")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("admin");
}
```

**Step 4: Implement `NoSystemPathsPolicy`**

```csharp
// src/AI.Sentinel/Authorization/Policies/NoSystemPathsPolicy.cs
using System.Text.Json;

namespace AI.Sentinel.Authorization.Policies;

/// <summary>Reference arg-aware policy: denies <c>Bash</c> calls whose <c>path</c> argument starts with <c>/etc/</c> or <c>/sys/</c>. Opt-in via DI registration.</summary>
[AuthorizationPolicy("no-system-paths")]
public sealed class NoSystemPathsPolicy : ToolCallAuthorizationPolicy
{
    protected override bool IsAuthorized(IToolCallSecurityContext ctx)
    {
        if (ctx.ToolName != "Bash") return true;
        if (!ctx.Args.TryGetProperty("path", out var p) || p.ValueKind != JsonValueKind.String) return true;
        var path = p.GetString();
        return path is null || (!path.StartsWith("/etc/", StringComparison.Ordinal)
                              && !path.StartsWith("/sys/", StringComparison.Ordinal));
    }
}
```

**Step 5: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "AdminOnlyPolicyTests|NoSystemPathsPolicyTests"
```
Expected: 5 pass.

**Step 6: Commit**

```bash
git add src/AI.Sentinel/Authorization/Policies/ \
        tests/AI.Sentinel.Tests/Authorization/Policies/
git commit -m "feat(authz): sample policies — AdminOnlyPolicy + NoSystemPathsPolicy"
```

---

## Task 7: `ClaimsPrincipalSecurityContext` (in `AI.Sentinel.AspNetCore`)

**Files:**
- Create: `src/AI.Sentinel.AspNetCore/Authorization/ClaimsPrincipalSecurityContext.cs`
- Create: `tests/AI.Sentinel.AspNetCore.Tests/Authorization/ClaimsPrincipalSecurityContextTests.cs`

**Step 1: Write failing tests**

```csharp
// tests/AI.Sentinel.AspNetCore.Tests/Authorization/ClaimsPrincipalSecurityContextTests.cs
using System.Security.Claims;
using AI.Sentinel.AspNetCore.Authorization;
using Xunit;

namespace AI.Sentinel.AspNetCore.Tests.Authorization;

public class ClaimsPrincipalSecurityContextTests
{
    [Fact]
    public void RoleClaims_ExposedAsRoles()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "alice"),
            new Claim(ClaimTypes.Role, "admin"),
            new Claim(ClaimTypes.Role, "auditor"),
        ], authenticationType: "Test"));

        var ctx = new ClaimsPrincipalSecurityContext(principal);
        Assert.Equal("alice", ctx.Id);
        Assert.Contains("admin", ctx.Roles);
        Assert.Contains("auditor", ctx.Roles);
        Assert.Equal(2, ctx.Roles.Count);
    }

    [Fact]
    public void NonRoleClaims_ExposedAsClaims()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, "alice"),
            new Claim("tenant", "acme"),
            new Claim("scope", "tools:execute"),
        ], "Test"));

        var ctx = new ClaimsPrincipalSecurityContext(principal);
        Assert.Equal("acme", ctx.Claims["tenant"]);
        Assert.Equal("tools:execute", ctx.Claims["scope"]);
        Assert.False(ctx.Claims.ContainsKey(ClaimTypes.NameIdentifier)); // Id is exposed via Id property, not Claims
    }

    [Fact]
    public void NoNameIdentifier_FallsBackToAnonymous()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity());
        var ctx = new ClaimsPrincipalSecurityContext(principal);
        Assert.Equal("anonymous", ctx.Id);
    }
}
```

**Step 2: Run tests**

```
dotnet test tests/AI.Sentinel.AspNetCore.Tests --filter "ClaimsPrincipalSecurityContextTests"
```
Expected: fail.

**Step 3: Implement**

```csharp
// src/AI.Sentinel.AspNetCore/Authorization/ClaimsPrincipalSecurityContext.cs
using System.Security.Claims;
using AI.Sentinel.Authorization;

namespace AI.Sentinel.AspNetCore.Authorization;

/// <summary>Adapts <see cref="ClaimsPrincipal"/> to <see cref="ISecurityContext"/>. Roles come from <see cref="ClaimTypes.Role"/>; Id from <see cref="ClaimTypes.NameIdentifier"/>; remaining claims (excluding role + name) go to <c>Claims</c>.</summary>
public sealed class ClaimsPrincipalSecurityContext : ISecurityContext
{
    public ClaimsPrincipalSecurityContext(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        Id = principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous";
        Roles = principal.FindAll(ClaimTypes.Role).Select(c => c.Value).ToHashSet();
        Claims = principal.Claims
            .Where(c => c.Type != ClaimTypes.Role && c.Type != ClaimTypes.NameIdentifier)
            .GroupBy(c => c.Type)
            .ToDictionary(g => g.Key, g => g.Last().Value);
    }

    public string Id { get; }
    public IReadOnlySet<string> Roles { get; }
    public IReadOnlyDictionary<string, string> Claims { get; }
}
```

**Step 4: Run tests**

```
dotnet test tests/AI.Sentinel.AspNetCore.Tests --filter "ClaimsPrincipalSecurityContextTests"
```
Expected: 3 pass.

**Step 5: Commit**

```bash
git add src/AI.Sentinel.AspNetCore/Authorization/ClaimsPrincipalSecurityContext.cs \
        tests/AI.Sentinel.AspNetCore.Tests/Authorization/ClaimsPrincipalSecurityContextTests.cs
git commit -m "feat(aspnetcore): ClaimsPrincipalSecurityContext for HTTP-driven caller identity"
```

---

## Task 8: In-process surface — `UseToolCallAuthorization()` + `[Authorize]` discovery

**Files:**
- Create: `src/AI.Sentinel/Authorization/AuthorizationChatClient.cs` (delegating `IChatClient`)
- Create: `src/AI.Sentinel/Authorization/AuthorizationChatClientBuilderExtensions.cs`
- Create: `tests/AI.Sentinel.Tests/Authorization/Integration/InProcessAuthorizationTests.cs`

**Step 1: Read the existing builder pattern**

Read `src/AI.Sentinel/SentinelChatClient.cs` to understand the existing `UseAISentinel()` pattern and the delegating-`IChatClient` shape used today.

**Step 2: Write failing tests** — exercise the actual `ChatClientBuilder` pipeline

```csharp
// tests/AI.Sentinel.Tests/Authorization/Integration/InProcessAuthorizationTests.cs
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Tests.Helpers;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AI.Sentinel.Tests.Authorization.Integration;

public class InProcessAuthorizationTests
{
    private static IChatClient BuildPipeline(SentinelOptions opts, ISecurityContext caller, IChatClient inner)
    {
        var services = new ServiceCollection();
        services.AddSingleton(opts);
        services.AddSingleton<IAuthorizationPolicy, AdminOnlyPolicy>();
        services.AddSingleton(caller);
        // Wire the guard manually for the test (mimicking AddAISentinel's registration).
        services.AddSingleton<IToolCallGuard>(sp =>
        {
            var policies = sp.GetServices<IAuthorizationPolicy>()
                .ToDictionary(p => p.GetType().GetCustomAttributes(typeof(AuthorizationPolicyAttribute), false)
                    .Cast<AuthorizationPolicyAttribute>().Single().Name);
            return new DefaultToolCallGuard(opts.GetAuthorizationBindings(), policies, opts.DefaultToolPolicy, null);
        });
        var sp = services.BuildServiceProvider();

        return new ChatClientBuilder(sp)
            .UseToolCallAuthorization()
            .Use(inner);
    }

    [Fact]
    public async Task BoundTool_AdminCaller_Allowed()
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("alice", "admin"), inner);

        var fnCall = new FunctionCallContent("call-1", "DeleteUser", new Dictionary<string, object?> { ["id"] = "42" });
        var resp = await client.GetResponseAsync([new ChatMessage(ChatRole.Assistant, [fnCall])]);
        Assert.NotNull(resp);
    }

    [Fact]
    public async Task BoundTool_NonAdminCaller_Throws()
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("bob"), inner);

        var fnCall = new FunctionCallContent("call-1", "DeleteUser", new Dictionary<string, object?> { ["id"] = "42" });
        var ex = await Assert.ThrowsAsync<ToolCallAuthorizationException>(() =>
            client.GetResponseAsync([new ChatMessage(ChatRole.Assistant, [fnCall])]));
        Assert.Equal("admin-only", ex.Decision.PolicyName);
    }

    [Fact]
    public async Task UnboundTool_AllowedByDefault()
    {
        var opts = new SentinelOptions(); // no bindings
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("bob"), inner);

        var fnCall = new FunctionCallContent("call-1", "Read", new Dictionary<string, object?> { ["path"] = "/tmp" });
        var resp = await client.GetResponseAsync([new ChatMessage(ChatRole.Assistant, [fnCall])]);
        Assert.NotNull(resp);
    }

    [Fact]
    public async Task NoFunctionCall_PassesThrough()
    {
        var opts = new SentinelOptions().RequireToolPolicy("DeleteUser", "admin-only");
        var inner = new EchoChatClient();
        var client = BuildPipeline(opts, new TestSecurityContext("bob"), inner);

        var resp = await client.GetResponseAsync([new ChatMessage(ChatRole.User, "hello")]);
        Assert.NotNull(resp);
    }

    private sealed class EchoChatClient : IChatClient
    {
        public Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, "ok")));
        public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
        public object? GetService(Type serviceType, object? serviceKey = null) => null;
        public void Dispose() { }
    }
}
```

**Step 3: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.Tests --filter "InProcessAuthorizationTests"
```
Expected: fail — `UseToolCallAuthorization` not found.

**Step 4: Implement `AuthorizationChatClient`**

```csharp
// src/AI.Sentinel/Authorization/AuthorizationChatClient.cs
using System.Text.Json;
using AI.Sentinel.Audit;
using AI.Sentinel.Domain;
using Microsoft.Extensions.AI;

namespace AI.Sentinel.Authorization;

/// <summary>Delegating <see cref="IChatClient"/> that authorizes tool calls before forwarding.</summary>
internal sealed class AuthorizationChatClient(
    IChatClient inner,
    IToolCallGuard guard,
    Func<ISecurityContext> callerProvider,
    IAuditStore? audit) : IChatClient
{
    public async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        await AuthorizeFunctionCallsAsync(messages, cancellationToken).ConfigureAwait(false);
        return await inner.GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
        => StreamCoreAsync(messages, options, cancellationToken);

    private async IAsyncEnumerable<ChatResponseUpdate> StreamCoreAsync(IEnumerable<ChatMessage> messages, ChatOptions? options, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await AuthorizeFunctionCallsAsync(messages, ct).ConfigureAwait(false);
        await foreach (var u in inner.GetStreamingResponseAsync(messages, options, ct).ConfigureAwait(false))
            yield return u;
    }

    private async ValueTask AuthorizeFunctionCallsAsync(IEnumerable<ChatMessage> messages, CancellationToken ct)
    {
        var caller = callerProvider();
        foreach (var msg in messages)
        {
            foreach (var content in msg.Contents)
            {
                if (content is not FunctionCallContent fnCall) continue;
                var argsJson = JsonSerializer.SerializeToElement(fnCall.Arguments);
                var d = await guard.AuthorizeAsync(caller, fnCall.Name, argsJson, ct).ConfigureAwait(false);
                if (d.Allowed) continue;

                if (audit is not null)
                {
                    await audit.AppendAsync(AuditEntryAuthorizationExtensions.AuthorizationDeny(
                        sender: new AgentId(caller.Id),
                        receiver: new AgentId(fnCall.Name),
                        session: SessionId.New(),
                        callerId: caller.Id,
                        roles: caller.Roles,
                        toolName: fnCall.Name,
                        policyName: d.PolicyName ?? "?",
                        reason: d.Reason ?? "?"), ct).ConfigureAwait(false);
                }

                throw new ToolCallAuthorizationException(d);
            }
        }
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
        => serviceType == typeof(IToolCallGuard) ? guard : inner.GetService(serviceType, serviceKey);

    public void Dispose() => inner.Dispose();
}
```

**Step 5: Implement the builder extension**

```csharp
// src/AI.Sentinel/Authorization/AuthorizationChatClientBuilderExtensions.cs
using AI.Sentinel.Audit;
using Microsoft.Extensions.AI;
using Microsoft.Extensions.DependencyInjection;

namespace AI.Sentinel.Authorization;

public static class AuthorizationChatClientBuilderExtensions
{
    /// <summary>Wraps the chain with an authorization gate that runs <see cref="IToolCallGuard"/> on every <see cref="FunctionCallContent"/>.</summary>
    public static ChatClientBuilder UseToolCallAuthorization(this ChatClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Use((inner, sp) =>
        {
            var guard = sp.GetRequiredService<IToolCallGuard>();
            var audit = sp.GetService<IAuditStore>();
            Func<ISecurityContext> callerProvider = () =>
                sp.GetService<ISecurityContext>() ?? AnonymousSecurityContext.Instance;
            return new AuthorizationChatClient(inner, guard, callerProvider, audit);
        });
    }
}
```

> **Note on `[Authorize]` discovery:** translating `[Authorize]` on an `AIFunction`-backed method into a binding is a follow-up. For v1 the explicit `RequireToolPolicy(...)` API is sufficient — add a TODO in the BACKLOG. Keep this task scope to the delegating client + builder extension.

**Step 6: Run tests**

```
dotnet test tests/AI.Sentinel.Tests --filter "InProcessAuthorizationTests"
```
Expected: 4 pass.

**Step 7: Commit**

```bash
git add src/AI.Sentinel/Authorization/AuthorizationChatClient.cs \
        src/AI.Sentinel/Authorization/AuthorizationChatClientBuilderExtensions.cs \
        tests/AI.Sentinel.Tests/Authorization/Integration/InProcessAuthorizationTests.cs
git commit -m "feat(authz): UseToolCallAuthorization() ChatClientBuilder extension + delegating client"
```

---

## Task 9: Claude Code surface — `HookConfig.CallerContextProvider` + `HookAdapter` extension

**Files:**
- Modify: `src/AI.Sentinel.ClaudeCode/HookConfig.cs` — add `CallerContextProvider` property
- Modify: `src/AI.Sentinel.ClaudeCode/HookAdapter.cs` — gate `PreToolUse` through guard
- Create: `tests/AI.Sentinel.ClaudeCode.Tests/AuthorizationTests.cs`

**Step 1: Read the existing files**

Read `src/AI.Sentinel.ClaudeCode/HookConfig.cs` and `src/AI.Sentinel.ClaudeCode/HookAdapter.cs` so the diff matches the existing structure.

**Step 2: Write failing tests**

```csharp
// tests/AI.Sentinel.ClaudeCode.Tests/AuthorizationTests.cs
using System.Text.Json;
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.ClaudeCode;
using AI.Sentinel.Tests.Helpers; // referenced from test project
using Xunit;

namespace AI.Sentinel.ClaudeCode.Tests;

public class AuthorizationTests
{
    private static HookAdapter BuildAdapter(SentinelOptions opts, HookConfig config)
    {
        // mirror the wiring HookAdapter expects — see HookAdapter ctor for exact dependencies.
        var guard = new DefaultToolCallGuard(
            opts.GetAuthorizationBindings(),
            new Dictionary<string, IAuthorizationPolicy> { ["admin-only"] = new AdminOnlyPolicy() },
            opts.DefaultToolPolicy, null);
        return HookAdapter.CreateForTests(opts, config, guard); // factory in HookAdapter; see Step 3
    }

    [Fact]
    public async Task PreToolUse_DenyByPolicy_ReturnsBlock()
    {
        var opts = new SentinelOptions().RequireToolPolicy("Bash", "admin-only");
        var config = new HookConfig
        {
            CallerContextProvider = _ => new TestSecurityContext("bob"), // no admin role
        };
        var adapter = BuildAdapter(opts, config);
        var input = new HookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement };

        var output = await adapter.HandleAsync(HookEvent.PreToolUse, input, default);
        Assert.Equal(HookDecision.Block, output.Decision);
        Assert.Contains("admin-only", output.Reason);
    }

    [Fact]
    public async Task PreToolUse_AllowByPolicy_FallsThroughToDetection()
    {
        var opts = new SentinelOptions().RequireToolPolicy("Bash", "admin-only");
        var config = new HookConfig
        {
            CallerContextProvider = _ => new TestSecurityContext("alice", "admin"),
        };
        var adapter = BuildAdapter(opts, config);
        var input = new HookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("""{"command":"ls"}""").RootElement };

        var output = await adapter.HandleAsync(HookEvent.PreToolUse, input, default);
        Assert.NotEqual(HookDecision.Block, output.Decision); // detection may still warn but authz allows
    }

    [Fact]
    public async Task PreToolUse_NoCallerContextProvider_AnonymousDeniesPolicy()
    {
        var opts = new SentinelOptions().RequireToolPolicy("Bash", "admin-only");
        var config = new HookConfig(); // no provider
        var adapter = BuildAdapter(opts, config);
        var input = new HookInput { SessionId = "s1", ToolName = "Bash", ToolInput = JsonDocument.Parse("{}").RootElement };

        var output = await adapter.HandleAsync(HookEvent.PreToolUse, input, default);
        Assert.Equal(HookDecision.Block, output.Decision);
    }
}
```

**Step 3: Run tests to confirm they fail**

```
dotnet test tests/AI.Sentinel.ClaudeCode.Tests --filter "AuthorizationTests"
```
Expected: fail.

**Step 4: Modify `HookConfig`**

Add to `src/AI.Sentinel.ClaudeCode/HookConfig.cs`:

```csharp
// add: using AI.Sentinel.Authorization;
/// <summary>Resolves the caller identity from the hook input. Default null → <see cref="AnonymousSecurityContext"/>.</summary>
public Func<HookInput, ISecurityContext>? CallerContextProvider { get; set; }
```

**Step 5: Modify `HookAdapter`**

In `src/AI.Sentinel.ClaudeCode/HookAdapter.cs`:

1. Add `IToolCallGuard? guard` constructor parameter (nullable for backwards compat with existing tests that don't supply one — default to `null`)
2. In `HandleAsync` for `HookEvent.PreToolUse`, before the existing detection scan, insert:

```csharp
if (evt == HookEvent.PreToolUse && guard is not null && input.ToolName is not null)
{
    var caller = config.CallerContextProvider?.Invoke(input) ?? AnonymousSecurityContext.Instance;
    var args = input.ToolInput ?? JsonDocument.Parse("{}").RootElement;
    var d = await guard.AuthorizeAsync(caller, input.ToolName, args, ct).ConfigureAwait(false);
    if (!d.Allowed)
    {
        if (audit is not null)
            await audit.AppendAsync(AuditEntryAuthorizationExtensions.AuthorizationDeny(
                sender: new AgentId(caller.Id),
                receiver: new AgentId(input.ToolName),
                session: new SessionId(input.SessionId),
                callerId: caller.Id,
                roles: caller.Roles,
                toolName: input.ToolName,
                policyName: d.PolicyName ?? "?",
                reason: d.Reason ?? "?"), ct).ConfigureAwait(false);

        return new HookOutput(HookDecision.Block,
            $"Authorization denied by policy '{d.PolicyName}': {d.Reason}");
    }
}
```

3. Add a static `internal static HookAdapter CreateForTests(SentinelOptions opts, HookConfig config, IToolCallGuard guard)` factory used by the test (mirror existing internal factories if any; otherwise expose a minimal one).

**Step 6: Run tests**

```
dotnet test tests/AI.Sentinel.ClaudeCode.Tests --filter "AuthorizationTests"
```
Expected: 3 pass.

**Step 7: Commit**

```bash
git add src/AI.Sentinel.ClaudeCode/HookConfig.cs \
        src/AI.Sentinel.ClaudeCode/HookAdapter.cs \
        tests/AI.Sentinel.ClaudeCode.Tests/AuthorizationTests.cs
git commit -m "feat(claudecode): IToolCallGuard integration on PreToolUse"
```

---

## Task 10: Copilot surface — parallel to Claude Code

**Files:**
- Modify: `src/AI.Sentinel.Copilot/CopilotHookConfig.cs` — add `CallerContextProvider`
- Modify: `src/AI.Sentinel.Copilot/CopilotHookAdapter.cs` — gate `preToolUse` through guard
- Create: `tests/AI.Sentinel.Copilot.Tests/AuthorizationTests.cs`

**Step 1–7: Same shape as Task 9** — read the existing Copilot files; mirror the changes from Task 9 with `CopilotHookInput`, `CopilotHookConfig`, `CopilotHookAdapter`. The hook decision shape is identical (`HookDecision.Block` is reused or has a Copilot-specific equivalent — verify by reading the file).

**Step 8: Commit**

```bash
git add src/AI.Sentinel.Copilot/CopilotHookConfig.cs \
        src/AI.Sentinel.Copilot/CopilotHookAdapter.cs \
        tests/AI.Sentinel.Copilot.Tests/AuthorizationTests.cs
git commit -m "feat(copilot): IToolCallGuard integration on preToolUse"
```

---

## Task 11: MCP proxy surface — `ToolCallInterceptor` extension + env-var resolver

**Files:**
- Create: `src/AI.Sentinel.Mcp/Authorization/EnvironmentSecurityContext.cs`
- Modify: `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs` — gate `tools/call` through guard
- Modify: `src/AI.Sentinel.Mcp/McpPipelineFactory.cs` — wire the guard
- Create: `tests/AI.Sentinel.Mcp.Tests/AuthorizationTests.cs`

**Step 1: Write the failing tests**

```csharp
// tests/AI.Sentinel.Mcp.Tests/AuthorizationTests.cs
using AI.Sentinel.Authorization;
using AI.Sentinel.Authorization.Policies;
using AI.Sentinel.Mcp.Authorization;
using AI.Sentinel.Tests.Helpers;
using ModelContextProtocol;
using Xunit;

namespace AI.Sentinel.Mcp.Tests;

public class AuthorizationTests
{
    [Fact]
    public void EnvironmentSecurityContext_ReadsEnvVars()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_CALLER_ID", "alice");
        Environment.SetEnvironmentVariable("SENTINEL_MCP_CALLER_ROLES", "admin,auditor");
        try
        {
            var ctx = EnvironmentSecurityContext.FromEnvironment();
            Assert.Equal("alice", ctx.Id);
            Assert.Contains("admin", ctx.Roles);
            Assert.Contains("auditor", ctx.Roles);
        }
        finally
        {
            Environment.SetEnvironmentVariable("SENTINEL_MCP_CALLER_ID", null);
            Environment.SetEnvironmentVariable("SENTINEL_MCP_CALLER_ROLES", null);
        }
    }

    [Fact]
    public void EnvironmentSecurityContext_NoVars_ReturnsAnonymous()
    {
        Environment.SetEnvironmentVariable("SENTINEL_MCP_CALLER_ID", null);
        Environment.SetEnvironmentVariable("SENTINEL_MCP_CALLER_ROLES", null);
        var ctx = EnvironmentSecurityContext.FromEnvironment();
        Assert.Same(AnonymousSecurityContext.Instance, ctx);
    }

    // Note: the actual ToolCallInterceptor integration test requires an in-memory MCP target.
    // For now use the existing test infrastructure pattern from McpPipelineFactoryTests
    // (or whatever tests already exercise ToolCallInterceptor). Add:
    //   ToolsCall_DenyByPolicy_ThrowsMcpException
    //   ToolsCall_AllowByPolicy_PassesThroughToTarget
}
```

**Step 2: Implement `EnvironmentSecurityContext`**

```csharp
// src/AI.Sentinel.Mcp/Authorization/EnvironmentSecurityContext.cs
using AI.Sentinel.Authorization;

namespace AI.Sentinel.Mcp.Authorization;

/// <summary>Resolves caller identity from <c>SENTINEL_MCP_CALLER_ID</c> and <c>SENTINEL_MCP_CALLER_ROLES</c> (comma-separated) env vars set by the MCP host.</summary>
public sealed class EnvironmentSecurityContext : ISecurityContext
{
    public string Id { get; }
    public IReadOnlySet<string> Roles { get; }
    public IReadOnlyDictionary<string, string> Claims { get; } = new Dictionary<string, string>();

    private EnvironmentSecurityContext(string id, IReadOnlySet<string> roles)
    {
        Id = id;
        Roles = roles;
    }

    public static ISecurityContext FromEnvironment()
    {
        var id = Environment.GetEnvironmentVariable("SENTINEL_MCP_CALLER_ID");
        if (string.IsNullOrWhiteSpace(id)) return AnonymousSecurityContext.Instance;
        var roles = (Environment.GetEnvironmentVariable("SENTINEL_MCP_CALLER_ROLES") ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet();
        return new EnvironmentSecurityContext(id, roles);
    }
}
```

**Step 3: Wire the guard into `ToolCallInterceptor`**

Read `src/AI.Sentinel.Mcp/ToolCallInterceptor.cs`. Add `IToolCallGuard? guard` and `Func<CallToolRequestParams, ISecurityContext>? callerResolver` parameters (both nullable for backwards compat). At the start of the intercept method (before the existing pre-scan):

```csharp
if (guard is not null)
{
    var caller = callerResolver?.Invoke(request) ?? EnvironmentSecurityContext.FromEnvironment();
    var args = ToJsonElement(request.Arguments); // existing helper
    var d = await guard.AuthorizeAsync(caller, request.Name, args, ct).ConfigureAwait(false);
    if (!d.Allowed)
    {
        await audit.AppendAsync(AuditEntryAuthorizationExtensions.AuthorizationDeny(
            sender: new AgentId(caller.Id), receiver: new AgentId(request.Name),
            session: SessionId.New(),
            callerId: caller.Id, roles: caller.Roles,
            toolName: request.Name, policyName: d.PolicyName ?? "?", reason: d.Reason ?? "?"), ct);

        throw new McpException(McpErrorCode.InvalidRequest,
            $"Authorization denied by policy '{d.PolicyName}': {d.Reason}");
    }
}
```

**Step 4: Wire `IToolCallGuard` in `McpPipelineFactory.Create`**

In `src/AI.Sentinel.Mcp/McpPipelineFactory.cs`, add a parameter `IToolCallGuard? guard = null` and pass it through to the `ToolCallInterceptor` constructor.

**Step 5: Run tests**

```
dotnet test tests/AI.Sentinel.Mcp.Tests --filter "AuthorizationTests"
dotnet test tests/AI.Sentinel.Mcp.Tests
```
Expected: new tests pass + existing tests unchanged.

**Step 6: Commit**

```bash
git add src/AI.Sentinel.Mcp/Authorization/EnvironmentSecurityContext.cs \
        src/AI.Sentinel.Mcp/ToolCallInterceptor.cs \
        src/AI.Sentinel.Mcp/McpPipelineFactory.cs \
        tests/AI.Sentinel.Mcp.Tests/AuthorizationTests.cs
git commit -m "feat(mcp): IToolCallGuard integration on tools/call + env-var caller resolver"
```

---

## Task 12: Dashboard — Authorization filter chip + `AUTHZ-DENY` row styling

**Files:**
- Modify: `src/AI.Sentinel.AspNetCore/` — find the dashboard component / Razor page that renders the filter chips and the audit feed (likely in `Components/` or `Pages/`)
- Create: `tests/AI.Sentinel.AspNetCore.Tests/AuthorizationDashboardTests.cs`

**Step 1: Locate dashboard rendering**

```
Glob: src/AI.Sentinel.AspNetCore/**/*.razor
Glob: src/AI.Sentinel.AspNetCore/**/Dashboard*.cs
```

Read what you find to understand the existing chip rendering + row styling.

**Step 2: Write a failing render test**

```csharp
// tests/AI.Sentinel.AspNetCore.Tests/AuthorizationDashboardTests.cs
// Test that an AuditEntry with DetectorId = "AUTHZ-DENY" is:
// - Rendered with a distinct CSS class (e.g. "audit-row-authz")
// - Included when the "Authorization" chip filter is applied
// - Excluded when only "Security" is selected
```

(Test details depend on the rendering layer — adapt to whatever pattern AI.Sentinel.AspNetCore tests use.)

**Step 3: Add the chip + styling**

- Add a new `Authorization` chip to the filter UI alongside `Security / Hallucination / Operational`. Filter predicate: `entry.DetectorId.Value.StartsWith("AUTHZ-", StringComparison.Ordinal)`.
- Add a CSS class `audit-row-authz` (distinct colour/icon) applied when the same predicate matches.

**Step 4: Run the test**

```
dotnet test tests/AI.Sentinel.AspNetCore.Tests --filter "AuthorizationDashboardTests"
```

**Step 5: Commit**

```bash
git add src/AI.Sentinel.AspNetCore/ tests/AI.Sentinel.AspNetCore.Tests/AuthorizationDashboardTests.cs
git commit -m "feat(dashboard): Authorization filter chip + AUTHZ-DENY row styling"
```

---

## Task 13: README + backlog updates + final review

**Files:**
- Modify: `README.md` — add an "Authorization" section
- Modify: `docs/BACKLOG.md` — remove the now-shipped tool-call-guard items, add follow-ups from the design's "Future Work" section

**Step 1: Update README**

In `README.md`, add a new top-level section after the OWASP table:

```markdown
## Tool-Call Authorization

AI.Sentinel ships with `IToolCallGuard` — a preventive control evaluated before every tool
call across all four surfaces. Decision model is binary `Allow | Deny`. Same policy
abstraction (`IAuthorizationPolicy`) as planned `ZeroAlloc.Mediator.Authorization`.

```csharp
[AuthorizationPolicy("admin-only")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("admin");
}

services.AddSingleton<IAuthorizationPolicy, AdminOnlyPolicy>();
services.AddAISentinel(opts =>
{
    opts.RequireToolPolicy("Bash",       "admin-only");
    opts.RequireToolPolicy("delete_*",   "admin-only");
    opts.DefaultToolPolicy = ToolPolicyDefault.Allow; // default
});

builder.Services.AddChatClient(p =>
    p.UseAISentinel()
     .UseToolCallAuthorization()
     .UseFunctionInvocation()
     .Use(new OpenAIChatClient(...)));
```

| Surface | Caller resolution default | Deny semantics |
|---|---|---|
| In-process | `IServiceProvider.GetService<ISecurityContext>()` → Anonymous | throw `ToolCallAuthorizationException` |
| Claude Code | `HookConfig.CallerContextProvider` → Anonymous | `HookOutput(Block, reason)` |
| Copilot | `CopilotHookConfig.CallerContextProvider` → Anonymous | `HookOutput(Block, reason)` |
| MCP proxy | DI provider → `SENTINEL_MCP_CALLER_ID/_ROLES` env → Anonymous | `McpException(InvalidRequest, reason)` |

Default behaviour: if no policies are registered, every call is allowed (drop-in upgrade).
```

**Step 2: Update BACKLOG**

In `docs/BACKLOG.md`:

1. **Remove** these items from the "Policy & Authorization" section (now shipped):
   - `Tool-call authorization (IToolCallGuard)`
   - `Tool-call guard — FunctionInvokingChatClient integration`
   - `Tool-call guard — Claude Code PreToolUse hook`
   - `Tool-call guard — Copilot preToolUse hook`
   - `Tool-call guard — MCP proxy tools/call interception`
   - `ASP.NET Core ICallerContext bridge` (now `ClaimsPrincipalSecurityContext` in `AI.Sentinel.AspNetCore`)

2. **Add** these follow-ups (from the design's "Future Work" section):
   - **PIM-style approval workflow** — `RequireApproval` decision, `IApprovalStore`, time-bound grants, dashboard Approve/Deny UI, Mediator pending notifications, per-surface wait strategies. Strictly additive to the binary v1 contract.
   - **`ZeroAlloc.Authorization.Abstractions` extraction** — once `ZeroAlloc.Mediator.Authorization` ships, lift `ISecurityContext`/`IAuthorizationPolicy`/`[Authorize]`/`[AuthorizationPolicy]` into a shared package so AI.Sentinel and Mediator share primitives.
   - **Async `IAuthorizationPolicy`** — `Task<bool> IsAuthorizedAsync(ISecurityContext)`. Coordinate with ZeroAlloc.Mediator.Authorization design.
   - **Source-gen-driven policy name lookup** — replace startup reflection scan in `DefaultToolCallGuard` registration with a generated `name → factory` table.
   - **Policy timeout** — `opts.PolicyTimeout` with deny-on-timeout for I/O-bound policies.
   - **`opts.AuditAllows`** — opt-in compliance mode that also audits Allow decisions.
   - **`[Authorize]` attribute discovery for AIFunction-bound methods** — translate method-level `[Authorize("policy")]` to a `RequireToolPolicy(funcName, "policy")` binding at registration time. (Deferred from Task 8 to keep the in-process surface scope tight.)

**Step 3: Run the full test suite**

```
dotnet build
dotnet test tests/AI.Sentinel.Tests
dotnet test tests/AI.Sentinel.AspNetCore.Tests
dotnet test tests/AI.Sentinel.ClaudeCode.Tests
dotnet test tests/AI.Sentinel.Copilot.Tests
dotnet test tests/AI.Sentinel.Mcp.Tests
```
Expected: all pass.

**Step 4: Commit**

```bash
git add README.md docs/BACKLOG.md
git commit -m "docs: tool-call authorization README section + backlog cleanup + follow-ups"
```

---

## Final review checklist

After Task 13, dispatch the `superpowers:code-reviewer` agent for a full implementation review against:
- The design doc at [docs/plans/2026-04-25-tool-call-authorization-design.md](2026-04-25-tool-call-authorization-design.md)
- This implementation plan
- Existing AI.Sentinel conventions (no XML docs noise, no over-engineering, no comments that just describe the code, ZeroAlloc.Inject `[Singleton]` pattern)

Then run `superpowers:finishing-a-development-branch`.
