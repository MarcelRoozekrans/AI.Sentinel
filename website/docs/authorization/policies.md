---
sidebar_position: 2
title: Policies
---

# Writing authorization policies

An `IAuthorizationPolicy` is a stateless decision class. Decorate it with `[AuthorizationPolicy("name")]`, register it in DI, and bind it to one or more tool-name patterns via `opts.RequireToolPolicy(pattern, name)`.

## The contract

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
```

`ISecurityContext` carries the caller's identity:

```csharp
public interface ISecurityContext
{
    string? UserId { get; }
    string? TenantId { get; }
    IReadOnlyCollection<string> Roles { get; }
    IReadOnlyDictionary<string, string> Claims { get; }
}
```

The default `AnonymousSecurityContext` returns empty/null for everything. To plug in real identity, register your own `ISecurityContext` implementation:

```csharp
public sealed class HttpContextSecurityContext(IHttpContextAccessor accessor) : ISecurityContext
{
    public string? UserId => accessor.HttpContext?.User.FindFirst("sub")?.Value;
    public string? TenantId => accessor.HttpContext?.User.FindFirst("tenant_id")?.Value;
    public IReadOnlyCollection<string> Roles => accessor.HttpContext?.User
        .FindAll(ClaimTypes.Role).Select(c => c.Value).ToHashSet() ?? new HashSet<string>();
    public IReadOnlyDictionary<string, string> Claims => /* materialize from User.Claims */;
}

services.AddSingleton<ISecurityContext, HttpContextSecurityContext>();
```

For non-HTTP surfaces (Claude Code hook, MCP proxy), use the surface-specific provider — see [Authorization → overview](./overview#per-surface-deny-semantics).

## Common patterns

### Role-based

```csharp
[AuthorizationPolicy("admin-only")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => ctx.Roles.Contains("admin");
}

services.AddSingleton<IAuthorizationPolicy, AdminOnlyPolicy>();
services.AddAISentinel(opts =>
{
    opts.RequireToolPolicy("Bash",     "admin-only");
    opts.RequireToolPolicy("delete_*", "admin-only");
});
```

### Tenant-scoped

```csharp
[AuthorizationPolicy("same-tenant")]
public sealed class SameTenantPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx)
    {
        // Tenant ID must be present — block any caller without a resolved tenant
        return !string.IsNullOrEmpty(ctx.TenantId);
    }
}

// Bind to all tenant-aware tools
opts.RequireToolPolicy("query_*",     "same-tenant");
opts.RequireToolPolicy("update_*",    "same-tenant");
```

For tools where the *target tenant* must match the caller's tenant, the check needs the tool's argument context — that's not surfaced to `IAuthorizationPolicy` in v1. Use a custom `IToolCallGuard` for cases needing argument inspection (or wait for the Phase B per-call-context API).

### Allow-list authentication

```csharp
[AuthorizationPolicy("authenticated")]
public sealed class AuthenticatedPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => !string.IsNullOrEmpty(ctx.UserId);
}

services.AddAISentinel(opts =>
{
    opts.DefaultToolPolicy = ToolPolicyDefault.Deny;       // strict deny
    opts.RequireToolPolicy("*", "authenticated");          // allow only authenticated callers
    opts.RequireToolPolicy("delete_*", "admin-only");      // additional check for delete
});
```

`*` catches every tool name that doesn't match a more-specific binding. With `DefaultToolPolicy = Deny`, you have to whitelist explicitly — useful for highly-restricted internal agents.

### Multi-policy AND

When multiple bindings match a tool call, **all matching policies must authorize**:

```csharp
opts.RequireToolPolicy("delete_*",     "admin-only");
opts.RequireToolPolicy("delete_*",     "same-tenant");
// delete_user requires BOTH: admin role AND same-tenant
```

This is logical AND, not OR. To implement OR (caller is admin OR caller is in same tenant), write a composite policy:

```csharp
[AuthorizationPolicy("admin-or-same-tenant")]
public sealed class AdminOrSameTenantPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) =>
        ctx.Roles.Contains("admin") || !string.IsNullOrEmpty(ctx.TenantId);
}
```

### Time-of-day / business-hours

Stateless implies "no instance state" — but reading the clock and checking ambient context is fine:

```csharp
[AuthorizationPolicy("business-hours")]
public sealed class BusinessHoursPolicy(TimeProvider clock) : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx)
    {
        var now = clock.GetLocalNow();
        var weekday = now.DayOfWeek is not DayOfWeek.Saturday and not DayOfWeek.Sunday;
        var businessHours = now.Hour is >= 9 and < 18;
        return weekday && businessHours;
    }
}
```

Useful for "destructive operations only allowed when humans are available to oversee".

### Step-up auth (claims-based)

```csharp
[AuthorizationPolicy("step-up-mfa")]
public sealed class StepUpMfaPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) =>
        ctx.Claims.TryGetValue("mfa_recent", out var recent)
            && DateTimeOffset.TryParse(recent, out var when)
            && DateTimeOffset.UtcNow - when < TimeSpan.FromMinutes(5);
}
```

The caller's identity provider would write `mfa_recent` after a successful step-up challenge. Tools tagged with this policy require fresh MFA — for high-stakes actions like changing passwords, transferring funds, or firing destructive operations.

## What NOT to put in a policy

- **No external IO** — policies are sync today. Async lookups (tenant resolver, IdP call) need to happen at request-boundary, with results cached on `ISecurityContext`.
- **No state** — the framework treats policies as singletons. Don't store per-request state in the policy class.
- **No exceptions for routine deny** — return `false`, don't throw. Throwing is treated as a policy bug, not a deny signal.

## Testing policies

Policies are stateless and trivially unit-testable:

```csharp
[Fact]
public void AdminOnly_AllowsAdminRole()
{
    var policy = new AdminOnlyPolicy();
    var ctx = new TestSecurityContext { Roles = new[] { "admin" } };
    Assert.True(policy.IsAuthorized(ctx));
}

[Fact]
public void AdminOnly_DeniesNonAdmin()
{
    var policy = new AdminOnlyPolicy();
    var ctx = new TestSecurityContext { Roles = new[] { "user" } };
    Assert.False(policy.IsAuthorized(ctx));
}

private sealed class TestSecurityContext : ISecurityContext
{
    public string? UserId { get; init; }
    public string? TenantId { get; init; }
    public IReadOnlyCollection<string> Roles { get; init; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, string> Claims { get; init; } = new Dictionary<string, string>();
}
```

For end-to-end tests of the binding wiring (does `RequireToolPolicy("delete_*", "admin-only")` actually deny?), use a real DI container with a stub `ISecurityContext` and invoke `IToolCallGuard.IsAllowed` directly:

```csharp
var services = new ServiceCollection();
services.AddSingleton<ISecurityContext>(new TestSecurityContext { Roles = new[] { "user" } });
services.AddSingleton<IAuthorizationPolicy, AdminOnlyPolicy>();
services.AddAISentinel(opts =>
{
    opts.RequireToolPolicy("delete_*", "admin-only");
});
var sp = services.BuildServiceProvider();
var guard = sp.GetRequiredService<IToolCallGuard>();
var allowed = await guard.IsAllowedAsync("delete_user", arguments: null, ct: CancellationToken.None);
Assert.False(allowed);
```

## Future: PIM-style approval workflow

A `RequireApproval` decision tier is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md) — for high-stakes tools where a yes/no policy isn't enough and you want time-bound approval grants with a human-in-the-loop dashboard. Phase B feature; would integrate with the existing `IAuthorizationPolicy` machinery.

## Next: [Cookbook → multi-tenant](../cookbook/multi-tenant)
