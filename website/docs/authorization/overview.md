---
sidebar_position: 1
title: Overview
---

# Authorization overview

A new pillar alongside detectors: **preventive controls** at the tool-call boundary. Detectors classify what happened; authorization decides what is *allowed to happen*.

`IToolCallGuard` evaluates incoming tool calls against registered policies. Bind tools to policies via `opts.RequireToolPolicy(pattern, policyName)`:

```csharp
services.AddAISentinel(opts =>
{
    opts.DefaultToolPolicy = ToolPolicyDefault.Allow;
    opts.RequireToolPolicy("admin/*", "AdminOnly");
    opts.RequireToolPolicy("delete_*", "AdminOnly");
});
```

Implement `IAuthorizationPolicy` and decorate with `[AuthorizationPolicy("AdminOnly")]`:

```csharp
[AuthorizationPolicy("AdminOnly")]
public sealed class AdminOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => ctx.IsInRole("admin");
}
```

> Full authorization guide — coming soon. See [Policies](./policies).
