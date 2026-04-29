---
sidebar_position: 2
title: Policies
---

# Authorization policies

Policies are stateless `IAuthorizationPolicy` implementations decorated with `[AuthorizationPolicy("name")]`. The framework's `DefaultToolCallGuard` registers all discovered policies at startup and routes tool calls through the configured bindings.

```csharp
[AuthorizationPolicy("ReadOnly")]
public sealed class ReadOnlyPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) =>
        !ctx.IsInRole("write");  // anyone NOT in 'write' can read-only
}
```

Bind it:

```csharp
opts.RequireToolPolicy("read_*", "ReadOnly");
opts.RequireToolPolicy("query_*", "ReadOnly");
```

Multiple bindings can match a single tool call — all matching policies must authorize.

> Full policy guide — coming soon. Roadmap: async policies, policy timeouts, audit-of-allow-decisions, PIM-style approval workflows.
