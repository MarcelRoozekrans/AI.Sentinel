---
sidebar_position: 1
title: Multi-tenant
---

# Multi-tenant cookbook

For SaaS apps where different tenants need different detector configurations or different action policies. Phase A solves this via [named pipelines](../configuration/named-pipelines) + chat-client-per-tenant routing. Phase B will add request-time selectors when a real user need surfaces.

## Pattern 1 — One chat client per tenant tier

Most SaaS apps don't need per-tenant pipelines — they need per-**tier** pipelines. Free tier gets lenient action; paid tier gets strict action; enterprise tier gets quarantine + dedicated audit.

```csharp
services.AddAISentinel(opts =>
{
    // Shared base config
    opts.EmbeddingGenerator = realGen;
    opts.AuditCapacity = 50_000;
});

services.AddAISentinel("tier-free", opts =>
{
    opts.OnCritical = SentinelAction.Log;
    opts.OnHigh     = SentinelAction.Log;
    opts.Configure<JailbreakDetector>(c => c.Enabled = false);  // free tier doesn't get jailbreak detection
});

services.AddAISentinel("tier-paid", opts =>
{
    opts.OnCritical = SentinelAction.Alert;
    opts.OnHigh     = SentinelAction.Log;
    opts.Configure<JailbreakDetector>(c => c.SeverityFloor = Severity.High);
});

services.AddAISentinel("tier-enterprise", opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.OnHigh     = SentinelAction.Alert;
    opts.Configure<PiiLeakageDetector>(c => c.SeverityFloor = Severity.High);
});

// Three chat clients, one per tier
services.AddChatClient("free", b =>
    b.UseAISentinel("tier-free").Use(new OpenAIChatClient(/* free-tier model */)));
services.AddChatClient("paid", b =>
    b.UseAISentinel("tier-paid").Use(new OpenAIChatClient(/* paid-tier model */)));
services.AddChatClient("enterprise", b =>
    b.UseAISentinel("tier-enterprise").Use(new OpenAIChatClient(/* enterprise-tier model */)));
```

Then in your request handler, resolve the right `IChatClient` based on the tenant's tier:

```csharp
public sealed class ChatController(IServiceProvider sp) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Chat(ChatRequest req, CancellationToken ct)
    {
        var tier = await tenantService.GetTierAsync(User.GetTenantId());
        var client = sp.GetRequiredKeyedService<IChatClient>(tier);  // "free" / "paid" / "enterprise"
        var response = await client.GetResponseAsync(req.Messages, ct: ct);
        return Ok(response);
    }
}
```

This works today (Phase A) without any custom routing logic. The chat client picks its pipeline at construction; tenant routing is at the request level.

## Pattern 2 — One pipeline, tenant-scoped audit

If all tenants share the same detection rules but need separate audit destinations:

```csharp
services.AddAISentinel(opts => /* shared detection config */);

// One audit forwarder that pivots on tenant ID at write time
public sealed class TenantAwareAuditForwarder(ITenantContext tenant) : IAuditForwarder
{
    public ValueTask SendAsync(AuditEntry entry, CancellationToken ct)
    {
        var tenantId = tenant.GetCurrentTenantId();
        // Push to tenant-specific destination
        return PushToTenantSiem(tenantId, entry, ct);
    }
}

services.AddSingleton<IAuditForwarder, TenantAwareAuditForwarder>();
```

`ITenantContext` is your application's per-request tenant resolver (typically scoped to `IHttpContextAccessor`). The forwarder is shared but routes per-call.

This pattern is simpler than per-tenant pipelines if your detection logic is uniform across tenants — only the audit destination varies.

## Pattern 3 — Per-tenant authorization

Use `ISecurityContext` to surface tenant ID, then write policies that check it:

```csharp
public sealed class HttpTenantSecurityContext(IHttpContextAccessor accessor) : ISecurityContext
{
    public string? UserId => accessor.HttpContext?.User.FindFirst("sub")?.Value;
    public string? TenantId => accessor.HttpContext?.User.FindFirst("tenant_id")?.Value;
    public IReadOnlyCollection<string> Roles => accessor.HttpContext?.User
        .FindAll(ClaimTypes.Role).Select(c => c.Value).ToHashSet() ?? new HashSet<string>();
    public IReadOnlyDictionary<string, string> Claims => /* materialize */;
}

[AuthorizationPolicy("same-tenant")]
public sealed class SameTenantPolicy : IAuthorizationPolicy
{
    public bool IsAuthorized(ISecurityContext ctx) => !string.IsNullOrEmpty(ctx.TenantId);
}

services.AddSingleton<ISecurityContext, HttpTenantSecurityContext>();
services.AddSingleton<IAuthorizationPolicy, SameTenantPolicy>();
services.AddAISentinel(opts =>
{
    opts.RequireToolPolicy("query_*", "same-tenant");
    opts.RequireToolPolicy("update_*", "same-tenant");
});
```

Authorization runs against `ISecurityContext` per call, so this works with a single shared pipeline. See [Authorization → policies](../authorization/policies) for more patterns.

**Phase A limitation:** tool-call authorization is global, not per-named-pipeline. If different tenant tiers need different authorization rules, you can't split them per pipeline today — Phase B will lift this restriction.

## Anti-pattern — N pipelines for N tenants

Don't create one named pipeline per tenant in a multi-tenant app:

```csharp
// ❌ Don't do this — registration explodes with tenant count
foreach (var tenant in tenants)
{
    services.AddAISentinel($"tenant-{tenant.Id}", opts => ApplyTenantConfig(opts, tenant));
}
```

Pipelines are configured at startup. New tenants would require a restart. Storage cost is per-pipeline (each has its own `IDetectionPipeline`, `InterventionEngine`). 1000 tenants → 1000 pipelines is wasteful and brittle.

If you genuinely need per-tenant detection rules (rare), the right pattern is:

- **Named pipelines for tiers** (free / paid / enterprise) — small, fixed set
- **Per-tenant authorization** via `ISecurityContext` + policies
- **Per-tenant audit routing** via a tenant-aware forwarder

For the truly tenant-specific case ("Tenant A wants PII detection disabled, Tenant B wants it Critical"), the Phase B request-time selector is the right primitive.

## Phase B preview — request-time selector

Today the pipeline is fixed at chat-client construction. Phase B will add a `Func<RequestContext, string>` selector that resolves the named pipeline per request:

```csharp
// Future API — Phase B, not in v1
services.AddAISentinel(req =>
{
    var tier = req.Headers["X-Tenant-Tier"].ToString();
    return tier switch
    {
        "enterprise" => "tier-enterprise",
        "paid"       => "tier-paid",
        _            => "tier-free",
    };
});
```

This will let one chat client serve all tenants with the right pipeline picked per call. Tracking [in the backlog](https://github.com/ZeroAlloc-Net/AI.Sentinel/blob/main/docs/BACKLOG.md) under "Per-pipeline configuration Phase B".

## Audit sharing across tenants

In Phase A, audit infrastructure is **shared** across all named pipelines — one `IAuditStore`, one set of forwarders. For multi-tenant deployments where tenant audit data must be isolated:

| Constraint | Approach |
|---|---|
| Shared infra OK, tenant ID in entries | Default — every audit entry already includes session ID; add tenant ID via `SentinelContextBuilder.WithSender(new AgentId($"tenant:{tenantId}"))` if you want it explicit in the audit record |
| Per-tenant database files | Wire a custom `IAuditStore` that pivots on `ITenantContext` and writes to per-tenant SQLite files |
| Per-tenant SIEM destinations | Custom `IAuditForwarder` (see Pattern 2 above) |
| Hard isolation guarantees (compliance) | Wait for Phase B per-name audit isolation — or run separate AI.Sentinel instances per tenant tier |

## Next: [Dev / staging / prod](./dev-staging-prod) — same patterns at the environment-tier level
