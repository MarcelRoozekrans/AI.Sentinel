---
sidebar_position: 1
title: Overview
---

# Authorization overview

AI.Sentinel has two complementary pillars:

| Pillar | Purpose | Decides... |
|---|---|---|
| **Detection** | Classify what happened — prompt injection, PII leak, hallucination | Severity (None / Low / Medium / High / Critical) |
| **Authorization** | Decide what's *allowed to happen* before it does | Allow / Deny on a per-tool-call basis |

Detection answers "is this content dangerous?". Authorization answers "is this caller allowed to invoke this tool?". They run on different signals, at different lifecycle points, and address different threats.

## `IToolCallGuard`

`IToolCallGuard` is the authorization runtime. Every tool call across all four AI.Sentinel surfaces (in-process middleware, Claude Code hook, Copilot hook, MCP proxy) routes through it. The decision model is binary — `Allow` or `Deny` — based on a configured `IAuthorizationPolicy` matched against the tool name.

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
    opts.DefaultToolPolicy = ToolPolicyDefault.Allow;  // default
});

builder.Services.AddChatClient(pipeline =>
    pipeline.UseAISentinel()
            .UseToolCallAuthorization()      // wires IToolCallGuard into the pipeline
            .UseFunctionInvocation()
            .Use(new OpenAIChatClient(...)));
```

## Concepts

| Type | Purpose |
|---|---|
| `IAuthorizationPolicy` | Implementation that evaluates "is this caller authorized?". Stateless, attribute-decorated with `[AuthorizationPolicy("name")]`. |
| `[AuthorizationPolicy("name")]` | Attribute that names the policy. Used by `RequireToolPolicy(pattern, "name")` to wire it up. |
| `ISecurityContext` | The caller identity. Carries roles, tenant ID, user ID, claims. Default implementation returns Anonymous. |
| `ToolPolicyDefault` | What happens when a tool call doesn't match any binding — `Allow` (default) or `Deny`. |
| `IToolCallGuard` | The runtime that pulls the right policies, evaluates them, and emits a decision. |

## Decision flow

```
1. Tool call invoked → "Bash" with arguments {...}
2. Guard looks up bindings: opts.RequireToolPolicy("Bash", "admin-only") matches
3. Guard resolves the "admin-only" policy via [AuthorizationPolicy] attribute scan
4. Guard resolves ISecurityContext from DI (or surface-specific provider)
5. Guard calls policy.IsAuthorized(ctx)
6. Allow → tool executes
   Deny → tool execution short-circuited, surface-specific deny semantics applied
```

If multiple bindings match a single tool call, **all matching policies must authorize** (logical AND). If no bindings match, `DefaultToolPolicy` decides.

## Wildcards in bindings

`RequireToolPolicy` accepts glob-style wildcards in the tool-name pattern:

```csharp
opts.RequireToolPolicy("delete_*",     "admin-only");      // delete_user, delete_database, ...
opts.RequireToolPolicy("get_*",        "read-only");       // get_user, get_invoice, ...
opts.RequireToolPolicy("Bash",         "admin-only");      // exact match
opts.RequireToolPolicy("*",            "any-authenticated"); // catch-all (overlaps with DefaultToolPolicy)
```

Wildcards don't anchor — `delete_*` matches `delete_user` and `delete_database` but not `user_delete`.

## Default behavior

If no policies are registered, **every tool call is allowed** — drop-in upgrade for existing AI.Sentinel users. No surprises, no breaking change.

If policies are registered but `DefaultToolPolicy = Deny`, calls without a matching binding are denied. This is the strict-deny pattern: explicitly allow what you want, deny everything else.

## Per-surface deny semantics

Each surface signals deny in its native way:

| Surface | Caller resolution | Deny semantics |
|---|---|---|
| In-process middleware | `IServiceProvider.GetService<ISecurityContext>()` → Anonymous | throws `ToolCallAuthorizationException` |
| Claude Code hook | `HookConfig.CallerContextProvider` → Anonymous | `HookOutput(Block, reason)` (exit code 2) |
| Copilot hook | `CopilotHookConfig.CallerContextProvider` → Anonymous | `HookOutput(Block, reason)` (exit code 2) |
| MCP proxy | DI provider → `SENTINEL_MCP_CALLER_ID/_ROLES` env → Anonymous | `McpProtocolException(InvalidRequest, reason)` |

The same policy implementation works on all four surfaces — write the policy once, AI.Sentinel handles surface-specific signaling.

## Why authorization vs. detection

Detection runs on **content**. It asks "does this prompt or response look like a threat?" — pattern matching, semantic similarity, hallucination heuristics. False positives are tolerable because the action tier (Quarantine / Alert / Log / PassThrough) is configurable per severity.

Authorization runs on **caller identity**. It asks "is this principal allowed to invoke this tool?" — a hard yes/no. It runs whether or not the call's content looks suspicious. A junior dev's `Bash` invocation is denied even when the bash command is benign — because they're not in the `admin` role.

In layered defense:

| Threat | Pillar that catches it |
|---|---|
| Prompt injection inside an `echo "hello"` call | Detection (`SEC-01`) |
| PII inside a tool result | Detection (`SEC-23`) |
| Junior dev invoking `delete_database()` | **Authorization** |
| External user reaching restricted MCP tool via the proxy | **Authorization** |
| Compromised LLM convincing the model to call a privileged tool | Detection (catches the prompt-injection signal) AND Authorization (catches the unauthorized call attempt) |

## Phase A limitations

Per the [Configuration → Named pipelines](../configuration/named-pipelines#phase-a-limitations) doc, **tool-call authorization is global, not per-named-pipeline.** Calling `opts.RequireToolPolicy(...)` on a named pipeline is silently ignored — only the default pipeline's bindings are consulted by `IToolCallGuard`.

For multi-tenant authorization where different named pipelines need different policies, pre-Phase B you wire surface-specific `ISecurityContext` resolution and use a single shared binding set on the default pipeline. Per-name auth bindings are on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md).

## Where it lives

| Component | Type |
|---|---|
| Policy registration | `services.AddSingleton<IAuthorizationPolicy, MyPolicy>()` (DI) |
| Policy naming | `[AuthorizationPolicy("name")]` attribute |
| Tool-name binding | `opts.RequireToolPolicy(pattern, name)` on `SentinelOptions` |
| Default policy | `opts.DefaultToolPolicy = ToolPolicyDefault.Allow / Deny` |
| Caller identity | `ISecurityContext` — register your implementation in DI |
| Runtime | `IToolCallGuard` (default `DefaultToolCallGuard`) — resolved by the framework |
| Pipeline wiring | `.UseToolCallAuthorization()` on the chat client builder, before `.UseFunctionInvocation()` |

## Async policies

`IAuthorizationPolicy.IsAuthorized` is **synchronous** in v1. For policies that need async resolution (tenant lookup, OPA call, external IdP), the work-around is to cache async results in `ISecurityContext` at request boundary so the policy itself reads from a pre-populated cache.

A `Task<bool> IsAuthorizedAsync(ISecurityContext ctx)` overload is on the [backlog](https://github.com/MarcelRoozekrans/AI.Sentinel/blob/main/docs/BACKLOG.md). Coordinated with the planned `ZeroAlloc.Mediator.Authorization` design before changing the interface.

## Next: [Policies](./policies) — writing IAuthorizationPolicy implementations + common patterns
