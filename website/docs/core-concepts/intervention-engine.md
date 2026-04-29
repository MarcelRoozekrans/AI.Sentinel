---
sidebar_position: 3
title: Intervention engine
---

# Intervention engine

`InterventionEngine` decides what to do when a detection fires. It maps the highest fired severity to a `SentinelAction` based on `SentinelOptions.OnCritical`/`OnHigh`/`OnMedium`/`OnLow` and applies it.

## Action types

```csharp
public enum SentinelAction
{
    PassThrough,    // do nothing — audit only
    Log,            // write to ILogger
    Alert,          // publish IMediator notification + invoke IAlertSink
    Quarantine,     // throw SentinelException — caller must catch
}
```

## Configuration

```csharp
services.AddAISentinel(opts =>
{
    opts.OnCritical = SentinelAction.Quarantine;
    opts.OnHigh     = SentinelAction.Alert;
    opts.OnMedium   = SentinelAction.Log;
    opts.OnLow      = SentinelAction.Log;
});
```

Defaults if you don't set them: all four are `Log`. That's a deliberately conservative default — the framework won't break your app out of the box; you opt into stricter actions.

## How the engine picks an action

```
1. Pipeline returns PipelineResult { Score, Detections }
2. Engine finds MaxSeverity = Detections.Max(d => d.Severity)
3. Engine looks up the action for MaxSeverity:
     Critical → opts.OnCritical
     High     → opts.OnHigh
     Medium   → opts.OnMedium
     Low      → opts.OnLow
     None     → no action (Clean — never reaches the engine)
4. Engine invokes the action's effect
```

There's no per-detector action override at the engine layer — every Critical-severity finding triggers the same `OnCritical` action regardless of which detector emitted it. To get per-detector behaviour, use [`Configure<T>(c => c.SeverityCap = Severity.Low)`](../configuration/fluent-config) to clamp a noisy detector down so it never reaches the higher action tier.

## Action effects

### `PassThrough`

No-op. The pipeline result is still appended to the audit store, but no exception, no log entry, no alert. Useful when you want detection telemetry without operational disruption — e.g., during initial rollout to gauge false-positive rates.

### `Log`

Calls `ILogger<InterventionEngine>.LogWarning`:

```
warn: AI.Sentinel.Intervention.InterventionEngine
      AI.Sentinel: severity=Medium detector=SEC-23 reason="PII: SSN pattern" session=abc-123
```

Standard logger plumbing — route to your logging pipeline (Serilog, console, Application Insights, etc.).

### `Alert`

Two effects, both fire-and-forget:

1. **`IMediator` notification** — if the DI container has an `IMediator` (ZeroAlloc.Mediator or MediatR-compatible), publishes:
   ```csharp
   readonly record struct ThreatDetectedNotification(
       SessionId      SessionId,
       AgentId        SenderId,
       AgentId        ReceiverId,
       PipelineResult PipelineResult,
       DateTimeOffset DetectedAt);

   readonly record struct InterventionAppliedNotification(
       SessionId      SessionId,
       SentinelAction Action,
       Severity       Severity,
       string         Reason,
       DateTimeOffset AppliedAt);
   ```
   Wire handlers via your Mediator's normal registration. Use this for cross-cutting concerns: page on-call, write to incident management, kick off automated remediation.

2. **`IAlertSink.SendAsync`** — pushes the alert to a configured sink. Default `NullAlertSink`. If `opts.AlertWebhook` is set, AI.Sentinel registers `WebhookAlertSink` automatically:
   ```csharp
   opts.AlertWebhook = new Uri("https://hooks.slack.com/services/...");
   ```
   The webhook payload is a JSON envelope describing the alert. A `DeduplicatingAlertSink` decorator collapses duplicate alerts within a configurable window (default 5 min) so a noisy session doesn't spam your channel.

### `Quarantine`

Throws `SentinelException`. The exception carries the firing `PipelineResult` so callers can inspect what fired:

```csharp
try
{
    var response = await chatClient.GetResponseAsync(messages);
}
catch (SentinelException ex)
{
    var result = ex.PipelineResult;
    var firingDetectors = result.Detections.Select(d => d.DetectorId.Value);
    logger.LogWarning("Blocked: {Severity}. Detectors: {Detectors}",
        result.MaxSeverity, string.Join(", ", firingDetectors));

    return BadRequest("Your request was blocked by the security middleware.");
}
```

For pass 1 (prompt scan), the inner LLM call is skipped — no token cost. For pass 2 (response scan), the LLM call has already happened (token cost paid) but the response never reaches the user.

## Audit happens regardless

Every action — including `PassThrough` — produces an audit entry. The intervention engine and the audit pipeline are decoupled; quarantining doesn't suppress audit, and pass-through doesn't skip audit. This is intentional: forensic investigation needs the full record even for low-severity hits you chose not to act on.

## Per-pipeline isolation

In [named-pipeline setups](../configuration/named-pipelines), each pipeline has its own `InterventionEngine` instance with its own action map. So:

```csharp
services.AddAISentinel("strict", opts => opts.OnHigh = SentinelAction.Quarantine);
services.AddAISentinel("lenient", opts => opts.OnHigh = SentinelAction.Log);
```

…produces two engines that respond differently to the same severity. The shared `IAlertSink` and `IAuditStore` see all of them.

## Custom actions

The four action types are fixed today. If you need something else (e.g., redirect to a fallback model on `Quarantine`, or run a remediation task on `Alert`), use the **`IMediator` notification** pattern:

```csharp
public sealed class RouteToFallbackHandler : INotificationHandler<InterventionAppliedNotification>
{
    public ValueTask Handle(InterventionAppliedNotification n, CancellationToken ct)
    {
        if (n.Action == SentinelAction.Alert && n.Severity >= Severity.High)
        {
            // route to fallback, queue a follow-up task, etc.
        }
        return ValueTask.CompletedTask;
    }
}
```

`SentinelAction.Reroute` (redirect to a fallback agent) is on the [backlog](https://github.com/ZeroAlloc-Net/AI.Sentinel/blob/main/docs/BACKLOG.md).

## Next: [Audit store](./audit-store)
